-- MCP agentic access (2026-09-26): API keys that resolve to a specific
-- user's own RLS context -- see docs/SECURITY.md's MCP entry and
-- supabase/functions/mcp/index.ts for the full request flow.
--
-- Only a SHA-256 hash of each key is stored, never the plaintext. The keys
-- are 32 random bytes (scripts/agent-keys.mjs), not human passwords, so a
-- fast hash is sufficient: there is no low-entropy input to brute-force.
--
-- Both tables are deliberately RLS-on with ZERO policies (deny-all), the
-- same permanent state docs/SECURITY.md's "RLS auto-enable gotcha" entry
-- records for stg_sensor_readings -- and, per that entry's two-gates
-- principle, ALSO revoked at the GRANT gate, because Supabase's default
-- privileges grant every new public table to anon/authenticated/
-- service_role. Nothing reads or writes these tables except the two
-- SECURITY DEFINER functions below and scripts/agent-keys.mjs (run by the
-- project owner directly against DATABASE_URL, never through PostgREST).

create table public.agent_api_keys (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references auth.users(id) on delete cascade,
  label        text not null,
  key_prefix   text not null,
  key_hash     bytea not null unique check (octet_length(key_hash) = 32),
  created_at   timestamptz not null default now(),
  created_by   text,
  last_used_at timestamptz,
  expires_at   timestamptz not null default now() + interval '90 days',
  revoked_at   timestamptz
);

create table public.agent_api_key_calls (
  id        bigint generated always as identity primary key,
  key_id    uuid not null references public.agent_api_keys(id) on delete cascade,
  tool      text not null,
  args      jsonb,
  called_at timestamptz not null default now(),
  is_error  boolean not null
);
create index agent_api_key_calls_key_called_idx on public.agent_api_key_calls (key_id, called_at desc);

alter table public.agent_api_keys enable row level security;
alter table public.agent_api_key_calls enable row level security;
revoke all on public.agent_api_keys from anon, authenticated, service_role;
revoke all on public.agent_api_key_calls from anon, authenticated, service_role;

-- Resolves a key hash (lowercase hex SHA-256, computed in the Edge Function
-- from the caller's bearer key) to the key id and the user it acts as.
-- Called by the function as mcp_gateway, BEFORE it switches to mcp_reader.
-- auth.uid() is null here (no claims set yet), so the role/approval check below
-- reads user_profiles directly, keyed off the key's own user_id.
-- Returns ZERO rows -- never an error that distinguishes the cases -- when
-- the key is unknown, revoked, expired, or bound to a user who is not an
-- approved operator/customer. The role check is an explicit allowlist, per
-- docs/SECURITY.md's "current_role_name() checks role, not approval" RULE,
-- so a future fourth status/role fails closed. It reads user_profiles
-- directly rather than calling current_role_name(), because auth.uid() is
-- null here (no claims are set yet) -- same predicate, keyed off the key's
-- user_id instead.
--
-- SECURITY DEFINER is a deliberate new entry on docs/SECURITY.md's
-- service-role-equivalent access points list: it is the only way the
-- mcp_gateway role (20260926150000) can see agent_api_keys at all. It exposes
-- nothing but (key_id, user_id) for a hash whose preimage the caller must
-- already hold. Not reachable through PostgREST: EXECUTE is granted to
-- mcp_gateway only, never anon/authenticated.
create function public.mcp_authenticate(p_key_hash text)
returns table (key_id uuid, user_id uuid)
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;

  return query
  update public.agent_api_keys k
     set last_used_at = now()
    from public.user_profiles p
   where k.key_hash = decode(p_key_hash, 'hex')
     and k.revoked_at is null
     and k.expires_at > now()
     and p.id = k.user_id
     and p.status = 'approved'
     and p.role in ('operator', 'customer')
  returning k.id, k.user_id;
end;
$$;

-- Appends one audit row per tools/call, called as mcp_gateway. Takes the key
-- HASH, not the key id, as proof of possession, so even the gateway role can
-- only log against a key whose plaintext it was actually presented with.
-- Re-checks the same active-key conditions as mcp_authenticate(). args is
-- capped so a caller can't use the log as unbounded storage.
create function public.mcp_log_call(p_key_hash text, p_tool text, p_args jsonb, p_is_error boolean)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;

  insert into public.agent_api_key_calls (key_id, tool, args, is_error)
  select k.id,
         left(coalesce(p_tool, ''), 100),
         case when length(coalesce(p_args, 'null'::jsonb)::text) > 4096
              then jsonb_build_object('truncated', true)
              else p_args end,
         coalesce(p_is_error, true)
    from public.agent_api_keys k
   where k.key_hash = decode(p_key_hash, 'hex')
     and k.revoked_at is null
     and k.expires_at > now();
end;
$$;

-- Functions default to EXECUTE for PUBLIC; narrow both to mcp_gateway only.
revoke execute on function public.mcp_authenticate(text) from public, anon, authenticated, service_role;
revoke execute on function public.mcp_log_call(text, text, jsonb, boolean) from public, anon, authenticated, service_role;
grant execute on function public.mcp_authenticate(text) to mcp_gateway;
grant execute on function public.mcp_log_call(text, text, jsonb, boolean) to mcp_gateway;
