-- MCP agent API key management from the web app's User Management overlay
-- (2026-09-26, branch feat/agent-keys-admin). See docs/SECURITY.md's
-- "Agent key admin" entry for the design and why it is shaped this way.
--
-- ONE implementation of issue/revoke/list, in Postgres, shared by both callers:
--
--   agent_key_issue / agent_key_revoke / agent_key_list
--     The implementation. Owner-only: EXECUTE is revoked from every API role,
--     so they are unreachable through PostgREST. scripts/agent-keys.mjs calls
--     them directly as the owner (DATABASE_URL), exactly as it used to run its
--     own SQL.
--
--   admin_issue_agent_key / admin_revoke_agent_key / admin_list_agent_keys
--     Thin wrappers for the browser (`sb.rpc(...)`), EXECUTE for
--     `authenticated` only. Each checks is_admin_user() itself -- the same
--     predicate behind admin_manages_profiles, i.e. the User Management gate --
--     so a non-admin calling the RPC directly gets 42501, whatever the UI shows.
--     admin_issue_agent_key additionally requires a password or Google sign-in
--     within the last 10 minutes (the JWT's `amr` claim), and records
--     created_by from the caller's own signed JWT, never a client string.
--
-- agent_api_keys / agent_api_key_calls stay exactly as 20260926150001 left
-- them: RLS on, zero policies, no grants to anon/authenticated/service_role.
-- Nothing here grants table access to anyone.
--
-- The plaintext key is generated INSIDE agent_key_issue (32 bytes from
-- pgcrypto's gen_random_bytes, the OpenSSL CSPRNG), so it never appears in
-- statement text (statement/slow-query logs, pg_stat_statements) -- only in
-- the single result row returned to the caller. Only its SHA-256 is stored.
-- The key shape is unchanged: "mtk_" + base64url(32 bytes) = 43 chars, the
-- exact form supabase/functions/mcp/auth.ts's KEY_PATTERN accepts, and the
-- hash is sha256 of the key's UTF-8 bytes, the exact form mcp_authenticate()
-- compares against (tests/agent-keys-sql.test.mjs pins both).

-- pgcrypto already lives in `extensions` on Supabase; this is a no-op there
-- and makes the dependency explicit.
create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------------
-- The implementation (owner-only)
-- ---------------------------------------------------------------------------

-- Eligibility mirrors mcp_authenticate()'s explicit allowlist (approved +
-- operator/customer), so a key is never issued that the gateway would reject.
-- p_allow_unapproved exists only for the CLI's negative-test flag.
create function public.agent_key_issue(
  p_user_id uuid,
  p_label text,
  p_days integer,
  p_created_by text,
  p_allow_unapproved boolean default false
)
returns table (id uuid, key text, key_prefix text, label text, expires_at timestamptz, account_role text, account_status text)
language plpgsql
volatile
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
  v_role text;
  v_status text;
  v_key text;
begin
  if p_user_id is null then
    raise exception 'a linked account is required' using errcode = '22023';
  end if;
  if nullif(trim(p_label), '') is null then
    raise exception 'a label is required' using errcode = '22023';
  end if;
  if length(trim(p_label)) > 100 then
    raise exception 'label must be 100 characters or fewer' using errcode = '22023';
  end if;
  if p_days is null or p_days < 1 or p_days > 365 then
    raise exception 'expiry must be from 1 to 365 days' using errcode = '22023';
  end if;

  select p.role, p.status into v_role, v_status from public.user_profiles p where p.id = p_user_id;
  if not found then
    raise exception 'no user_profiles row for %', p_user_id using errcode = '22023';
  end if;
  if not (v_status = 'approved' and v_role in ('operator', 'customer')) and not coalesce(p_allow_unapproved, false) then
    raise exception 'account % is %/%; mcp_authenticate() would reject this key', p_user_id, v_role, v_status
      using errcode = '22023';
  end if;

  -- base64 of 32 bytes is 44 chars with one '=' pad and no line break;
  -- translate() maps +/ to -_ and deletes any \n defensively.
  v_key := 'mtk_' || rtrim(translate(encode(extensions.gen_random_bytes(32), 'base64'), E'+/\n', '-_'), '=');

  return query
  insert into public.agent_api_keys as k (user_id, label, key_prefix, key_hash, created_by, expires_at)
  values (
    p_user_id,
    trim(p_label) || ' [user ' || left(p_user_id::text, 8) || ']',
    left(v_key, 12),
    sha256(convert_to(v_key, 'UTF8')),
    p_created_by,
    now() + make_interval(days => p_days)
  )
  returning k.id, v_key, k.key_prefix, k.label, k.expires_at, v_role, v_status;
end;
$$;

-- Zero rows = unknown id or already revoked. The row is kept (revoked_at set),
-- never deleted, so the audit trail in agent_api_key_calls stays joined.
create function public.agent_key_revoke(p_id uuid)
returns table (id uuid, label text, key_prefix text, revoked_at timestamptz)
language sql
volatile
security definer
set search_path = ''
as $$
  update public.agent_api_keys k
     set revoked_at = now()
   where k.id = p_id
     and k.revoked_at is null
  returning k.id, k.label, k.key_prefix, k.revoked_at
$$;

-- Everything about a key EXCEPT key_hash. status is computed the way the CLI's
-- `list` always computed it. owner_eligible is whether mcp_authenticate()
-- would currently accept the owner (approved operator/customer) -- an
-- 'active' key whose owner has since been demoted or suspended does not work.
create function public.agent_key_list()
returns table (
  id uuid, label text, key_prefix text, user_id uuid,
  account_first_name text, account_last_name text, account_role text, account_status text,
  account_data_mode text, owner_eligible boolean,
  created_at timestamptz, created_by text, last_used_at timestamptz, expires_at timestamptz,
  revoked_at timestamptz, status text
)
language sql
stable
security definer
set search_path = ''
as $$
  select k.id, k.label, k.key_prefix, k.user_id,
         p.first_name, p.last_name, p.role, p.status, p.data_mode,
         coalesce(p.status = 'approved' and p.role in ('operator', 'customer'), false),
         k.created_at, k.created_by, k.last_used_at, k.expires_at, k.revoked_at,
         case when k.revoked_at is not null then 'revoked'
              when k.expires_at <= now() then 'expired'
              else 'active' end
    from public.agent_api_keys k
    left join public.user_profiles p on p.id = k.user_id
   order by k.created_at desc
$$;

-- ---------------------------------------------------------------------------
-- Admin wrappers (authenticated only, is_admin_user() enforced here)
-- ---------------------------------------------------------------------------

create function public.admin_list_agent_keys()
returns table (
  id uuid, label text, key_prefix text, user_id uuid,
  account_first_name text, account_last_name text, account_role text, account_status text,
  account_data_mode text, owner_eligible boolean,
  created_at timestamptz, created_by text, last_used_at timestamptz, expires_at timestamptz,
  revoked_at timestamptz, status text
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_admin_user() then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return query select * from public.agent_key_list();
end;
$$;

-- Fresh-auth rule: the caller's JWT must carry an `amr` entry with method
-- 'password' or 'oauth' stamped within the last 10 minutes.
--
-- What GoTrue actually writes (read from supabase/auth's source, 2026-09-26,
-- not assumed): each amr entry is {"method": <string>, "timestamp": <int unix
-- seconds>} (plus "provider" only for SAML SSO), built from the session's
-- auth.mfa_amr_claims rows, timestamp = the row's updated_at. A row is written
-- when a session is ISSUED -- password sign-in -> "password", Google (any
-- OAuth provider) sign-in -> "oauth" -- and on MFA verification. Token
-- refresh writes none: "token_refresh" is only passed to the access-token
-- hook, never stored, and amr is rebuilt from the stored rows. So an idle or
-- hijacked long-lived session cannot satisfy this; only a new sign-in can.
-- web/index.html's create-key form triggers one for the signed-in account:
-- signInWithPassword for the session's own email, or signInWithOAuth(google)
-- with prompt=select_account (the same call the sign-in screen makes) and a
-- login_hint of that email.
--
-- The server sees only the resulting token, not how it was obtained. The
-- Google path relies on the CLIENT requesting interactive account selection;
-- a compromised client could skip that -- the same trust boundary as the
-- password path, where a compromised client could replay a stored password.
-- 'oauth' is the only OAuth provider this project enables (Google). Anything
-- else fails closed: no amr (e.g. the MCP gateway's claims), a non-array, a
-- non-numeric timestamp, stale entries, or other methods (recovery, otp,
-- magiclink, ...).
create function public.admin_issue_agent_key(p_user_id uuid, p_label text, p_days integer default 90)
returns table (id uuid, key text, key_prefix text, label text, expires_at timestamptz)
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_amr jsonb := auth.jwt() -> 'amr';
  v_signed_in_at double precision;
begin
  if not public.is_admin_user() then
    raise exception 'forbidden' using errcode = '42501';
  end if;

  select max((e ->> 'timestamp')::double precision) into v_signed_in_at
    from jsonb_array_elements(case when jsonb_typeof(v_amr) = 'array' then v_amr else '[]'::jsonb end) e
   where e ->> 'method' in ('password', 'oauth')
     and jsonb_typeof(e -> 'timestamp') = 'number';
  if v_signed_in_at is null or to_timestamp(v_signed_in_at) < now() - interval '10 minutes' then
    raise exception 'recent sign-in required: re-enter your password or re-authenticate with Google to create a key'
      using errcode = '42501', hint = 'reauth_required';
  end if;

  return query
  select i.id, i.key, i.key_prefix, i.label, i.expires_at
    from public.agent_key_issue(
      p_user_id, p_label, p_days,
      coalesce(auth.jwt() ->> 'email', 'unknown email') || ' (' || auth.uid()::text || ') via web admin',
      false
    ) i;
end;
$$;

create function public.admin_revoke_agent_key(p_id uuid)
returns table (id uuid, label text, key_prefix text, revoked_at timestamptz)
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if not public.is_admin_user() then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return query select * from public.agent_key_revoke(p_id);
end;
$$;

-- ---------------------------------------------------------------------------
-- Grants. Functions default to EXECUTE for PUBLIC and Supabase's default
-- privileges also grant anon/authenticated/service_role explicitly, so revoke
-- from all four (mcp_reader/mcp_gateway only ever had PUBLIC's).
-- ---------------------------------------------------------------------------

revoke execute on function
  public.agent_key_issue(uuid, text, integer, text, boolean),
  public.agent_key_revoke(uuid),
  public.agent_key_list()
from public, anon, authenticated, service_role;

revoke execute on function
  public.admin_list_agent_keys(),
  public.admin_issue_agent_key(uuid, text, integer),
  public.admin_revoke_agent_key(uuid)
from public, anon, authenticated, service_role;

grant execute on function
  public.admin_list_agent_keys(),
  public.admin_issue_agent_key(uuid, text, integer),
  public.admin_revoke_agent_key(uuid)
to authenticated;

notify pgrst, 'reload schema';
