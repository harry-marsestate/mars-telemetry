-- Security fix (2026-09-26, branch fix/mcp-auth-banned-users): a banned or
-- soft-deleted Supabase Auth user's MCP API keys kept working.
--
-- mcp_authenticate() checked the key (not revoked, not expired) and the
-- owner's user_profiles row (approved operator/customer) but never
-- auth.users. Banning someone in Supabase Auth during an incident -- which
-- does stop every GoTrue sign-in and token refresh (confirmed in
-- supabase/auth's source) -- left their mtk_ keys working, because the
-- gateway never touches GoTrue. Now a key whose owner has banned_until in the
-- future, or a deleted_at, fails exactly like a revoked key: zero rows from
-- mcp_authenticate(), the same indistinguishable 401, on the very next
-- request (nothing is cached).
--
-- Why in mcp_authenticate() rather than the Edge Function handler: it is the
-- single choke point every gateway request already passes, next to the
-- revoked/expired/approved predicates, so there's one definition of "usable
-- key". It runs SECURITY DEFINER as the owner, which can read auth.users;
-- doing it in the handler would mean granting the mcp_gateway role access to
-- auth.users, and that role deliberately has no table access at all
-- (docs/SECURITY.md, Option B'). No gateway code or deploy changes.
--
-- mcp_log_call() re-checks the same active-key conditions, so it gets the
-- same predicate. agent_key_issue() (eligibility, which mirrors
-- mcp_authenticate) refuses to issue a dead key for a banned/deleted owner,
-- and agent_key_list()'s owner_eligible now reflects it, so the web tab shows
-- such keys as "won't work". All four keep their exact signatures (create or
-- replace), so every existing GRANT stays as it is.

create or replace function public.mcp_authenticate(p_key_hash text)
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
    from public.user_profiles p, auth.users u
   where k.key_hash = decode(p_key_hash, 'hex')
     and k.revoked_at is null
     and k.expires_at > now()
     and p.id = k.user_id
     and p.status = 'approved'
     and p.role in ('operator', 'customer')
     and u.id = k.user_id
     and (u.banned_until is null or u.banned_until <= now())
     and u.deleted_at is null
  returning k.id, k.user_id;
end;
$$;

create or replace function public.mcp_log_call(p_key_hash text, p_tool text, p_args jsonb, p_is_error boolean)
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
    join auth.users u on u.id = k.user_id
   where k.key_hash = decode(p_key_hash, 'hex')
     and k.revoked_at is null
     and k.expires_at > now()
     and (u.banned_until is null or u.banned_until <= now())
     and u.deleted_at is null;
end;
$$;

create or replace function public.agent_key_issue(
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
  v_blocked boolean;
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
  select (u.banned_until is not null and u.banned_until > now()) or u.deleted_at is not null
    into v_blocked from auth.users u where u.id = p_user_id;
  if coalesce(v_blocked, true) and not coalesce(p_allow_unapproved, false) then
    raise exception 'account % is banned or deleted in Supabase Auth; mcp_authenticate() would reject this key', p_user_id
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

create or replace function public.agent_key_list()
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
         coalesce(p.status = 'approved' and p.role in ('operator', 'customer'), false)
           and u.id is not null and (u.banned_until is null or u.banned_until <= now()) and u.deleted_at is null,
         k.created_at, k.created_by, k.last_used_at, k.expires_at, k.revoked_at,
         case when k.revoked_at is not null then 'revoked'
              when k.expires_at <= now() then 'expired'
              else 'active' end
    from public.agent_api_keys k
    left join public.user_profiles p on p.id = k.user_id
    left join auth.users u on u.id = k.user_id
   order by k.created_at desc
$$;
