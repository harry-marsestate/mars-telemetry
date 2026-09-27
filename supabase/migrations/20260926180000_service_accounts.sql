-- Service accounts (2026-09-26, branch feat/agent-keys-admin): non-human
-- identities for AI agents' MCP API keys. See docs/SECURITY.md's "Service
-- accounts" entry.
--
-- A service account is an ordinary auth.users + user_profiles pair (keys must
-- link to one: the gateway resolves RLS and data_mode from the key owner on
-- every request), created only by scripts/service-accounts.mjs through the
-- Supabase Admin API as:
--   svc-<name>@service.invalid, email confirmed, NO password, no ban,
--   app_metadata.account_type = 'service'
-- Nobody can sign in as one: no password to enter, the .invalid address can't
-- receive a magic link / OTP / recovery email, and no Google account can have
-- it. No ban on purpose -- a ban now kills the owner's keys (20260926165000),
-- which keeps "ban" a uniform incident kill switch for every account.
--
-- Nothing in the gateway changes: mcp_authenticate() still checks the key,
-- approved operator/customer, and not banned/deleted; a service profile
-- satisfies that like any other, with its own role, customer scope and
-- data_mode.

-- ---------------------------------------------------------------------------
-- account_type: 'human' (default, every existing row) or 'service'.
-- ---------------------------------------------------------------------------
alter table public.user_profiles
  add column account_type text not null default 'human'
    constraint user_profiles_account_type_check check (account_type in ('human', 'service'));

-- A service account can never be an admin: is_admin grants the whole User
-- Management surface (every profile, every key). Enforced here, not just by
-- hiding the checkbox -- admin_manages_profiles lets an admin update any
-- column through the REST API.
alter table public.user_profiles
  add constraint user_profiles_service_never_admin check (not (account_type = 'service' and is_admin));

-- account_type is fixed at creation. Otherwise a service account could be
-- turned "human" and then made admin, or a human turned "service" to dodge
-- whatever treats the two differently. Set only by handle_new_user() below.
create function public.prevent_account_type_change() returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.account_type is distinct from old.account_type then
    raise exception 'account_type cannot change after an account is created' using errcode = '42501';
  end if;
  return new;
end;
$$;

create trigger guard_account_type before update on public.user_profiles
for each row execute function public.prevent_account_type_change();

-- ---------------------------------------------------------------------------
-- handle_new_user(): unchanged from 20260903170000 except that it now sets
-- account_type from raw_APP_meta_data, which only the service role (Admin
-- API) and GoTrue itself can write. Never from raw_USER_meta_data: a signing-
-- up user controls that (supabase.auth.signUp's options.data), so reading it
-- would let anyone self-declare as a service account. Anything but exactly
-- 'service' is 'human', so this can't throw on odd input -- this trigger runs
-- inside every signup and must not break it.
-- ---------------------------------------------------------------------------
create or replace function handle_new_user() returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_full_name text := new.raw_user_meta_data->>'full_name';
  v_name      text := coalesce(v_full_name, new.raw_user_meta_data->>'name');
  v_space     int  := 0;
  v_first     text := nullif(trim(coalesce(new.raw_user_meta_data->>'first_name', new.raw_user_meta_data->>'given_name')), '');
  v_last      text := nullif(trim(coalesce(new.raw_user_meta_data->>'last_name',  new.raw_user_meta_data->>'family_name')), '');
  v_type      text := case when new.raw_app_meta_data->>'account_type' = 'service' then 'service' else 'human' end;
begin
  if v_name is not null then
    v_space := position(' ' in v_name);
  end if;
  if v_first is null then
    v_first := case when v_space > 0 then split_part(v_name, ' ', 1) else v_name end;
  end if;
  if v_last is null and v_space > 0 then
    v_last := trim(substring(v_name from v_space + 1));
  end if;

  insert into user_profiles (id, full_name, role, first_name, last_name, account_type)
  values (new.id, v_full_name, 'customer', nullif(trim(v_first), ''), nullif(trim(v_last), ''), v_type);
  return new;
end $$;

-- ---------------------------------------------------------------------------
-- The key list gains account_type (so the web tab can mark service accounts).
-- A return-type change needs drop + create; the body is 20260926165000's
-- (including the banned/deleted-owner predicate) plus the one column.
-- ---------------------------------------------------------------------------
drop function public.admin_list_agent_keys();
drop function public.agent_key_list();

create function public.agent_key_list()
returns table (
  id uuid, label text, key_prefix text, user_id uuid,
  account_first_name text, account_last_name text, account_role text, account_status text,
  account_data_mode text, account_type text, owner_eligible boolean,
  created_at timestamptz, created_by text, last_used_at timestamptz, expires_at timestamptz,
  revoked_at timestamptz, status text
)
language sql
stable
security definer
set search_path = ''
as $$
  select k.id, k.label, k.key_prefix, k.user_id,
         p.first_name, p.last_name, p.role, p.status, p.data_mode, p.account_type,
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

create function public.admin_list_agent_keys()
returns table (
  id uuid, label text, key_prefix text, user_id uuid,
  account_first_name text, account_last_name text, account_role text, account_status text,
  account_data_mode text, account_type text, owner_eligible boolean,
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

revoke execute on function public.agent_key_list() from public, anon, authenticated, service_role;
revoke execute on function public.admin_list_agent_keys() from public, anon, authenticated, service_role;
grant execute on function public.admin_list_agent_keys() to authenticated;

notify pgrst, 'reload schema';
