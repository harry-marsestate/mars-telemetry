-- Agent key admin, round 2 (2026-09-26, branch feat/agent-keys-admin): a
-- per-key detail view (audit trail of gateway calls, expiry history) and
-- editable expiry. Same shape as 20260926160000: owner-only implementation
-- functions + admin_* wrappers for the browser (EXECUTE for authenticated
-- only, is_admin_user() checked inside). See docs/SECURITY.md's "Agent key
-- admin" entry.
--
-- Nothing here returns key_hash or any key material beyond key_prefix, and
-- no table becomes reachable from any API role.

-- ---------------------------------------------------------------------------
-- Expiry-change audit log. Append-only history rather than "last changed by"
-- columns on agent_api_keys, so every change (and the value it replaced)
-- stays on record. Deny-all exactly like agent_api_keys/agent_api_key_calls:
-- RLS on, zero policies, no grants to any API role.
-- ---------------------------------------------------------------------------
create table public.agent_api_key_expiry_changes (
  id             bigint generated always as identity primary key,
  key_id         uuid not null references public.agent_api_keys(id) on delete cascade,
  old_expires_at timestamptz not null,
  new_expires_at timestamptz not null,
  changed_by     text not null,
  changed_at     timestamptz not null default now()
);
create index agent_api_key_expiry_changes_key_idx on public.agent_api_key_expiry_changes (key_id, changed_at desc);
alter table public.agent_api_key_expiry_changes enable row level security;
revoke all on public.agent_api_key_expiry_changes from anon, authenticated, service_role;

-- ---------------------------------------------------------------------------
-- The implementation (owner-only)
-- ---------------------------------------------------------------------------

-- Sets expires_at to now() + p_days, for an ACTIVE key only, and appends the
-- change to agent_api_key_expiry_changes in the same transaction.
--
-- Range rule: 1 to 365 days from now, AND never later than created_at + 365
-- days. The cap is measured from ISSUE, not from now, so extending can never
-- give a key more total lifetime than issuing it could -- otherwise a
-- metadata edit that needs no re-authentication could keep one credential
-- alive forever, sidestepping the fresh-auth step that issuing requires and
-- the rotation that re-issuing forces. Past the 365-day mark, issue a new key.
-- Revoked and expired keys can't be changed: resurrecting an expired key
-- would be the same bypass. Under a day: revoke instead.
create function public.agent_key_set_expiry(p_id uuid, p_days integer, p_changed_by text)
returns table (id uuid, key_prefix text, old_expires_at timestamptz, expires_at timestamptz)
language plpgsql
volatile
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
  v_key public.agent_api_keys%rowtype;
  v_new timestamptz;
  v_cap timestamptz;
begin
  if p_days is null or p_days < 1 or p_days > 365 then
    raise exception 'expiry must be from 1 to 365 days from now' using errcode = '22023';
  end if;
  if nullif(trim(p_changed_by), '') is null then
    raise exception 'changed_by is required' using errcode = '22023';
  end if;

  select * into v_key from public.agent_api_keys k where k.id = p_id for update;
  if not found then
    raise exception 'no key with id %', p_id using errcode = '22023';
  end if;
  if v_key.revoked_at is not null then
    raise exception 'key % is revoked; its expiry can no longer change', v_key.key_prefix using errcode = '22023';
  end if;
  if v_key.expires_at <= now() then
    raise exception 'key % has expired; issue a new key instead', v_key.key_prefix using errcode = '22023';
  end if;

  v_new := now() + make_interval(days => p_days);
  v_cap := v_key.created_at + interval '365 days';
  if v_new > v_cap then
    raise exception 'a key can live at most 365 days from issue: % can be set at most % days from now',
      v_key.key_prefix, greatest(floor(extract(epoch from (v_cap - now())) / 86400), 0)::int
      using errcode = '22023';
  end if;

  update public.agent_api_keys k set expires_at = v_new where k.id = v_key.id;
  insert into public.agent_api_key_expiry_changes (key_id, old_expires_at, new_expires_at, changed_by)
  values (v_key.id, v_key.expires_at, v_new, p_changed_by);

  return query select v_key.id, v_key.key_prefix, v_key.expires_at, v_new;
end;
$$;

-- The gateway's audit rows for one key (written only by mcp_log_call()),
-- newest first, capped at 200 per call. total_calls is the key's full count.
create function public.agent_key_calls(p_id uuid, p_limit integer default 50)
returns table (called_at timestamptz, tool text, is_error boolean, args jsonb, total_calls bigint)
language sql
stable
security definer
set search_path = ''
as $$
  select c.called_at, c.tool, c.is_error, c.args, count(*) over ()
    from public.agent_api_key_calls c
   where c.key_id = p_id
   order by c.called_at desc, c.id desc
   limit least(greatest(coalesce(p_limit, 50), 1), 200)
$$;

create function public.agent_key_expiry_changes(p_id uuid)
returns table (old_expires_at timestamptz, new_expires_at timestamptz, changed_by text, changed_at timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
  select e.old_expires_at, e.new_expires_at, e.changed_by, e.changed_at
    from public.agent_api_key_expiry_changes e
   where e.key_id = p_id
   order by e.changed_at desc, e.id desc
$$;

-- ---------------------------------------------------------------------------
-- Admin wrappers (authenticated only, is_admin_user() enforced here). No
-- fresh-auth step: changing an existing key's expiry is metadata at the same
-- trust level as revoke -- it creates no new credential, and the cap above
-- stops it from extending one past what issuing (with re-auth) granted.
-- ---------------------------------------------------------------------------

create function public.admin_update_agent_key_expiry(p_id uuid, p_days integer)
returns table (id uuid, key_prefix text, old_expires_at timestamptz, expires_at timestamptz)
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if not public.is_admin_user() then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return query
  select * from public.agent_key_set_expiry(
    p_id, p_days,
    coalesce(auth.jwt() ->> 'email', 'unknown email') || ' (' || auth.uid()::text || ') via web admin'
  );
end;
$$;

create function public.admin_list_agent_key_calls(p_id uuid, p_limit integer default 50)
returns table (called_at timestamptz, tool text, is_error boolean, args jsonb, total_calls bigint)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_admin_user() then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return query select * from public.agent_key_calls(p_id, p_limit);
end;
$$;

create function public.admin_list_agent_key_expiry_changes(p_id uuid)
returns table (old_expires_at timestamptz, new_expires_at timestamptz, changed_by text, changed_at timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_admin_user() then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return query select * from public.agent_key_expiry_changes(p_id);
end;
$$;

-- ---------------------------------------------------------------------------
-- Grants: same as 20260926160000.
-- ---------------------------------------------------------------------------

revoke execute on function
  public.agent_key_set_expiry(uuid, integer, text),
  public.agent_key_calls(uuid, integer),
  public.agent_key_expiry_changes(uuid)
from public, anon, authenticated, service_role;

revoke execute on function
  public.admin_update_agent_key_expiry(uuid, integer),
  public.admin_list_agent_key_calls(uuid, integer),
  public.admin_list_agent_key_expiry_changes(uuid)
from public, anon, authenticated, service_role;

grant execute on function
  public.admin_update_agent_key_expiry(uuid, integer),
  public.admin_list_agent_key_calls(uuid, integer),
  public.admin_list_agent_key_expiry_changes(uuid)
to authenticated;

notify pgrst, 'reload schema';
