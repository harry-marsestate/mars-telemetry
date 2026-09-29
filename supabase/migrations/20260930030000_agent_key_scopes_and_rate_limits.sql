-- Per-key tool scopes and per-key rate limits for the MCP gateway
-- (docs/SECURITY.md, "Nightly health checks", guardrails 1 and 5).
--
-- Scopes: every agent API key carries allowed_tools. Existing keys get exactly
-- the five round-one tools they could already call; no key gains a tool
-- implicitly -- widening one is an explicit agent_key_set_tools() call, which
-- is audited. Health tools can only ever be granted to a key whose owner is an
-- operator (enforced by a trigger on the table, and re-checked at call time).
--
-- Rate limits: rate_per_minute / rate_per_day per key (defaults 60 / 2000;
-- the heaviest real key so far peaked at 10/min and 36/day). Counted from the
-- existing audit table, agent_api_key_calls. A throttled call is itself
-- audited (outcome 'throttled') and not counted toward the limit.
--
-- The gateway calls mcp_key_scope() for tools/list and mcp_authorize_call()
-- before every tools/call; both are EXECUTE for mcp_gateway only, like
-- mcp_authenticate()/mcp_log_call().

-- ------------------------------------------------------------ catalogue ---
create table public.mcp_tool_catalogue (
  tool              text primary key check (tool ~ '^get_[a-z_]+$'),
  kind              text not null check (kind in ('data', 'health')),
  requires_operator boolean not null,
  note              text not null
);
alter table public.mcp_tool_catalogue enable row level security;
revoke all on public.mcp_tool_catalogue from public, anon, authenticated, service_role;

insert into public.mcp_tool_catalogue (tool, kind, requires_operator, note) values
  ('get_berry_maturity',   'data',   false, 'round one; operator-only data by RLS'),
  ('get_smoke_markers',    'data',   false, 'round one; operator-only data by RLS'),
  ('get_wine_lab_results', 'data',   false, 'round one; operator-only data by RLS'),
  ('get_lot_analyses',     'data',   false, 'round one; operator-only data by RLS'),
  ('get_labour_summary',   'data',   false, 'round one; operator-only data by RLS'),
  ('get_series',           'data',   false, 'nightly-health round; block-scoped by RLS'),
  ('get_derived_series',   'data',   false, 'nightly-health round'),
  ('get_anomalies',        'data',   false, 'nightly-health round; explicit as_of required'),
  ('get_vessels',          'data',   false, 'nightly-health round; operator-only data by RLS'),
  ('get_system_health',    'health', true,  'nightly-health round; operator-owned keys only'),
  ('get_health_history',   'health', true,  'nightly-health round; operator-owned keys only'),
  ('get_health_baselines', 'health', true,  'nightly-health round; operator-owned keys only');

-- --------------------------------------------------------- key columns ---
alter table public.agent_api_keys
  add column allowed_tools text[],
  add column rate_per_minute int not null default 60 check (rate_per_minute between 1 and 600),
  add column rate_per_day int not null default 2000 check (rate_per_day between 1 and 100000);

-- Every existing key: exactly the five round-one tools.
update public.agent_api_keys
   set allowed_tools = array['get_berry_maturity', 'get_smoke_markers', 'get_wine_lab_results', 'get_lot_analyses', 'get_labour_summary'];

alter table public.agent_api_keys
  alter column allowed_tools set not null,
  add constraint agent_api_keys_allowed_tools_nonempty check (cardinality(allowed_tools) between 1 and 50);

-- audit outcome for calls the gateway refused before running them; null = a
-- normal call (is_error says whether the tool itself failed).
alter table public.agent_api_key_calls
  add column outcome text check (outcome in ('rejected_scope', 'throttled'));

-- Append-only record of every scope change, like agent_api_key_expiry_changes.
create table public.agent_api_key_scope_changes (
  id         bigint generated always as identity primary key,
  key_id     uuid not null references public.agent_api_keys (id) on delete cascade,
  old_tools  text[] not null,
  new_tools  text[] not null,
  changed_by text not null,
  changed_at timestamptz not null default now()
);
alter table public.agent_api_key_scope_changes enable row level security;
revoke all on public.agent_api_key_scope_changes from public, anon, authenticated, service_role;

-- ------------------------------------------------------------ the guard ---
-- Every tool must be in the catalogue, no duplicates, and a health tool needs
-- an operator owner. Runs on insert and on any change to allowed_tools or the
-- owner, whoever makes it.
create function public.agent_api_keys_scope_guard()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_unknown text;
  v_role text;
begin
  if (select count(distinct t) from unnest(new.allowed_tools) t) <> cardinality(new.allowed_tools) then
    raise exception 'allowed_tools has duplicates' using errcode = '22023';
  end if;
  select string_agg(t, ', ') into v_unknown
    from unnest(new.allowed_tools) t
   where not exists (select 1 from public.mcp_tool_catalogue c where c.tool = t);
  if v_unknown is not null then
    raise exception 'unknown tool(s): %', v_unknown using errcode = '22023';
  end if;
  if exists (select 1 from unnest(new.allowed_tools) t join public.mcp_tool_catalogue c on c.tool = t where c.requires_operator) then
    select p.role into v_role from public.user_profiles p where p.id = new.user_id;
    if v_role is distinct from 'operator' then
      raise exception 'health tools can only be granted to a key whose owner is an operator (owner role: %)', coalesce(v_role, 'none')
        using errcode = '22023';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function public.agent_api_keys_scope_guard() from public, anon, authenticated, service_role;
create trigger agent_api_keys_scope_guard
  before insert or update of allowed_tools, user_id on public.agent_api_keys
  for each row execute function public.agent_api_keys_scope_guard();

-- ------------------------------------------------- gateway: list + call ---
-- The allowed tools of an ACTIVE key (the same predicates as
-- mcp_authenticate), for tools/list and the P4 self-check. Empty for anything
-- else, so an unknown or dead key lists nothing.
create function public.mcp_key_scope(p_key_hash text)
returns table (key_id uuid, allowed_tools text[], rate_per_minute int, rate_per_day int, owner_role text, expires_at timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
  select k.id, k.allowed_tools, k.rate_per_minute, k.rate_per_day, p.role, k.expires_at
    from public.agent_api_keys k
    join public.user_profiles p on p.id = k.user_id
    join auth.users u on u.id = k.user_id
   where p_key_hash ~ '^[0-9a-f]{64}$'
     and k.key_hash = decode(p_key_hash, 'hex')
     and k.revoked_at is null
     and k.expires_at > now()
     and p.status = 'approved'
     and p.role in ('operator', 'customer')
     and (u.banned_until is null or u.banned_until <= now())
     and u.deleted_at is null
$$;

-- Decides one tools/call before it runs: scope first, then the key's rate
-- limits. A refusal is audited here (outcome rejected_scope / throttled); an
-- allowed call is audited afterwards by mcp_log_call() as before.
-- Calls in flight (authorised, not yet logged) aren't counted -- bounded by
-- the gateway's connection pool, and documented rather than engineered away.
create function public.mcp_authorize_call(p_key_hash text, p_tool text)
returns table (allowed boolean, http_status int, reason text, retry_after_seconds int)
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  k record;
  v_tool text := left(coalesce(p_tool, ''), 100);
  v_minute int; v_day int; v_oldest timestamptz;
begin
  select s.* into k from public.mcp_key_scope(p_key_hash) s;
  if k.key_id is null then
    return query select false, 401, 'unauthorized'::text, null::int;
    return;
  end if;

  -- One decision per key at a time, so the count and the audit insert agree.
  perform pg_advisory_xact_lock(hashtextextended('mcp_rate:' || k.key_id::text, 0));

  if not (v_tool = any (k.allowed_tools))
     or exists (select 1 from public.mcp_tool_catalogue c where c.tool = v_tool and c.requires_operator and k.owner_role <> 'operator') then
    insert into public.agent_api_key_calls (key_id, tool, args, is_error, outcome) values (k.key_id, v_tool, null, true, 'rejected_scope');
    return query select false, 403, ('tool not permitted for this key: ' || v_tool)::text, null::int;
    return;
  end if;

  select count(*) filter (where c.called_at > now() - interval '1 minute'),
         count(*)
    into v_minute, v_day
    from public.agent_api_key_calls c
   where c.key_id = k.key_id and c.called_at > now() - interval '1 day' and c.outcome is distinct from 'throttled';

  if v_minute >= k.rate_per_minute then
    select min(c.called_at) into v_oldest from public.agent_api_key_calls c
     where c.key_id = k.key_id and c.called_at > now() - interval '1 minute' and c.outcome is distinct from 'throttled';
    insert into public.agent_api_key_calls (key_id, tool, args, is_error, outcome)
      values (k.key_id, v_tool, jsonb_build_object('limit', 'per_minute', 'max', k.rate_per_minute), true, 'throttled');
    return query select false, 429, format('rate limit: %s calls per minute', k.rate_per_minute),
      greatest(1, ceil(extract(epoch from (v_oldest + interval '1 minute' - now())))::int);
    return;
  end if;
  if v_day >= k.rate_per_day then
    select min(c.called_at) into v_oldest from public.agent_api_key_calls c
     where c.key_id = k.key_id and c.called_at > now() - interval '1 day' and c.outcome is distinct from 'throttled';
    insert into public.agent_api_key_calls (key_id, tool, args, is_error, outcome)
      values (k.key_id, v_tool, jsonb_build_object('limit', 'per_day', 'max', k.rate_per_day), true, 'throttled');
    return query select false, 429, format('rate limit: %s calls per day', k.rate_per_day),
      greatest(1, ceil(extract(epoch from (v_oldest + interval '1 day' - now())))::int);
    return;
  end if;

  return query select true, 200, 'ok'::text, null::int;
end;
$$;

revoke all on function public.mcp_key_scope(text), public.mcp_authorize_call(text, text) from public, anon, authenticated, service_role;
grant execute on function public.mcp_key_scope(text), public.mcp_authorize_call(text, text) to mcp_gateway;

-- -------------------------------------------- owner-only key functions ---
-- agent_key_issue gains p_allowed_tools (null = the five round-one tools, as
-- every key had before) and returns the key's allowed_tools.
drop function public.agent_key_issue(uuid, text, integer, text, boolean);
create function public.agent_key_issue(
  p_user_id uuid, p_label text, p_days integer, p_created_by text,
  p_allow_unapproved boolean default false, p_allowed_tools text[] default null
)
returns table (id uuid, key text, key_prefix text, label text, expires_at timestamptz, account_role text, account_status text, allowed_tools text[])
language plpgsql
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
  insert into public.agent_api_keys as k (user_id, label, key_prefix, key_hash, created_by, expires_at, allowed_tools)
  values (
    p_user_id,
    trim(p_label) || ' [user ' || left(p_user_id::text, 8) || ']',
    left(v_key, 12),
    sha256(convert_to(v_key, 'UTF8')),
    p_created_by,
    now() + make_interval(days => p_days),
    coalesce(p_allowed_tools, array['get_berry_maturity', 'get_smoke_markers', 'get_wine_lab_results', 'get_lot_analyses', 'get_labour_summary'])
  )
  returning k.id, v_key, k.key_prefix, k.label, k.expires_at, v_role, v_status, k.allowed_tools;
end;
$$;

-- Changes an ACTIVE key's allowed_tools and records old/new/who. Owner-only
-- (the CLI); the web app shows scopes read-only for now.
create function public.agent_key_set_tools(p_id uuid, p_tools text[], p_changed_by text)
returns table (id uuid, key_prefix text, allowed_tools text[])
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
  v_old text[];
begin
  if nullif(trim(p_changed_by), '') is null then
    raise exception 'changed_by is required' using errcode = '22023';
  end if;
  select k.allowed_tools into v_old from public.agent_api_keys k
   where k.id = p_id and k.revoked_at is null and k.expires_at > now() for update;
  if not found then
    raise exception 'no active key with id %', p_id using errcode = '22023';
  end if;
  update public.agent_api_keys k set allowed_tools = p_tools where k.id = p_id;  -- the scope guard validates
  insert into public.agent_api_key_scope_changes (key_id, old_tools, new_tools, changed_by) values (p_id, v_old, p_tools, p_changed_by);
  return query select k.id, k.key_prefix, k.allowed_tools from public.agent_api_keys k where k.id = p_id;
end;
$$;

-- agent_key_list / agent_key_calls gain scope columns; their admin_* wrappers
-- are recreated unchanged apart from the return type.
drop function public.admin_list_agent_keys();
drop function public.agent_key_list();
create function public.agent_key_list()
returns table (id uuid, label text, key_prefix text, user_id uuid, account_first_name text, account_last_name text, account_role text, account_status text, account_data_mode text, account_type text, owner_eligible boolean, created_at timestamptz, created_by text, last_used_at timestamptz, expires_at timestamptz, revoked_at timestamptz, status text, allowed_tools text[], rate_per_minute int, rate_per_day int)
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
              else 'active' end,
         k.allowed_tools, k.rate_per_minute, k.rate_per_day
    from public.agent_api_keys k
    left join public.user_profiles p on p.id = k.user_id
    left join auth.users u on u.id = k.user_id
   order by k.created_at desc
$$;
create function public.admin_list_agent_keys()
returns table (id uuid, label text, key_prefix text, user_id uuid, account_first_name text, account_last_name text, account_role text, account_status text, account_data_mode text, account_type text, owner_eligible boolean, created_at timestamptz, created_by text, last_used_at timestamptz, expires_at timestamptz, revoked_at timestamptz, status text, allowed_tools text[], rate_per_minute int, rate_per_day int)
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

drop function public.admin_list_agent_key_calls(uuid, integer);
drop function public.agent_key_calls(uuid, integer);
create function public.agent_key_calls(p_id uuid, p_limit integer default 50)
returns table (called_at timestamptz, tool text, is_error boolean, args jsonb, total_calls bigint, outcome text)
language sql
stable
security definer
set search_path = ''
as $$
  select c.called_at, c.tool, c.is_error, c.args, count(*) over (), c.outcome
    from public.agent_api_key_calls c
   where c.key_id = p_id
   order by c.called_at desc, c.id desc
   limit least(greatest(coalesce(p_limit, 50), 1), 200)
$$;
create function public.admin_list_agent_key_calls(p_id uuid, p_limit integer default 50)
returns table (called_at timestamptz, tool text, is_error boolean, args jsonb, total_calls bigint, outcome text)
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

-- Grants: implementation owner-only, admin wrappers authenticated-only --
-- exactly the matrix of 20260926160000 / 20260926170000.
revoke execute on function
  public.agent_key_issue(uuid, text, integer, text, boolean, text[]),
  public.agent_key_set_tools(uuid, text[], text),
  public.agent_key_list(),
  public.agent_key_calls(uuid, integer),
  public.admin_list_agent_keys(),
  public.admin_list_agent_key_calls(uuid, integer)
from public, anon, authenticated, service_role;
grant execute on function
  public.admin_list_agent_keys(),
  public.admin_list_agent_key_calls(uuid, integer)
to authenticated;

notify pgrst, 'reload schema';
