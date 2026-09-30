-- Gateway health tools (docs/SECURITY.md, "Nightly health checks"):
-- get_system_health, get_health_history, get_health_baselines, plus the P4
-- self-check computed on every get_system_health call, and the 12:40 UTC
-- prune.
--
-- Three SECURITY DEFINER read functions in public (the gateway's mcp_reader
-- has no access to the system_health schema and gets none): EXECUTE for
-- mcp_reader only, and each refuses any caller whose own account isn't an
-- operator (the key-scope trigger already limits these tools to
-- operator-owned keys; this is the second gate). They read system_health and,
-- for P4, the calling key's own row (found by the mcp_key_id claim the
-- gateway sets), nothing else.

create function public.health_require_operator()
returns void
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  if current_role_name() is distinct from 'operator' then
    raise exception 'health tools are available to operator accounts only' using errcode = '42501';
  end if;
end $$;

-- One run's summary: counts by status and every non-pass result.
create function public.health_run_summary(p_run_id bigint)
returns jsonb
language sql
stable
security definer
set search_path = public
as $$
  select jsonb_build_object(
    'counts', coalesce((select jsonb_object_agg(status, n) from (select status, count(*) n from system_health.health_results where run_id = p_run_id group by status) c), '{}'),
    'problems', coalesce((select jsonb_agg(jsonb_build_object('check_id', check_id, 'layer', layer, 'status', status, 'detail', detail, 'observed', observed, 'expected', expected) order by check_id)
                            from system_health.health_results where run_id = p_run_id and status <> 'pass'), '[]'))
$$;

create function public.health_system_status()
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_producers jsonb;
  v_key_id uuid;
  v_key record;
  v_days_left numeric;
  v_p4 jsonb;
  v_rank int := 1;
  v_catalogue text[];
begin
  perform health_require_operator();

  -- Latest run per producer; stale if missing or older than 26 hours.
  select jsonb_agg(jsonb_build_object(
           'producer', p.producer, 'schedule_utc', p.schedule,
           'run_id', r.id, 'started_at', r.started_at, 'finished_at', r.finished_at,
           'status', case when r.id is null then 'fail' when r.started_at < now() - interval '26 hours' then 'fail' else r.status end,
           'stale', r.id is null or r.started_at < now() - interval '26 hours',
           'summary', case when r.id is null then null else health_run_summary(r.id) end)
         order by p.ord)
    into v_producers
    from (values (1, 'p1_database', '12:00'), (2, 'p2_probes', '12:10'), (3, 'p3_frontend', '12:20')) p(ord, producer, schedule)
    left join lateral (select id, started_at, finished_at, status from system_health.health_runs h
                        where h.producer = p.producer order by started_at desc limit 1) r on true;

  -- P4: the gateway checking itself, now. Reaching this line proves the
  -- database answered through the gateway's own read-only path.
  begin
    v_key_id := (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'mcp_key_id')::uuid;
  exception when others then
    v_key_id := null;
  end;
  select expires_at, revoked_at, allowed_tools, key_prefix into v_key from agent_api_keys where id = v_key_id;
  select array_agg(tool) into v_catalogue from mcp_tool_catalogue;
  v_days_left := round(extract(epoch from v_key.expires_at - now()) / 86400, 1);
  v_p4 := jsonb_build_array(
    jsonb_build_object('check_id', 'gateway.p4.database_reachable', 'status', 'pass', 'observed', jsonb_build_object('checked_at', now())),
    jsonb_build_object('check_id', 'gateway.p4.key_expiry',
      'status', case when v_key_id is null or v_key.expires_at is null then 'warn' when v_days_left <= 0 then 'fail' when v_days_left <= 14 then 'warn' else 'pass' end,
      'observed', jsonb_build_object('key_prefix', v_key.key_prefix, 'expires_at', v_key.expires_at, 'days_left', v_days_left),
      'detail', case when v_days_left <= 14 then 'this key expires within 14 days: issue a replacement (docs/SECURITY.md)' end),
    jsonb_build_object('check_id', 'gateway.p4.allowed_tools', 'status', 'pass', 'observed', jsonb_build_object('allowed_tools', to_jsonb(v_key.allowed_tools))),
    jsonb_build_object('check_id', 'gateway.p4.write_capable_tools',
      'status', case when exists (select 1 from unnest(coalesce(v_key.allowed_tools, '{}')) t where t !~ '^get_' or not t = any(coalesce(v_catalogue, '{}'))) then 'fail' else 'pass' end,
      'observed', jsonb_build_object('write_capable_tools', coalesce((select jsonb_agg(t) from unnest(coalesce(v_key.allowed_tools, '{}')) t where t !~ '^get_' or not t = any(coalesce(v_catalogue, '{}'))), '[]')),
      'detail', 'every catalogued tool is read-only (get_*, SELECT-only mcp_reader in a READ ONLY transaction); anything else is flagged'));

  select max(case s when 'error' then 4 when 'fail' then 3 when 'warn' then 2 else 1 end) into v_rank
    from (select e->>'status' s from jsonb_array_elements(v_producers) e
          union all select e->>'status' from jsonb_array_elements(v_p4) e) x;

  return jsonb_build_object(
    'generated_at', now(),
    'overall', case v_rank when 4 then 'error' when 3 then 'fail' when 2 then 'warn' else 'pass' end,
    'stale_after_hours', 26,
    'producers', v_producers,
    'p4_gateway_self_check', v_p4);
end $$;

create function public.health_history(p_days int default 7)
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  perform health_require_operator();
  if p_days is null or p_days < 1 or p_days > 30 then
    raise exception 'days must be between 1 and 30' using errcode = '22023';
  end if;
  return jsonb_build_object('days', p_days, 'runs', coalesce((
    select jsonb_agg(jsonb_build_object('run_id', r.id, 'producer', r.producer, 'started_at', r.started_at, 'finished_at', r.finished_at,
                                        'status', r.status, 'summary', health_run_summary(r.id)) order by r.started_at desc)
      from system_health.health_runs r
     where r.started_at >= now() - make_interval(days => p_days)), '[]'));
end $$;

-- Every baseline, uncapped: the reference values P1 compares against.
create function public.health_baselines()
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  perform health_require_operator();
  return jsonb_build_object('baselines', coalesce((
    select jsonb_agg(jsonb_build_object('check_id', check_id, 'value', value, 'set_at', set_at, 'set_by', set_by) order by check_id)
      from system_health.health_baselines), '[]'));
end $$;

revoke all on function public.health_require_operator() from public, anon, authenticated, service_role;
revoke all on function public.health_run_summary(bigint) from public, anon, authenticated, service_role;
revoke all on function public.health_system_status() from public, anon, authenticated, service_role;
revoke all on function public.health_history(int) from public, anon, authenticated, service_role;
revoke all on function public.health_baselines() from public, anon, authenticated, service_role;
grant execute on function public.health_system_status() to mcp_reader;
grant execute on function public.health_history(int) to mcp_reader;
grant execute on function public.health_baselines() to mcp_reader;

-- 90-day retention at 12:40 UTC, after every producer (P3 starts 12:20).
select cron.schedule('health-prune', '40 12 * * *', 'select system_health.prune(90)');
