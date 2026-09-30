-- Nightly health follow-up (docs/SECURITY.md, "Nightly health checks: the
-- checks, schedule, secrets and operations"):
--   1. Schedule-aware staleness: a producer is stale if it has no run since
--      its most recent scheduled slot whose 30-minute grace has passed
--      (P1 12:00, P2 12:10, P3 12:17 UTC), or if its latest run is older than
--      26 hours.
--   2. P3 safety net: pg_cron at 12:35 UTC dispatches nightly-health-p3.yml
--      through GitHub's workflow_dispatch API when no p3_frontend run has
--      started since 12:17 today. The GitHub token (fine-grained, this repo
--      only, Actions read/write) is read from Vault by name at call time; it
--      is never in a cron command or function body. Each backup dispatch is
--      recorded as producer 'p3_backup' (warn), so it can never pass for a
--      P3 run.

alter table system_health.health_runs drop constraint health_runs_producer_check;
alter table system_health.health_runs add constraint health_runs_producer_check
  check (producer in ('p1_database', 'p2_probes', 'p3_frontend', 'p3_backup'));

-- Stale iff no run, or the latest run is older than 26 h, or it started
-- before the most recent slot whose grace (30 min) has already elapsed.
create function public.health_producer_stale(p_last timestamptz, p_slot time, p_now timestamptz default now())
returns boolean
language sql
immutable
set search_path = public
as $$
  -- today's slot as an absolute UTC instant, independent of the session time zone
  with s as (select (((p_now at time zone 'UTC')::date + p_slot) at time zone 'UTC') as today_slot)
  select p_last is null
      or p_last < p_now - interval '26 hours'
      or p_last < case when p_now >= s.today_slot + interval '30 minutes' then s.today_slot
                       else s.today_slot - interval '1 day' end
    from s
$$;
revoke all on function public.health_producer_stale(timestamptz, time, timestamptz) from public, anon, authenticated, service_role;

create or replace function public.health_system_status()
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
  v_backups jsonb;
begin
  perform health_require_operator();

  -- Latest run per producer. Stale (health_producer_stale): no run since the
  -- most recent scheduled slot whose 30-minute grace has passed, or older
  -- than 26 hours. P3's slot is 12:17 (its GitHub cron).
  select jsonb_agg(jsonb_build_object(
           'producer', p.producer, 'schedule_utc', p.schedule,
           'run_id', r.id, 'started_at', r.started_at, 'finished_at', r.finished_at,
           'status', case when health_producer_stale(r.started_at, p.slot) then 'fail' else r.status end,
           'stale', health_producer_stale(r.started_at, p.slot),
           'summary', case when r.id is null then null else health_run_summary(r.id) end)
         order by p.ord)
    into v_producers
    from (values (1, 'p1_database', '12:00', time '12:00'), (2, 'p2_probes', '12:10', time '12:10'), (3, 'p3_frontend', '12:17', time '12:17')) p(ord, producer, schedule, slot)
    left join lateral (select id, started_at, finished_at, status from system_health.health_runs h
                        where h.producer = p.producer order by started_at desc limit 1) r on true;

  -- The P3 backup trigger's own records (12:35): each one means the GitHub
  -- schedule was missed that day. Shown for 26 hours and counted in overall.
  select coalesce(jsonb_agg(jsonb_build_object('run_id', h.id, 'started_at', h.started_at, 'status', h.status,
                                               'summary', health_run_summary(h.id)) order by h.started_at desc), '[]')
    into v_backups
    from system_health.health_runs h
   where h.producer = 'p3_backup' and h.started_at > now() - interval '26 hours';

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
          union all select e->>'status' from jsonb_array_elements(v_p4) e
          union all select e->>'status' from jsonb_array_elements(v_backups) e) x;

  return jsonb_build_object(
    'generated_at', now(),
    'overall', case v_rank when 4 then 'error' when 3 then 'fail' when 2 then 'warn' else 'pass' end,
    'stale_rule', 'no run since the latest scheduled slot + 30 min grace, or older than 26 h',
    'producers', v_producers,
    'p3_backup_dispatches', v_backups,
    'p4_gateway_self_check', v_p4);
end $$;

create function system_health.p3_backup_dispatch(p_now timestamptz default now())
returns text
language plpgsql
set search_path = public
as $$
declare
  v_slot timestamptz := ((p_now at time zone 'UTC')::date + time '12:17') at time zone 'UTC';
  v_token text;
  v_run bigint;
  v_req bigint;
begin
  if exists (select 1 from system_health.health_runs where producer = 'p3_frontend' and started_at >= v_slot) then
    return 'p3 ran; nothing to do';
  end if;
  v_run := system_health.record_run('p3_backup');  -- the real time; p_now only picks the slot
  select decrypted_secret into v_token from vault.decrypted_secrets where name = 'github_p3_dispatch_token';
  if v_token is null then
    perform system_health.record_result(v_run, 'frontend', 'frontend.p3.schedule_backup', 'fail',
      jsonb_build_object('p3_since', v_slot, 'dispatched', false), '{"dispatched": true}'::jsonb,
      'P3 schedule missed and the backup cannot dispatch: Vault secret github_p3_dispatch_token is missing (docs/SECURITY.md)');
    return 'missed; no token';
  end if;
  v_req := net.http_post(
    url := 'https://api.github.com/repos/harry-marsestate/mars-telemetry/actions/workflows/nightly-health-p3.yml/dispatches',
    body := '{"ref":"main"}'::jsonb,
    headers := jsonb_build_object('Authorization', 'Bearer ' || v_token, 'Accept', 'application/vnd.github+json',
                                  'X-GitHub-Api-Version', '2022-11-28', 'User-Agent', 'mars-telemetry-health-backup',
                                  'Content-Type', 'application/json'),
    timeout_milliseconds := 15000);
  perform system_health.record_result(v_run, 'frontend', 'frontend.p3.schedule_backup', 'warn',
    jsonb_build_object('p3_since', v_slot, 'dispatched', true, 'pg_net_request_id', v_req), '{"dispatched": false}'::jsonb,
    'P3 schedule missed, dispatched by backup');
  return 'missed; dispatched (pg_net request ' || v_req || ')';
end $$;
revoke all on function system_health.p3_backup_dispatch(timestamptz) from public, anon, authenticated, service_role;

select cron.schedule('health-p3-backup', '35 12 * * *', 'select system_health.p3_backup_dispatch()');
