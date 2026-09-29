-- Nightly end-to-end health checks: storage, writers, retention
-- (docs/SECURITY.md, "Nightly health checks"). Nothing here is reachable from
-- PostgREST: the schema isn't exposed, every table is RLS-on with zero
-- policies AND has no grants to any API role (both gates, as for
-- agent_api_keys). Writers and readers go through SECURITY DEFINER functions
-- only:
--   system_health.record_run / record_result -- health_writer (P2 Edge
--     Function, P3 GitHub Action) and the P1 pg_cron job (as postgres);
--   public.log_ingestion_run                 -- service_role only (the two
--     ingest Edge Functions, via PostgREST rpc);
--   read functions for the MCP gateway      -- a later migration (step k).

create schema system_health;
revoke all on schema system_health from public, anon, authenticated, service_role;

create table system_health.health_runs (
  id          bigserial primary key,
  producer    text not null check (producer in ('p1_database', 'p2_probes', 'p3_frontend')),
  started_at  timestamptz not null default now(),
  finished_at timestamptz,
  status      text not null default 'running' check (status in ('running', 'pass', 'warn', 'fail', 'error'))
);
create index health_runs_producer_started_idx on system_health.health_runs (producer, started_at desc);

create table system_health.health_results (
  id         bigserial primary key,
  run_id     bigint not null references system_health.health_runs (id) on delete cascade,
  layer      text not null check (layer in ('source', 'ingestion', 'database', 'gateway', 'frontend', 'security')),
  check_id   text not null check (check_id ~ '^[a-z0-9_.]{3,100}$'),
  status     text not null check (status in ('pass', 'warn', 'fail', 'error')),
  observed   jsonb,
  expected   jsonb,
  detail     text check (length(detail) <= 2000),
  checked_at timestamptz not null default now(),
  unique (run_id, check_id)
);
create index health_results_checked_idx on system_health.health_results (checked_at);

create table system_health.health_baselines (
  check_id text primary key check (check_id ~ '^[a-z0-9_.]{3,100}$'),
  value    jsonb not null,
  set_at   timestamptz not null default now(),
  set_by   text not null
);

-- One row per ingest Edge Function run, written from a finally block on every
-- run, including exceptions and upstream failures (step d). Before this, a
-- failed run was recorded nowhere durable: pg_cron only knows the request was
-- queued, and net._http_response keeps the function's answer for ~6 hours.
create table system_health.ingestion_runs (
  id           bigserial primary key,
  asset        text not null check (asset in ('ingest-innovint', 'ingest-climate-2026')),
  started_at   timestamptz not null,
  finished_at  timestamptz not null default now(),
  status       text not null check (status in ('success', 'partial', 'error')),
  http_status  int,
  rows_written int,
  error        text check (length(error) <= 2000),
  detail       jsonb
);
create index ingestion_runs_asset_started_idx on system_health.ingestion_runs (asset, started_at desc);

alter table system_health.health_runs enable row level security;
alter table system_health.health_results enable row level security;
alter table system_health.health_baselines enable row level security;
alter table system_health.ingestion_runs enable row level security;
revoke all on all tables in schema system_health from public, anon, authenticated, service_role;
revoke all on all sequences in schema system_health from public, anon, authenticated, service_role;

-- ---------------------------------------------------------------- writers --

-- Opens a run and returns its id. Producers call this first, then
-- record_result once per check.
create function system_health.record_run(p_producer text, p_started_at timestamptz default now())
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id bigint;
begin
  if p_started_at < now() - interval '3 hours' or p_started_at > now() + interval '5 minutes' then
    raise exception 'record_run: started_at must be within the last 3 hours';
  end if;
  insert into system_health.health_runs (producer, started_at) values (p_producer, p_started_at) returning id into v_id;
  return v_id;
end $$;

-- Appends one check's result to an open run, and keeps the run's own status
-- the worst of its results (error > fail > warn > pass). A run can only be
-- written for 3 hours after it started, so a writer can't rewrite history.
create function system_health.record_result(
  p_run_id bigint, p_layer text, p_check_id text, p_status text,
  p_observed jsonb default null, p_expected jsonb default null, p_detail text default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_started timestamptz;
begin
  select started_at into v_started from system_health.health_runs where id = p_run_id for update;
  if v_started is null then raise exception 'record_result: no run %', p_run_id; end if;
  if v_started < now() - interval '3 hours' then raise exception 'record_result: run % is closed', p_run_id; end if;
  if pg_column_size(p_observed) > 65536 or pg_column_size(p_expected) > 65536 then
    raise exception 'record_result: observed/expected over 64 KB';
  end if;
  insert into system_health.health_results (run_id, layer, check_id, status, observed, expected, detail)
  values (p_run_id, p_layer, p_check_id, p_status, p_observed, p_expected, left(p_detail, 2000));
  update system_health.health_runs r
     set finished_at = now(),
         status = (select case max(case s.status when 'error' then 4 when 'fail' then 3 when 'warn' then 2 else 1 end)
                            when 4 then 'error' when 3 then 'fail' when 2 then 'warn' else 'pass' end
                     from system_health.health_results s where s.run_id = p_run_id)
   where r.id = p_run_id;
end $$;

-- Called by ingest-innovint / ingest-climate-2026 through PostgREST as
-- service_role, from a finally block. In public (not system_health) because
-- PostgREST only exposes public; EXECUTE for service_role alone.
create function public.log_ingestion_run(
  p_asset text, p_started_at timestamptz, p_status text,
  p_http_status int default null, p_rows_written int default null,
  p_error text default null, p_detail jsonb default null
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id bigint;
begin
  if pg_column_size(p_detail) > 65536 then p_detail := jsonb_build_object('truncated', true); end if;
  insert into system_health.ingestion_runs (asset, started_at, status, http_status, rows_written, error, detail)
  values (p_asset, p_started_at, p_status, p_http_status, p_rows_written, left(p_error, 2000), p_detail)
  returning id into v_id;
  return v_id;
end $$;

-- 90-day retention, run daily by pg_cron (the cron job itself is created
-- separately, with the other health schedules). Baselines are kept.
create function system_health.prune(p_days int default 90)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_runs int; v_ingest int;
begin
  delete from system_health.health_runs where started_at < now() - make_interval(days => p_days);
  get diagnostics v_runs = row_count;
  delete from system_health.ingestion_runs where started_at < now() - make_interval(days => p_days);
  get diagnostics v_ingest = row_count;
  return jsonb_build_object('health_runs_deleted', v_runs, 'ingestion_runs_deleted', v_ingest);
end $$;

revoke all on all functions in schema system_health from public, anon, authenticated, service_role;
revoke all on function public.log_ingestion_run(text, timestamptz, text, int, int, text, jsonb) from public, anon, authenticated;
grant execute on function public.log_ingestion_run(text, timestamptz, text, int, int, text, jsonb) to service_role;

-- ------------------------------------------------------------ health_writer --
-- The P2 Edge Function and the P3 GitHub Action's only credential. It can open
-- runs and append results -- nothing else: no table grants, no BYPASSRLS, no
-- membership in any other role. Created NOLOGIN here; LOGIN and a password
-- (a SCRAM verifier, never plaintext) are set by
-- scripts/rotate-health-writer-password.mjs, which also stores the connection
-- string straight into the Supabase and GitHub secrets.
create role health_writer nologin noinherit nobypassrls connection limit 5;
alter role health_writer set statement_timeout = '15s';
alter role health_writer set idle_in_transaction_session_timeout = '10s';
grant usage on schema system_health to health_writer;
grant execute on function system_health.record_run(text, timestamptz) to health_writer;
grant execute on function system_health.record_result(bigint, text, text, text, jsonb, jsonb, text) to health_writer;
