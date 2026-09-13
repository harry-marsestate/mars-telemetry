-- Real 2026 climate ingestion: schema support for the new daily
-- Open-Meteo backfill (Edge Function `ingest-climate-2026` + pg_cron,
-- same architecture as insights-scan). Three pieces:
--
-- 1. daily_weather needs a real (vintage, day) unique constraint so the
--    daily job can UPSERT it idempotently. It never had one --
--    20260830000005_daily_weather_vintage_day_index.sql added a plain
--    index for read performance and explicitly deferred "enforcing dbt's
--    unique_key as a real DB constraint" as "a separate, larger
--    decision." This is that decision, made now because the ingestion
--    job requires it. Replaces the plain index with a unique one over
--    the same columns in the same order, so the WindowAgg-friendly
--    ascending scan that migration tuned for is preserved.
drop index daily_weather_vintage_day_idx;
alter table daily_weather add constraint daily_weather_vintage_day_key unique (vintage, day);

-- 2. refresh_daily_weather_range(): recomputes and upserts daily_weather
-- rows for one vintage's day range, deliberately duplicating
-- daily_weather.sql's (dbt) aggregation + real/mock precedence logic
-- rather than invoking dbt from an Edge Function (not possible -- dbt is
-- a Python CLI tool, not something Deno can shell out to in this
-- environment). This is a THIRD independent implementation of the same
-- real-supersedes-mock precedence rule, alongside series_bucketed()
-- (20260826000000/...002) and daily_weather.sql itself -- the exact
-- "two independent implementations kept in sync by hand" risk
-- insights-scan's realVintagesByMetric() comment already flags. Flagged
-- here for the same reason: if the precedence rule ever changes, grep
-- all three.
--
-- Deliberately scoped to the caller's (p_start, p_end) window, not the
-- whole vintage: real_scope below is computed FROM THE ROWS THIS CALL
-- READS (a padded window around p_start/p_end), not from every row that
-- exists for p_vintage. This matters because the daily ingestion job
-- only pulls a rolling ~14-day window per run (see ingest-climate-2026)
-- -- if real_scope were evaluated per-vintage instead of per-call, the
-- first day any real row landed would flip the WHOLE vintage's
-- precedence to "real, source_system=open_meteo_era5 only," silently
-- blanking out every day this function hasn't recomputed yet (which
-- still has only the original mock rows, now excluded by a real_scope
-- that no longer matches their source_system). Scoping real_scope to
-- just the window being recomputed means days outside that window keep
-- whatever daily_weather row they already had -- upgraded to real once
-- their own turn in the rolling window arrives, never blanked in the
-- meantime.
create or replace function refresh_daily_weather_range(p_vintage int, p_start date, p_end date)
returns void
security definer
set search_path = public
language plpgsql as $$
declare
  pad_start timestamptz := (p_start::timestamp - interval '1 day') at time zone 'America/Los_Angeles';
  pad_end   timestamptz := (p_end::timestamp + interval '2 days') at time zone 'America/Los_Angeles';
begin
  with hourly_raw as (
    select vintage, source_system,
      (recorded_at at time zone 'America/Los_Angeles')::date::timestamptz as day,
      metric_key, value
    from sensor_readings
    where vintage = p_vintage
      and metric_key in ('air_temp','humidity','solar','wind_speed')
      and recorded_at >= pad_start and recorded_at < pad_end
  ),
  real_scope as (
    select distinct vintage, metric_key
    from hourly_raw where source_system = 'open_meteo_era5'
  ),
  hourly as (
    select h.vintage, h.day, h.metric_key, h.value
    from hourly_raw h
    left join real_scope rs on rs.vintage = h.vintage and rs.metric_key = h.metric_key
    where rs.vintage is null or h.source_system = 'open_meteo_era5'
  ),
  hourly_raw_ts as (
    select vintage, source_system, recorded_at, metric_key, value
    from sensor_readings
    where vintage = p_vintage
      and metric_key in ('air_temp','humidity')
      and recorded_at >= pad_start and recorded_at < pad_end
  ),
  hourly_ts as (
    select h.vintage, h.recorded_at, h.metric_key, h.value
    from hourly_raw_ts h
    left join real_scope rs on rs.vintage = h.vintage and rs.metric_key = h.metric_key
    where rs.vintage is null or h.source_system = 'open_meteo_era5'
  ),
  hourly_vpd as (
    select
      t.vintage,
      (t.recorded_at at time zone 'America/Los_Angeles')::date::timestamptz as day,
      (0.6108 * exp(17.27 * ((t.value - 32) * 5.0/9) / (((t.value - 32) * 5.0/9) + 237.3)))
        * (1 - h.value / 100.0) as vpd_kpa_hourly
    from hourly_ts t
    join hourly_ts h
      on h.vintage = t.vintage and h.recorded_at = t.recorded_at and h.metric_key = 'humidity'
    where t.metric_key = 'air_temp'
  ),
  daily_vpd_peak as (
    select vintage, day, max(vpd_kpa_hourly) as vpd_peak_kpa
    from hourly_vpd
    group by vintage, day
  ),
  computed as (
    select
      hourly.vintage, hourly.day,
      max(value) filter (where metric_key='air_temp')  as tmax_f,
      min(value) filter (where metric_key='air_temp')  as tmin_f,
      avg(value) filter (where metric_key='air_temp')  as tavg_f,
      max(value) filter (where metric_key='air_temp') - min(value) filter (where metric_key='air_temp') as dtr_f,
      avg(value) filter (where metric_key='humidity')  as rh_avg,
      avg(value) filter (where metric_key='solar')     as solar_avg,
      avg(value) filter (where metric_key='wind_speed') as wind_avg,
      max(dvp.vpd_peak_kpa) as vpd_peak_kpa
    from hourly
    left join daily_vpd_peak dvp on dvp.vintage = hourly.vintage and dvp.day = hourly.day
    where hourly.day >= p_start::timestamptz and hourly.day < (p_end + 1)::timestamptz
    group by hourly.vintage, hourly.day
  )
  insert into daily_weather (vintage, day, tmax_f, tmin_f, tavg_f, dtr_f, rh_avg, solar_avg, wind_avg, vpd_peak_kpa)
  select vintage, day, tmax_f, tmin_f, tavg_f, dtr_f, rh_avg, solar_avg, wind_avg, vpd_peak_kpa
  from computed
  on conflict (vintage, day) do update set
    tmax_f = excluded.tmax_f, tmin_f = excluded.tmin_f, tavg_f = excluded.tavg_f,
    dtr_f = excluded.dtr_f, rh_avg = excluded.rh_avg, solar_avg = excluded.solar_avg,
    wind_avg = excluded.wind_avg, vpd_peak_kpa = excluded.vpd_peak_kpa;
end;
$$;

-- SECURITY DEFINER (owned by the migration role) because it writes
-- daily_weather directly -- same reasoning as the other SECURITY
-- DEFINER functions in docs/SECURITY.md's "Service-role-equivalent
-- access points" list. EXECUTE is intentionally NOT left at the default
-- PUBLIC grant real_metric_vintage_counts()/series_bucketed() use --
-- those only ever read; this writes, so only the ingestion function's
-- own service-role caller should be able to invoke it.
revoke execute on function refresh_daily_weather_range(int, date, date) from public;
grant execute on function refresh_daily_weather_range(int, date, date) to service_role;

-- 3. real_climate_as_of_2026(): the single source of truth for the
-- filter bar's "as of" badge. Returns null until ALL FIVE in-scope
-- metrics have at least one real (open_meteo_era5) row for 2026 --
-- deliberately the MIN across metrics, not the max: showing "as of
-- Sep 8" while soil_moisture is still only real through Sep 5 would
-- overclaim for the metrics that lag. Plain read of sensor_readings
-- (nothing here a caller couldn't already query directly), so left at
-- the same implicit-PUBLIC-execute default as real_metric_vintage_counts().
create or replace function real_climate_as_of_2026()
returns date
language sql stable as $$
  with required as (
    select unnest(array['air_temp','humidity','precipitation','soil_moisture','soil_temp']) as metric_key
  ),
  per_metric as (
    select r.metric_key,
      (select max(recorded_at at time zone 'America/Los_Angeles')
       from sensor_readings
       where vintage = 2026 and source_system = 'open_meteo_era5' and metric_key = r.metric_key
      ) as max_ts
    from required r
  )
  select case when bool_and(max_ts is not null) then min(max_ts)::date else null end
  from per_metric
$$;
