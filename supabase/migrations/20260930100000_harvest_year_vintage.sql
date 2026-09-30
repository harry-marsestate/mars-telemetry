-- Vintage = harvest year; the cycle starts November 1 Pacific (decided
-- 2026-09-30; docs/SECURITY.md "Vintage is the harvest year"). Hours from
-- Nov 1 onward belong to the NEXT year's vintage; Jan-Oct to their own
-- calendar year. No existing row changes: no sensor_readings or daily_weather
-- row has a Pacific Nov/Dec date or a year other than its vintage (checked).
--
-- 1. public.harvest_vintage(ts): the rule in SQL (same as window.ts
--    harvestVintage()).
-- 2. daily_derived: a vintage's derived rows (GDD/DTR/VPD/ET0) start at day of
--    year 91 OF ITS OWN YEAR. Without the year condition, next vintage's
--    Nov-Dec days (day of year 305+) would count toward its GDD before April.
--    Identical output for every existing row (all have year = vintage);
--    columns, security_invoker and grants unchanged. The existing DOY-91
--    condition is kept as is (it includes Mar 31 in leap years; 2024-03-31's
--    gdd_day is 0), so the calibration stays exactly valid.
-- 3. run_p1_checks(): the vintage-dependent checks follow the rule
--    (ingestion.climate.current_vintage re-written; daily_weather_through and
--    daily_weather_pacific_days look at the current and previous vintage).

create function public.harvest_vintage(p_ts timestamptz)
returns integer
language sql
immutable
set search_path = public
as $$
  select extract(year from p_ts at time zone 'America/Los_Angeles')::int
       + case when extract(month from p_ts at time zone 'America/Los_Angeles') >= 11 then 1 else 0 end
$$;
revoke all on function public.harvest_vintage(timestamptz) from public, anon, authenticated, service_role;

create or replace view public.daily_derived with (security_invoker = true) as
 WITH d AS (
         SELECT daily_weather.vintage,
            daily_weather.day,
            daily_weather.tmax_f,
            daily_weather.tmin_f,
            daily_weather.tavg_f,
            daily_weather.dtr_f,
            daily_weather.rh_avg,
            daily_weather.solar_avg,
            daily_weather.wind_avg,
            daily_weather.vpd_peak_kpa
           FROM daily_weather
        ), gdd AS (
         SELECT d.vintage,
            d.day,
            GREATEST(0::numeric, (d.tmax_f + d.tmin_f) / 2::numeric - 50::numeric) AS gdd_day,
            d.dtr_f,
            0.6108 * exp(17.27 * ((d.tavg_f - 32::numeric) * 5::numeric / 9::numeric) / ((d.tavg_f - 32::numeric) * 5::numeric / 9::numeric + 237.3)) * (1::numeric - d.rh_avg / 100.0) AS vpd_kpa,
            0.0023 * ((d.tavg_f - 32::numeric) * 5::numeric / 9::numeric + 17.8) * sqrt(GREATEST(0::numeric, (d.tmax_f - d.tmin_f) * 5::numeric / 9::numeric)) * 15.0 / 25.4 AS et0_in,
            d.vpd_peak_kpa
           FROM d
          WHERE EXTRACT(doy FROM d.day) >= 91::numeric
            AND EXTRACT(year FROM d.day AT TIME ZONE 'UTC') = d.vintage::numeric
        )
 SELECT gdd.vintage,
    gdd.day,
    gdd.gdd_day,
    gdd.dtr_f,
    gdd.vpd_kpa,
    gdd.et0_in,
    sum(gdd.gdd_day) OVER (PARTITION BY gdd.vintage ORDER BY gdd.day) AS gdd_cumulative,
    gdd.gdd_day * COALESCE(c.scalar, 1::numeric) AS gdd_day_calibrated,
    sum(gdd.gdd_day * COALESCE(c.scalar, 1::numeric)) OVER (PARTITION BY gdd.vintage ORDER BY gdd.day) AS gdd_cumulative_calibrated,
    gdd.dtr_f * COALESCE(c.scalar, 1::numeric) AS dtr_f_calibrated,
    gdd.vpd_peak_kpa
   FROM gdd
     LEFT JOIN vintage_climate_calibration c ON c.vintage = gdd.vintage;

CREATE OR REPLACE FUNCTION system_health.run_p1_checks()
 RETURNS bigint
 LANGUAGE plpgsql
 SET search_path TO 'public'
AS $function$
declare
  v_run bigint;
  v_obs jsonb;
  v_exp jsonb;
  v_base jsonb;
  v_status text;
  v_detail text;
  v_n bigint;
  v_n2 bigint;
  v_rec record;
  v_svc constant uuid := '3c254617-caf0-4498-8e1e-a9dfff9800b8'; -- svc-nightly-checks' account (operator, service)
  v_pacific_today date := (now() at time zone 'America/Los_Angeles')::date;
begin
  v_run := system_health.record_run('p1_database');

  ------------------------------------------------------------------ ingestion
  -- Last recorded run of each ingest function (ingestion_runs, step d).
  for v_rec in select * from (values ('ingest-climate-2026', 'ingestion.climate.last_run'), ('ingest-innovint', 'ingestion.innovint.last_run')) a(asset, check_id) loop
    begin
      select jsonb_build_object('started_at', started_at, 'status', status, 'http_status', http_status, 'rows_written', rows_written,
                                'age_hours', round(extract(epoch from now() - started_at) / 3600, 1), 'error', left(error, 300))
        into v_obs
        from system_health.ingestion_runs where asset = v_rec.asset order by started_at desc limit 1;
      v_exp := jsonb_build_object('status', 'success', 'max_age_hours', 26, 'rows_written', '> 0');
      if v_obs is null then
        v_status := 'fail'; v_detail := 'no recorded run';
      elsif v_obs->>'status' <> 'success' then
        v_status := 'fail'; v_detail := 'last run did not succeed';
      elsif (v_obs->>'age_hours')::numeric > 26 then
        v_status := 'fail'; v_detail := 'last run is older than 26 hours';
      elsif coalesce((v_obs->>'rows_written')::int, 0) = 0 then
        v_status := 'warn'; v_detail := 'last run succeeded but wrote no rows';
      else
        v_status := 'pass'; v_detail := null;
      end if;
      perform system_health.record_result(v_run, 'ingestion', v_rec.check_id, v_status, v_obs, v_exp, v_detail);
    exception when others then
      perform system_health.record_result(v_run, 'ingestion', v_rec.check_id, 'error', null, null, left(sqlerrm, 500));
    end;
  end loop;

  -- Newest real ERA5 hour. The 13:17 UTC ingest stores through the last
  -- elapsed hour, so at 12:00 the newest hour is ~23h old.
  begin
    select jsonb_build_object('newest_real_hour', max(recorded_at), 'age_hours', round(extract(epoch from now() - max(recorded_at)) / 3600, 1))
      into v_obs from sensor_readings where metric_key = 'air_temp' and source_system = 'open_meteo_ecmwf_ifs';
    v_exp := jsonb_build_object('max_age_hours', 26);
    v_status := case when (v_obs->>'age_hours') is null or (v_obs->>'age_hours')::numeric > 26 then 'fail' else 'pass' end;
    perform system_health.record_result(v_run, 'ingestion', 'ingestion.climate.freshness', v_status, v_obs, v_exp,
      case when v_status = 'fail' then 'real climate data is more than 26 hours old' end);
  exception when others then
    perform system_health.record_result(v_run, 'ingestion', 'ingestion.climate.freshness', 'error', null, null, left(sqlerrm, 500));
  end;

  -- daily_weather is rebuilt through the last complete Pacific day before the
  -- 13:17 UTC run, i.e. two Pacific days before "today" at 12:00 UTC.
  begin
    select jsonb_build_object('daily_weather_through', max((day at time zone 'UTC')::date), 'pacific_today', v_pacific_today)
      into v_obs from daily_weather where vintage >= public.harvest_vintage(now()) - 1;
    v_exp := jsonb_build_object('daily_weather_through_at_least', v_pacific_today - 2);
    v_status := case when (v_obs->>'daily_weather_through') is null or (v_obs->>'daily_weather_through')::date < v_pacific_today - 2 then 'fail' else 'pass' end;
    perform system_health.record_result(v_run, 'ingestion', 'ingestion.climate.daily_weather_through', v_status, v_obs, v_exp,
      case when v_status = 'fail' then 'daily_weather is behind' end);
  exception when others then
    perform system_health.record_result(v_run, 'ingestion', 'ingestion.climate.daily_weather_through', 'error', null, null, left(sqlerrm, 500));
  end;

  -- Vintage = harvest year, starting Nov 1 Pacific (public.harvest_vintage).
  -- Fail if any recent real climate row breaks the rule, or if the current
  -- harvest vintage is missing from public.vintages (the ingest refuses its
  -- hours); warn from 14 days before Nov 1 if the next vintage is missing.
  begin
    select jsonb_build_object(
        'rows_checked', count(*),
        'rows_breaking_rule', count(*) filter (where vintage is distinct from public.harvest_vintage(recorded_at)),
        'newest_hour', max(recorded_at),
        'current_harvest_vintage', public.harvest_vintage(now()),
        'current_vintage_in_table', exists (select 1 from vintages where vintage = public.harvest_vintage(now())),
        'vintage_in_14_days', public.harvest_vintage(now() + interval '14 days'),
        'vintage_in_14_days_in_table', exists (select 1 from vintages where vintage = public.harvest_vintage(now() + interval '14 days')))
      into v_obs from sensor_readings
     where source_system in ('open_meteo_ecmwf_ifs', 'open_meteo_era5_land') and recorded_at > now() - interval '3 days';
    v_exp := '{"rows_breaking_rule": 0, "current_vintage_in_table": true, "vintage_in_14_days_in_table": true}'::jsonb;
    v_status := case when (v_obs->>'rows_checked')::int = 0 or (v_obs->>'rows_breaking_rule')::int > 0 or not (v_obs->>'current_vintage_in_table')::boolean then 'fail'
                     when not (v_obs->>'vintage_in_14_days_in_table')::boolean then 'warn' else 'pass' end;
    perform system_health.record_result(v_run, 'ingestion', 'ingestion.climate.current_vintage', v_status, v_obs, v_exp,
      case when (v_obs->>'rows_checked')::int = 0 then 'no real climate rows in 3 days'
           when (v_obs->>'rows_breaking_rule')::int > 0 then 'real climate rows whose vintage breaks the harvest-year rule (Nov 1 Pacific starts next vintage)'
           when not (v_obs->>'current_vintage_in_table')::boolean then 'the current harvest vintage is not in public.vintages: the climate ingest is refusing its hours'
           when v_status = 'warn' then 'the next vintage starts Nov 1 and is not in public.vintages yet: add it before then (docs/SECURITY.md)' end);
  exception when others then
    perform system_health.record_result(v_run, 'ingestion', 'ingestion.climate.current_vintage', 'error', null, null, left(sqlerrm, 500));
  end;

  ------------------------------------------------------------------ integrity
  begin
    select jsonb_build_object('out_of_range', count(*) filter (where value < 0 or value > 100), 'min', min(value), 'max', max(value))
      into v_obs from sensor_readings where metric_key = 'soil_moisture';
    perform system_health.record_result(v_run, 'database', 'database.integrity.soil_moisture_range',
      case when (v_obs->>'out_of_range')::int > 0 then 'fail' else 'pass' end, v_obs, '{"range": [0, 100], "out_of_range": 0}'::jsonb, null);
  exception when others then
    perform system_health.record_result(v_run, 'database', 'database.integrity.soil_moisture_range', 'error', null, null, left(sqlerrm, 500));
  end;

  -- Calibrated season GDD for the closed real vintages.
  begin
    select jsonb_object_agg(vintage::text, g) into v_obs
      from (select vintage, round(max(gdd_cumulative_calibrated), 1) g from daily_derived where vintage between 2022 and 2025 group by vintage) s;
    select count(*) into v_n from jsonb_each_text(coalesce(v_obs, '{}')) e where e.value::numeric not between 3000 and 4400;
    v_status := case when v_obs is null or (select count(*) from jsonb_object_keys(v_obs)) <> 4 or v_n > 0 then 'fail' else 'pass' end;
    perform system_health.record_result(v_run, 'database', 'database.integrity.gdd_calibrated_2022_2025', v_status, v_obs,
      '{"vintages": [2022, 2023, 2024, 2025], "each_between": [3000, 4400]}'::jsonb, null);
  exception when others then
    perform system_health.record_result(v_run, 'database', 'database.integrity.gdd_calibrated_2022_2025', 'error', null, null, left(sqlerrm, 500));
  end;

  -- Real and mock rows may coexist in a vintage (the mock generator runs to
  -- MOCK_NOW); series_bucketed() must still never blend them. For every
  -- coexisting (metric, vintage), the no-vintage series over the overlap must
  -- equal the vintage-scoped one (the 2026-09-30 blending bug).
  begin
    v_obs := '[]'::jsonb; v_n := 0;
    for v_rec in
      with k as (
        select metric_key, vintage, source_system in (select source_system from real_data_sources) as is_real,
               min(recorded_at) lo, max(recorded_at) hi,
               array_agg(distinct block_id) filter (where block_id is not null) blocks
          from sensor_readings
         group by 1, 2, 3
      )
      select r.metric_key, r.vintage, greatest(r.lo, m.lo) lo, least(r.hi, m.hi) hi, coalesce(m.blocks, '{}') blocks
        from k r join k m on m.metric_key = r.metric_key and m.vintage = r.vintage and r.is_real and not m.is_real
       where least(r.hi, m.hi) > greatest(r.lo, m.lo)
       order by 1, 2
    loop
      -- estate-wide (p_block NULL) and every block that has mock rows
      v_n2 := 0;
      for v_detail in select unnest(array[null::text] || v_rec.blocks) loop
        v_n2 := v_n2 + (select count(*) from (
          select a.t from series_bucketed(v_rec.metric_key, v_detail, null, date_trunc('day', v_rec.lo), v_rec.hi, '24 hours') a
          full join series_bucketed(v_rec.metric_key, v_detail, v_rec.vintage, date_trunc('day', v_rec.lo), v_rec.hi, '24 hours') b using (t)
           where a.v is distinct from b.v) d);
      end loop;
      v_obs := v_obs || jsonb_build_object('metric', v_rec.metric_key, 'vintage', v_rec.vintage, 'blocks_checked', 1 + cardinality(v_rec.blocks), 'mismatched_buckets', v_n2);
      v_n := v_n + v_n2;
    end loop;
    v_base := system_health.baseline_or_init('database.integrity.mock_real_precedence',
      coalesce((select jsonb_agg(jsonb_build_object('metric', e->>'metric', 'vintage', (e->>'vintage')::int)) from jsonb_array_elements(v_obs) e), '[]'));
    v_status := case when v_n > 0 then 'fail'
                     when v_base is not null and v_base <> coalesce((select jsonb_agg(jsonb_build_object('metric', e->>'metric', 'vintage', (e->>'vintage')::int)) from jsonb_array_elements(v_obs) e), '[]') then 'warn'
                     else 'pass' end;
    perform system_health.record_result(v_run, 'database', 'database.integrity.mock_real_precedence', v_status,
      jsonb_build_object('coexisting', v_obs), jsonb_build_object('mismatched_buckets', 0, 'coexisting_pairs', v_base),
      case when v_n > 0 then 'series_bucketed blends mock into real when no vintage is passed'
           when v_status = 'warn' then 'the set of vintages with both real and mock rows changed'
           when v_base is null then 'baseline initialised' end);
  exception when others then
    perform system_health.record_result(v_run, 'database', 'database.integrity.mock_real_precedence', 'error', null, null, left(sqlerrm, 500));
  end;

  -- daily_weather days are Pacific calendar days, stored as that date at
  -- 00:00 UTC. Recompute the newest real day's tmax AND tavg from the hourly
  -- ERA5 rows bucketed by Pacific date. tavg is the discriminating one: a
  -- UTC-bucketed rebuild shifts 7-8 hours and changes the average, while the
  -- afternoon maximum often falls in both buckets (2026-09-28: 80.5 either way).
  declare
    v_day date; v_tmax numeric; v_tavg numeric; v_la numeric; v_la_avg numeric; v_utc numeric; v_utc_avg numeric; v_bad bigint;
  begin
    select count(*) filter (where (day at time zone 'UTC')::time <> '00:00') into v_bad from daily_weather;
    select (day at time zone 'UTC')::date, tmax_f, tavg_f into v_day, v_tmax, v_tavg from daily_weather
     where vintage >= public.harvest_vintage(now()) - 1 order by day desc limit 1;
    select max(value), avg(value) into v_la, v_la_avg from sensor_readings
     where metric_key = 'air_temp' and source_system = 'open_meteo_ecmwf_ifs' and (recorded_at at time zone 'America/Los_Angeles')::date = v_day;
    select max(value), avg(value) into v_utc, v_utc_avg from sensor_readings
     where metric_key = 'air_temp' and source_system = 'open_meteo_ecmwf_ifs' and (recorded_at at time zone 'UTC')::date = v_day;
    v_obs := jsonb_build_object('day', v_day, 'daily_weather_tmax_f', v_tmax, 'pacific_bucketed_tmax_f', v_la, 'utc_bucketed_tmax_f', v_utc,
                                'daily_weather_tavg_f', round(v_tavg, 4), 'pacific_bucketed_tavg_f', round(v_la_avg, 4), 'utc_bucketed_tavg_f', round(v_utc_avg, 4),
                                'days_not_at_utc_midnight', v_bad);
    v_status := case when v_bad > 0 or v_tmax is null or v_la is null or abs(v_tmax - v_la) > 0.001 or abs(v_tavg - v_la_avg) > 0.0001 then 'fail' else 'pass' end;
    perform system_health.record_result(v_run, 'database', 'database.integrity.daily_weather_pacific_days', v_status, v_obs,
      '{"daily_weather_tmax_f": "= pacific_bucketed_tmax_f", "daily_weather_tavg_f": "= pacific_bucketed_tavg_f", "days_not_at_utc_midnight": 0}'::jsonb, null);
  exception when others then
    perform system_health.record_result(v_run, 'database', 'database.integrity.daily_weather_pacific_days', 'error', null, null, left(sqlerrm, 500));
  end;

  -- B1 had no irrigation logged in 2024 (farm records); any row is spurious.
  begin
    select count(*) into v_n from sensor_readings where metric_key = 'irrigation_volume' and block_id = 'B1' and vintage = 2024;
    perform system_health.record_result(v_run, 'database', 'database.integrity.no_b1_2024_irrigation',
      case when v_n > 0 then 'fail' else 'pass' end, jsonb_build_object('rows', v_n), '{"rows": 0}'::jsonb, null);
  exception when others then
    perform system_health.record_result(v_run, 'database', 'database.integrity.no_b1_2024_irrigation', 'error', null, null, left(sqlerrm, 500));
  end;

  -- The upserts in both ingest functions rely on this constraint.
  begin
    select count(*) into v_n from pg_constraint
     where conrelid = 'public.sensor_readings'::regclass and contype = 'u'
       and pg_get_constraintdef(oid) = 'UNIQUE (metric_key, sensor_id, recorded_at)';
    perform system_health.record_result(v_run, 'database', 'database.integrity.sensor_readings_unique',
      case when v_n = 1 then 'pass' else 'fail' end, jsonb_build_object('matching_constraints', v_n),
      '{"constraint": "UNIQUE (metric_key, sensor_id, recorded_at)"}'::jsonb, null);
  exception when others then
    perform system_health.record_result(v_run, 'database', 'database.integrity.sensor_readings_unique', 'error', null, null, left(sqlerrm, 500));
  end;

  -- The forecast-hours bug (2026-09-29): no real row may be in the future.
  begin
    select count(*) into v_n from sensor_readings where recorded_at > now() and source_system in (select source_system from real_data_sources);
    perform system_health.record_result(v_run, 'database', 'database.integrity.no_future_real_rows',
      case when v_n > 0 then 'fail' else 'pass' end, jsonb_build_object('rows', v_n), '{"rows": 0}'::jsonb, null);
  exception when others then
    perform system_health.record_result(v_run, 'database', 'database.integrity.no_future_real_rows', 'error', null, null, left(sqlerrm, 500));
  end;

  ------------------------------------------------------------------ checksums
  -- Closed vintages must not change. Order-independent 64-bit checksums per
  -- vintage (count + sum of row hashes; ids and ingest timestamps excluded).
  begin
    select jsonb_object_agg(vintage::text, jsonb_build_object('rows', n, 'sum', s)) into v_obs from (
      select vintage, count(*) n, sum(hashtextextended(concat_ws('|', metric_key, sensor_id, block_id, tank_id, recorded_at, value, source_system), 0))::text s
        from sensor_readings where vintage between 2022 and 2025 group by vintage) x;
    v_base := system_health.baseline_or_init('database.checksum.sensor_readings_closed_vintages', v_obs);
    perform system_health.record_result(v_run, 'database', 'database.checksum.sensor_readings_closed_vintages',
      case when v_base is null or v_base = v_obs then 'pass' else 'fail' end, v_obs, v_base,
      case when v_base is null then 'baseline initialised' when v_base <> v_obs then 'sensor_readings for a closed vintage (2022-2025) changed' end);
  exception when others then
    perform system_health.record_result(v_run, 'database', 'database.checksum.sensor_readings_closed_vintages', 'error', null, null, left(sqlerrm, 500));
  end;

  begin
    select jsonb_object_agg(vintage::text, jsonb_build_object('rows', n, 'sum', s)) into v_obs from (
      select vintage, count(*) n, sum(hashtextextended(concat_ws('|', day, tmax_f, tmin_f, tavg_f, dtr_f, rh_avg, solar_avg, wind_avg, vpd_peak_kpa), 0))::text s
        from daily_weather where vintage between 2022 and 2025 group by vintage) x;
    v_base := system_health.baseline_or_init('database.checksum.daily_weather_closed_vintages', v_obs);
    perform system_health.record_result(v_run, 'database', 'database.checksum.daily_weather_closed_vintages',
      case when v_base is null or v_base = v_obs then 'pass' else 'fail' end, v_obs, v_base,
      case when v_base is null then 'baseline initialised' when v_base <> v_obs then 'daily_weather for a closed vintage (2022-2025) changed' end);
  exception when others then
    perform system_health.record_result(v_run, 'database', 'database.checksum.daily_weather_closed_vintages', 'error', null, null, left(sqlerrm, 500));
  end;

  -- InnoVint/lab/labour history can legitimately be corrected upstream, so a
  -- change is a warning to look at, not a failure. Surrogate ids and
  -- sync/ingest timestamps are excluded: a re-sync of unchanged rows is not a change.
  begin
    v_obs := jsonb_build_object(
      'harvest_receipts', (select jsonb_object_agg(vintage::text, jsonb_build_object('rows', n, 'sum', s)) from (
          select vintage, count(*) n, sum(hashtextextended((to_jsonb(t) - 'id' - 'synced_at' - 'ingested_at')::text, 0))::text s from harvest_receipts t where vintage between 2022 and 2025 group by vintage) x),
      'lab_samples', (select jsonb_object_agg(vintage::text, jsonb_build_object('rows', n, 'sum', s)) from (
          select vintage, count(*) n, sum(hashtextextended((to_jsonb(t) - 'id' - 'synced_at' - 'ingested_at')::text, 0))::text s from lab_samples t where vintage between 2022 and 2025 group by vintage) x),
      'labour_actuals', (select jsonb_object_agg(vintage::text, jsonb_build_object('rows', n, 'sum', s)) from (
          select vintage, count(*) n, sum(hashtextextended((to_jsonb(t) - 'id' - 'synced_at' - 'ingested_at')::text, 0))::text s from labour_actuals t where vintage between 2022 and 2025 group by vintage) x));
    v_base := system_health.baseline_or_init('database.checksum.winery_closed_vintages', v_obs);
    perform system_health.record_result(v_run, 'database', 'database.checksum.winery_closed_vintages',
      case when v_base is null or v_base = v_obs then 'pass' else 'warn' end, v_obs, v_base,
      case when v_base is null then 'baseline initialised' when v_base <> v_obs then 'closed-vintage harvest/lab/labour rows changed (upstream correction or re-ingest?)' end);
  exception when others then
    perform system_health.record_result(v_run, 'database', 'database.checksum.winery_closed_vintages', 'error', null, null, left(sqlerrm, 500));
  end;

  ------------------------------------------------------------------ anomalies
  -- Known anomaly anchors, evaluated as the svc-nightly-checks account through
  -- RLS (SET LOCAL ROLE authenticated + its claims), then back to postgres.
  declare
    v_a bigint; v_b bigint;
  begin
    perform set_config('request.jwt.claims', jsonb_build_object('sub', v_svc, 'role', 'authenticated')::text, true);
    set local role authenticated;
    select count(*) into v_a from anomalies_eval(2024, '2024-07-06T02:00:00Z');
    select count(*) into v_b from anomalies_eval(2024, '2024-04-06T14:00:00Z');
    reset role;
    perform set_config('request.jwt.claims', '', true);
    perform system_health.record_result(v_run, 'database', 'database.anomalies.anchor_2024_07_06',
      case when v_a = 3 then 'pass' else 'fail' end, jsonb_build_object('hits', v_a, 'as', 'svc-nightly-checks'), '{"hits": 3}'::jsonb, null);
    perform system_health.record_result(v_run, 'database', 'database.anomalies.anchor_2024_04_06',
      case when v_b = 2 then 'pass' else 'fail' end, jsonb_build_object('hits', v_b, 'as', 'svc-nightly-checks'), '{"hits": 2}'::jsonb, null);
  exception when others then
    reset role;
    perform set_config('request.jwt.claims', '', true);
    perform system_health.record_result(v_run, 'database', 'database.anomalies.anchor_2024_07_06', 'error', null, null, left(sqlerrm, 500));
    perform system_health.record_result(v_run, 'database', 'database.anomalies.anchor_2024_04_06', 'error', null, null, left(sqlerrm, 500));
  end;

  ------------------------------------------------------------------ vessels
  begin
    select jsonb_build_object('active', count(*) filter (where not archived), 'total', count(*),
                              'capacity_suspect', count(*) filter (where capacity_suspect))
      into v_obs from vessels;
    v_base := system_health.baseline_or_init('database.vessels.counts', v_obs);
    v_status := case
      when (v_obs->>'active')::int = 0 then 'fail'
      when v_base is null then 'pass'
      when (v_obs->>'capacity_suspect')::int > (v_base->>'capacity_suspect')::int then 'warn'
      when abs((v_obs->>'active')::int - (v_base->>'active')::int) > greatest(5, (v_base->>'active')::int / 4) then 'warn'
      else 'pass' end;
    perform system_health.record_result(v_run, 'database', 'database.vessels.counts', v_status, v_obs, v_base,
      case when v_base is null then 'baseline initialised'
           when v_status = 'warn' then 'more capacity_suspect vessels than baseline, or active count moved by more than 25%' end);
  exception when others then
    perform system_health.record_result(v_run, 'database', 'database.vessels.counts', 'error', null, null, left(sqlerrm, 500));
  end;

  ------------------------------------------------------------------ structure / security
  begin
    select jsonb_build_object(
      'security_invoker', coalesce((select option_value from pg_options_to_table(c.reloptions) where option_name = 'security_invoker'), 'false'),
      'columns', (select jsonb_agg(attname::text order by attnum) from pg_attribute where attrelid = c.oid and attnum > 0 and not attisdropped),
      'grants', (select jsonb_agg(distinct g.grantee || ':' || g.privilege_type order by g.grantee || ':' || g.privilege_type)
                   from information_schema.role_table_grants g where g.table_schema = 'public' and g.table_name = 'daily_derived'),
      'mcp_reader_columns', (select jsonb_agg(column_name::text order by column_name) from information_schema.column_privileges
                   where table_schema = 'public' and table_name = 'daily_derived' and grantee = 'mcp_reader'))
      into v_obs from pg_class c where c.oid = 'public.daily_derived'::regclass;
    v_base := system_health.baseline_or_init('security.structure.daily_derived', v_obs);
    v_status := case when v_obs->>'security_invoker' <> 'true' then 'fail' when v_base is null or v_base = v_obs then 'pass' else 'fail' end;
    perform system_health.record_result(v_run, 'security', 'security.structure.daily_derived', v_status, v_obs, v_base,
      case when v_obs->>'security_invoker' <> 'true' then 'daily_derived is no longer security_invoker: it would bypass RLS'
           when v_base is null then 'baseline initialised' when v_status = 'fail' then 'daily_derived columns or grants changed' end);
  exception when others then
    perform system_health.record_result(v_run, 'security', 'security.structure.daily_derived', 'error', null, null, left(sqlerrm, 500));
  end;

  begin
    select coalesce(jsonb_agg(n.nspname || '.' || c.relname order by n.nspname, c.relname), '[]') into v_obs
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname in ('public', 'system_health') and c.relkind in ('r', 'p') and not c.relrowsecurity;
    perform system_health.record_result(v_run, 'security', 'security.rls.enabled_on_every_table',
      case when jsonb_array_length(v_obs) = 0 then 'pass' else 'fail' end, jsonb_build_object('tables_without_rls', v_obs), '{"tables_without_rls": []}'::jsonb, null);
  exception when others then
    perform system_health.record_result(v_run, 'security', 'security.rls.enabled_on_every_table', 'error', null, null, left(sqlerrm, 500));
  end;

  -- anon: no data privilege on any public relation (fail); the residual
  -- REFERENCES/TRIGGER/TRUNCATE grants are tracked against a baseline (warn).
  begin
    select coalesce(jsonb_agg(distinct table_name || ':' || privilege_type), '[]') into v_obs
      from information_schema.role_table_grants
     where grantee = 'anon' and table_schema in ('public', 'system_health') and privilege_type in ('SELECT', 'INSERT', 'UPDATE', 'DELETE');
    perform system_health.record_result(v_run, 'security', 'security.anon.no_data_privileges',
      case when jsonb_array_length(v_obs) = 0 then 'pass' else 'fail' end, jsonb_build_object('privileges', v_obs), '{"privileges": []}'::jsonb, null);
  exception when others then
    perform system_health.record_result(v_run, 'security', 'security.anon.no_data_privileges', 'error', null, null, left(sqlerrm, 500));
  end;
  begin
    select jsonb_build_object('rows', count(*), 'md5', md5(string_agg(table_name || ':' || privilege_type, ',' order by table_name, privilege_type)))
      into v_obs from information_schema.role_table_grants where grantee = 'anon' and table_schema = 'public';
    v_base := system_health.baseline_or_init('security.anon.residual_privileges', v_obs);
    perform system_health.record_result(v_run, 'security', 'security.anon.residual_privileges',
      case when v_base is null or v_base = v_obs then 'pass' else 'warn' end, v_obs, v_base,
      case when v_base is null then 'baseline initialised (REFERENCES/TRIGGER/TRUNCATE only; see docs/SECURITY.md)'
           when v_base <> v_obs then 'anon''s table privileges changed' end);
  exception when others then
    perform system_health.record_result(v_run, 'security', 'security.anon.residual_privileges', 'error', null, null, left(sqlerrm, 500));
  end;

  -- Policies: per-policy fingerprints against the baseline; the result names
  -- what was added, removed or changed.
  declare
    v_now jsonb; v_added jsonb; v_removed jsonb; v_changed jsonb;
  begin
    select jsonb_object_agg(schemaname || '.' || tablename || '.' || policyname,
             md5(concat_ws('|', permissive, roles::text, cmd, qual, with_check)))
      into v_now from pg_policies where schemaname in ('public', 'system_health');
    v_base := system_health.baseline_or_init('security.policies.baseline', v_now);
    if v_base is null then
      perform system_health.record_result(v_run, 'security', 'security.policies.baseline', 'pass',
        jsonb_build_object('policies', (select count(*) from jsonb_object_keys(v_now))), null, 'baseline initialised');
    else
      select coalesce(jsonb_agg(k), '[]') into v_added from jsonb_object_keys(v_now) k where not v_base ? k;
      select coalesce(jsonb_agg(k), '[]') into v_removed from jsonb_object_keys(v_base) k where not v_now ? k;
      select coalesce(jsonb_agg(k), '[]') into v_changed from jsonb_object_keys(v_now) k where v_base ? k and v_base->>k <> v_now->>k;
      v_status := case when jsonb_array_length(v_added) + jsonb_array_length(v_removed) + jsonb_array_length(v_changed) = 0 then 'pass' else 'fail' end;
      perform system_health.record_result(v_run, 'security', 'security.policies.baseline', v_status,
        jsonb_build_object('policies', (select count(*) from jsonb_object_keys(v_now)), 'added', v_added, 'removed', v_removed, 'changed', v_changed),
        jsonb_build_object('policies', (select count(*) from jsonb_object_keys(v_base))),
        case when v_status = 'fail' then 'RLS policies differ from the baseline: if deliberate, re-baseline (docs/SECURITY.md)' end);
    end if;
  exception when others then
    perform system_health.record_result(v_run, 'security', 'security.policies.baseline', 'error', null, null, left(sqlerrm, 500));
  end;

  begin
    select coalesce(jsonb_agg(f order by f), '[]') into v_obs from unnest(array[
      'public.accessible_blocks()', 'public.current_role_name()', 'public.current_data_mode()', 'public.is_admin_user()',
      'public.domain_reality(integer[])', 'public.series_bucketed(text,text,integer,timestamp with time zone,timestamp with time zone,interval,text)',
      'public.anomalies_eval(integer,timestamp with time zone,text)', 'public.refresh_daily_weather_range(integer,date,date)',
      'public.mcp_authenticate(text)', 'public.mcp_log_call(text,text,jsonb,boolean)', 'public.mcp_key_scope(text)', 'public.mcp_authorize_call(text,text)',
      'public.log_ingestion_run(text,timestamp with time zone,text,integer,integer,text,jsonb)', 'public.notify_admin_approval_webhook()',
      'system_health.record_run(text,timestamp with time zone)', 'system_health.record_result(bigint,text,text,text,jsonb,jsonb,text)',
      'system_health.prune(integer)']) f
     where to_regprocedure(f) is null;
    perform system_health.record_result(v_run, 'security', 'security.functions.required_present',
      case when jsonb_array_length(v_obs) = 0 then 'pass' else 'fail' end, jsonb_build_object('missing', v_obs), '{"missing": []}'::jsonb, null);
  exception when others then
    perform system_health.record_result(v_run, 'security', 'security.functions.required_present', 'error', null, null, left(sqlerrm, 500));
  end;

  begin
    select coalesce(jsonb_agg(n.nspname || '.' || p.proname order by n.nspname, p.proname), '[]') into v_obs
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname in ('public', 'system_health') and p.prosecdef
       and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) c where c like 'search_path=%');
    perform system_health.record_result(v_run, 'security', 'security.definer.search_path_pinned',
      case when jsonb_array_length(v_obs) = 0 then 'pass' else 'fail' end, jsonb_build_object('definer_functions_without_search_path', v_obs),
      '{"definer_functions_without_search_path": []}'::jsonb, null);
  exception when others then
    perform system_health.record_result(v_run, 'security', 'security.definer.search_path_pinned', 'error', null, null, left(sqlerrm, 500));
  end;

  -- mcp_reader's grants are the gateway's boundary (check-mcp-boundaries.mjs
  -- section 4 checks the migrations; this checks the live catalog).
  begin
    select jsonb_build_object(
      'tables', (select coalesce(jsonb_agg(distinct table_name || ':' || privilege_type), '[]') from information_schema.role_table_grants where grantee = 'mcp_reader'),
      'columns', (select md5(string_agg(table_name || '.' || column_name || ':' || privilege_type, ',' order by table_name, column_name, privilege_type))
                    from information_schema.column_privileges where grantee = 'mcp_reader'))
      into v_obs;
    v_base := system_health.baseline_or_init('security.mcp_reader.grants', v_obs);
    perform system_health.record_result(v_run, 'security', 'security.mcp_reader.grants',
      case when v_base is null or v_base = v_obs then 'pass' else 'fail' end, v_obs, v_base,
      case when v_base is null then 'baseline initialised' when v_base <> v_obs then 'mcp_reader''s privileges changed: re-run check-mcp-boundaries and re-baseline if deliberate' end);
  exception when others then
    perform system_health.record_result(v_run, 'security', 'security.mcp_reader.grants', 'error', null, null, left(sqlerrm, 500));
  end;

  -- health_writer may run the two writer functions and nothing else.
  begin
    select jsonb_build_object(
      'functions', (select coalesce(jsonb_agg(p.oid::regprocedure::text order by p.oid::regprocedure::text), '[]') from pg_proc p
                     where has_function_privilege('health_writer', p.oid, 'execute')
                       and p.pronamespace not in ('pg_catalog'::regnamespace, 'information_schema'::regnamespace)
                       and not exists (select 1 from aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a where a.grantee = 0 and a.privilege_type = 'EXECUTE')),
      'tables', (select count(*) from information_schema.role_table_grants where grantee = 'health_writer'),
      'bypassrls', (select rolbypassrls from pg_roles where rolname = 'health_writer'),
      'superuser', (select rolsuper from pg_roles where rolname = 'health_writer'))
      into v_obs;
    v_exp := '{"functions": ["system_health.record_result(bigint,text,text,text,jsonb,jsonb,text)", "system_health.record_run(text,timestamp with time zone)"], "tables": 0, "bypassrls": false, "superuser": false}'::jsonb;
    perform system_health.record_result(v_run, 'security', 'security.health_writer.privileges',
      case when v_obs = v_exp then 'pass' else 'fail' end, v_obs, v_exp, null);
  exception when others then
    perform system_health.record_result(v_run, 'security', 'security.health_writer.privileges', 'error', null, null, left(sqlerrm, 500));
  end;

  -- No key may live in a trigger argument, function body, view, cron command
  -- or role setting (the pg_trigger incident, 2026-09-29). NAMES only.
  declare
    v_pat constant text := '(sb_secret_[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})';
  begin
    select coalesce(jsonb_agg(o order by o), '[]') into v_obs from (
      select 'trigger ' || t.tgrelid::regclass || '.' || t.tgname o from pg_trigger t where encode(t.tgargs, 'escape') ~ v_pat
      union all
      select 'function ' || p.oid::regprocedure from pg_proc p join pg_namespace n on n.oid = p.pronamespace
       where n.nspname not in ('pg_catalog', 'information_schema') and p.prosrc ~ v_pat
      union all
      select 'view ' || c.oid::regclass from pg_class c join pg_namespace n on n.oid = c.relnamespace
       where c.relkind in ('v', 'm') and n.nspname not in ('pg_catalog', 'information_schema') and pg_get_viewdef(c.oid) ~ v_pat
      union all
      select 'cron job ' || j.jobname from cron.job j where j.command ~ v_pat
      union all
      select 'role setting ' || coalesce(r.rolname, '*') || '/' || coalesce(d.datname, '*') from pg_db_role_setting s
        left join pg_roles r on r.oid = s.setrole left join pg_database d on d.oid = s.setdatabase
       where array_to_string(s.setconfig, ' ') ~ v_pat
    ) x;
    perform system_health.record_result(v_run, 'security', 'security.no_embedded_keys',
      case when jsonb_array_length(v_obs) = 0 then 'pass' else 'fail' end, jsonb_build_object('objects', v_obs), '{"objects": []}'::jsonb,
      case when jsonb_array_length(v_obs) > 0 then 'a key-shaped string is embedded in these objects: move it to Vault and rotate it (docs/SECURITY.md)' end);
  exception when others then
    perform system_health.record_result(v_run, 'security', 'security.no_embedded_keys', 'error', null, null, left(sqlerrm, 500));
  end;

  -- pg_net's queue is readable by PUBLIC and holds request headers (the
  -- Vault-decrypted key) until sent: accepted residual risk while requests
  -- leave within seconds. The queue has no timestamp; a queued request is
  -- stale if a LATER request (higher id) got its response over 10 minutes ago.
  begin
    select jsonb_build_object('queued', (select count(*) from net.http_request_queue),
      'stale', (select count(*) from net.http_request_queue q
                 where q.id < (select max(r.id) from net._http_response r where r.created < now() - interval '10 minutes')))
      into v_obs;
    perform system_health.record_result(v_run, 'security', 'security.pg_net.queue_not_stale',
      case when (v_obs->>'stale')::int > 0 then 'warn' else 'pass' end, v_obs, '{"stale": 0}'::jsonb,
      case when (v_obs->>'stale')::int > 0 then 'pg_net requests have waited over 10 minutes; their headers (incl. the Vault key) stay readable while queued' end);
  exception when others then
    perform system_health.record_result(v_run, 'security', 'security.pg_net.queue_not_stale', 'error', null, null, left(sqlerrm, 500));
  end;

  -- Climate source labels (2026-09-30 relabel): no atmospheric row may claim
  -- ERA5, soil from Open-Meteo must be ERA5-Land, and the legacy
  -- open_meteo_era5 / OM-ERA5 labels must be gone.
  begin
    select jsonb_build_object(
      'legacy_label_rows', count(*) filter (where source_system = 'open_meteo_era5' or sensor_id = 'OM-ERA5'),
      'non_soil_labelled_era5', count(*) filter (where metric_key not in ('soil_moisture', 'soil_temp') and (source_system ilike '%era5%' or sensor_id ilike '%era5%')),
      'soil_not_era5_land', count(*) filter (where metric_key in ('soil_moisture', 'soil_temp') and source_system <> 'open_meteo_era5_land'),
      'rows_by_label', (select jsonb_object_agg(k, n) from (select source_system || ' / ' || sensor_id k, count(*) n from sensor_readings
                          where source_system like 'open_meteo%' or sensor_id like 'OM-%' group by 1) x))
      into v_obs
      from sensor_readings where source_system like 'open_meteo%' or sensor_id like 'OM-%';
    v_status := case when (v_obs->>'legacy_label_rows')::int + (v_obs->>'non_soil_labelled_era5')::int + (v_obs->>'soil_not_era5_land')::int > 0 then 'fail' else 'pass' end;
    perform system_health.record_result(v_run, 'database', 'database.integrity.climate_source_labels', v_status, v_obs,
      '{"legacy_label_rows": 0, "non_soil_labelled_era5": 0, "soil_not_era5_land": 0}'::jsonb,
      case when v_status = 'fail' then 'a climate row is labelled with a model it did not come from (docs/SECURITY.md, "Climate rows were labelled ERA5 but came from ECMWF IFS")' end);
  exception when others then
    perform system_health.record_result(v_run, 'database', 'database.integrity.climate_source_labels', 'error', null, null, left(sqlerrm, 500));
  end;

  -- The newest climate ingest must have pinned its models (never best_match):
  -- ingest-climate-2026 records the models its request URLs actually carried.
  begin
    select jsonb_build_object('started_at', started_at, 'requested_models', detail->'requested_models')
      into v_obs from system_health.ingestion_runs where asset = 'ingest-climate-2026' order by started_at desc limit 1;
    v_exp := '{"requested_models": {"weather": "ecmwf_ifs", "soil": "era5_land"}}'::jsonb;
    v_status := case when v_obs->'requested_models' = v_exp->'requested_models' then 'pass' else 'fail' end;
    perform system_health.record_result(v_run, 'ingestion', 'ingestion.climate.model_pinned', v_status, v_obs, v_exp,
      case when v_status = 'fail' then 'the newest climate ingest did not request the pinned models (missing = best_match)' end);
  exception when others then
    perform system_health.record_result(v_run, 'ingestion', 'ingestion.climate.model_pinned', 'error', null, null, left(sqlerrm, 500));
  end;

  return v_run;
end $function$;

revoke all on function system_health.run_p1_checks() from public, anon, authenticated, service_role;
