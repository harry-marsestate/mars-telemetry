-- anomalies_eval()'s latest_sensor/derived_unpivot union sits on the
-- inner side of a Nested Loop against anomaly_thresholds (7 enabled
-- rules per tab) -- because latest_sensor was a plain (non-materialized)
-- CTE, Postgres re-executed its entire expensive DISTINCT ON scan once
-- per outer row: 7 times per call, not once (confirmed via loops=7 in
-- EXPLAIN ANALYZE). This was invisible to the sensor_read RLS
-- investigation above because that investigation tested latest_sensor
-- as a standalone query, never through anomalies_eval()'s actual join
-- structure. Marking latest_sensor and latest_derived_row MATERIALIZED
-- forces single-evaluation, matching the same "compute once, reuse"
-- discipline already applied to current_role_name() in the RLS fix
-- above -- same shape of bug, a different layer of the same function.
--
-- Verified equivalent, full output not row counts, before proposing
-- this: md5 checksums of the complete ordered result set matched
-- exactly across 7 dates covering a multi-hit case, several zero-hit
-- cases, both sides of frost_risk's doy=130 boundary, and a real
-- frost-conditions date where frost_risk and humidity_high both
-- genuinely fire. See docs/SECURITY.md.
--
-- Measured impact: vineyard (2024-07-06) 550.9ms -> 151.2ms (3.6x);
-- winery (2026-08-30) 1,232.0ms -> 242.2ms (5.1x) -- closes, and here
-- reverses, the tab asymmetry the RLS fix left unexplained.
create or replace function anomalies_eval(p_vintage integer, p_as_of timestamptz, p_tab text default 'vineyard')
returns table(rule_key text, tab text, severity text, title text, message text, metric_key text, block_id text, tank_id text, observed_value numeric, evaluated_at timestamptz)
language sql stable as $function$
  with latest_sensor as materialized (
    select distinct on (metric_key, coalesce(block_id,''), coalesce(tank_id,''))
      metric_key, block_id, tank_id, value, recorded_at
    from sensor_readings
    where vintage = p_vintage
      and recorded_at <= p_as_of
    order by metric_key, coalesce(block_id,''), coalesce(tank_id,''), recorded_at desc
  ),
  latest_derived_row as materialized (
    select gdd_cumulative, dtr_f, vpd_kpa, et0_in, vpd_peak_kpa, day
    from daily_derived
    where vintage = p_vintage
      and day <= p_as_of
    order by day desc
    limit 1
  ),
  derived_unpivot as (
    select 'gdd'::text as metric_key, null::text as block_id, null::text as tank_id, gdd_cumulative as value, day::timestamptz as recorded_at from latest_derived_row
    union all
    select 'dtr', null, null, dtr_f, day::timestamptz from latest_derived_row
    union all
    select 'vpd', null, null, vpd_kpa, day::timestamptz from latest_derived_row
    union all
    select 'et0', null, null, et0_in, day::timestamptz from latest_derived_row
    union all
    select 'vpd_peak', null, null, vpd_peak_kpa, day::timestamptz from latest_derived_row
  ),
  all_latest as (
    select * from latest_sensor
    union all
    select * from derived_unpivot
  ),
  evaluated as (
    select
      t.rule_key, t.tab, t.severity, t.title, t.message,
      t.metric_key, a.block_id, a.tank_id,
      a.value as observed_value, a.recorded_at as evaluated_at,
      case
        when t.operator = 'lt' then a.value < t.threshold
        when t.operator = 'gt' then a.value > t.threshold
      end as breached
    from anomaly_thresholds t
    join all_latest a on a.metric_key = t.metric_key
    where t.enabled
      and t.tab = p_tab
      and a.recorded_at >= p_as_of - (t.window_hours || ' hours')::interval
      and (
        case
          when t.valid_from_doy is null and t.valid_to_doy is null then true
          when coalesce(t.valid_from_doy,1) <= coalesce(t.valid_to_doy,366)
            then extract(doy from p_as_of) between coalesce(t.valid_from_doy,1) and coalesce(t.valid_to_doy,366)
          else extract(doy from p_as_of) >= t.valid_from_doy or extract(doy from p_as_of) <= t.valid_to_doy
        end
      )
  )
  select rule_key, tab, severity, title, message, metric_key, block_id, tank_id,
         observed_value, evaluated_at
  from evaluated
  where breached
$function$;
