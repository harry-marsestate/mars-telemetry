-- Real, parameterized anomaly evaluation, replacing the frontend's need to
-- query anomalies_asof/anomalies directly. Both existing dbt-built views are
-- unusable for this: anomalies_asof's as_of cutoff is a literal timestamp
-- frozen at dbt-build time (not a runtime parameter), and neither view has a
-- vintage column/filter at all -- anomalies_asof always picks the globally
-- latest sensor_readings row across every vintage combined, and anomalies
-- hardcodes latest_derived to vintage = max(vintage). Neither can answer
-- "what breached as of this archived vintage's snapshot date", which the
-- mock RULES system already does today via endOf(v)/endOfReal(v).
--
-- This function takes vintage and as-of-date as real SQL parameters and
-- replicates the anomaly_thresholds join/breach logic (same shape as the
-- anomalies dbt model's derived_unpivot pattern), filtered by p_vintage,
-- callable via sb.rpc() exactly like series_bucketed.
--
-- Scoped to tab = 'vineyard' only for now: all vineyard rules
-- (soil_below_refill, dtr_low, vpd_high, humidity_high, wind_high) are
-- backed by metrics already wired to real data. Winery rules split --
-- cellar_temp/cellar_rh rules are data-ready but ferment_hot/ferment_warm/
-- brix_dry are tank-scoped and depend on real tank/fermentation data, which
-- is the same gap already deferred for the ferm/tanks/fruit panels. Adding
-- winery support later needs more than flipping a tab filter -- it needs
-- real tank joins -- so it's left out entirely rather than half-wired.
create or replace function anomalies_eval(p_vintage int, p_as_of timestamptz)
returns table (
  rule_key text, tab text, severity text, title text, message text,
  metric_key text, block_id text, tank_id text,
  observed_value numeric, evaluated_at timestamptz
)
language sql stable as $$
  with latest_sensor as (
    select distinct on (metric_key, coalesce(block_id,''), coalesce(tank_id,''))
      metric_key, block_id, tank_id, value, recorded_at
    from sensor_readings
    where vintage = p_vintage
      and recorded_at <= p_as_of
    order by metric_key, coalesce(block_id,''), coalesce(tank_id,''), recorded_at desc
  ),

  -- daily_derived's columns don't match anomaly_thresholds.metric_key (which
  -- uses metric_registry's short keys) -- same mapping the frontend already
  -- applies: gdd -> gdd_cumulative, dtr -> dtr_f, vpd -> vpd_kpa, et0 -> et0_in
  latest_derived_row as (
    select gdd_cumulative, dtr_f, vpd_kpa, et0_in, day
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
      and t.tab = 'vineyard'
      and a.recorded_at >= p_as_of - (t.window_hours || ' hours')::interval
  )

  select rule_key, tab, severity, title, message, metric_key, block_id, tank_id,
         observed_value, evaluated_at
  from evaluated
  where breached
$$;

grant execute on function anomalies_eval(int, timestamptz) to authenticated;

-- Gap found during investigation: anomaly_thresholds had no SELECT grant for
-- authenticated at all (only postgres could read it). anomalies_eval reads
-- it as the invoking (authenticated) role -- no SECURITY DEFINER, same as
-- series_bucketed -- so without this grant every call would 42501.
grant select on anomaly_thresholds to authenticated;
