-- Phase 12 Step 4: wire up valid_from_doy/valid_to_doy in anomalies_eval().
--
-- These columns were added in Step 1 but never consumed by anomalies_eval()
-- -- confirmed via pg_get_functiondef before writing this: the live function
-- referenced neither column, so any row that set them would silently have
-- no seasonal restriction at all. This migration is what actually activates
-- them.
--
-- Purely additive: all 13 existing rows have both columns NULL, and the
-- CASE below evaluates to `true` whenever both are NULL -- byte-identical
-- breach behavior for every rule that exists today. Only a future row that
-- sets one or both columns (starting with frost_risk, added separately
-- once this is verified) is affected.
--
-- Wrap-around handling mirrors web/index.html's rainDay() (`dy<105||dy>295`
-- for a wet season spanning Dec31/Jan1): when valid_from_doy > valid_to_doy,
-- the window is treated as wrapping across year-end and matched via OR
-- instead of BETWEEN. frost_risk itself (valid_to_doy=130 only,
-- valid_from_doy null) doesn't exercise that branch -- it's a plain
-- non-wrapping "day 1 through day 130" window -- but the CASE handles a
-- wrapping row correctly if one is ever added.
--
-- Boundary: valid_to_doy is inclusive (day N itself counts as valid).
-- Confirmed acceptable even though it's a one-day drift from the original
-- dead-code's strict `doy<130` -- that code was never live-tested, and a
-- clean inclusive semantic matters more for a mechanism future rules will
-- reuse than exact fidelity to it.

create or replace function anomalies_eval(p_vintage int, p_as_of timestamptz, p_tab text default 'vineyard')
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
$$;

grant execute on function anomalies_eval(int, timestamptz, text) to authenticated;
