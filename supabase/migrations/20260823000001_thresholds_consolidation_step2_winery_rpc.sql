-- Phase 12 Step 2: extend anomalies_eval() to also evaluate tab='winery'
-- rows, for the 4 cellar rules only. ferment_hot/ferment_warm/brix_dry
-- remain untouched -- standing verdict from the provenance investigation,
-- not reopened here: confirmed mock data (same seed batch/CSV/commit as
-- every other sensor_readings row), no real path to the RPC.
--
-- Minimal change: latest_sensor already selects every metric_key from
-- sensor_readings with no filter, so cellar_temp/cellar_rh readings are
-- already flowing into all_latest today -- they're just never joined
-- against a tab='winery' row because of the tab='vineyard' hardcode below.
-- Adding p_tab and changing one line is the entire functional change.
--
-- Must drop the old 2-arg signature first: CREATE OR REPLACE does not
-- replace a function when the argument list changes shape (int,timestamptz)
-- vs (int,timestamptz,text) are different signatures to Postgres, so
-- without the drop this would create a second, overloaded function and
-- make the existing 2-arg frontend call ambiguous -- same failure mode
-- documented in 20260806100100_series_bucketed_agg.sql for series_bucketed.
-- p_tab defaults to 'vineyard' so the existing 2-arg call keeps working
-- with zero frontend change.

drop function if exists anomalies_eval(int, timestamptz);

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
  )

  select rule_key, tab, severity, title, message, metric_key, block_id, tank_id,
         observed_value, evaluated_at
  from evaluated
  where breached
$$;

grant execute on function anomalies_eval(int, timestamptz, text) to authenticated;

-- ferment_warm description-only fix. threshold/operator are already 85/gt
-- (matches the client's lower bound already -- no numeric change needed).
-- tooltip_phrase previously described its relationship to ferment_hot's
-- threshold ("within 3°F of the intervention threshold") instead of being
-- self-contained -- the same hand-typed-relationship pattern as the DTR
-- bug, one row removed. Rewritten to interpolate only its own threshold.
-- Still data_status='mock', still unwired -- this changes display text
-- only, on a row nothing reads yet.

update anomaly_thresholds set
  tooltip_phrase = 'above {threshold}°F and climbing — worth a check before it runs hotter'
where rule_key = 'ferment_warm';
