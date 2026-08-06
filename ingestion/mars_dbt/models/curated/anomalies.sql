with latest_sensor as (
  select distinct on (metric_key, coalesce(block_id,''), coalesce(tank_id,''))
    metric_key, block_id, tank_id, value, recorded_at
  from {{ source('raw','sensor_readings') }}
  order by metric_key, coalesce(block_id,''), coalesce(tank_id,''), recorded_at desc
),

latest_derived as (
  select day, vintage,
    gdd_cumulative as gdd, dtr_f as dtr, vpd_kpa as vpd, et0_in as et0
  from {{ ref('daily_derived') }}
  where vintage = (select max(vintage) from {{ source('raw','vintages') }})
  order by day desc
  limit 1
),

derived_unpivot as (
  select 'gdd' as metric_key, null::text as block_id, null::text as tank_id, gdd as value, day::timestamptz as recorded_at from latest_derived
  union all
  select 'dtr', null, null, dtr, day::timestamptz from latest_derived
  union all
  select 'vpd', null, null, vpd, day::timestamptz from latest_derived
  union all
  select 'et0', null, null, et0, day::timestamptz from latest_derived
),

all_latest as (
  select * from latest_sensor
  union all
  select * from derived_unpivot
),

evaluated as (
  select
    t.rule_key, t.tab, t.severity, t.title, t.message,
    t.metric_key, t.scope_level, a.block_id, a.tank_id,
    a.value as observed_value, a.recorded_at as evaluated_at,
    case
      when t.operator = 'lt' then a.value < t.threshold
      when t.operator = 'gt' then a.value > t.threshold
    end as breached
  from {{ source('raw','anomaly_thresholds') }} t
  join all_latest a on a.metric_key = t.metric_key
  where t.enabled
    and a.recorded_at >= now() - (t.window_hours || ' hours')::interval
)

select * from evaluated where breached