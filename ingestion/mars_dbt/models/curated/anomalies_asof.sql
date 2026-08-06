{% set as_of = "'" ~ var('as_of_date', 'now()') ~ "'" %}

with latest_sensor as (
  select distinct on (metric_key, coalesce(block_id,''), coalesce(tank_id,''))
    metric_key, block_id, tank_id, value, recorded_at
  from {{ source('raw','sensor_readings') }}
  where recorded_at <= {{ as_of }}
  order by metric_key, coalesce(block_id,''), coalesce(tank_id,''), recorded_at desc
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
  from {{ source('raw','anomaly_thresholds') }} t
  join latest_sensor a on a.metric_key = t.metric_key
  where t.enabled
    and a.recorded_at >= {{ as_of }}::timestamptz - (t.window_hours || ' hours')::interval
)

select * from evaluated where breached