{{ config(materialized='incremental', unique_key=['vintage','day']) }}

with hourly as (
  select vintage, date_trunc('day', recorded_at) as day, metric_key, value
  from {{ source('raw','sensor_readings') }}
  where metric_key in ('air_temp','humidity','solar','wind_speed')
  {% if is_incremental() %}
    and recorded_at > (select coalesce(max(day), '1900-01-01') from {{ this }})
  {% endif %}
)
select
  vintage, day,
  max(value) filter (where metric_key='air_temp')  as tmax_f,
  min(value) filter (where metric_key='air_temp')  as tmin_f,
  avg(value) filter (where metric_key='air_temp')  as tavg_f,
  max(value) filter (where metric_key='air_temp') - min(value) filter (where metric_key='air_temp') as dtr_f,
  avg(value) filter (where metric_key='humidity')  as rh_avg,
  avg(value) filter (where metric_key='solar')     as solar_avg,
  avg(value) filter (where metric_key='wind_speed') as wind_avg
from hourly
group by vintage, day