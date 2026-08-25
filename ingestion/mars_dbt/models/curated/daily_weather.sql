{{ config(materialized='incremental', unique_key=['vintage','day']) }}

with hourly as (
  -- (recorded_at at time zone 'America/Los_Angeles')::date::timestamptz,
  -- not date_trunc('day', recorded_at): the database session runs in
  -- UTC, so date_trunc('day', ...) buckets by UTC calendar day. Real
  -- sensor timestamps (Open-Meteo, confirmed) represent genuine Pacific
  -- local hours -- 7 hours of true Pacific-evening data (17:00-23:59
  -- PDT) were silently landing in the next UTC day's bucket, corrupting
  -- tmax_f/tmin_f/dtr_f/gdd_day/vpd_kpa/et0_in for any real vintage.
  -- Confirmed harmless for mock data only by coincidence: mock's
  -- recorded_at values are generated on UTC-aligned hours as an
  -- arbitrary internal day-numbering convention, never claiming genuine
  -- Pacific-local semantics, so date_trunc's UTC bucketing happened to
  -- match mock's own convention. The output stays a timestamptz at UTC
  -- midnight (::date::timestamptz), matching this table's existing `day`
  -- column type/convention -- only which calendar day each hour is
  -- attributed to changes, not the storage shape downstream code expects.
  select vintage, (recorded_at at time zone 'America/Los_Angeles')::date::timestamptz as day, metric_key, value
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