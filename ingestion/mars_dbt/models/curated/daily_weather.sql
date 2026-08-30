{{ config(materialized='incremental', unique_key=['vintage','day']) }}

with hourly_raw as (
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
  select vintage, source_system,
    (recorded_at at time zone 'America/Los_Angeles')::date::timestamptz as day,
    metric_key, value
  from {{ source('raw','sensor_readings') }}
  where metric_key in ('air_temp','humidity','solar','wind_speed')
  {% if is_incremental() %}
    and recorded_at > (select coalesce(max(day), '1900-01-01') from {{ this }})
  {% endif %}
),
-- Same precedence rule as series_bucketed() (see
-- supabase/migrations/20260826000000_series_bucketed_source_aware.sql):
-- real data, when present for a (vintage, metric_key), fully supersedes
-- mock for that combination rather than being averaged with it. No block
-- dimension here by construction -- daily_weather never carries soil, the
-- one metric where block_id has mattered -- so unlike series_bucketed()
-- this scoping needs no block-level fallback; vintage+metric_key alone is
-- and stays correct here regardless of any future per-block real source.
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

-- Hour-level (NOT day-truncated) air_temp+humidity, needed to pair
-- same-hour readings for a genuine per-hour VPD. `hourly` above already
-- collapses recorded_at to `day` before this point (fine for tmax_f/
-- tmin_f/rh_avg -- single-metric extremes/averages don't need the hour --
-- but two metrics can't be paired at the same hour once that's gone).
-- Reuses real_scope (defined above) rather than recomputing real/mock
-- precedence a second time -- one source of truth for which
-- (vintage, metric_key) pairs are real.
hourly_raw_ts as (
  select vintage, source_system, recorded_at, metric_key, value
  from {{ source('raw','sensor_readings') }}
  where metric_key in ('air_temp','humidity')
  {% if is_incremental() %}
    and recorded_at > (select coalesce(max(day), '1900-01-01') from {{ this }})
  {% endif %}
),
hourly_ts as (
  select h.vintage, h.recorded_at, h.metric_key, h.value
  from hourly_raw_ts h
  left join real_scope rs on rs.vintage = h.vintage and rs.metric_key = h.metric_key
  where rs.vintage is null or h.source_system = 'open_meteo_era5'
),
-- Same Tetens formula as daily_derived.vpd_kpa (see
-- 20260824000001_restore_daily_derived_post_refresh.sql), applied per HOUR
-- instead of to the day's average temp/RH -- this is the whole point:
-- vpd_kpa folds a day's diurnal swing into one average-based number that
-- can never approach a real afternoon peak; vpd_peak_kpa computes VPD at
-- each actual hour, then takes the day's max.
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
)

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
group by hourly.vintage, hourly.day