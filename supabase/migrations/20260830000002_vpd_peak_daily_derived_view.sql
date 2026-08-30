-- Threads daily_weather.vpd_peak_kpa (see daily_weather.sql) through as a
-- plain pass-through column -- same cost as dtr_f's existing pass-through,
-- zero added view-time computation. Requires daily_weather.vpd_peak_kpa to
-- already exist (dbt full-refresh) before this migration is applied, or
-- the column reference below will fail.
--
-- No other column needs touching: gdd_day/gdd_cumulative/et0_in/
-- dtr_f_calibrated etc. are untouched, and vpd_kpa (average-based) stays
-- exactly as-is -- it's still the correct source for the existing chart
-- panel, which keeps showing the daily-average trend by design.
create or replace view daily_derived as
with d as (
  select vintage, day, tmax_f, tmin_f, tavg_f, dtr_f, rh_avg, solar_avg, wind_avg, vpd_peak_kpa
  from daily_weather
),
gdd as (
  select vintage, day,
    greatest(0, (tmax_f + tmin_f)/2 - 50) as gdd_day,
    dtr_f,
    (0.6108 * exp(17.27 * ((tavg_f-32)*5/9) / (((tavg_f-32)*5/9) + 237.3)))
      * (1 - rh_avg/100.0) as vpd_kpa,
    (0.0023 * ((tavg_f-32)*5/9 + 17.8) * sqrt(greatest(0,(tmax_f-tmin_f)*5/9))
      * 15.0) / 25.4 as et0_in,
    vpd_peak_kpa
  from d
  where extract(doy from day) >= 91
)
select
  gdd.vintage, gdd.day, gdd.gdd_day, gdd.dtr_f, gdd.vpd_kpa, gdd.et0_in,
  sum(gdd.gdd_day) over (partition by gdd.vintage order by gdd.day) as gdd_cumulative,
  gdd.gdd_day * coalesce(c.scalar, 1) as gdd_day_calibrated,
  sum(gdd.gdd_day * coalesce(c.scalar, 1)) over (partition by gdd.vintage order by gdd.day) as gdd_cumulative_calibrated,
  gdd.dtr_f * coalesce(c.scalar, 1) as dtr_f_calibrated,
  gdd.vpd_peak_kpa
from gdd
left join vintage_climate_calibration c on c.vintage = gdd.vintage;

alter view daily_derived set (security_invoker = true);
grant select on daily_derived to authenticated;
