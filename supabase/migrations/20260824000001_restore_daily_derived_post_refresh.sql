-- Restores state lost by the dbt full-refresh of daily_weather run while
-- fixing its day-bucketing bug (see docs/SECURITY.md). A full-refresh on
-- an incremental dbt model does a real DROP + CREATE of the underlying
-- table, which had two consequences neither obvious in advance nor
-- caught by dbt's own tooling:
--
-- 1. daily_derived (a plain view created by migration, layered on top of
--    daily_weather for the climate-calibration project) was CASCADE
--    dropped along with the table it depends on. Recreated here,
--    byte-identical to the version in
--    20260824000000_climate_calibration_schema.sql.
-- 2. `grant select on daily_weather to authenticated` did not survive
--    either. dbt's apply_security_invoker post-hook (models/macros/
--    apply_security.sql) re-applies the RLS policy on every run --
--    confirmed still present after the refresh -- but it only handles
--    RLS enable+policy, not the separate GRANT. Two independent gates,
--    same two-gates principle already on record in docs/SECURITY.md,
--    just triggered by a dbt refresh instead of a new-table creation:
--    the policy alone would have made this fail silently (empty rows);
--    what actually happened is the grant-only gate missing, a hard
--    "permission denied for table daily_weather" for every authenticated
--    user until this migration.
--
-- Operational note for next time: any future `dbt run --full-refresh`
-- (or equivalent drop+recreate) on daily_weather will reproduce BOTH of
-- these -- re-run this migration's view-recreation and grant statements
-- after any such refresh, don't assume dbt's post-hook covers it.

grant select on daily_weather to authenticated;

create or replace view daily_derived as
with d as (
  select vintage, day, tmax_f, tmin_f, tavg_f, dtr_f, rh_avg, solar_avg, wind_avg
  from daily_weather
),
gdd as (
  select vintage, day,
    greatest(0, (tmax_f + tmin_f)/2 - 50) as gdd_day,
    dtr_f,
    (0.6108 * exp(17.27 * ((tavg_f-32)*5/9) / (((tavg_f-32)*5/9) + 237.3)))
      * (1 - rh_avg/100.0) as vpd_kpa,
    (0.0023 * ((tavg_f-32)*5/9 + 17.8) * sqrt(greatest(0,(tmax_f-tmin_f)*5/9))
      * 15.0) / 25.4 as et0_in
  from d
  where extract(doy from day) >= 91
)
select
  gdd.vintage, gdd.day, gdd.gdd_day, gdd.dtr_f, gdd.vpd_kpa, gdd.et0_in,
  sum(gdd.gdd_day) over (partition by gdd.vintage order by gdd.day) as gdd_cumulative,
  gdd.gdd_day * coalesce(c.scalar, 1) as gdd_day_calibrated,
  sum(gdd.gdd_day * coalesce(c.scalar, 1)) over (partition by gdd.vintage order by gdd.day) as gdd_cumulative_calibrated,
  gdd.dtr_f * coalesce(c.scalar, 1) as dtr_f_calibrated
from gdd
left join vintage_climate_calibration c on c.vintage = gdd.vintage;

alter view daily_derived set (security_invoker = true);
grant select on daily_derived to authenticated;
