with d as (select * from {{ ref('daily_weather') }}),
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
select *, sum(gdd_day) over (partition by vintage order by day) as gdd_cumulative
from gdd