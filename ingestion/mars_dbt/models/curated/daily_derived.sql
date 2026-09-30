{{ config(materialized='view') }}
{#
  Mirrors the production view exactly (supabase/migrations/20260930100000_harvest_year_vintage.sql,
  which supersedes 20260830000002). Until 2026-09-30 this file was an older
  definition WITHOUT the calibration columns, so a dbt run would have replaced
  the production view and broken the dashboard, the MCP gateway and P1.
  Vintage = harvest year from Nov 1 Pacific: the year condition keeps next
  vintage's Nov-Dec days out of its GDD. apply_security_invoker (post-hook)
  keeps security_invoker on.
#}
WITH d AS (
         SELECT daily_weather.vintage,
            daily_weather.day,
            daily_weather.tmax_f,
            daily_weather.tmin_f,
            daily_weather.tavg_f,
            daily_weather.dtr_f,
            daily_weather.rh_avg,
            daily_weather.solar_avg,
            daily_weather.wind_avg,
            daily_weather.vpd_peak_kpa
           FROM {{ ref('daily_weather') }} daily_weather
        ), gdd AS (
         SELECT d.vintage,
            d.day,
            GREATEST(0::numeric, (d.tmax_f + d.tmin_f) / 2::numeric - 50::numeric) AS gdd_day,
            d.dtr_f,
            0.6108 * exp(17.27 * ((d.tavg_f - 32::numeric) * 5::numeric / 9::numeric) / ((d.tavg_f - 32::numeric) * 5::numeric / 9::numeric + 237.3)) * (1::numeric - d.rh_avg / 100.0) AS vpd_kpa,
            0.0023 * ((d.tavg_f - 32::numeric) * 5::numeric / 9::numeric + 17.8) * sqrt(GREATEST(0::numeric, (d.tmax_f - d.tmin_f) * 5::numeric / 9::numeric)) * 15.0 / 25.4 AS et0_in,
            d.vpd_peak_kpa
           FROM d
          WHERE EXTRACT(doy FROM d.day) >= 91::numeric
            AND EXTRACT(year FROM d.day AT TIME ZONE 'UTC') = d.vintage::numeric
        )
 SELECT gdd.vintage,
    gdd.day,
    gdd.gdd_day,
    gdd.dtr_f,
    gdd.vpd_kpa,
    gdd.et0_in,
    sum(gdd.gdd_day) OVER (PARTITION BY gdd.vintage ORDER BY gdd.day) AS gdd_cumulative,
    gdd.gdd_day * COALESCE(c.scalar, 1::numeric) AS gdd_day_calibrated,
    sum(gdd.gdd_day * COALESCE(c.scalar, 1::numeric)) OVER (PARTITION BY gdd.vintage ORDER BY gdd.day) AS gdd_cumulative_calibrated,
    gdd.dtr_f * COALESCE(c.scalar, 1::numeric) AS dtr_f_calibrated,
    gdd.vpd_peak_kpa
   FROM gdd
     LEFT JOIN {{ source('raw','vintage_climate_calibration') }} c ON c.vintage = gdd.vintage
