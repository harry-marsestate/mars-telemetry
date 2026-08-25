-- Real-climate-data project, schema step. Adds vintage_climate_calibration
-- (one row per vintage: the GDD/DTR correction scalar, its confidence
-- tier, and provenance) and extends daily_derived with calibrated GDD/DTR
-- columns alongside the existing raw ones.
--
-- Deliberately does NOT touch daily_weather, or the raw gdd_day/dtr_f/
-- vpd_kpa/et0_in columns already on daily_derived. Confirmed by reading
-- the actual dbt model (ingestion/mars_dbt/models/curated/daily_derived.sql)
-- rather than assuming: vpd_kpa and et0_in are computed from the exact
-- same tavg_f/rh_avg/dtr_f columns that a calibrated air_temp would flow
-- through if correction were applied upstream in daily_weather -- doing it
-- there would silently pull VPD/ET0 along with it, contradicting the
-- decision that only GDD/DTR get Grapegrowers-calibrated while raw air
-- temp, VPD, ET0, and soil stay uncorrected. Calibration lives here
-- instead, as an explicit downstream layer that leaves the shared
-- upstream stats table untouched.
--
-- combine_mode/valid_from_doy-style dormant-column mistake avoided on
-- purpose: coalesce(scalar,1) means a vintage with no calibration row
-- (2026, and any future vintage before this project reaches it) is a
-- true no-op -- gdd_day_calibrated = gdd_day, byte-identical to today's
-- behavior, not silently zero or null.
--
-- Two-gates reminder (docs/SECURITY.md): new tables get RLS auto-enabled
-- with zero policies -- grant and policy both included below, not just
-- one.

create table vintage_climate_calibration (
  vintage           int primary key references vintages(vintage),
  scalar            numeric not null,
  confidence        text not null check (confidence in ('anchored','borrowed')),
  reference_source  text,
  reference_value   numeric,
  notes             text
);

grant select on vintage_climate_calibration to authenticated;
create policy vintage_climate_calibration_read on vintage_climate_calibration
  for select using (true);

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

-- CREATE OR REPLACE VIEW does not guarantee reloptions/grants survive --
-- re-issued defensively, matching this project's established pattern of
-- re-stating grants after CREATE OR REPLACE FUNCTION even when not
-- strictly required (see Step 4's anomalies_eval migration).
alter view daily_derived set (security_invoker = true);
grant select on daily_derived to authenticated;

-- Calibration values themselves: solved so each anchored vintage's raw
-- Open-Meteo GDD total (elevation=670, ERA5-Land) exactly reproduces
-- Angwin's real, same-year Napa Valley Grapegrowers Growing Conditions
-- Report total. Angwin chosen over Deer Park or an average of the two:
-- Angwin sits at 533m, much closer to this site's confirmed 670m than
-- Deer Park's 173m -- and elevation is the established driver of the
-- Open-Meteo/regional-report divergence, not a coin-flip choice.
--
-- 2022 and 2025 have no same-year Angwin figure available (no 2022
-- report found; 2025's not yet published) -- both use the average of the
-- 2023/2024 scalars, flagged confidence='borrowed'. Two data points don't
-- establish a trend worth extrapolating; the average is the
-- least-assumption default, not a claim of accuracy equal to the
-- anchored years.
--
-- Known open questions, deliberately not resolved by nudging these
-- numbers to close the gap:
-- - The 2023 report's own narrative text names "Howell Mountain" as a
--   distinct tracked region (not one of the 16 stations on its own GDD
--   map) at 3,675 GDD by Sept 30 alone -- already higher than Angwin's
--   full-season 3,576. Its station provenance doesn't reconcile with the
--   16-station map and isn't used as the calibration target here, but it
--   suggests this calibration may be conservative (under-correcting),
--   not that it's wrong.
-- - 2025's calibrated total (using the borrowed scalar) still lands ~12%
--   below GreenCast's reported 2025 Angwin figure (3,826 for zip 94508).
--   GreenCast itself is suggestive, not confirmatory (opaque station
--   sourcing, documented community complaints of highs running 5-10F
--   low), and 2025 has no real Angwin anchor at all -- this gap is
--   left visible as a known limit of the borrowed-scalar approach for
--   this specific year, not closed by adjusting the method.
insert into vintage_climate_calibration (vintage, scalar, confidence, reference_source, reference_value, notes) values
  (2023, 1.253220, 'anchored', 'napagrowers_2023_gcr_angwin', 3576,
   'Own-year anchor. 2023 GCR narrative also names a distinct "Howell Mountain" figure (3,675 GDD by Sept 30 alone) not reconciled with the 16-station map -- this calibration may be conservative relative to the true site.'),
  (2024, 1.121165, 'anchored', 'napagrowers_2024_gcr_angwin', 4058,
   'Own-year anchor.'),
  (2022, 1.187192, 'borrowed', 'average_of_2023_2024_scalars', null,
   'No 2022 Napa Valley Grapegrowers report found. Uses the average of the 2023/2024 anchored scalars -- lower confidence than an own-year anchor.'),
  (2025, 1.187192, 'borrowed', 'average_of_2023_2024_scalars', null,
   'No 2025 Napa Valley Grapegrowers report published yet. Uses the average of the 2023/2024 anchored scalars. Cross-checked against GreenCast (zip 94508, Angwin) 2025 total of 3,826 GDD: this calibration lands ~12% below that figure. GreenCast is suggestive only (undocumented station sourcing, community-reported 5-10F low bias) -- gap left visible, not closed by adjusting the scalar.');
