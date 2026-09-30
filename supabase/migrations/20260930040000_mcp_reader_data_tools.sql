-- mcp_reader: COLUMN-level SELECT for the four data tools the gateway now
-- exposes (get_series, get_derived_series, get_anomalies, get_vessels) --
-- exactly the columns those tools read, directly or through the objects they
-- call, and nothing else (docs/SECURITY.md, "Nightly health checks",
-- guardrail 4). RLS still applies to every row: every policy here is `to
-- public`, so queries run under the key owner's own identity, never a bypass.
--
-- Traced from the live definitions, 2026-09-30:
--   get_series        -> series_bucketed() (SECURITY INVOKER):
--                        sensor_readings(recorded_at, metric_key, block_id,
--                        vintage, source_system, value), real_data_sources(source_system)
--   get_anomalies     -> anomalies_eval() (SECURITY INVOKER):
--                        sensor_readings(metric_key, block_id, tank_id, value,
--                        recorded_at, vintage), daily_derived(gdd_cumulative,
--                        dtr_f, vpd_kpa, et0_in, vpd_peak_kpa, day, vintage),
--                        anomaly_thresholds(the columns it reads)
--   get_derived_series-> daily_derived(day, gdd_cumulative_calibrated, dtr_f,
--                        vpd_kpa, vpd_peak_kpa, et0_in, vintage)
--   daily_derived is a security_invoker view: it reads every column of
--                        daily_weather in its first CTE, and
--                        vintage_climate_calibration(vintage, scalar)
--   sensor_readings' RLS policy (sensor_read) reads metric_registry(metric_key, min_role)
--   get_vessels       -> vessels(vessel_id, code, vessel_type, capacity_gal,
--                        volume_gal, current_lot_name, current_lot_code,
--                        block_id, archived)
-- Deliberately NOT granted: sensor_readings.id/sensor_id/ingested_at,
-- vessels.capacity_suspect/current_lot_id/updated_at/ingested_at/source_system,
-- daily_derived's other columns, vintage_climate_calibration's reference
-- columns.
grant select (recorded_at, metric_key, block_id, tank_id, vintage, source_system, value) on public.sensor_readings to mcp_reader;
grant select (source_system) on public.real_data_sources to mcp_reader;
grant select (metric_key, min_role) on public.metric_registry to mcp_reader;
grant select (vintage, day, tmax_f, tmin_f, tavg_f, dtr_f, rh_avg, solar_avg, wind_avg, vpd_peak_kpa) on public.daily_weather to mcp_reader;
grant select (vintage, scalar) on public.vintage_climate_calibration to mcp_reader;
grant select (vintage, day, gdd_cumulative, gdd_cumulative_calibrated, dtr_f, vpd_kpa, vpd_peak_kpa, et0_in) on public.daily_derived to mcp_reader;
grant select (rule_key, tab, severity, title, message, metric_key, operator, threshold, enabled, window_hours, valid_from_doy, valid_to_doy) on public.anomaly_thresholds to mcp_reader;
grant select (vessel_id, code, vessel_type, capacity_gal, volume_gal, current_lot_name, current_lot_code, block_id, archived) on public.vessels to mcp_reader;
