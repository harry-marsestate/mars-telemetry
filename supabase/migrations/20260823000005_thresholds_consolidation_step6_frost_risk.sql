-- Phase 12 Step 6: frost_risk -- the first row to actually exercise the
-- valid_to_doy filtering added in Step 4. Non-wrapping window: valid_from_doy
-- left null, valid_to_doy=130 (inclusive, per the earlier decision -- day
-- 130 itself still counts as valid).
--
-- enabled=true: same restores-previously-live-behavior reasoning as
-- heat_spike (Step 5) -- 34°F is exactly as legitimate as 95°F, same
-- provenance, previously live before the RPC cutover stranded it, not
-- contested by any other code path. Additionally verified (see chat):
-- a cold reading on day 130 fires, the identical construct on day 131
-- does not, and the existing baseline breach + heat_spike behavior are
-- unaffected -- so unlike air_temp_high this isn't deferring an unresolved
-- ambiguity, it's a proven-correct restore.
--
-- window_hours=1: instantaneous check, matching heat_spike/wind_high.

insert into anomaly_thresholds
  (rule_key, tab, severity, metric_key, scope_level, operator, threshold,
   window_hours, title, message, enabled, data_status, tooltip_phrase,
   action_line, valid_to_doy)
values
  ('frost_risk', 'vineyard', 'warn', 'air_temp', 'estate', 'lt', 34, 1,
   'Frost risk',
   'Action - frost watch overnight',
   true, 'real',
   'Below {threshold}°F inside the budbreak window. Cold air pools in the lower rows of Block 3.',
   'Action · frost watch overnight',
   130);
