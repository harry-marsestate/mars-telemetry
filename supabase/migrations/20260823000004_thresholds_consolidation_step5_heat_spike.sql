-- Phase 12 Step 5: heat_spike, a plain new row -- no RPC change needed.
--
-- Confirmed before writing this: the evaluated CTE joins anomaly_thresholds
-- to the latest reading on metric_key with no row-collapsing, so multiple
-- rows sharing a metric_key at different thresholds/severities already
-- coexist and evaluate independently -- ferment_hot (gt,88,alert) /
-- ferment_warm (gt,85,warn) is the exact same shape, already live today.
-- air_temp_high (warn,92, Step 3) and heat_spike (alert,95, here) will do
-- the same: both get evaluated every call, either, neither, or both can
-- fire, independently.
--
-- enabled=true: restores previously-live behavior an earlier, unrelated
-- RPC cutover accidentally stranded as unreachable RULES code -- not new
-- unvalidated functionality. 95 also isn't contested by any other live
-- code path the way 92-vs-95 was before Step 3.
--
-- window_hours=1: the original dead-code checked the current reading only,
-- no sustained-duration semantics -- matches wind_high's window_hours=1,
-- the other purely-instantaneous rule in this table.

insert into anomaly_thresholds
  (rule_key, tab, severity, metric_key, scope_level, operator, threshold,
   window_hours, title, message, enabled, data_status, tooltip_phrase, action_line)
values
  ('heat_spike', 'vineyard', 'alert', 'air_temp', 'estate', 'gt', 95, 1,
   'Heat spike',
   'Action - check Block 3 and the Block 1 margins',
   true, 'real',
   'Sustained temperatures above {threshold}°F sunburn exposed fruit on the west-facing rows.',
   'Action · check Block 3 and the Block 1 margins');
