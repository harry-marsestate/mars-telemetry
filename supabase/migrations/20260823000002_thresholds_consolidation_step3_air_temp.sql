-- Phase 12 Step 3: add the missing air_temp row.
--
-- Before this, air temperature had THREE independent hardcoded numbers for
-- "too hot" scattered across web/index.html, all disagreeing: the overview
-- tile's seasonal-norm gate (92, live), the chart tooltip's sunburn copy
-- (95, live), and the dead RULES 'Heat spike' entry (95, unreachable --
-- deleted in the frontend cleanup landing alongside this migration).
--
-- threshold=92 is NOT a validated agronomic number. It's picked only
-- because it's the value the two live code paths already agreed on
-- (formatVineyardTiles' t>92 / overviewStats' t<=92 norm-fetch gate) --
-- converging on it removes a real, currently-live inconsistency without
-- requiring us to invent a number neither path already used. 95 (the old
-- tooltip figure) is explicitly NOT treated as more valid than 92 -- both
-- were hand-typed guesses; this just stops there being two of them.
-- Real Howell-Mountain-specific heat-stress validation is still pending.
--
-- enabled=false, deliberately: inserting an enabled vineyard-tab row here
-- would make anomalies_eval() start surfacing a brand new "alert" in the
-- live Anomalies panel the moment this ships (its WHERE clause is just
-- `t.enabled and t.tab=p_tab`, no other gate) -- a behavior change nobody
-- asked for. This row exists so the frontend has one number to read for
-- tile/tooltip display; it is not yet a live breach rule. Flip enabled
-- once the threshold itself is validated, as its own deliberate step.

insert into anomaly_thresholds
  (rule_key, tab, severity, metric_key, scope_level, operator, threshold,
   window_hours, title, message, enabled, data_status, tooltip_phrase, action_line)
values
  ('air_temp_high', 'vineyard', 'warn', 'air_temp', 'estate', 'gt', 92, 6,
   'Air temperature above seasonal norm',
   'Note - provisional threshold, not yet validated for this site',
   false, 'real',
   'above roughly {threshold}°F',
   'Note · provisional, pending Howell Mountain-specific heat-stress research');
