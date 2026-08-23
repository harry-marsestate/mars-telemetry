-- Phase 12 Step 1: additive, reversible schema extension to
-- anomaly_thresholds. No RPC change, no enabled-state change, no threshold
-- value change. Behavior must be byte-identical after this migration.
--
-- New columns are the single source of truth this table is moving toward:
-- display_label/tooltip_phrase/action_line carry the copy that today lives
-- hand-typed in web/index.html (chart bands, info: tooltips, RULES array)
-- and duplicated again in this table's own title/message columns. Backfilled
-- from those existing hand-typed copies, not invented.
--
-- Interpolation convention (frontend consolidation, a later step, depends on
-- this): plain {threshold} / {threshold_low} / {threshold_high} tokens
-- stored as literal text, resolved client-side at render time -- NOT
-- resolved by Postgres. {threshold} = this row's own threshold column.
-- {threshold_low}/{threshold_high} = the sibling row sharing the same
-- rule_group (lt-row supplies _low, gt-row supplies _high).
--
-- Known gap, not fixed here: soil_below_refill's band (15-25) and
-- vpd_high's band (0.4-3.1) each have only ONE edge backed by a row in this
-- table (15 and 3.1 respectively) -- there's no soil_above_field_capacity
-- or vpd_low row, so the *other* number in those two display_labels stays a
-- plain literal, not an interpolation. Out of scope for this step.

alter table anomaly_thresholds
  add column display_label   text,
  add column tooltip_phrase  text,
  add column action_line     text,
  add column rule_group      text,
  add column combine_mode    text not null default 'or'
    check (combine_mode in ('or','and')),
  add column valid_from_doy  int,
  add column valid_to_doy    int,
  add column data_status     text
    check (data_status in ('real','mock'));

-- Backfill: vineyard (5 rows, all data_status='real', all already enabled)

update anomaly_thresholds set
  tooltip_phrase = 'against the {threshold}°F typical here',
  action_line = 'Watch · monitor the Brix–pH gap',
  data_status = 'real'
where rule_key = 'dtr_low';

update anomaly_thresholds set
  tooltip_phrase = 'above roughly {threshold}% raises mildew pressure, especially with warm nights',
  action_line = 'Watch · review the spray interval',
  data_status = 'real'
where rule_key = 'humidity_high';

update anomaly_thresholds set
  display_label = 'Target 15–25 % VWC',
  tooltip_phrase = 'under the {threshold}% VWC floor for deficit irrigation',
  action_line = 'Action · schedule an irrigation set within 48 h',
  data_status = 'real'
where rule_key = 'soil_below_refill';

update anomaly_thresholds set
  display_label = 'Productive band 0.4–{threshold} kPa',
  tooltip_phrase = 'above roughly {threshold} kPa the vine starts closing stomata to conserve water',
  action_line = 'Watch · reassess at 16:00',
  data_status = 'real'
where rule_key = 'vpd_high';

update anomaly_thresholds set
  tooltip_phrase = 'above about {threshold} mph creates spray drift risk',
  action_line = 'Action · suspend spraying',
  data_status = 'real'
where rule_key = 'wind_high';

-- Backfill: winery cellar rules (4 rows, data_status='real', paired via rule_group)

update anomaly_thresholds set
  display_label = 'Target {threshold_low}–{threshold_high} °F',
  tooltip_phrase = 'Sustained drift outside the {threshold_low}–{threshold_high}°F target shows up later as inconsistency across lots aging side by side',
  action_line = 'Action · check the HVAC set point',
  rule_group = 'cellar_temp_band',
  data_status = 'real'
where rule_key in ('cellar_temp_high','cellar_temp_low');

update anomaly_thresholds set
  display_label = 'Target {threshold_low}–{threshold_high} %',
  tooltip_phrase = 'Dry air accelerates barrel evaporation loss; too humid raises mold risk on barrel exteriors',
  action_line = 'Watch · review the topping schedule',
  rule_group = 'cellar_rh_band',
  data_status = 'real'
where rule_key in ('cellar_rh_high','cellar_rh_low');

-- Backfill: winery ferment/brix rules (3 rows, data_status='mock' -- confirmed
-- mock-only per the Phase 12 investigation: same seed batch/CSV/commit as
-- every other sensor_readings row, README says "All synthetic", and the
-- later lot_analyses_vessels migration confirms the ferm/tanks/fruit panels
-- never wired to this data at all. enabled left untouched -- see note above,
-- it was already true and nothing in this step changes that column.

update anomaly_thresholds set
  tooltip_phrase = 'over the {threshold}°F ceiling. Risk of a stuck ferment and volatile acidity',
  action_line = 'Action · engage the tank jacket',
  data_status = 'mock'
where rule_key = 'ferment_hot';

update anomaly_thresholds set
  tooltip_phrase = 'within 3°F of the intervention threshold',
  action_line = 'Watch · recheck in 2 h',
  data_status = 'mock'
where rule_key = 'ferment_warm';

update anomaly_thresholds set
  tooltip_phrase = 'at or near dryness',
  action_line = 'Note · schedule press within 2–3 days',
  data_status = 'mock'
where rule_key = 'brix_dry';

-- Explicit per your approval to revive these 4 for the RPC in a later step.
-- No-op today: all 12 rows, including these 4, already have enabled=true
-- (confirmed via a fresh query immediately before writing this migration).
-- Issued anyway so the migration itself documents the decision rather than
-- relying on a state that happened to already be true.
update anomaly_thresholds set enabled = true
where rule_key in ('cellar_temp_high','cellar_temp_low','cellar_rh_high','cellar_rh_low');
