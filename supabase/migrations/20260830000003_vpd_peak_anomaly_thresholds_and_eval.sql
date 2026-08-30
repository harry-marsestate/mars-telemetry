-- Two-tier peak-hour VPD anomaly, replacing (via a NEW metric_key, not a
-- redefinition) the average-based vpd_high as the live "is the vine
-- stressed" check. Reasoning, real distribution, and literature
-- cross-check: docs/SECURITY.md (VPD peak-hour design entries).
--
-- metric_key='vpd_peak', NOT a redefinition of the existing 'vpd' key:
-- traced every consumer of the literal string 'vpd' before choosing this
-- (anomalies_eval's own derived_unpivot, the orphaned dbt anomalies.sql
-- model, and two unrelated namespaces -- web/index.html's panel id 'vpd',
-- and the chat tool's raw vpd_kpa column reference). Nothing else depends
-- on 'vpd' meaning "average VPD" except the one row being disabled below,
-- so redefining it in place would have silently changed what an
-- already-enabled row's threshold compared against, with the 3.1 value
-- itself untouched.
insert into anomaly_thresholds
  (rule_key, tab, severity, metric_key, scope_level, operator, threshold,
   window_hours, title, message, enabled, display_label, tooltip_phrase,
   action_line, rule_group, combine_mode, valid_from_doy, valid_to_doy, data_status)
values
  ('vpd_peak_warn', 'vineyard', 'warn', 'vpd_peak', 'estate', 'gt', 5.0, 3,
   'Elevated afternoon vapour pressure deficit',
   'Watch - afternoon vine stress rising, consider midday irrigation',
   true,
   'Elevated above {threshold} kPa (afternoon peak)',
   'peak afternoon VPD above roughly {threshold} kPa signals rising vine water stress',
   'Watch · reassess at 16:00',
   null, 'or', null, null, 'real'),
  ('vpd_peak_alert', 'vineyard', 'alert', 'vpd_peak', 'estate', 'gt', 6.5, 3,
   'Severe afternoon vapour pressure deficit',
   'Action - severe vine stress, irrigate promptly if not already scheduled',
   true,
   'Severe above {threshold} kPa (afternoon peak)',
   'peak afternoon VPD above roughly {threshold} kPa is among this site''s most severe stress days on record',
   'Action · irrigate today if not already scheduled',
   null, 'or', null, null, 'real');

-- Threshold values: real 2022-2025 daily-peak VPD (860 days, computed from
-- true hourly air_temp+humidity) has p90=4.87, p95=5.40, p99=7.05,
-- max=8.38 kPa. 5.0 sits just above p90 (top ~8% of real days). 6.5 is
-- anchored directly to the literature's own cited "genuinely severe"
-- ceiling (Scholasch et al. 2009 Napa field study, and an independent
-- primary-source sap-flow paper by the same researcher, both ~6.5-6.6
-- kPa) -- and real local data reaches it too: 13/860 days (~3/season)
-- exceed 6.5, matching what an 'alert' tier should mean.
--
-- rule_group left null on both: interpolateThreshold()'s sibling lookup
-- is built for an lt/gt PAIR describing one band, not two same-direction
-- (gt) escalating tiers -- the frontend panel reads both rows
-- independently via th.byKey.get(...) instead.

-- Old vpd_high (average-based, metric_key='vpd', threshold 3.1) disabled,
-- not deleted. enabled=false is an established pattern in this exact
-- table -- air_temp_high already sits disabled today while every other
-- row (including mock-backed ones) stays enabled. anomalies_eval()'s
-- WHERE clause already filters `where t.enabled`, so this alone silences
-- it from firing -- no other change needed for that half. Not deleted:
-- preserves the row's exact historical definition for comparison or
-- reversion.
update anomaly_thresholds set enabled = false where rule_key = 'vpd_high';

-- Found while re-verifying the already-applied vpd_low display fix:
-- vpd_high.display_label stores "0.4" as LITERAL text, not a
-- {threshold_low}/{threshold_high} placeholder -- interpolateThreshold()
-- only substitutes {threshold}/{threshold_low}/{threshold_high}, so the
-- literal "0.4" renders verbatim regardless of the JS-side lo fix, and
-- getThresholds() fetches ALL rows with no `enabled` filter -- disabling
-- this row (above) does NOT stop the chart panel from reading its
-- display_label for the band legend. Corrected here, same migration,
-- since it's the same row already being touched. Kept as the same
-- hardcoded-literal-text shape the row already used (not switched to
-- {threshold_low} templating, which needs a paired sibling row via
-- rule_group -- out of scope for this pass).
update anomaly_thresholds set display_label = 'Productive band 0.16–{threshold} kPa' where rule_key = 'vpd_high';

-- anomalies_eval(): fifth branch in derived_unpivot, sourced from
-- daily_derived.vpd_peak_kpa. latest_derived_row's own select list
-- extended to include it -- everything else in this function is
-- byte-identical to the live definition (pulled via pg_get_functiondef
-- immediately before writing this migration).
create or replace function public.anomalies_eval(p_vintage integer, p_as_of timestamp with time zone, p_tab text default 'vineyard'::text)
returns table(rule_key text, tab text, severity text, title text, message text, metric_key text, block_id text, tank_id text, observed_value numeric, evaluated_at timestamp with time zone)
language sql
stable
as $function$
  with latest_sensor as (
    select distinct on (metric_key, coalesce(block_id,''), coalesce(tank_id,''))
      metric_key, block_id, tank_id, value, recorded_at
    from sensor_readings
    where vintage = p_vintage
      and recorded_at <= p_as_of
    order by metric_key, coalesce(block_id,''), coalesce(tank_id,''), recorded_at desc
  ),

  latest_derived_row as (
    select gdd_cumulative, dtr_f, vpd_kpa, et0_in, vpd_peak_kpa, day
    from daily_derived
    where vintage = p_vintage
      and day <= p_as_of
    order by day desc
    limit 1
  ),
  derived_unpivot as (
    select 'gdd'::text as metric_key, null::text as block_id, null::text as tank_id, gdd_cumulative as value, day::timestamptz as recorded_at from latest_derived_row
    union all
    select 'dtr', null, null, dtr_f, day::timestamptz from latest_derived_row
    union all
    select 'vpd', null, null, vpd_kpa, day::timestamptz from latest_derived_row
    union all
    select 'et0', null, null, et0_in, day::timestamptz from latest_derived_row
    union all
    select 'vpd_peak', null, null, vpd_peak_kpa, day::timestamptz from latest_derived_row
  ),

  all_latest as (
    select * from latest_sensor
    union all
    select * from derived_unpivot
  ),

  evaluated as (
    select
      t.rule_key, t.tab, t.severity, t.title, t.message,
      t.metric_key, a.block_id, a.tank_id,
      a.value as observed_value, a.recorded_at as evaluated_at,
      case
        when t.operator = 'lt' then a.value < t.threshold
        when t.operator = 'gt' then a.value > t.threshold
      end as breached
    from anomaly_thresholds t
    join all_latest a on a.metric_key = t.metric_key
    where t.enabled
      and t.tab = p_tab
      and a.recorded_at >= p_as_of - (t.window_hours || ' hours')::interval
      and (
        case
          when t.valid_from_doy is null and t.valid_to_doy is null then true
          when coalesce(t.valid_from_doy,1) <= coalesce(t.valid_to_doy,366)
            then extract(doy from p_as_of) between coalesce(t.valid_from_doy,1) and coalesce(t.valid_to_doy,366)
          else extract(doy from p_as_of) >= t.valid_from_doy or extract(doy from p_as_of) <= t.valid_to_doy
        end
      )
  )

  select rule_key, tab, severity, title, message, metric_key, block_id, tank_id,
         observed_value, evaluated_at
  from evaluated
  where breached
$function$;
