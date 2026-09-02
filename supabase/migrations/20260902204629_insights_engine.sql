-- Insights engine: two independent statistical tiers over already-real
-- data (see docs/SECURITY.md for the underlying real/mock precedence
-- rules this design reuses rather than reimplements).

-- ── metric_derivation ────────────────────────────────────────────────
-- Declares which metrics are computed FROM which others, so the scanner
-- can exclude tautological pairs before testing (not as a "discovery").
-- New derived metrics register here going forward -- no scanner code
-- change needed. Also reused by insights-scan/metrics.ts's
-- realVintagesByMetric() to derive a derived metric's real-vintage
-- coverage from its declared inputs' -- a second purpose this table
-- wasn't originally built for, chosen over adding a third lookup table.
--
-- et0_in -> air_temp ONLY. Confirmed live against daily_derived's actual
-- SQL (Hargreaves-Samani: tavg_f, tmax_f, tmin_f -- all air_temp
-- derivatives, nothing else), NOT from DATA_SOURCES.et0_in's UI label
-- ('from temperature, humidity, wind, and solar radiation' -- web/index.html),
-- which overclaims relative to what's actually computed. Declaring et0 as
-- depending on humidity/solar here (matching the stale label instead of
-- the real formula) would have wrongly excluded et0 x humidity / et0 x
-- solar as "tautological" when they're actually legitimate, non-
-- definitional pairs to test.
create table metric_derivation (
  metric_key    text not null,
  derived_from  text not null,
  notes         text,
  primary key (metric_key, derived_from)
);

-- Static, non-sensitive reference config -- same class of data as
-- anomaly_thresholds, same open-read precedent
-- (20260806120400_anomaly_thresholds_rls.sql: "static rule metadata...
-- a fully open read policy is correct").
grant select on metric_derivation to authenticated;
create policy metric_derivation_read on metric_derivation
  for select using (true);

insert into metric_derivation (metric_key, derived_from, notes) values
  ('dtr',           'air_temp',  'daily max - min of air_temp'),
  ('gdd_day',       'air_temp',  '(tmax+tmin)/2 - 50, base 50F'),
  ('vpd_kpa',       'air_temp',  'Tetens formula on daily-avg air_temp + humidity'),
  ('vpd_kpa',       'humidity',  'Tetens formula on daily-avg air_temp + humidity'),
  ('vpd_peak_kpa',  'air_temp',  'same Tetens formula, hourly, day''s max'),
  ('vpd_peak_kpa',  'humidity',  'same Tetens formula, hourly, day''s max'),
  ('et0_in',        'air_temp',  'Hargreaves-Samani: tavg_f, tmax_f, tmin_f ONLY -- '
                                  'confirmed live against daily_derived''s SQL, not the '
                                  'DATA_SOURCES.et0_in UI label (web/index.html), which '
                                  'still claims humidity/wind/solar as inputs. That label '
                                  'is stale relative to the real formula; not fixed here.');

-- ── real_metric_vintage_counts ──────────────────────────────────────
-- Server-side aggregation for insights-scan's real-vintage derivation.
-- NOT a client-side row-count-and-filter -- that would hit exactly the
-- PostgREST 1000-row default cap documented elsewhere in docs/SECURITY.md
-- (6 raw metrics x hourly cadence x a full season is well over 1000 rows
-- per metric/vintage). No explicit grant needed: matches series_bucketed()'s
-- own precedent of a plain `language sql stable` function, implicitly
-- PUBLIC-executable, since it exposes nothing beyond aggregate counts of
-- rows a caller could already read directly.
create or replace function real_metric_vintage_counts(p_metrics text[], p_vintages int[])
returns table(metric_key text, vintage int, n bigint)
language sql stable as $$
  select metric_key, vintage, count(*) as n
  from sensor_readings
  where metric_key = any(p_metrics)
    and vintage = any(p_vintages)
    and source_system in (select source_system from real_data_sources)
  group by metric_key, vintage
$$;

-- ── insights ──────────────────────────────────────────────────────────
create table insights (
  id                bigint generated always as identity primary key,
  run_id            uuid not null,
  computed_at       timestamptz not null default now(),
  -- 'vineyard' is the only value populated today (both tiers are
  -- vineyard-operations findings). Kept as a column, not hardcoded,
  -- since a future real lot-level link (see the winery-tab empty-state
  -- comment in web/index.html) could someday produce a winery-tab
  -- finding without a schema change.
  tab               text not null default 'vineyard' check (tab in ('vineyard','winery')),
  tier              text not null check (tier in ('A','B')),
  metric_a          text not null,
  metric_b          text not null,
  scope_kind        text not null check (scope_kind in ('estate','block')),
  scope_block_id    text references blocks(block_id),
  scope_vintages    int[] not null,
  date_range_start  date,
  date_range_end    date,
  method            text not null check (method in ('spearman_lag','rank_concordance')),
  effect            numeric not null,
  -- Signed lag, Tier A only. lag_days > 0: metric_b lags metric_a
  -- (metric_a[day t] paired with metric_b[day t+lag]). lag_days < 0:
  -- metric_a lags metric_b. metric_a/metric_b order is alphabetical
  -- (a storage-canonicalization convention only -- see
  -- insights_metric_order below), NOT a claim about which metric is
  -- physically upstream, so the search tests both directions
  -- (-21..21) rather than assuming metric_a always leads.
  lag_days          int,
  n_observations    int not null,
  p_value           numeric,
  p_adjusted        numeric,
  vintages_agreeing int,
  vintages_tested   int,
  confidence_label  text not null check (confidence_label in ('reproduced','single_season','directional_only')),
  status            text not null check (status in ('surfaced','below_threshold','excluded_derived','excluded_low_n')),
  rejection_reason  text,
  narration         text,
  narration_model   text,
  narrated_at       timestamptz,
  constraint insights_metric_order check (metric_a < metric_b)
);

create index insights_run_idx on insights (run_id);
create index insights_narration_retry_idx on insights (status, narrated_at)
  where status = 'surfaced' and narrated_at is null;
create index insights_latest_run_idx on insights (computed_at desc);

-- Operator-only read, matching lot_analyses_read/vessels_read exactly
-- (20260811215238_lot_analyses_vessels.sql) -- the same precedent
-- anom-v/anom-w already gate on at the UI layer (renderTab's
-- `if(isOperator)` before either panel is even created).
grant select on insights to authenticated;
create policy insights_read on insights
  for select using (current_role_name() = 'operator');

-- No insert/update/delete policy: only the insights-scan Edge Function
-- (service-role client, bypasses RLS) ever writes this table -- by
-- design, not an oversight to close later. See docs/SECURITY.md's
-- "Service-role-equivalent access points" list.

-- ── Tier B note, on the record per the requirement ───────────────────
-- Tier B (irrigation_volume x harvest yield) is a SINGLE HARDCODED JOIN,
-- not a generic block-vintage scanner. Exactly one real, joinable Tier B
-- pair exists today: real irrigation_volume (source_system
-- 'farm_irrigation_log') against real harvest_receipts yield, restricted
-- to (block, vintage) pairs where BOTH are real -- which today resolves
-- to exactly 5 rows (B1/2023, B2/2023, B3/2023, B2/2024, B3/2024; B1/2024
-- has zero real irrigation data by deliberate permanent deletion, see
-- docs/SECURITY.md's Track 2 Phase 3 entry, and 2022 has no real
-- irrigation source file at all). Unlike Tier A's REAL_CLIMATE_VINTAGES
-- (now derived dynamically, see realVintagesByMetric()), this join was
-- ALREADY dynamic from the start -- it's a live join of real rows, no
-- hardcoded vintage/block list. A future session should NOT read this as
-- "the pattern for a generic Tier B scanner" -- there is currently no
-- second real, block-vintage-joinable pair to generalize over. See
-- insights-scan/metrics.ts's fetchTierBPairs, which is written as one
-- specific join, not a loop over candidate metric pairs.
