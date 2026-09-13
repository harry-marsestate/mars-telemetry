-- Real-only data mode: an admin-settable per-account flag that hides
-- simulated data from a user entirely (dashboard panels + chat tools),
-- rather than trusting a subtitle/label alone. Motivated by this
-- session's real-vs-simulated audit, which found multiple panels/labels
-- overclaiming realness in the past (GDD calibration, DTR, solar, ET0's
-- input list) -- an account meant to show only trustworthy data needs a
-- mechanism independent of display text, not another label that can
-- eventually drift stale the same way SOLAR_LABEL_REAL_VINTAGES did.
alter table user_profiles add column data_mode text not null default 'all'
  check (data_mode in ('all','real_only'));

-- No new RLS policy needed for ADMIN read/write of another account's
-- data_mode: admin_reads_all_profiles/admin_manages_profiles already
-- cover it (RLS is row-level, not column-level, so a policy already
-- permitting UPDATE on a row permits updating any column on it, this
-- one included). Same reasoning applies to the table-wide UPDATE grant
-- `authenticated` already has (see
-- 20260810164048_admin_manages_profiles.sql's docs/SECURITY.md note).
--
-- current_data_mode(): a caller reading their OWN data_mode (dashboard
-- session boot, chat request) should NOT do it via a bare
-- `select data_mode from user_profiles` relying on own_profile_read
-- (id = auth.uid()) to narrow to one row -- confirmed live this session:
-- an ADMIN caller also matches admin_reads_all_profiles (using
-- (is_admin_user()), no row restriction), and Postgres RLS combines
-- multiple permissive policies with OR, so an admin's unfiltered select
-- returns EVERY profile, not just their own -- a `.maybeSingle()` caller
-- throws PGRST116 ("multiple rows returned") instead of resolving to
-- that admin's own row. Mirrors current_role_name()'s exact pattern
-- (SECURITY DEFINER, keyed off auth.uid() inside the function body) so
-- neither the frontend nor the chat backend has to reason about which
-- RLS policy will end up admitting the row -- there is no row-visibility
-- ambiguity to have in the first place.
create or replace function current_data_mode() returns text
language sql stable security definer
set search_path = public
as $$
  select coalesce((select data_mode from user_profiles where id = auth.uid()), 'all')
$$;

-- domain_reality(): ONE consistent, server-side interface for "is this
-- domain/vintage real," callable by both web/index.html and
-- supabase/functions/chat/tools.ts -- see docs/SECURITY.md for the
-- domain-by-domain real/mock audit this reuses rather than re-derives.
--
-- SECURITY DEFINER: "is X real" must be a role-INDEPENDENT fact about
-- the data. irrigation_volume/cellar_temp/cellar_rh/ferment_temp/
-- ferment_brix are metric_registry min_role='operator' -- a customer
-- session calling this as a plain invoker-rights function would see
-- sensor_readings through their OWN narrower RLS view (sensor_read's
-- policy denies customer access to operator-only metrics entirely) and
-- undercount real rows to zero, wrongly reporting a genuinely-real
-- 2023/2024 irrigation vintage as simulated for that caller only. No
-- sensor VALUES are exposed here, only a boolean already true regardless
-- of who's asking, so bypassing the caller's own RLS for this specific
-- computation is safe -- same reasoning as current_role_name()/
-- accessible_blocks()/is_admin_user().
--
-- Existence-based (>=1 real row), not real_metric_vintage_counts()'s own
-- >=100-row callers use (insights-scan/web/index.html's real-vintage
-- chart-range logic) -- that threshold answers a different question
-- ("enough real data for a meaningful season chart/statistical test"),
-- not "does real-only mode have anything real to show." Using it here
-- would have wrongly classified irrigation_volume as simulated for
-- 2023/2024: real coverage is sparse event-log data (53 and 51 rows
-- respectively, confirmed live), under 100 either year. Matches this
-- session's own harvest_receipts decision (sparse real data still counts
-- as real, no minimum-row-count threshold that wasn't asked for),
-- applied uniformly rather than as a harvest_receipts-only special case.
create or replace function domain_reality(p_vintages int[])
returns table(domain text, vintage int, is_real boolean)
language plpgsql stable security definer
set search_path = public as $$
declare
  -- Every sensor_readings-backed domain this project's tools/panels
  -- reference, EXCEPT solar -- one mechanism via
  -- real_metric_vintage_counts()'s existing real_data_sources-membership
  -- check, not a hardcoded true/false split. wind_speed/wind_dir/uv/
  -- cellar_temp/cellar_rh/ferment_temp/ferment_brix correctly and
  -- automatically resolve to is_real=false for every vintage this way
  -- (no real_data_sources row has ever existed for their source_system
  -- values) -- self-correcting if a real source is ever registered for
  -- one of them, rather than a second hardcoded list to remember to
  -- update.
  --
  -- solar is deliberately EXCLUDED from this dynamic check and instead
  -- fixed false below (Tier 4), even though real open_meteo_era5
  -- shortwave_radiation rows DO exist in sensor_readings for 2022-2025
  -- (confirmed live: this domain-reality query returned is_real=true for
  -- solar/2022-2025 before this fix, which would have been WRONG).
  -- renderSolar() in web/index.html never reads that real data for ANY
  -- vintage -- confirmed in this session's real/mock audit -- it's a
  -- known-stale mismatch between what's sitting in the table and what
  -- the one consumer that would display it actually renders. Real-only
  -- mode's contract is about what a user is ACTUALLY SHOWN, not what
  -- happens to exist unused in a table, so solar must answer false here
  -- regardless of sensor_readings content until renderSolar() itself is
  -- fixed to read real data (a separate, not-yet-scoped project).
  sensor_domains text[] := array['air_temp','humidity','precipitation','soil_moisture','soil_temp',
                                  'irrigation_volume','wind_speed','wind_dir','uv',
                                  'cellar_temp','cellar_rh','ferment_temp','ferment_brix'];
begin
  return query
    -- Tier 1: sensor_readings-backed domains. Reuses
    -- real_metric_vintage_counts() itself (not a re-implementation), so
    -- this, web/index.html's isRealClimateVintage(), and insights-scan's
    -- realVintagesByMetric() all share one source of truth for what
    -- counts as real sensor data. Any row this returns means >=1 real
    -- row exists for that (metric, vintage) -- existence alone, see the
    -- function-level comment above for why not the 100-row threshold.
    select c.metric_key, c.vintage, true
    from real_metric_vintage_counts(sensor_domains, p_vintages) c
  union all
    -- real_metric_vintage_counts() only returns rows with n>=1 -- fills
    -- in every remaining (domain, vintage) pair explicitly as
    -- is_real=false, rather than leaving it silently absent from the
    -- result set.
    select d, v, false
    from unnest(sensor_domains) d, unnest(p_vintages) v
    where not exists (
      select 1 from real_metric_vintage_counts(sensor_domains, p_vintages) c
      where c.metric_key = d and c.vintage = v
    )
  union all
    -- Tier 2: derived climate metrics. Domain names match the actual
    -- daily_derived column names tools.ts/web/index.html both read
    -- (gdd_cumulative_calibrated, dtr_f) -- metric_derivation's own key
    -- names (gdd_day, dtr) serve a different purpose (insights-scan's
    -- tautological-pair exclusion) and are bridged here, the same
    -- naming gap web/index.html's DERIVED_METRIC_KEY_MAP already bridges
    -- client-side. Real iff EVERY declared raw input is real for that
    -- vintage -- same rule isRealClimateVintage()/realVintagesByMetric()
    -- already apply.
    select bridge.domain, v.vintage, bool_and(coalesce(t1.is_real, false))
    from (values
      ('gdd_cumulative_calibrated','gdd_day'),
      ('dtr_f','dtr'),
      ('vpd_kpa','vpd_kpa'),
      ('vpd_peak_kpa','vpd_peak_kpa'),
      ('et0_in','et0_in')
    ) as bridge(domain, derivation_key)
    cross join unnest(p_vintages) as v(vintage)
    join metric_derivation md on md.metric_key = bridge.derivation_key
    left join (
      select c.metric_key, c.vintage, true as is_real
      from real_metric_vintage_counts(sensor_domains, p_vintages) c
    ) t1 on t1.metric_key = md.derived_from and t1.vintage = v.vintage
    group by bridge.domain, v.vintage
  union all
    -- Tier 3: harvest_receipts -- its own table, its own source_system
    -- column. Sparse real data still counts as real (2022: 1 row, 2023:
    -- 3, 2024: 2, confirmed live) -- existence only, per this session's
    -- own harvest_receipts decision.
    select 'harvest_receipts', v.vintage,
      exists(select 1 from harvest_receipts h where h.vintage = v.vintage and h.source_system = 'innovint')
    from unnest(p_vintages) as v(vintage)
  union all
    -- Tier 4: fixed, vintage-invariant domains. lot_analyses/vessels:
    -- InnoVint-only, no mock generator has ever existed for either
    -- table (confirmed this session's audit) -- no per-vintage variance
    -- is structurally possible. labour: work_events has no
    -- real_data_sources-registered source (always 'excel') and no real
    -- ingestion path exists yet -- a separate future effort, out of
    -- scope here. solar: fixed false despite real sensor_readings rows
    -- existing for 2022-2025 -- see the sensor_domains comment above for
    -- why this one is a deliberate exception, not an oversight.
    select dom, v.vintage, real_flag
    from unnest(p_vintages) as v(vintage),
         (values ('lot_analyses', true), ('vessels', true), ('labour', false), ('solar', false)) as f(dom, real_flag);
end;
$$;

-- Left at the default PUBLIC execute grant, matching current_role_name()/
-- accessible_blocks()/is_admin_user()'s own convention in this file --
-- safe for an anon caller regardless (auth.uid() is null, but this
-- function doesn't reference auth.uid() at all; it answers a role- and
-- caller-independent question about the data itself).
