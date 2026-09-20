-- Regression caught during this round's own verification, fixed before
-- moving on rather than left for later: the Phase 2 winery backfill
-- (20260920180000) added lab_samples rows with sample_type in
-- ('must','wine','ferment','stability_trial') for 2022 (MA22CS/CSV2/
-- CSV3/ZIN) -- a vintage that has NO berry sampling at all. The
-- existing 'berry_sampling' clause, `exists(select 1 from lab_samples
-- ls where ls.vintage = v.vintage)`, was never scoped to berry
-- sample_types -- it silently meant "any lab_samples row of any kind,"
-- which was harmless only because every lab_samples row happened to be
-- berry-side until this exact migration. Confirmed live before writing
-- this fix, not assumed: berry_sampling(2022) had flipped from `false`
-- (correct -- 2022 genuinely has no berry data) to `true` (wrong -- only
-- winery wine-chemistry samples exist for 2022).
--
-- Fix: scope the exists() to the three berry sample_types, matching
-- what this domain has always meant to represent. Full function body
-- copied forward from the current live definition (confirmed via
-- pg_get_functiondef before writing this), one clause changed.
create or replace function domain_reality(p_vintages int[])
returns table(domain text, vintage int, is_real boolean)
language plpgsql stable security definer
set search_path = public as $$
declare
  sensor_domains text[] := array['air_temp','humidity','precipitation','soil_moisture','soil_temp',
                                  'irrigation_volume','wind_speed','wind_dir','uv',
                                  'cellar_temp','cellar_rh','ferment_temp','ferment_brix'];
begin
  return query
    select c.metric_key, c.vintage, true
    from real_metric_vintage_counts(sensor_domains, p_vintages) c
  union all
    select d, v, false
    from unnest(sensor_domains) d, unnest(p_vintages) v
    where not exists (
      select 1 from real_metric_vintage_counts(sensor_domains, p_vintages) c
      where c.metric_key = d and c.vintage = v
    )
  union all
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
    select 'harvest_receipts', v.vintage,
      exists(select 1 from harvest_receipts_current h where h.vintage = v.vintage and h.source_system = 'innovint')
    from unnest(p_vintages) as v(vintage)
  union all
    select 'labour', v.vintage,
      exists(select 1 from labour_actuals la where la.vintage = v.vintage)
    from unnest(p_vintages) as v(vintage)
  union all
    -- Fixed: scoped to berry sample_types only, not "any lab_samples row."
    select 'berry_sampling', v.vintage,
      exists(
        select 1 from lab_samples ls
        where ls.vintage = v.vintage
          and ls.sample_type in ('berry_maturity', 'berry_smoke', 'trial_ferment')
      )
    from unnest(p_vintages) as v(vintage)
  union all
    -- New: winery ETS lab data (must/wine/ferment/stability_trial),
    -- existence-based, mirroring berry_sampling's own pattern exactly.
    -- Never gated by real-only mode (no application code checks this
    -- domain today, same as lot_analyses/vessels) -- added for
    -- completeness and symmetry with berry_sampling, not because
    -- anything currently depends on it.
    select 'wine_lab_results', v.vintage,
      exists(
        select 1 from lab_samples ls
        where ls.vintage = v.vintage
          and ls.sample_type in ('must', 'wine', 'ferment', 'stability_trial')
      )
    from unnest(p_vintages) as v(vintage)
  union all
    select dom, v.vintage, real_flag
    from unnest(p_vintages) as v(vintage),
         (values ('lot_analyses', true), ('vessels', true), ('solar', false)) as f(dom, real_flag);
end;
$$;
