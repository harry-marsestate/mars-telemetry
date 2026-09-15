-- domain_reality()'s Tier 4 fixed list hardcoded ('labour', false) --
-- correct at the time (no real ingestion path existed), now wrong: real
-- labour_actuals data exists for 2023/2024/2026, absent for 2022/2025.
-- Replaces the fixed labour entry with a genuine per-vintage existence
-- check, the same shape as harvest_receipts' Tier 3 (existence-based, no
-- minimum-row-count threshold -- 2026 has exactly one month of real data
-- and that still counts as real, matching this function's own
-- documented reasoning for sparse-but-real domains).
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
      exists(select 1 from harvest_receipts h where h.vintage = v.vintage and h.source_system = 'innovint')
    from unnest(p_vintages) as v(vintage)
  union all
    -- labour: existence-based, per vintage, against real labour_actuals
    -- rows -- replaces the old fixed ('labour', false) entry below.
    select 'labour', v.vintage,
      exists(select 1 from labour_actuals la where la.vintage = v.vintage)
    from unnest(p_vintages) as v(vintage)
  union all
    -- Tier 4: fixed, vintage-invariant domains. lot_analyses/vessels:
    -- InnoVint-only, no mock generator has ever existed for either table.
    -- solar: fixed false despite real sensor_readings rows existing for
    -- 2022-2025 -- see the sensor_domains comment in the prior version of
    -- this function (20260913150000_real_only_data_mode.sql) for why this
    -- one is a deliberate exception, not an oversight. labour REMOVED from
    -- this fixed list -- see the union clause above.
    select dom, v.vintage, real_flag
    from unnest(p_vintages) as v(vintage),
         (values ('lot_analyses', true), ('vessels', true), ('solar', false)) as f(dom, real_flag);
end;
$$;
