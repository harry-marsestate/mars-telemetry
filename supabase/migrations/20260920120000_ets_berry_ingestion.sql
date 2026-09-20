-- ETS Labs CSV ingestion, Phase 1: vineyard-side (berry) samples only.
-- Winery-side wine-chemistry lots (MA22*/MA23*/MA24*/MA25CH/25CHMR-LF/
-- 23 Zinfandel/23 Zin 90/10/T-7 V-2, and the 26MARCH must panel) are
-- deliberately out of scope this round -- they overlap substantially with
-- the existing lot_analyses table (1,405 InnoVint-synced rows, matching
-- lot_code/date/analyte combinations -- confirmed live in the prior
-- reconciliation investigation) and need a row-level dedup pass that is
-- its own round, not bundled here. See docs/SECURITY.md's ETS berry
-- ingestion entry for the full source/parsing investigation.
--
-- No berry/maturity/brix-sampling table existed anywhere before this
-- (grepped: berry, brix, maturity, veraison, ripeness, sample, lab --
-- confirmed green field; the one prior brix-bearing table, harvest_lots,
-- was dropped in 20260830000007 as leftover mock data). This is that
-- table's first real home.

-- ── lab_samples ─────────────────────────────────────────────────────────
-- One row per physical/logical ETS sample. lab_sample_no is a genuine
-- natural key (ETS's own Sample #), unlike labour_actuals' synthetic
-- (source_file, source_row_id) -- ETS samples don't have labour's
-- "two rows can be legitimately identical" problem.
--
-- reissue_of handles ETS's re-issued-report case (511110861 ->
-- 511110861A this round): a trailing letter suffix on the sample number
-- means "expanded/corrected reissue of the base sample", not a second
-- physical sample. Both are ingested losslessly; consumers filter to
-- reissue_of is null for the current version.
create table lab_samples (
  id                      bigint generated always as identity primary key,
  lab_sample_no           text not null unique,
  lab_group_no            text not null,
  sample_description_raw  text not null,
  -- berry_maturity/berry_smoke/trial_ferment are this round's three
  -- values. must/wine/stability_trial reserved for the winery-side round.
  sample_type             text not null check (sample_type in (
                             'berry_maturity', 'berry_smoke', 'trial_ferment',
                             'must', 'wine', 'stability_trial'
                           )),
  -- Nullable: the trial micro-ferment sample (BUCKET FERMENT) names no
  -- block in its description and none is inferred -- see
  -- docs/SECURITY.md, flagged for the owner to confirm.
  block_id                text references blocks(block_id),
  vintage                 int not null references vintages(vintage),
  collected_on            date not null,
  -- 'description': the sample description embeds an explicit collection
  -- date (e.g. "08/25/26", "9/6/24"). 'inferred_from_receipt': no
  -- embedded date, collected_on falls back to received_on (decoded from
  -- lab_sample_no). The 2024 MRS samples are the one case in this round
  -- where the two genuinely differ (collected 9/6, received 9/7).
  collected_on_source     text not null check (collected_on_source in ('description', 'inferred_from_receipt')),
  received_on             date not null,
  reissue_of              text references lab_samples(lab_sample_no),
  -- All Phase 1 rows are 'estate' -- no purchased fruit in this dataset.
  -- Reserved for when a non-estate lot (e.g. the 26MARCH Chardonnay must,
  -- winery-side/out of scope) needs representing.
  fruit_source             text not null default 'estate' check (fruit_source in ('estate', 'purchased')),
  source_system            text not null default 'ets_labs',
  source_file              text not null,
  ingested_at              timestamptz not null default now()
);
create index on lab_samples (block_id, collected_on);
create index on lab_samples (vintage, sample_type);

-- ── lab_results ─────────────────────────────────────────────────────────
-- Lossless: every CSV row for a Phase 1 sample lands here except the
-- Dyostem histogram bins, which go to berry_volume_histogram instead.
--
-- analysis_code normalizes ETS's two parallel method-string conventions
-- for the same nine free volatile phenols -- "X (GC/MS)" (the 2025-08
-- berry/ug-per-kg samples) and "X GC MS/MS" (the 2025-09 fruit and
-- bucket-ferment/ug-per-L samples) both strip to the same code (e.g.
-- 'guaiacol'), while analysis_name_raw and units preserve the original
-- string and the mass-vs-liquid basis untouched -- ug/kg and ug/L are
-- NOT interchangeable and are never converted.
--
-- result_operator/result_numeric/result_raw: ETS reports ~22 Phase-1
-- results as detection-limit censored ("< 0.5" etc). Never coerced to a
-- bare number or to null -- result_raw keeps the original string,
-- result_operator/result_numeric make it queryable.
create table lab_results (
  id                bigint generated always as identity primary key,
  sample_id         bigint not null references lab_samples(id) on delete cascade,
  analysis_name_raw text not null,
  analysis_code     text not null,
  result_raw        text not null,
  result_numeric    numeric not null,
  result_operator   text not null check (result_operator in ('=', '<')),
  units             text,
  analyzed_at       timestamptz not null,
  ingested_at       timestamptz not null default now(),
  unique (sample_id, analysis_name_raw, analyzed_at)
);
create index on lab_results (sample_id, analysis_code);

-- ── berry_volume_histogram ─────────────────────────────────────────────
-- Dyostem berry-size distribution: 20 bins (0.1-2.0 mL) per 2026 sample,
-- berry_count summing to that sample's total measured berries (ETS's own
-- reported sums range 97-103 across this round's 8 samples -- one
-- (608250191) sits above the 97-100 typical Dyostem sample size; checked
-- against the raw CSV bin-by-bin, all 20 bins present with no duplicates,
-- so this is ETS's own reported count, not a parsing artifact -- see
-- docs/SECURITY.md).
create table berry_volume_histogram (
  id          bigint generated always as identity primary key,
  sample_id   bigint not null references lab_samples(id) on delete cascade,
  bin_ml      numeric not null,
  berry_count int not null,
  analyzed_at timestamptz not null,
  unique (sample_id, bin_ml)
);

-- ── RLS: two independent gates (docs/SECURITY.md) ──────────────────────
-- Mirrors lot_analyses' operator-only read exactly (grant + policy
-- together, in this same migration, not left for a follow-up).
alter table lab_samples enable row level security;
create policy lab_samples_read on lab_samples for select
  using (current_role_name() = 'operator');
grant select on lab_samples to authenticated;

alter table lab_results enable row level security;
create policy lab_results_read on lab_results for select
  using (current_role_name() = 'operator');
grant select on lab_results to authenticated;

alter table berry_volume_histogram enable row level security;
create policy berry_volume_histogram_read on berry_volume_histogram for select
  using (current_role_name() = 'operator');
grant select on berry_volume_histogram to authenticated;

-- ── berry_maturity_by_block ─────────────────────────────────────────────
-- One row per (block, collected_on), pivoting the nine maturity analytes.
-- security_invoker so a caller who can't read lab_samples/lab_results
-- directly gets nothing from the view either, same as
-- labour_actuals_by_category. Restricted to sample_type='berry_maturity'
-- and reissue_of is null (no reissued berry_maturity sample exists this
-- round, but this is the same "filter to the current version" rule the
-- reissue handling requires elsewhere). The 2023/2024 rows are mostly
-- NULL by design -- those samples genuinely only ran brix/pH/TA.
create view berry_maturity_by_block as
select
  s.block_id,
  s.collected_on,
  s.vintage,
  max(r.result_numeric) filter (where r.analysis_code = 'brix') as brix,
  max(r.result_numeric) filter (where r.analysis_code = 'ph') as ph,
  max(r.result_numeric) filter (where r.analysis_code = 'titratable_acidity') as titratable_acidity,
  max(r.result_numeric) filter (where r.analysis_code = 'l_malic_acid') as l_malic_acid,
  max(r.result_numeric) filter (where r.analysis_code = 'glucose_fructose') as glucose_fructose,
  max(r.result_numeric) filter (where r.analysis_code = 'berry_weight') as berry_weight_g,
  max(r.result_numeric) filter (where r.analysis_code = 'berry_volume') as berry_volume_ml,
  max(r.result_numeric) filter (where r.analysis_code = 'berry_volume_variability') as berry_volume_variability_pct,
  max(r.result_numeric) filter (where r.analysis_code = 'sugar_per_berry_by_volume') as sugar_per_berry_mg
from lab_samples s
join lab_results r on r.sample_id = s.id
where s.sample_type = 'berry_maturity' and s.reissue_of is null
group by s.block_id, s.collected_on, s.vintage;

alter view berry_maturity_by_block set (security_invoker = true);
grant select on berry_maturity_by_block to authenticated;

-- ── domain_reality(): new Tier-3 existence clause ──────────────────────
-- Mirrors the harvest_receipts/labour precedent exactly (own table,
-- existence-based per vintage, no minimum-row-count threshold -- sparse
-- real data still counts as real). NOT registered in real_data_sources:
-- that path is sensor_readings/series_bucketed()-only (confirmed against
-- 20260826000001's own scope), which this data never flows through.
-- Full function body copied forward from 20260914120002 (the current
-- live definition) with one addition, same pattern that migration itself
-- used against 20260913150000.
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
    select 'labour', v.vintage,
      exists(select 1 from labour_actuals la where la.vintage = v.vintage)
    from unnest(p_vintages) as v(vintage)
  union all
    -- New: berry_sampling, existence-based against lab_samples. 2023-2026
    -- have Phase-1 rows (2023-10-18, 2024-09-06/07, 2025-08-26/09-18/
    -- 11-11, 2026-08-25 through 09-15, confirmed live); 2022 has none.
    select 'berry_sampling', v.vintage,
      exists(select 1 from lab_samples ls where ls.vintage = v.vintage)
    from unnest(p_vintages) as v(vintage)
  union all
    -- Tier 4: fixed, vintage-invariant domains.
    select dom, v.vintage, real_flag
    from unnest(p_vintages) as v(vintage),
         (values ('lot_analyses', true), ('vessels', true), ('solar', false)) as f(dom, real_flag);
end;
$$;
