-- Closes the same structural gap the previous migration
-- (20260920130000_lab_results_current.sql) fixed for lab_results, now for
-- the other two tables that share the identical reissue shape.
--
-- lab_results_current's own fix was correct but incomplete: it covered
-- lab_results, but nothing covered lab_samples or berry_volume_histogram.
-- Both have exactly the same exposure lab_results had -- a reissued
-- sample's superseded rows are still there, lossless, with nothing
-- excluding them from a plain read:
--   - lab_samples: COUNT(*) counts 511110861 AND 511110861A as two rows
--     for one physical sample (18 where 17 physical samples exist).
--   - berry_volume_histogram: if a Dyostem sample is ever reissued, its
--     20 bins exist twice (once per sample version) -- a naive read
--     would return 40 bins and every berry_count sum would double. No
--     Dyostem sample has been reissued yet (confirmed: this round's 8
--     Dyostem samples all have reissue_of is null and nothing reissues
--     any of them), so this is not live-observable today, but the
--     exposure is structurally identical to the one that WAS live for
--     lab_results before that fix -- "harmless by coincidence, not
--     because the logic was right" (docs/SECURITY.md, previous entry)
--     applies here just as much as it did there. Extending the pattern
--     now rather than waiting for the first real Dyostem reissue to make
--     it live-observable.
--
-- lab_samples_current becomes the single source of truth for "current":
-- lab_results_current and the new berry_volume_histogram_current both
-- join through it rather than repeating the NOT EXISTS condition, so
-- there is one place, not three, that defines what "current" means.
create view lab_samples_current as
select s.*
from lab_samples s
where not exists (
  select 1 from lab_samples newer where newer.reissue_of = s.lab_sample_no
);

alter view lab_samples_current set (security_invoker = true);
grant select on lab_samples_current to authenticated;

-- Redefined to join lab_samples_current instead of repeating the NOT
-- EXISTS condition inline. Output columns/types unchanged (select r.*
-- from lab_results, same as before), so this create-or-replace is a
-- pure refactor -- verified live to return the same 159 rows as before.
create or replace view lab_results_current as
select r.*
from lab_results r
join lab_samples_current s on s.id = r.sample_id;

alter view lab_results_current set (security_invoker = true);
grant select on lab_results_current to authenticated;

create view berry_volume_histogram_current as
select h.*
from berry_volume_histogram h
join lab_samples_current s on s.id = h.sample_id;

alter view berry_volume_histogram_current set (security_invoker = true);
grant select on berry_volume_histogram_current to authenticated;

-- Redefined to source block_id/collected_on/vintage from
-- lab_samples_current rather than lab_samples directly -- consistent
-- with lab_results_current's own filtering rather than relying on the
-- join to lab_results_current alone to exclude superseded rows.
-- Observably unchanged (still 12 rows: no berry_maturity sample has
-- been reissued).
create or replace view berry_maturity_by_block as
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
from lab_samples_current s
join lab_results_current r on r.sample_id = s.id
where s.sample_type = 'berry_maturity'
group by s.block_id, s.collected_on, s.vintage;

alter view berry_maturity_by_block set (security_invoker = true);
grant select on berry_maturity_by_block to authenticated;
