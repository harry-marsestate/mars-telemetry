-- Fixes a real duplication bug in the ETS berry ingestion
-- (20260920120000): lab_results is intentionally lossless (both
-- 511110861 and its reissue 511110861A are stored), but nothing read
-- lab_results directly ever excluded the superseded base sample's rows.
-- Confirmed live before this fix: querying lab_results for the bucket
-- ferment's guaiacol/4-methylguaiacol returned each value TWICE (once
-- from 511110861, once from 511110861A, byte-identical) -- 17 raw rows
-- for that sample where only 15 are the current report.
--
-- berry_maturity_by_block's `s.reissue_of is null` filter didn't just
-- fail to cover this case (it's scoped to sample_type='berry_maturity',
-- and the only reissue is a trial_ferment sample) -- worth stating
-- plainly, that filter's *direction* was also backwards. `reissue_of is
-- null` is true for 511110861 (an ORIGINAL sample, not itself a reissue
-- of anything) and false for 511110861A (which IS a reissue). Applied to
-- a reissued sample, that filter would have kept the SUPERSEDED base and
-- dropped the current reissue -- the opposite of what "current version"
-- means. It happened to be harmless only because no berry_maturity
-- sample has ever been reissued. See docs/SECURITY.md.
--
-- lab_results_current is the fix, and is now the documented read
-- surface for every consumer of lab_results going forward, covering ALL
-- sample_types (not just berry_maturity): a sample is current unless
-- some other sample's reissue_of names it -- i.e. unless it has been
-- superseded. This is the inverse of (and correct replacement for) the
-- old reissue_of-is-null check.
create view lab_results_current as
select r.*
from lab_results r
join lab_samples s on s.id = r.sample_id
where not exists (
  select 1 from lab_samples newer where newer.reissue_of = s.lab_sample_no
);

alter view lab_results_current set (security_invoker = true);
grant select on lab_results_current to authenticated;

-- berry_maturity_by_block now reads lab_results_current instead of
-- lab_results directly, and drops the old (backwards-safe-only-by-luck)
-- `s.reissue_of is null` clause -- redundant now that the join itself
-- only ever sees current rows. Observably unchanged this round (still 12
-- rows: no berry_maturity sample has been reissued), but this makes it
-- correct by construction instead of correct by coincidence if one ever
-- is.
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
from lab_samples s
join lab_results_current r on r.sample_id = s.id
where s.sample_type = 'berry_maturity'
group by s.block_id, s.collected_on, s.vintage;

alter view berry_maturity_by_block set (security_invoker = true);
grant select on berry_maturity_by_block to authenticated;
