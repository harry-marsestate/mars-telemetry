-- ETS Labs CSV ingestion, Phase 2: winery-side samples, into the EXISTING
-- lab_samples/lab_results tables from Phase 1 -- no new base tables. Per
-- the owner's explicit decision (docs/SECURITY.md's Phase 2 investigation):
-- ingest ALL of it losslessly and flag overlap with lot_analyses in a
-- view, rather than skipping the ~5 rows that already have an InnoVint
-- counterpart.

-- sample_type gains 'ferment' (the one active-fermentation sample, T-7
-- V-2) -- 'must'/'wine'/'stability_trial' were already reserved by
-- Phase 1's own migration for exactly this round.
alter table lab_samples drop constraint lab_samples_sample_type_check;
alter table lab_samples add constraint lab_samples_sample_type_check
  check (sample_type in ('berry_maturity', 'berry_smoke', 'trial_ferment',
                          'must', 'wine', 'ferment', 'stability_trial'));

-- lab_results.result_numeric/result_operator widened to nullable: two
-- winery rows (MA25CH's conductivity-test disclaimer and its Heat
-- Stability Trial protocol description) carry multi-line free-text
-- Result content with no number to extract. result_raw keeps the full
-- text either way -- never dropped, never coerced to a bare 0 or a
-- fabricated operator. No CHECK constraint change needed: `result_operator
-- in ('=','<')` already evaluates to NULL (not FALSE) when
-- result_operator IS NULL, which Postgres CHECK constraints treat as
-- satisfied -- verified against Postgres's own documented NULL-in-CHECK
-- semantics, not assumed.
alter table lab_results alter column result_numeric drop not null;
alter table lab_results alter column result_operator drop not null;

-- ── Reconciliation: the ETS-vs-lot_analyses bridge ─────────────────────
-- Operationalizes the Phase 2 investigation's own matching logic as a
-- live, auditable mapping rather than a one-off script -- the "flag
-- overlaps" mechanism the owner chose over skipping. Two small lookup
-- tables (which ETS description maps to which InnoVint lot_code(s); which
-- ETS analysis_code maps to which lot_analyses analysis_type) rather than
-- a hardcoded CASE tree buried in the view, same "explicit mapping, not
-- guessing in query logic" precedent as block_innovint_map/
-- lot_canonical_map. A description/code absent from either table means
-- "no InnoVint counterpart, unconditionally ETS-only" -- re-confirmed
-- live before writing these, not re-asserted from memory: MA22CSV2 (no
-- lot_code, and 100% microbial data lot_analyses never stores anyway),
-- 25CHMR-LF/25CH MR-LF (zero lot_analyses coverage in their own active
-- date range), '23 Zinfandel'/'23 Zin 90/10' (no lot_analyses rows in
-- that date window for any Zin lot), 'T-7 V-2 (fermenting)' (no such
-- vessel/lot in InnoVint), '26MARCH' (no 2026 Chardonnay lot exists yet)
-- all correctly have NO rows in either table below.
create table ets_lot_bridge (
  ets_description        text not null,
  lot_analyses_lot_code  text not null,
  primary key (ets_description, lot_analyses_lot_code)
);
insert into ets_lot_bridge (ets_description, lot_analyses_lot_code) values
  ('MA22CS', 'MA22CS'),
  ('MA22CSV3', 'MA22CSV3'),
  ('MA22ZIN', 'MA22ZIN'),
  ('MA23CSV2', 'MA23CSV2-AP'),
  ('MA23CSV3', 'MA23CSV3'), ('MA23CSV3', 'MA23CSV3-AP'), ('MA23CSV3', 'MA23CSV322'),
  ('MA23ZIN', 'MA23ZIN'), ('MA23ZIN', 'MA23ZIN-AP'),
  ('MA24CS', 'MA24CS'),
  ('MA24CSV2', 'MA24CSV2'),
  ('MA24CSV3', 'MA24CSV3'),
  ('MA25CH', 'MA25CH');
  -- MA22CSV2, 25CHMR-LF, 25CH MR-LF, 23 Zinfandel, 23 Zin 90/10,
  -- T-7 V-2 (fermenting), 26MARCH: deliberately no rows (see above).

create table ets_analyte_bridge (
  ets_analysis_code            text not null,
  lot_analyses_analysis_type   text not null,
  primary key (ets_analysis_code, lot_analyses_analysis_type)
);
insert into ets_analyte_bridge (ets_analysis_code, lot_analyses_analysis_type) values
  ('ethanol_at_20c', 'ethanol-20c'), ('ethanol_at_20c', 'ethanol'),
  ('ethanol_at_60f', 'ethanol-60f'),
  ('volatile_acidity_acetic_acid', 'volatile-acidity'),
  ('free_sulfur_dioxide', 'free-so2'),
  ('l_malic_acid', 'malic-acid'),
  ('glucose_fructose', 'glucosefructose'),
  ('ph', 'ph'),
  ('titratable_acidity', 'titratable-acidity'),
  ('alpha_amino_compounds_as_n', 'alpha-amino-nitrogen'),
  ('ammonia', 'ammonia-nh3'),
  ('potassium', 'potassium'),
  ('yeast_assimilable_nitrogen', 'yeast-assimilable-nitrogen-yan'),
  ('brix', 'brix');
  -- molecular_sulfur_dioxide, tartaric_acid, every scorpion_*/heat_stab_*/
  -- fining_trial_*/conductivity_test_dit/heat_stability_trial_* code:
  -- deliberately no rows -- lot_analyses has never stored any of these
  -- (confirmed live against its own 19 distinct analysis_type values).

-- Same open-read shape as metric_derivation/real_data_sources/
-- lot_canonical_map -- static, non-sensitive mapping metadata, not
-- winery lab data itself (that's still gated by lab_results/lot_analyses'
-- own operator-only RLS, inherited by the reconciliation view below via
-- security_invoker).
alter table ets_lot_bridge enable row level security;
grant select on ets_lot_bridge to authenticated;
create policy ets_lot_bridge_read on ets_lot_bridge for select using (true);

alter table ets_analyte_bridge enable row level security;
grant select on ets_analyte_bridge to authenticated;
create policy ets_analyte_bridge_read on ets_analyte_bridge for select using (true);

-- One row per winery ETS result (current, non-superseded samples only --
-- built on lab_samples_current/lab_results_current, never the raw
-- tables), classified into exactly the buckets the Phase 2 investigation
-- used: 'exact' (same lot/date/analyte/value), 'value_conflict' (same
-- lot/date/analyte, different value), 'date_near' (matched within +/-3
-- days, not same day), 'ets_only' (no InnoVint counterpart at all -- no
-- lot mapping, no analyte mapping, or no row within the window). The
-- LATERAL picks the single closest-date candidate across every valid
-- (lot_code, analyte) combination at once, rather than joining the
-- bridge tables directly into the main FROM (which would fan out to one
-- row per candidate lot_code -- 3 redundant rows for a single MA23CSV3
-- result, say, since MA23CSV3/MA23CSV3-AP/MA23CSV322 are exact
-- duplicates of each other).
create view ets_lot_analyses_reconciliation as
select
  s.lab_sample_no, s.sample_description_raw, s.sample_type, s.vintage, s.collected_on,
  r.id as lab_result_id, r.analysis_code, r.analysis_name_raw,
  r.result_operator, r.result_numeric, r.result_raw, r.units, r.analyzed_at,
  m.lot_code as matched_lot_code, m.value as matched_value, m.unit as matched_unit,
  m.recorded_at as matched_recorded_at,
  case
    when m.value is null then 'ets_only'
    when m.recorded_at::date = r.analyzed_at::date and m.value = r.result_numeric then 'exact'
    when m.recorded_at::date = r.analyzed_at::date and m.value <> r.result_numeric then 'value_conflict'
    else 'date_near'
  end as match_status
from lab_results_current r
join lab_samples_current s on s.id = r.sample_id
left join lateral (
  select la.lot_code, la.value, la.unit, la.recorded_at
  from lot_analyses la
  where la.lot_code in (
          select lot_analyses_lot_code from ets_lot_bridge
          where ets_description = s.sample_description_raw
        )
    and la.analysis_type in (
          select lot_analyses_analysis_type from ets_analyte_bridge
          where ets_analysis_code = r.analysis_code
        )
    and r.result_numeric is not null
    and abs(extract(epoch from (la.recorded_at - r.analyzed_at)) / 86400) <= 3
  order by abs(extract(epoch from (la.recorded_at - r.analyzed_at))) asc,
           (la.value = r.result_numeric) desc
  limit 1
) m on true
where s.sample_type in ('must', 'wine', 'ferment', 'stability_trial');

alter view ets_lot_analyses_reconciliation set (security_invoker = true);
grant select on ets_lot_analyses_reconciliation to authenticated;
