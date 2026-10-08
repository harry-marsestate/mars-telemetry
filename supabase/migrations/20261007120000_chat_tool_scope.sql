-- Chat/MCP tool findings from Colin's 5 Oct 2026 agentic tests
-- (docs/SECURITY.md, "Chat tool findings: source selection, date bounds,
-- identifiers, coverage, provenance").
--
-- 1. berry_maturity_by_block gains three provenance columns, appended so the
--    existing columns, their order and the view's consumers are unchanged:
--      lab_sample_no          the ETS sample number(s) behind the row
--      collected_on_source    how collected_on was obtained: 'description'
--                             (parsed from the sample description),
--                             'report' (stated on the ETS PDF report) or
--                             'inferred_from_receipt' (the lab's receipt date)
--      collected_on_inferred  true when any sample's date was inferred
--    Every block/date has exactly one sample today; string_agg keeps the row
--    honest if that ever changes instead of silently picking one.
--
-- 2. Two scope functions. Each returns ONE jsonb value, so no PostgREST
--    db-max-rows (1000) cap applies to the counts, date ranges and match sets
--    the tools report -- the bug behind get_lot_analyses' broad query reporting
--    MA24CSV3 as ending March 2025 (an unordered 1000-row scan of 1264 rows).
--    SECURITY INVOKER: the caller's own RLS applies (operator-only on every
--    table read here), exactly as for the builder queries they replace.
--
-- Not applied by this branch: the owner applies it after review.

-- ── 1. berry_maturity_by_block: provenance ─────────────────────────────
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
  max(r.result_numeric) filter (where r.analysis_code = 'sugar_per_berry_by_volume') as sugar_per_berry_mg,
  string_agg(distinct s.lab_sample_no, ', ' order by s.lab_sample_no) as lab_sample_no,
  string_agg(distinct s.collected_on_source, ', ' order by s.collected_on_source) as collected_on_source,
  bool_or(s.collected_on_source = 'inferred_from_receipt') as collected_on_inferred
from lab_samples_current s
join lab_results_current r on r.sample_id = s.id
where s.sample_type = 'berry_maturity'
group by s.block_id, s.collected_on, s.vintage;

alter view berry_maturity_by_block set (security_invoker = true);

-- ── 2a. chat_lot_analyses_scope ────────────────────────────────────────
-- get_lot_analyses' match set, computed in full: every matching lot_code with
-- its exact row count and first/last recorded_at, the total, and every
-- analysis_type on file for those lots (ignoring p_analysis_type, so the tool
-- can point at a temperature variant such as ethanol-60f next to ethanol-20c).
-- Filters mirror chat/tools.ts getLotAnalyses exactly: an explicit lot_code is
-- honored as asked (superseded or not); otherwise lot_name is a partial match
-- and superseded duplicates (lot_canonical_map) are excluded. Bounds arrive
-- already resolved by the tool: [p_start, p_end_exclusive) for a bare date
-- (the Pacific calendar day), p_end_inclusive for an explicit timestamp.
--
-- When an identifier was given and nothing matches, ets_samples lists ETS
-- samples the same identifier names (description, sample number, or the
-- ets_lot_bridge mapping), so the tool can point at the other source before
-- the model asks the user.
create function public.chat_lot_analyses_scope(
  p_lot_code text default null,
  p_lot_name text default null,
  p_analysis_type text default null,
  p_start timestamptz default null,
  p_end_exclusive timestamptz default null,
  p_end_inclusive timestamptz default null
) returns jsonb
language sql
stable
security invoker
set search_path = public
as $$
  with m as (
    select a.lot_code, a.lot_name, a.analysis_type, a.recorded_at
      from lot_analyses a
     where (p_lot_code is null or a.lot_code = p_lot_code)
       and (p_lot_code is not null or p_lot_name is null or a.lot_name ilike '%' || replace(p_lot_name, '*', '%') || '%')
       and (p_lot_code is not null or a.lot_code not in (select c.duplicate_lot_code from lot_canonical_map c))
       and (p_start is null or a.recorded_at >= p_start)
       and (p_end_exclusive is null or a.recorded_at < p_end_exclusive)
       and (p_end_inclusive is null or a.recorded_at <= p_end_inclusive)
  ), typed as (
    select * from m where p_analysis_type is null or analysis_type = p_analysis_type
  ), term as (
    select coalesce(p_lot_code, p_lot_name) as t
  )
  select jsonb_build_object(
    'total', (select count(*) from typed),
    'lots', coalesce((
      select jsonb_agg(l order by l.lot_code) from (
        select lot_code, (array_agg(lot_name order by recorded_at desc))[1] as lot_name,
               count(*) as n, min(recorded_at) as first_at, max(recorded_at) as last_at
          from typed group by lot_code) l), '[]'::jsonb),
    'analysis_types', coalesce((
      select jsonb_agg(t order by t.analysis_type) from (
        select analysis_type, count(*) as n from m group by analysis_type) t), '[]'::jsonb),
    'ets_samples', case
      when (select t from term) is null or exists (select 1 from m) then '[]'::jsonb
      else coalesce((
        select jsonb_agg(x order by x.collected_on, x.lab_sample_no) from (
          select s.lab_sample_no, s.sample_description_raw, s.sample_type, s.block_id, s.vintage, s.collected_on,
                 (select count(*) from lab_results_current r where r.sample_id = s.id) as n_results,
                 (select string_agg(distinct r.analysis_code, ', ' order by r.analysis_code) from lab_results_current r where r.sample_id = s.id) as analysis_codes
            from lab_samples_current s, term
           where s.sample_description_raw ilike '%' || replace(btrim(term.t), '*', '%') || '%'
              or s.lab_sample_no = upper(btrim(term.t))
              or s.sample_description_raw in (select b.ets_description from ets_lot_bridge b where b.lot_analyses_lot_code = upper(btrim(term.t)))
        ) x), '[]'::jsonb)
    end
  );
$$;

-- ── 2b. chat_ets_winery_scope ──────────────────────────────────────────
-- get_wine_lab_results' match set, computed in full. samples: every matching
-- winery sample (sample-level filters only) -- the tool fetches results for
-- exactly these ids, so display and coverage can never disagree. total: the
-- results matching every filter. analysis_codes: every code on file for those
-- samples within the date bounds (ignoring p_analysis_code), for temperature
-- variants such as ethanol_at_60f next to ethanol_at_20c.
--
-- p_description: partial match on sample_description_raw, OR an exact ETS
-- sample number (a model passing '310310429' as a description finds it).
-- p_lab_sample_no: exact sample number. p_lot_code: exact description, or an
-- InnoVint lot_code mapped by ets_lot_bridge (MA23CSV3-AP -> MA23CSV3).
--
-- When an identifier was given and no winery sample matches:
-- vineyard_samples lists ETS vineyard samples (berry maturity / smoke) with
-- that identifier, and innovint_lots lists InnoVint lots it names, so the tool
-- can point at the right tool or source.
create function public.chat_ets_winery_scope(
  p_sample_type text default null,
  p_description text default null,
  p_lab_sample_no text default null,
  p_lot_code text default null,
  p_vintage integer default null,
  p_analysis_code text default null,
  p_start timestamptz default null,
  p_end_exclusive timestamptz default null,
  p_end_inclusive timestamptz default null
) returns jsonb
language sql
stable
security invoker
set search_path = public
as $$
  with ident as (
    select s.*
      from lab_samples_current s
     where (p_description is null
            or s.sample_description_raw ilike '%' || replace(btrim(p_description), '*', '%') || '%'
            or s.lab_sample_no = upper(btrim(p_description)))
       and (p_lab_sample_no is null or s.lab_sample_no = p_lab_sample_no)
       and (p_lot_code is null
            or upper(s.sample_description_raw) = p_lot_code
            or s.sample_description_raw in (select b.ets_description from ets_lot_bridge b where b.lot_analyses_lot_code = p_lot_code))
       and (p_vintage is null or s.vintage = p_vintage)
  ), smp as (
    select * from ident
     where sample_type = any(case when p_sample_type is null then array['must', 'wine', 'ferment', 'stability_trial'] else array[p_sample_type] end)
  ), res as (
    select r.analysis_code
      from lab_results_current r
     where r.sample_id in (select id from smp)
       and (p_start is null or r.analyzed_at >= p_start)
       and (p_end_exclusive is null or r.analyzed_at < p_end_exclusive)
       and (p_end_inclusive is null or r.analyzed_at <= p_end_inclusive)
  ), has_ident as (
    select coalesce(p_description, p_lab_sample_no, p_lot_code) is not null as yes
  )
  select jsonb_build_object(
    'samples', coalesce((
      select jsonb_agg(jsonb_build_object(
               'id', id, 'lab_sample_no', lab_sample_no, 'sample_description_raw', sample_description_raw,
               'sample_type', sample_type, 'vintage', vintage, 'collected_on', collected_on,
               'collected_on_source', collected_on_source, 'fruit_source', fruit_source)
             order by collected_on, lab_sample_no)
        from smp), '[]'::jsonb),
    'total', (select count(*) from res where p_analysis_code is null or analysis_code = p_analysis_code),
    'analysis_codes', coalesce((
      select jsonb_agg(c order by c.analysis_code) from (
        select analysis_code, count(*) as n from res group by analysis_code) c), '[]'::jsonb),
    'vineyard_samples', case
      when not (select yes from has_ident) or exists (select 1 from smp) then '[]'::jsonb
      else coalesce((
        select jsonb_agg(jsonb_build_object(
                 'lab_sample_no', lab_sample_no, 'sample_description_raw', sample_description_raw,
                 'sample_type', sample_type, 'block_id', block_id, 'vintage', vintage, 'collected_on', collected_on)
               order by collected_on, lab_sample_no)
          from ident where sample_type not in ('must', 'wine', 'ferment', 'stability_trial')), '[]'::jsonb)
    end,
    'innovint_lots', case
      when not (select yes from has_ident) or exists (select 1 from smp) then '[]'::jsonb
      else coalesce((
        select jsonb_agg(l order by l.lot_code) from (
          select a.lot_code, (array_agg(a.lot_name order by a.recorded_at desc))[1] as lot_name, count(*) as n,
                 min(a.recorded_at) as first_at, max(a.recorded_at) as last_at
            from lot_analyses a
           where a.lot_code = upper(btrim(coalesce(p_lot_code, p_description, p_lab_sample_no)))
              or a.lot_name ilike '%' || replace(btrim(coalesce(p_description, p_lot_code, p_lab_sample_no)), '*', '%') || '%'
           group by a.lot_code) l), '[]'::jsonb)
    end
  );
$$;

-- Same pattern as latest_reading() (20261001120000): no EXECUTE for anon or
-- PUBLIC; authenticated (in-app chat, RLS decides) and mcp_reader (the
-- gateway's tool role, allowlisted in mcp/allowlist.ts RPCS).
revoke all on function public.chat_lot_analyses_scope(text, text, text, timestamptz, timestamptz, timestamptz) from public, anon;
grant execute on function public.chat_lot_analyses_scope(text, text, text, timestamptz, timestamptz, timestamptz) to authenticated, service_role, mcp_reader;
revoke all on function public.chat_ets_winery_scope(text, text, text, text, integer, text, timestamptz, timestamptz, timestamptz) from public, anon;
grant execute on function public.chat_ets_winery_scope(text, text, text, text, integer, text, timestamptz, timestamptz, timestamptz) to authenticated, service_role, mcp_reader;
