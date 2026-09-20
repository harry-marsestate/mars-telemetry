-- lot_analyses reconciliation follow-up: InnoVint carries genuine duplicate
-- lot OBJECTS for the same physical wine (confirmed live, not inferred --
-- distinct source_id/lot_id per duplicate row, ingest-innovint/index.ts
-- writes one row per one real InnoVint analysis with no double-write path,
-- so this is an upstream reality, not our ingest bug). get_lot_analyses'
-- lot_name ILIKE match returns every one of these duplicates as if they
-- were independent readings (confirmed live: 8 real 2023 brix readings for
-- the Cab Sauv V3 lot came back as 24 rows). Same shape problem
-- block_innovint_map (20260831000000) already solves for the block/
-- InnoVint-block identity question -- an explicit mapping table, not
-- guessing in query logic.
--
-- Deliberately NOT copied verbatim from block_innovint_map's shape: that
-- table's valid_from/valid_to_vintage columns exist to handle a local
-- entity being reissued to a DIFFERENT upstream id over time (the B1
-- replant). A duplicate-lot pairing has no analogous time dimension --
-- a 2023 lot's duplication status doesn't change vintage to vintage --
-- so duplicate_lot_code is a plain primary key, no surrogate id or
-- validity window needed. Neither column is a real FK: there is no
-- standalone "lots" dimension table, lot_code is a repeated text column
-- on lot_analyses rows -- the same limitation block_innovint_map's own
-- innovint_block_id already lives with on its upstream side.
--
-- Only superseded lot_codes get a row. A lot_code's absence means
-- "already canonical" -- the common case, not worth a bloat row for
-- every one of the ~11 unaffected lot_codes.
create table lot_canonical_map (
  duplicate_lot_code text primary key,
  canonical_lot_code text not null check (canonical_lot_code <> duplicate_lot_code),
  confidence         text not null check (confidence in ('confirmed', 'provisional')),
  notes              text,
  created_at         timestamptz not null default now()
);

-- RLS: open read, not operator-only -- and this choice is load-bearing,
-- not a style preference. get_lot_analyses reads this table through
-- ctx.supabase (the caller's own RLS-scoped client, per this file's own
-- header comment -- never ctx.supabaseAdmin). If this table were
-- operator-only and a non-operator session somehow reached this code
-- path, the read would silently return zero rows rather than erroring --
-- an empty exclusion list is indistinguishable from "no duplicates
-- exist," and the dedup filter would silently stop applying instead of
-- failing loudly. Fail-open here is the WRONG direction (unlike
-- isDomainReal()'s deliberate fail-open in tools.ts, where the risk
-- direction is "don't hide real data from an honest account" -- here
-- fail-open means "silently let the exact bug this table exists to fix
-- reappear"). Same class of data as metric_derivation/real_data_sources
-- (static, non-sensitive reference config) -- same open-read precedent.
alter table lot_canonical_map enable row level security;
grant select on lot_canonical_map to authenticated;
create policy lot_canonical_map_read on lot_canonical_map
  for select using (true);

-- ── Resolved clusters ───────────────────────────────────────────────────
-- MA23CS / MA23CSV2-AP deliberately has NO row: different lot_name
-- ("Cabernet Sauvignon - Estate" vs "Cabernet Sauvignon, V2") despite
-- 100% chemistry overlap, unlike both clusters below where the paired
-- lot_codes share one lot_name. That could be two genuinely distinct
-- wines (an estate blend vs. a block-designate) rather than one
-- duplicated lot -- collapsing it without the owner's answer risks
-- erasing a real distinction. Left unresolved on purpose; add a row here
-- later with no other schema or code change required.
insert into lot_canonical_map (duplicate_lot_code, canonical_lot_code, confidence, notes) values

  ('MA23CSV3-AP', 'MA23CSV3', 'confirmed',
   'Byte-exact duplicate of MA23CSV3 across the full shared date range '
   '(2023-10-27 to 2024-07-11): confirmed live via self-join on '
   '(analysis_type, value, recorded_at) -- 78 of 78 distinct row-tuples '
   'in both lots match exactly, and neither lot has a single distinct '
   'row the other lacks. lot_name ("Cabernet Sauvignon, V3"), block_id '
   '(B3) and date range are identical on both sides; no evidence '
   'distinguishes them. Picked the bare code for consistency with the '
   'ZIN cluster below (bare code is the one InnoVint keeps writing to '
   'after -AP stops) -- for THIS pair specifically that tiebreak carries '
   'zero information either way, since both sides stop at the same last '
   'date (2024-07-11) with nothing to lose by the choice. See '
   'docs/SECURITY.md for the drift risk this creates if InnoVint ever '
   'resumes writing to MA23CSV3-AP alone.'),

  ('MA23CSV322', 'MA23CSV3', 'confirmed',
   'Byte-exact duplicate of a SUBSET of MA23CSV3''s rows: all 33 of its '
   'distinct row-tuples match MA23CSV3 exactly, but MA23CSV322 only '
   'covers the early-fermentation window (2023-10-27 to 2023-11-16) -- '
   'strictly less complete than MA23CSV3, no tiebreak needed.'),

  ('MA23ZIN-AP', 'MA23ZIN', 'confirmed',
   'Duplicate of a subset of MA23ZIN''s rows: all 90 of its distinct '
   'row-tuples match MA23ZIN exactly, but MA23ZIN continues 35 MORE '
   'rows after MA23ZIN-AP stops (2024-07-11 -> 2025-03-12), including a '
   'January 2025 finished-wine alcohol reading MA23ZIN-AP never '
   'received. Strictly more complete, not a tiebreak call.');

-- ── Separate, out-of-scope finding, recorded here rather than left
-- undocumented: within-lot exact duplicate ROWS (distinct from the
-- cross-lot duplication this table resolves). Confirmed live: each of
-- MA22CS/MA23CS/MA23CSV2-AP/MA23CSV3/MA23CSV3-AP/MA23ZIN/MA23ZIN-AP has
-- 2-3 rows sharing (analysis_type, value, recorded_at) WITHIN that same
-- lot_code, all dated exactly 2024-05-01 07:00:00+00 (ph/titratable-
-- acidity, sometimes total-so2) -- 15 extra rows total, each pair with
-- genuinely distinct id/source_id (two real, separate InnoVint analysis
-- records, not a re-ingested duplicate -- ingest-innovint's upsert key
-- is (source_system, source_id), which would prevent that). This is why
-- MA23CSV3's raw row count (80) doesn't match its distinct-tuple count
-- (78) used as evidence above -- NOT because the cross-lot overlap
-- evidence was wrong. A second, unrelated within-lot duplicate cluster
-- exists on MA24CSV3 in October 2024 (mostly temperature, 11 extra
-- rows) -- different lot, different date, not part of this pattern, not
-- investigated further here. Neither is fixed by this migration -- see
-- docs/SECURITY.md.
