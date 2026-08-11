-- Real InnoVint-backed replacement for the mock tanks/harvest_lots tables,
-- following the ferm/tanks InnoVint data inventory (1,411 real lot-scoped
-- analysis records across 15/47 lots; 241 real vessels, mostly empty/
-- archived). tanks/harvest_lots are deliberately left untouched here -- the
-- ferm/tanks/fruit panels still run entirely on the client-side TANKS mock
-- array today, so dropping the old tables now would be dead-code removal
-- disconnected from the real cutover. That drop belongs in a follow-up
-- migration once renderFerm/renderTanks actually query these tables.

-- One row per InnoVint analysis record (ana_* id). Long format, matching
-- sensor_readings' shape/intent, with two deliberate deviations:
--   - uniqueness keys off InnoVint's own id (source_id), not a
--     (lot_id, analysis_type, recorded_at) tuple -- lot analyses have no
--     sensor_id-equivalent natural key the way physical sensor feeds do,
--     and re-running ingestion needs a trustworthy dedup anchor.
--   - unit is stored per-row rather than looked up from metric_registry --
--     InnoVint's analysis taxonomy (Brix/pH/TA/VA/YAN/Ammonia/Potassium/
--     Malic acid/...) is a distinct vocabulary from metric_registry's
--     vineyard/cellar metrics; forcing a merge isn't needed unless/until
--     these get wired into anomaly_thresholds.
create table lot_analyses (
  id              bigint generated always as identity primary key,
  source_system   text not null default 'innovint',
  source_id       text not null,               -- InnoVint's ana_* id
  lot_id          text not null,               -- InnoVint's lot_* id, raw
  block_id        text references blocks(block_id),
  analysis_type   text not null,               -- InnoVint analysisType.slug
  value           numeric not null,
  unit            text not null,               -- InnoVint unit.unit, per-row
  recorded_at     timestamptz not null,
  ingested_at     timestamptz not null default now(),
  unique (source_system, source_id)
);
create index lot_analyses_lot_type_idx on lot_analyses (lot_id, analysis_type, recorded_at desc);
create index lot_analyses_block_type_idx on lot_analyses (block_id, analysis_type, recorded_at desc)
  where block_id is not null;

-- block_id is nullable and best-effort: resolved via InnoVint's
-- blockComponents -> blocks.innovint_block_id chain, which is incomplete
-- (B1 has no innovint_block_id mapping -- see the innovint_block_id
-- migration and docs/SECURITY.md) and ambiguous for blended lots
-- (blockComponents can return multiple weighted blocks for one lot).
-- Ingestion should only populate this for single-block, 100%-component
-- lots and leave it null otherwise -- a judgment call, not a solved
-- problem.
comment on column lot_analyses.block_id is
  'Best-effort resolution via blockComponents -> blocks.innovint_block_id. NULL for unresolved/multi-block-blend lots; do not treat absence as an error.';

-- Operator-only, not the harvest_lots "operator OR own block" pattern:
-- both panels this data feeds (ferm, tanks) are already minRole:'operator'
-- at the UI layer, and block_id here is null for most real rows (unlike
-- harvest_lots, where it's reliably populated per row). Mirroring
-- harvest_lots' policy would grant customers access only when the
-- InnoVint block-resolution join happens to succeed -- a coincidental
-- property of data completeness, not a deliberate scoping decision. This
-- policy makes RLS honestly match the access decision that already exists
-- at the panel layer, rather than create a new, accidental one.
grant select on lot_analyses to authenticated;
create policy lot_analyses_read on lot_analyses for select
  using (current_role_name() = 'operator');

-- One row per InnoVint vessel, current-state snapshot -- not an
-- append-only event log like sensor_readings/lot_analyses/work_events.
-- A vessel's real-world shape from the InnoVint API is "what's in this
-- tank right now," so ingestion should upsert on vessel_id (bumping
-- updated_at) rather than accumulate one row per run. This is a
-- deliberate departure from the append-only pattern used elsewhere in
-- this schema.
create table vessels (
  vessel_id         text primary key,          -- InnoVint's ves_* id
  source_system     text not null default 'innovint',
  vessel_type       text not null check (vessel_type in ('tank','barrel','keg','steel_drum')),
  code              text,                       -- InnoVint's human code, e.g. 'TD-07'
  capacity_gal      numeric,
  capacity_suspect  boolean not null default false,
  current_lot_id    text,                       -- nullable; InnoVint's lot_* id, raw
  block_id          text references blocks(block_id),
  archived          boolean not null default false,
  ingested_at       timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);
create index vessels_current_lot_idx on vessels (current_lot_id) where current_lot_id is not null;

-- capacity_suspect flags known-placeholder values (e.g. InnoVint's
-- TD-07/TD-08 both reporting exactly 500,000 gal, dwarfing every real
-- volume in this account) without hardcoding a magic-number cutoff into
-- the schema itself -- ingestion applies whatever heuristic makes sense
-- (e.g. flag an exact 500000, or flag anything far above the largest real
-- volume ever recorded in that vessel) and queries can opt in/out
-- explicitly.
comment on column vessels.capacity_suspect is
  'True when capacity_gal looks like an unset InnoVint placeholder (e.g. exactly 500000) rather than a real vessel size. Set by ingestion heuristics, not a hard constraint, so a bad value never blocks landing the row.';
comment on column vessels.block_id is
  'Same best-effort resolution and caveats as lot_analyses.block_id, derived from current_lot_id''s blockComponents when available. Expect this to be null for most vessels -- unlike the mock tanks table, real vessels have no permanent block affiliation.';

-- Operator-only, same reasoning as lot_analyses_read above.
grant select on vessels to authenticated;
create policy vessels_read on vessels for select
  using (current_role_name() = 'operator');
