-- ── Time-scoped block mapping ────────────────────────────────────────────
--
-- Supersedes the single-valued blocks.innovint_block_id column, which can
-- express neither a bounded validity window nor a second mapping for the
-- same local block. NOT dropped here: lot_analyses.block_id still carries a
-- column comment referencing it, and that needs its own migration.
--
-- Vintage grain, not date: /growerReceipts is natively vintage-scoped and
-- the whole app is vintage-partitioned (sensor_readings.vintage, vintages,
-- vintage_climate_calibration). A block's identity only changes between
-- seasons, so vintage is the correct resolution. Known tradeoff: a
-- mid-season replant cannot be expressed.
create table block_innovint_map (
  id                  bigint generated always as identity primary key,
  block_id            text not null references blocks(block_id),
  innovint_block_id   text not null,
  valid_from_vintage  int,          -- null = open start
  valid_to_vintage    int,          -- null = still current
  confidence          text not null check (confidence in ('confirmed','provisional')),
  notes               text,
  constraint block_innovint_map_vintage_order
    check (valid_from_vintage is null or valid_to_vintage is null
           or valid_from_vintage <= valid_to_vintage)
);

-- Chosen over a btree_gist EXCLUDE constraint on int4range: this table holds
-- 3 rows, is only ever written by hand in migrations (no runtime writer), and
-- the nullable-bound coalesce expression an EXCLUDE would need is fiddly
-- enough to risk false confidence. These two indexes catch the realistic
-- failure mode -- adding a new mapping without closing the previous one.
-- Overlapping *closed* windows are caught loudly by resolve_block_id() in
-- db.py instead, which raises rather than silently picking a winner.
create unique index block_innovint_map_one_open_per_block
  on block_innovint_map (block_id) where valid_to_vintage is null;
create unique index block_innovint_map_one_open_per_innovint_block
  on block_innovint_map (innovint_block_id) where valid_to_vintage is null;

-- Two gates, not one: every new public table gets RLS auto-enabled by the
-- ensure_rls event trigger with NO policy (deny-all). GRANT alone is not
-- sufficient. See docs/SECURITY.md.
grant select on block_innovint_map to authenticated;
create policy block_innovint_map_read on block_innovint_map
  for select using (true);

-- B2/B3: migrated verbatim from the existing column, open-ended.
insert into block_innovint_map
  (block_id, innovint_block_id, valid_from_vintage, valid_to_vintage, confidence, notes)
select b.block_id, b.innovint_block_id, null, null, 'confirmed',
       'Migrated from blocks.innovint_block_id. Open-ended: block still current.'
from blocks b
where b.innovint_block_id is not null;

-- B1: bounded to <=2023. Deliberately NOT the coincidental-acreage-match
-- backfill that docs/SECURITY.md rules out -- confirmed by the winery
-- directly, and independently corroborated by the receipt timeline
-- (Zinfandel receipts exist for 2022 and 2023, last one FL-23-ZI-ME-V1 at
-- 10.469 tons on 2023-09-27, and stop entirely thereafter; the 2024 harvest
-- is Cabernet from V2/V3 only).
--
-- The 2023 boundary is PROVISIONAL -- the exact replant year is not fully
-- confirmed. Revising it is a single-row UPDATE of valid_to_vintage; no
-- other file in this project encodes a B1 cutover year.
--
-- No row for 2024+: absence IS the unmapped state. When InnoVint gains a
-- post-replant B1 block object, add a second row with valid_from_vintage set
-- and valid_to_vintage null.
insert into block_innovint_map
  (block_id, innovint_block_id, valid_from_vintage, valid_to_vintage, confidence, notes)
values
  ('B1', 'block_O3Z1R4Q2KMVN9L57NVD68P5W', null, 2023, 'confirmed',
   'InnoVint "xxV1" = Block 1 as planted to Zinfandel, before the post-2023 '
   'replant to Cab Sauv/Cab Franc/Petit Verdot. Winery-confirmed; corroborated '
   'by Zinfandel receipts ending after the 2023 harvest. Cutover year 2023 is '
   'provisional. Note that planting year was never a reliable discriminator '
   'in this dataset: the confirmed B2/V2 mapping disagrees by 4 years and '
   'B3/V3 by 6.');

-- ── Harvest intake receipts ──────────────────────────────────────────────
--
-- A new table rather than an extension: growerReceipts is one row per lot per
-- vintage -- a fact table, not a time series. sensor_readings' long
-- (metric_key, value) format would shred one receipt across rows or need
-- columns that don't exist there; block_lots is keyed (block_id, variety_key)
-- for static acreage composition. Neither shape fits.
create table harvest_receipts (
  innovint_receipt_id  text primary key,          -- grwrec_...
  innovint_action_id   text not null,             -- act_...
  innovint_lot_id      text not null,             -- lot_...
  innovint_block_id    text not null,             -- block_..., stored RAW
  block_id             text references blocks(block_id),   -- resolved; nullable
  vintage              int  not null,
  weight_value         numeric not null,          -- raw totalWeight.value
  weight_unit          text    not null,          -- raw totalWeight.unit
  weight_tons          numeric not null,          -- normalized (US short tons)
  receipt_date         timestamptz not null,
  weigh_tag_number     text not null,
  varietal_name        text,
  lot_code             text,
  lot_name             text,
  grower_id            text,
  vineyard_id          text,
  appellation_id       text,
  source_system        text not null default 'innovint',
  synced_at            timestamptz not null
);

-- Deliberately NO foreign key on vintage -> vintages(vintage): the sync sweeps
-- through current_year+1, so a receipt for a season not yet seeded into
-- `vintages` would fail the whole run. Ingestion must not break because a
-- lookup table wasn't seeded ahead of a new harvest.
comment on column harvest_receipts.block_id is
  'Local block resolved via block_innovint_map at (innovint_block_id, vintage). '
  'NULL when no mapping covers that vintage (e.g. B1 for 2024+, post-replant). '
  'innovint_block_id always retains the raw value so an unmapped receipt is '
  'recoverable once a mapping exists -- do not treat NULL as an error.';
comment on column harvest_receipts.weight_tons is
  'US short tons, normalized in Python (see weights.py). weight_value/'
  'weight_unit retain the API values verbatim. FloatUnit.unit is a 17-value '
  'enum including four spellings of tons plus kg/lbs and volume units.';

create index harvest_receipts_vintage_idx on harvest_receipts (vintage);
create index harvest_receipts_block_vintage_idx on harvest_receipts (block_id, vintage);
create index harvest_receipts_reconcile_idx on harvest_receipts (source_system, vintage);

grant select on harvest_receipts to authenticated;
create policy harvest_receipts_read on harvest_receipts
  for select using (true);
