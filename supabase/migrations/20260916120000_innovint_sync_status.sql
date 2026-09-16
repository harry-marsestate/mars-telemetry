-- Minimal freshness tracking for ingest-innovint, so the winery Harvest
-- strip's "as of" text can reflect when this app last actually confirmed
-- its InnoVint copy is current, rather than a value derived from the
-- data's own content -- see docs/SECURITY.md's "winery Harvest 'as of'"
-- entry for the full reasoning on why this differs from
-- real_climate_as_of_2026()'s approach (climate has one clean daily
-- grain to derive freshness FROM; InnoVint's receipt/analysis dates
-- reflect when the WINERY entered them, not when this app last checked,
-- so a content-derived date could look "fresh" while the sync itself is
-- silently broken).
--
-- Keyed per resource (not one blanket InnoVint-wide row): the ingest job
-- already fails independently per phase (see ingest-innovint's own
-- per-phase try/catch), so a blanket timestamp would risk claiming
-- freshness for a resource whose phase actually failed. Only
-- harvest_receipts is read by the frontend today (the only winery panel
-- with a vintage-scoped "as of" claim at all -- ferm/tanks have no
-- freshness text to begin with, see the investigation), but
-- lot_analyses/vessels are written by the same function today too, at
-- the same trivial cost, so a future "as of" for ferm/tanks needs no
-- schema change.
--
-- Deliberately just a timestamp, not a run-history log: this project's
-- own precedent for "minimal" (real_data_sources, block_innovint_map)
-- is a single small row per concern, not an audit trail. duration_ms/
-- http_call_count are already visible in the function's own JSON
-- response/logs if that's ever needed; not duplicated here.
create table innovint_sync_status (
  resource         text primary key,   -- 'harvest_receipts' | 'lot_analyses' | 'vessels'
  last_success_at  timestamptz not null
);

grant select on innovint_sync_status to authenticated;
create policy innovint_sync_status_read on innovint_sync_status
  for select using (true);

-- service_role writes this from ingest-innovint on every successful
-- phase -- UPDATE included because this is an upsert target (the row is
-- created once, then updated in place every successful run), matching
-- the SELECT-is-also-required-for-upsert correction already on record
-- for this same function (docs/SECURITY.md).
grant select, insert, update on innovint_sync_status to service_role;
