-- ingest-innovint (the new daily InnoVint sync Edge Function) writes
-- lot_analyses/vessels/harvest_receipts directly via
-- ctx.supabaseAdmin.from(...) and reads block_innovint_map to resolve
-- local block ids. Checked each table individually rather than assuming
-- the standing "service_role has no table-level GRANTs" gap
-- (docs/SECURITY.md) was already closed for these four: it wasn't.
-- service_role currently has only SELECT on harvest_receipts (granted
-- for insights-scan's read path,
-- 20260902211836_insights_scan_service_role_grants.sql) and nothing at
-- all on lot_analyses, vessels, or block_innovint_map.
--
-- Grants exactly what this job does and nothing more, same narrowly
-- scoped one-at-a-time pattern as ingest-climate-2026's own grants
-- migration (20260913120001) -- not a blanket
-- ALTER DEFAULT PRIVILEGES fix.
--
-- No SELECT added on lot_analyses/vessels: the job only ever
-- upserts into them (INSERT ... ON CONFLICT DO UPDATE needs INSERT +
-- UPDATE, not SELECT) and never reads them back -- every other input
-- comes from the InnoVint API directly or from block_innovint_map.
--
-- harvest_receipts additionally needs DELETE: unlike lot_analyses/
-- vessels (pure upsert, since their InnoVint sources carry
-- deleted/archived flags), harvest_receipts reconciles deletions by
-- deleting stale rows scoped to source_system='innovint' AND the
-- specific vintages fetched that run (see docs/SECURITY.md,
-- "harvest_receipts reconciles deletions; lot_analyses/vessels don't").
grant insert, update on lot_analyses to service_role;
grant insert, update on vessels to service_role;
grant select on block_innovint_map to service_role;
grant insert, update, delete on harvest_receipts to service_role;
