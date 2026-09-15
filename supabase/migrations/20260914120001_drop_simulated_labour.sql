-- Drop the 100%-simulated labour pipeline now that labour_actuals (real
-- data, see the preceding migration) replaces it entirely. Confirmed
-- before dropping that nothing else reads these three objects:
--   - work_events: only consumer was labour_summary (dbt view, dropped
--     below) and the chat's get_labour_summary tool (rewritten to read
--     labour_actuals_by_category instead -- see supabase/functions/chat).
--   - work_type_lookup: no consumer at all -- confirmed dormant in
--     docs/SECURITY.md's RLS-audit entry (RLS on, no policy, no grant,
--     unreachable by any path). Not merely dormant now but unused by
--     design -- labour_actuals stores canonical task/role names directly
--     (code prefix already stripped at ingestion), so no lookup table is
--     needed for the real pipeline.
--   - labour_summary: a VIEW over work_events, no other table depends on
--     it (confirmed: no FK anywhere references work_events either).
-- The client-side web/index.html panels never queried any of these three
-- directly -- labhours/labcost were driven entirely by a pure client-side
-- mock generator (OPS/labour()), independent of the database, which is
-- removed in the same panel-rewrite commit as this migration.
drop view if exists labour_summary;
drop table if exists work_events;
drop table if exists work_type_lookup;
