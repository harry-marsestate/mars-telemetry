-- Enables Postgres Changes for the overview tiles' realtime subscription
-- (Phase 7). Confirmed via current Supabase docs before writing any
-- subscription code: Postgres Changes respects the table's own RLS
-- policies automatically, no separate authorization config needed here --
-- distinct from realtime.messages' RLS, which only governs Broadcast/
-- Presence, not Postgres Changes on a regular table. sensor_read's
-- existing policy (approved role + block scoping) applies to subscribers
-- exactly as it does to REST queries.
alter publication supabase_realtime add table sensor_readings;
