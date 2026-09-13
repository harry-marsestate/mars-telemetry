-- ingest-climate-2026 (the new daily real-2026-climate Edge Function)
-- writes sensor_readings directly via ctx.supabaseAdmin.from(...).upsert(...).
-- Confirmed live, by an actual failed run: service_role already had SELECT
-- on sensor_readings (granted for insights-scan,
-- 20260902211836_insights_scan_service_role_grants.sql) but not INSERT/
-- UPDATE -- same two-gates gap that migration documents, narrowly closed
-- again here for exactly the grant this new function needs, same
-- one-at-a-time precedent as that file (not a blanket
-- ALTER DEFAULT PRIVILEGES fix).
grant insert, update on sensor_readings to service_role;
