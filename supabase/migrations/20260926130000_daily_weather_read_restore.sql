-- Restore daily_weather_read to what 20260810204144_approval_status_rls_gaps.sql
-- intended. The dbt post-hook ingestion/mars_dbt/macros/apply_security.sql
-- dropped and re-created it as `using (true)` on every dbt run, so since the
-- first dbt run after 2026-08-10 pending/rejected accounts (and any fresh
-- open signup) could read daily_weather. The macro now re-applies the
-- condition the model declares instead (same branch); this migration fixes
-- the live policy without requiring a dbt run -- which is itself unsafe
-- against production right now (the dbt daily_derived model predates the
-- calibration/vpd_peak migrations; see docs/SECURITY.md).
--
-- Explicit allowlist, per the current_role_name() 'pending' RULE.
drop policy if exists daily_weather_read on daily_weather;
create policy daily_weather_read on daily_weather for select using (
  current_role_name() in ('operator','customer')
);
