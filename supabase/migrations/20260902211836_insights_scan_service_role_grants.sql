-- Discovered live, by an actual failed run, not assumed in advance:
-- service_role in this project has NEVER had table-level SELECT/INSERT/
-- UPDATE/DELETE grants on ANY public-schema table -- confirmed via
-- information_schema.role_table_grants across sensor_readings,
-- daily_weather, harvest_receipts, vintages, real_data_sources,
-- metric_derivation, and insights: service_role has only REFERENCES/
-- TRIGGER/TRUNCATE everywhere (a schema-level default, not per-table
-- grants). BYPASSRLS (which service_role does have) only removes the RLS
-- POLICY gate -- it does nothing for the separate GRANT gate, per this
-- file's own two-gates principle above. Neither existing Edge Function
-- ever exercised ctx.supabaseAdmin.from(table) directly (notify-admin-
-- approval only calls the Auth Admin API; chat deliberately never uses
-- ctx.supabaseAdmin, per its own comment), so nothing had hit this gap
-- before insights-scan.
--
-- Deliberately NOT a blanket `grant ... on all tables in schema public to
-- service_role` / ALTER DEFAULT PRIVILEGES fix. That would be a much
-- larger security-posture change than this task asked for, made
-- unilaterally on a live project, and would cut against this file's own
-- stated philosophy for service-role holes: "each one is a deliberate
-- hole punched through the RLS model... not just 'another function.'"
-- This grants exactly the tables insights-scan actually reads/writes,
-- narrowly, the same way every other service-role access point in this
-- list is scoped one at a time.
--
-- daily_weather (not daily_derived, which is queried directly) needs its
-- own grant too: daily_derived has `security_invoker = true`
-- (20260830000002_vpd_peak_daily_derived_view.sql), so querying the view
-- runs as the caller's own privileges, not the view owner's -- same
-- reasoning applies to series_bucketed()/real_metric_vintage_counts(),
-- both plain `language sql stable` (not SECURITY DEFINER), so calling
-- them as service_role still requires service_role to hold the
-- underlying table grants directly.
grant select on sensor_readings to service_role;
grant select on daily_weather to service_role;
grant select on harvest_receipts to service_role;
grant select on vintages to service_role;
grant select on real_data_sources to service_role;
grant select on metric_derivation to service_role;
grant select, insert, update on insights to service_role;
