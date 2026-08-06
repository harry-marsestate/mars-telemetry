-- anomaly_thresholds has row level security enabled but had zero policies,
-- which is a hard deny-all for every role except the table owner / a
-- BYPASSRLS role. anomalies_eval() is plain SECURITY INVOKER (matching
-- series_bucketed), so it runs as the calling authenticated role and got
-- nothing back from this table -- the earlier `grant select ... to
-- authenticated` fixed table-level privilege but did nothing for row-level
-- visibility; those are independent gates. Confirmed via a simulated
-- authenticated session (test-operator JWT) that anomaly_thresholds
-- returned 0 visible rows while sensor_readings for the same query returned
-- 3848, and anomalies_eval(2022, ...) returned empty as a result.
--
-- This table is static rule metadata (thresholds/titles/messages), not
-- customer- or block-scoped data, so a fully open read policy is correct --
-- mirrors daily_weather_read's existing precedent (qual = true, role public)
-- for the same class of non-sensitive reference data.
create policy anomaly_thresholds_read on anomaly_thresholds
  for select using (true);
