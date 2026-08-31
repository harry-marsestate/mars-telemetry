-- sensor_read (sensor_readings) was measured at 2-6s end-to-end for a real
-- authenticated operator on anomalies_eval()'s hot path -- EXPLAIN ANALYZE
-- as role authenticated (not superuser-bypassed) showed 843ms in-DB alone,
-- vs 264ms bypassing RLS. Two distinct per-row costs were found, isolated
-- separately before combining the fix:
--
-- 1. The metric_registry lookup was a correlated scalar subquery
--    ((select m.min_role from metric_registry m where m.metric_key =
--    sensor_readings.metric_key) = 'all'), re-executed as an index scan
--    17,656 times (once per candidate row) rather than once. Rewritten as
--    a non-correlated IN against metric_registry filtered by min_role='all'
--    -- the planner can hash/materialize that (18-row) result once and
--    probe it per row. Safe because sensor_readings.metric_key has a NOT
--    NULL FK to metric_registry.metric_key, so every row has exactly one
--    matching metric_registry row -- no NULL/missing-row edge case the
--    scalar-subquery form and the IN form could disagree on.
--    Measured impact alone: 843ms -> 729ms.
--
-- 2. The larger cost, found while isolating (1): current_role_name() is a
--    zero-argument STABLE SQL function, but Postgres does not
--    automatically hoist a bare per-row FuncExpr call the way it can hoist
--    a non-correlated subquery -- it was called once per candidate row too
--    (confirmed via a diagnostic: removing ONLY the metric_registry cost
--    while keeping a real current_role_name() call per row still measured
--    ~712ms, essentially the whole cost). Wrapping it as a scalar subquery,
--    (select current_role_name()), makes the planner treat it as an
--    InitPlan -- evaluated once, cached, reused for every row. This is the
--    same idiomatic fix Supabase's own RLS performance guidance recommends
--    for auth.uid() in policies, applied here to a locally-defined STABLE
--    function of the identical shape.
--
-- Combined measured impact (rolled-back transaction test, pre-apply):
-- 843ms -> 53ms for the raw query; 980ms -> 323ms for the full
-- anomalies_eval() RPC call, in-DB. Behaviorally verified identical before
-- applying: full-table MD5 checksums of sensor_readings under this exact
-- rewrite, for both an unrestricted operator and a B2-scoped customer,
-- matched the pre-change checksums exactly (40,527 and 35,952 rows
-- respectively) -- this changes only speed, not which rows any role can
-- see. Re-verified again against this migration once live, not just the
-- pre-apply rolled-back test -- see docs/SECURITY.md.
drop policy sensor_read on sensor_readings;
create policy sensor_read on sensor_readings for select using (
  (
    (
      metric_key in (select metric_key from metric_registry where min_role = 'all')
      and (select current_role_name()) in ('operator','customer')
    )
    or (select current_role_name()) = 'operator'
  )
  and (block_id is null or block_id in (select accessible_blocks()))
);
