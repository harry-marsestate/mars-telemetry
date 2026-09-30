-- series_bucketed(): real-over-mock precedence now applies per ROW vintage
-- when the caller passes no vintage (docs/SECURITY.md, "series_bucketed
-- blended mock into real when no vintage was passed", 2026-09-30).
--
-- The precedence test was `r2.vintage = p_vintage`. With p_vintage NULL that
-- is never true, so `not exists (...)` was always true and every mock row was
-- averaged in next to the real ones. Measured live: air_temp 2026-07-01 06:00Z
-- (6h bucket) 62.47 blended vs 54.80 real; soil_moisture B2 returned mock
-- soil_probe values where the vintage-scoped call returns none. Reached by
-- chat's get_series (vintage is optional) and so by the MCP gateway; a
-- real_only account's year check passed (2026 air_temp IS real) and it got the
-- blend. The dashboard always passes a vintage.
--
-- Fix: with a vintage passed, the original test, byte for byte -- identical
-- results for every existing vintage-scoped call (checked live against the
-- previous definition). With none, a mock row is kept only if its OWN
-- vintage has no real rows for the metric/block, as if the caller had split
-- the range by vintage. The real vintages are collected once per call into a
-- constant array (an InitPlan), so the per-row test stays a cheap scalar
-- `<> all(...)` and the per-bucket index scan plan is kept. Measured live on
-- a year-long no-vintage window: correlated EXISTS 12x slower, hashed NOT IN
-- 10x slower (the planner switched to a materialised nested loop), the array
-- ~1.15x; vintage-scoped calls unchanged. sensor_readings.vintage has no NULLs
-- (checked); a NULL-vintage row would be kept, as before. Grants and owner
-- are unchanged (create or replace).
create or replace function public.series_bucketed(p_metric text, p_block text, p_vintage integer, p_start timestamp with time zone, p_end timestamp with time zone, p_bucket interval, p_agg text default 'avg'::text)
 returns table(t timestamp with time zone, v numeric)
 language sql
 stable
as $function$
  select gs.b as t,
    case when p_agg = 'sum' then sum(r.value) else avg(r.value) end as v
  from generate_series(p_start, p_end, p_bucket) as gs(b)
  left join sensor_readings r
    on r.recorded_at >= gs.b
   and r.recorded_at <  gs.b + p_bucket
   and r.metric_key = p_metric
   and (p_block is null or r.block_id = p_block)
   and (p_vintage is null or r.vintage = p_vintage)
   and (
     r.source_system in (select source_system from real_data_sources)
     -- vintage passed: unchanged from 20260826000001
     or (p_vintage is not null and not exists (
       select 1 from sensor_readings r2
       where r2.metric_key = p_metric
         and r2.vintage = p_vintage
         and r2.source_system in (select source_system from real_data_sources)
         and (p_block is null or r2.block_id = p_block or r2.block_id is null)
     ))
     -- no vintage: a mock row counts only if its OWN vintage has no real rows
     or (p_vintage is null and (r.vintage is null or r.vintage <> all (array(
       select distinct r2.vintage from sensor_readings r2
       where r2.metric_key = p_metric
         and r2.vintage is not null
         and r2.source_system in (select source_system from real_data_sources)
         and (p_block is null or r2.block_id = p_block or r2.block_id is null)
     ))))
   )
  group by gs.b
  order by gs.b
$function$;
