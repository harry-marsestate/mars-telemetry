-- series_bucketed() previously aggregated sensor_readings across every
-- source_system with no precedence, silently averaging mock and real
-- values together for any (metric, vintage) where both exist for the same
-- bucket window. Confirmed live and active for 2023 humidity: 1,709 of
-- 5,139 hourly readings collided at the identical timestamp, and even
-- non-colliding hours were pooled together at 5D/30D bucket widths -- not
-- a rare edge case. See docs/SECURITY.md for the full investigation.
--
-- Fix: real data, when present for a given (metric, vintage, block),
-- fully supersedes mock for that combination rather than being merged
-- with it -- matching the mental model Phase 3 deletion already assumes.
-- 'open_meteo_era5' is the only authoritative/real source today; any
-- future real source must be added to this check (and to the equivalent
-- check in daily_weather.sql's real_scope CTE -- same rule, two separate
-- implementations, kept in sync manually since one is a live SQL function
-- and the other a dbt-materialized incremental model).
--
-- The exists-check matches p_block specifically (falling back to
-- estate-level real rows via `block_id is null`) rather than checking
-- existence at the metric+vintage level alone -- necessary so that a
-- future, unevenly-rolled-out per-block real source doesn't suppress
-- still-valid mock data for a block that hasn't received real data yet.
-- Today this collapses to the same result as a block-agnostic check,
-- since every authoritative row is currently estate-level (block_id is
-- null) and therefore matches every p_block via that fallback branch.
create or replace function series_bucketed(
  p_metric text, p_block text, p_vintage integer,
  p_start timestamptz, p_end timestamptz, p_bucket interval, p_agg text default 'avg'
) returns table(t timestamptz, v numeric)
language sql stable as $$
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
     r.source_system = 'open_meteo_era5'
     or not exists (
       select 1 from sensor_readings r2
       where r2.metric_key = p_metric
         and r2.vintage = p_vintage
         and r2.source_system = 'open_meteo_era5'
         and (p_block is null or r2.block_id = p_block or r2.block_id is null)
     )
   )
  group by gs.b
  order by gs.b
$$;
