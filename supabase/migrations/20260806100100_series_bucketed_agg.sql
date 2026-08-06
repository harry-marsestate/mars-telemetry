-- Adds an optional p_agg parameter to series_bucketed so callers that need a
-- total per bucket (precipitation, irrigation volume) aren't forced through
-- avg(), which silently dilutes sum-shaped metrics with same-bucket zeros.
-- Existing callers that don't pass p_agg keep the original avg() behaviour.
-- NOTE: adding a parameter changes the function's arg-type signature, so
-- `create or replace` creates a new overload rather than replacing the old
-- one in place — drop the old 6-arg version explicitly to avoid ending up
-- with two ambiguous overloads (which also breaks unqualified GRANT).
drop function if exists series_bucketed(text, text, int, timestamptz, timestamptz, interval);

create or replace function series_bucketed(
  p_metric text, p_block text, p_vintage int,
  p_start timestamptz, p_end timestamptz, p_bucket interval,
  p_agg text default 'avg'
) returns table (t timestamptz, v numeric)
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
  group by gs.b
  order by gs.b
$$;

grant execute on function series_bucketed to authenticated;
