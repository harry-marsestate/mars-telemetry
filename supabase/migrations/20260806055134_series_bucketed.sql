create or replace function series_bucketed(
  p_metric text, p_block text, p_vintage int,
  p_start timestamptz, p_end timestamptz, p_bucket interval
) returns table (t timestamptz, v numeric)
language sql stable as $$
  select gs.b as t, avg(r.value) as v
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