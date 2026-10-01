-- latest_reading(): the newest RAW reading at or before an as-of instant
-- (docs/SECURITY.md, "Latest value: one point-in-time reading on every
-- range", 2026-10-01).
--
-- The dashboard read each panel's "latest" value off the last
-- series_bucketed() bucket, whose size depends on the selected range (1 h /
-- 3 h / 1 day / 1 month), so the newest point was a 1 h, 3 h, 24 h or month
-- average (or sum) and changed with the range. This returns the reading
-- itself, so every panel headline, the newest-point tooltip and the "Estate
-- at a glance" overview read one value.
--
-- Same row eligibility as series_bucketed() (20260930045000), clause for
-- clause: metric, block (NULL = every block, i.e. estate scope), vintage,
-- and the real-over-mock precedence with and without a vintage. Rows at the
-- newest eligible timestamp are averaged (p_agg 'avg') or summed ('sum'),
-- exactly as a bucket holding only that timestamp would be. NULL values are
-- skipped (avg/sum ignore them in series_bucketed too).
--
-- SECURITY INVOKER like series_bucketed(): sensor_readings RLS applies to the
-- caller unchanged. EXECUTE for authenticated and service_role only (not
-- PUBLIC/anon -- the dashboard calls it signed in, and anon holds no
-- sensor_readings privilege anyway).
create or replace function public.latest_reading(
  p_metric text, p_block text, p_vintage integer, p_as_of timestamp with time zone, p_agg text default 'avg'::text)
 returns table(t timestamp with time zone, v numeric)
 language sql
 stable
 security invoker
 set search_path = ''
as $function$
  with eligible as (
    select r.recorded_at, r.value
    from public.sensor_readings r
    where r.metric_key = p_metric
      and (p_block is null or r.block_id = p_block)
      and (p_vintage is null or r.vintage = p_vintage)
      and r.recorded_at <= p_as_of
      and r.value is not null
      and (
        r.source_system in (select source_system from public.real_data_sources)
        or (p_vintage is not null and not exists (
          select 1 from public.sensor_readings r2
          where r2.metric_key = p_metric
            and r2.vintage = p_vintage
            and r2.source_system in (select source_system from public.real_data_sources)
            and (p_block is null or r2.block_id = p_block or r2.block_id is null)
        ))
        or (p_vintage is null and (r.vintage is null or r.vintage <> all (array(
          select distinct r2.vintage from public.sensor_readings r2
          where r2.metric_key = p_metric
            and r2.vintage is not null
            and r2.source_system in (select source_system from public.real_data_sources)
            and (p_block is null or r2.block_id = p_block or r2.block_id is null)
        ))))
      )
  ), newest as (
    select max(recorded_at) as t from eligible
  )
  select n.t,
    case when p_agg = 'sum' then sum(e.value) else avg(e.value) end as v
  from newest n
  join eligible e on e.recorded_at = n.t
  group by n.t
$function$;

revoke all on function public.latest_reading(text, text, integer, timestamp with time zone, text) from public, anon;
grant execute on function public.latest_reading(text, text, integer, timestamp with time zone, text) to authenticated, service_role;
