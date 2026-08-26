-- Track 2 (irrigation), Phase 0. series_bucketed() hardcoded a single
-- literal, 'open_meteo_era5', in two separate places as "the" real/
-- authoritative source (see 20260826000000_series_bucketed_source_aware.sql).
-- That was fine when only one real source existed, but Track 2 is about
-- to introduce a second (real irrigation records, source_system
-- 'farm_irrigation_log') for a different metric (irrigation_volume).
-- Editing two hardcoded string literals by hand for every future real
-- source is exactly the kind of thing that's easy to get half-right --
-- this same investigation caught a real near-miss of that shape already
-- (the recap for this round misremembered irrigation_volume's mock
-- source_system as 'weather_station' when it's actually 'flow_meter';
-- scoping a future DELETE against the wrong literal would have been a
-- silent no-op). A lookup table turns "add a source" into an INSERT
-- instead of a function redefinition, removing that whole class of risk.
--
-- Two-gates reminder (docs/SECURITY.md): new tables get RLS auto-enabled
-- with zero policies -- grant and policy both included below, not just
-- one.

create table real_data_sources (
  source_system text primary key,
  notes         text
);

grant select on real_data_sources to authenticated;
create policy real_data_sources_read on real_data_sources
  for select using (true);

insert into real_data_sources (source_system, notes) values
  ('open_meteo_era5', 'Open-Meteo ERA5/ERA5-Land reanalysis -- air_temp, humidity, precipitation, soil_moisture, soil_temp, solar. Estate-level (block_id always null).');

-- series_bucketed(): same precedence logic as before (real data, when it
-- exists for a metric+vintage[+block], fully supersedes mock rather than
-- being averaged with it), now checking membership in real_data_sources
-- instead of a single hardcoded string. Block-aware fallback (matching
-- p_block, or falling back to an estate-level real row via block_id is
-- null) is unchanged from the soil fix -- see that migration for why it's
-- scoped that way.
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
     r.source_system in (select source_system from real_data_sources)
     or not exists (
       select 1 from sensor_readings r2
       where r2.metric_key = p_metric
         and r2.vintage = p_vintage
         and r2.source_system in (select source_system from real_data_sources)
         and (p_block is null or r2.block_id = p_block or r2.block_id is null)
     )
   )
  group by gs.b
  order by gs.b
$$;
