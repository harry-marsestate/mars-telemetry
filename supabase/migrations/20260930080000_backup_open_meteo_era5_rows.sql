-- Step 1 of the climate source relabel (docs/SECURITY.md, "Climate rows were
-- labelled ERA5 but came from ECMWF IFS"): snapshot every row about to be
-- relabelled, BEFORE any UPDATE, into a schema outside the public API.
--
-- backup is not an exposed PostgREST schema, and every privilege is revoked
-- from the API roles; RLS is on with no policies (both gates, as for
-- system_health). The manifest records exact per-metric row counts and a
-- value checksum over (metric_key, recorded_at as epoch, value) -- the same
-- checksum the relabel migration re-computes after its UPDATEs.
create schema if not exists backup;
revoke all on schema backup from public, anon, authenticated, service_role;

create table backup.sensor_readings_open_meteo_era5_20260930 as
  select * from public.sensor_readings where source_system = 'open_meteo_era5';
alter table backup.sensor_readings_open_meteo_era5_20260930 add primary key (id);
alter table backup.sensor_readings_open_meteo_era5_20260930 enable row level security;
revoke all on backup.sensor_readings_open_meteo_era5_20260930 from public, anon, authenticated, service_role;

create table backup.open_meteo_relabel_manifest_20260930 as
  select metric_key, count(*)::bigint as row_count,
         md5(string_agg(concat_ws('|', metric_key, extract(epoch from recorded_at)::bigint, value), ',' order by metric_key, recorded_at)) as value_checksum,
         now() as taken_at
    from backup.sensor_readings_open_meteo_era5_20260930
   group by metric_key;
alter table backup.open_meteo_relabel_manifest_20260930 enable row level security;
revoke all on backup.open_meteo_relabel_manifest_20260930 from public, anon, authenticated, service_role;

do $$
declare
  v_live bigint; v_bak bigint; v_man bigint;
begin
  select count(*) into v_live from public.sensor_readings where source_system = 'open_meteo_era5';
  select count(*) into v_bak from backup.sensor_readings_open_meteo_era5_20260930;
  select sum(row_count) into v_man from backup.open_meteo_relabel_manifest_20260930;
  if v_live <> v_bak or v_bak <> v_man or v_bak = 0 then
    raise exception 'backup: % live rows, % backed up, % in the manifest', v_live, v_bak, v_man;
  end if;
  if (select count(*) from backup.open_meteo_relabel_manifest_20260930) <> 6 then
    raise exception 'backup: expected 6 metrics (air_temp, humidity, precipitation, solar, soil_moisture, soil_temp)';
  end if;
end $$;
