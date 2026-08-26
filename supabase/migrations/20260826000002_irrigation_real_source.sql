-- Track 2 (irrigation), Phase 1. Registers the new real source so
-- series_bucketed() recognizes it as authoritative over mock the moment
-- the ingestion script inserts rows -- a genuine prerequisite of Phase 1
-- (not separate scope), per the real_data_sources table added in
-- 20260826000001.

insert into real_data_sources (source_system, notes) values
  ('farm_irrigation_log', 'Real farm irrigation records (Mars Irrigation 2023/2024.xlsx), event-level, hours converted to gallons per block''s own rate. Block-level (block_id populated), unlike Open-Meteo''s estate-level convention -- these records genuinely have block resolution.');
