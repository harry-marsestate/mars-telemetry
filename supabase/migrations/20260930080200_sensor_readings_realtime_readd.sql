-- Step 3 of the climate source relabel: put sensor_readings back in the
-- supabase_realtime publication (taken out by 20260930080100 so Realtime
-- wouldn't decode ~145k label UPDATEs). Applied once Realtime had moved past
-- that commit; the dashboard's INSERT subscription works again from here.
alter publication supabase_realtime add table public.sensor_readings;
