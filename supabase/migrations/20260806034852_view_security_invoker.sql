alter view daily_derived set (security_invoker = true);
alter view labour_summary set (security_invoker = true);
alter view anomalies set (security_invoker = true);
alter view anomalies_asof set (security_invoker = true);

alter table daily_weather enable row level security;
create policy daily_weather_read on daily_weather for select using (true);