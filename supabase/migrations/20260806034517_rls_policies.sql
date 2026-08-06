alter table sensor_readings enable row level security;

create policy sensor_read on sensor_readings for select using (
  (
    (select min_role from metric_registry m where m.metric_key = sensor_readings.metric_key) = 'all'
    or current_role_name() = 'operator'
  )
  and (
    block_id is null or block_id in (select accessible_blocks())
  )
);

alter table work_events enable row level security;

create policy work_read on work_events for select
  using (current_role_name() = 'operator');

alter table harvest_lots enable row level security;

create policy harvest_read on harvest_lots for select
  using (current_role_name() = 'operator' or block_id in (select accessible_blocks()));

alter table blocks enable row level security;

create policy blocks_read on blocks for select using (true);

alter table vintages enable row level security;

create policy vintages_read on vintages for select using (true);

alter table metric_registry enable row level security;

create policy metric_registry_read on metric_registry for select using (true);