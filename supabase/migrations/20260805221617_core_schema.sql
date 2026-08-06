create table blocks (
  block_id     text primary key,
  label        text not null,
  designation  text,
  acres        numeric not null,
  row_count    int,
  planted      text,
  aspect       text,
  elev_ft      int,
  color        text
);

create table block_lots (
  block_id     text references blocks(block_id),
  variety_key  text not null,
  variety_name text not null,
  acres        numeric not null,
  primary key (block_id, variety_key)
);

create table vintages (
  vintage             int primary key,
  is_current          boolean default false,
  temp_offset_f       numeric,
  water_offset        numeric,
  harvest_shift_days  int,
  character           text
);

create table tanks (
  tank_id      text primary key,
  block_id     text references blocks(block_id),
  variety_key  text,
  variety_name text,
  volume_l     numeric
);
create table metric_registry (
  metric_key    text primary key,
  label         text not null,
  unit          text not null,
  decimals      int default 1,
  source_system text,
  scope_level   text check (scope_level in ('estate','block','cellar','tank')),
  min_role      text not null default 'operator' check (min_role in ('all','operator')),
  is_derived    boolean default false
);

create table anomaly_thresholds (
  rule_key     text primary key,
  tab          text check (tab in ('vineyard','winery')),
  severity     text check (severity in ('alert','warn','note')),
  metric_key   text,
  scope_level  text,
  operator     text check (operator in ('lt','gt')),
  threshold    numeric,
  window_hours int default 1,
  title        text,
  message      text,
  enabled      boolean default true
);
create table stg_sensor_readings (
  metric_key    text,
  sensor_id     text,
  block_id      text,
  tank_id       text,
  recorded_at   timestamptz,
  value         numeric,
  source_system text,
  vintage       int
);

create table sensor_readings (
  id            bigint generated always as identity primary key,
  metric_key    text not null references metric_registry(metric_key),
  sensor_id     text not null,
  block_id      text references blocks(block_id),
  tank_id       text references tanks(tank_id),
  recorded_at   timestamptz not null,
  value         numeric not null,
  source_system text not null,
  vintage       int references vintages(vintage),
  ingested_at   timestamptz default now(),
  unique (metric_key, sensor_id, recorded_at)
);
create index on sensor_readings (metric_key, recorded_at desc);
create index on sensor_readings (block_id, metric_key, recorded_at desc);
create index on sensor_readings (vintage, metric_key, recorded_at desc);

create table work_events (
  id             bigint generated always as identity primary key,
  work_date      date not null,
  block_id       text references blocks(block_id),
  work_type_raw  text,
  work_type      text,
  hours          numeric,
  cost_usd       numeric,
  crew           text,
  vintage        int references vintages(vintage),
  source_system  text not null,
  source_file    text,
  ingested_at    timestamptz default now()
);

create table work_type_lookup (
  raw_name       text primary key,
  canonical_name text not null
);

create table harvest_lots (
  lot_id       text primary key,
  vintage      int references vintages(vintage),
  tank_id      text references tanks(tank_id),
  block_id     text references blocks(block_id),
  variety_key  text,
  variety_name text,
  pick_date    date,
  tons         numeric,
  brix         numeric,
  ph           numeric,
  volume_l     numeric,
  source_system text
);
create table user_profiles (
  id                  uuid primary key references auth.users(id) on delete cascade,
  full_name           text,
  role                text not null default 'customer' check (role in ('operator','customer')),
  customer_account_id text
);

create table customer_block_access (
  customer_account_id text,
  block_id            text references blocks(block_id),
  primary key (customer_account_id, block_id)
);