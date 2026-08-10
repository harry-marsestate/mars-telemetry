-- Same root cause, three places: RLS policies/functions written before the
-- Phase 6 approval system existed were never reconciled with it. Each one
-- grants access based on role or metric classification alone, without ever
-- checking current_role_name() resolves to an approved value at all.
-- current_role_name() already resolves unapproved/rejected users to
-- 'pending', which matches neither 'operator' nor 'customer' -- so
-- requiring current_role_name() in ('operator','customer') (or ='customer'
-- for the accessible_blocks() customer branch) closes each gap without
-- needing a separate status lookup at each call site.
--
-- Confirmed live via a simulated session for a genuinely pending
-- Google-OAuth signup before this fix: current_role_name() correctly
-- returned 'pending', but sensor_readings still returned 79,471 rows --
-- every estate-scoped 'all'-tier metric (air_temp, humidity, solar, uv,
-- wind, precipitation) was visible to any authenticated session regardless
-- of approval status.

-- 1. sensor_read: the min_role='all' branch only checked the metric's own
-- registry classification, never the caller's approval status.
drop policy sensor_read on sensor_readings;

create policy sensor_read on sensor_readings for select using (
  (
    (
      (select m.min_role from metric_registry m where m.metric_key = sensor_readings.metric_key) = 'all'
      and current_role_name() in ('operator','customer')
    )
    or current_role_name() = 'operator'
  )
  and (block_id is null or block_id in (select accessible_blocks()))
);

-- 2. daily_weather_read: same class of gap, worse -- qual was a bare
-- `true`, no role or status check of any kind. Backs daily_derived, the
-- source for the gdd/dtr/vpd/et0 panels and anomalies_eval().
drop policy daily_weather_read on daily_weather;

create policy daily_weather_read on daily_weather for select using (
  current_role_name() in ('operator','customer')
);

-- 3. accessible_blocks(): the operator branch is already implicitly gated
-- correctly, since current_role_name() can only return 'operator' when
-- status='approved' (otherwise the CASE in current_role_name() falls
-- through to 'pending' regardless of the stored role column). But the
-- customer branch matched customer_account_id directly, with no equivalent
-- gate -- if a customer_account_id mapping is ever assigned before a
-- customer is approved (a plausible real workflow: set up block access,
-- then approve), they'd get real block-scoped data while still pending.
create or replace function accessible_blocks() returns setof text
language sql stable security definer
as $$
  select block_id from blocks
  where current_role_name() = 'operator'
  union
  select block_id from customer_block_access
  where customer_account_id = (select customer_account_id from user_profiles where id = auth.uid())
    and current_role_name() = 'customer'
$$;
