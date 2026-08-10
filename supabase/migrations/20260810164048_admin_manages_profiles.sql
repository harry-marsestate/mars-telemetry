-- Add is_admin if the prior attempt at this migration (caught before push)
-- didn't already add it via the separate admin_flag migration.
alter table user_profiles add column if not exists is_admin boolean not null default false;

-- SECURITY DEFINER, mirroring current_role_name()/accessible_blocks() --
-- bypasses RLS on user_profiles entirely (runs as the function owner), so
-- unlike a bare exists(...) subquery in the policy body, this has no
-- dependency on own_profile_read or any other policy staying in place.
create or replace function is_admin_user() returns boolean
language sql stable security definer
set search_path = public
as $$
  select coalesce((select is_admin from user_profiles where id = auth.uid()), false)
$$;

-- Drop all four names from both prior attempts (the bare is_admin=true
-- version was never pushed, but drop it defensively too) so nothing stale
-- is left regardless of which attempt actually landed.
drop policy if exists operator_manages_profiles on user_profiles;
drop policy if exists operator_reads_all_profiles on user_profiles;
drop policy if exists admin_reads_all_profiles on user_profiles;
drop policy if exists admin_manages_profiles on user_profiles;

create policy admin_reads_all_profiles on user_profiles for select
  using (is_admin_user());

create policy admin_manages_profiles on user_profiles for update
  using (is_admin_user())
  with check (is_admin_user());
