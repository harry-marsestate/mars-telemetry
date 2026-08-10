-- everyone can read their own row, including while pending, so the frontend
-- can decide which screen to show
create policy own_profile_read on user_profiles for select
  using (id = auth.uid());

-- operators can see and act on every profile -- this is what the approval
-- queue reads and writes
create policy operator_reads_all_profiles on user_profiles for select
  using (current_role_name() = 'operator');

create policy operator_updates_status on user_profiles for update
  using (current_role_name() = 'operator')
  with check (current_role_name() = 'operator');

grant select, update on user_profiles to authenticated;