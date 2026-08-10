-- operator_updates_status implied status-only, but it legitimately grants
-- full profile edit rights to operators (role + customer_account_id +
-- status together, matching the approval queue's actual requirements).
-- Rename only -- same logic, no functional change.
drop policy operator_updates_status on user_profiles;

create policy operator_manages_profiles on user_profiles for update
  using (current_role_name() = 'operator')
  with check (current_role_name() = 'operator');
