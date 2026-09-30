-- The approval UI's "Block access" step (web/index.html renderApproveForm:
-- sb.from('customer_block_access').insert(...)) could never succeed:
-- authenticated had no INSERT grant AND the table had no INSERT policy -- both
-- gates closed (docs/SECURITY.md's two-gates entries). Every per-block
-- customer so far was set up by hand in SQL. Admin-only, exactly like
-- admin_manages_profiles on user_profiles: the policy is the enforcement, the
-- grant just opens the gate for it. No UPDATE/DELETE: the UI doesn't do them.
grant insert on public.customer_block_access to authenticated;
create policy customer_block_access_admin_insert on public.customer_block_access
  for insert with check (is_admin_user());
