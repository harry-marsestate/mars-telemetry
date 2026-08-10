-- customer_block_access has had RLS enabled with zero policies since the
-- very first RLS sweep (see docs/SECURITY.md's dormant-instances list) --
-- only reachable internally via accessible_blocks(). The approval queue's
-- customer_account_id collision check needs a direct read: seed data has
-- ACCT-01/ACCT-02 in customer_block_access with no corresponding
-- user_profiles.customer_account_id row, so checking user_profiles alone
-- would miss a real collision. Admin-only, matching every other Phase 6
-- policy's pattern.
create policy customer_block_access_admin_read on customer_block_access
  for select using (is_admin_user());
