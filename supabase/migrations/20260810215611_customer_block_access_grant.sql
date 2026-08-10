-- customer_block_access_admin_read added the RLS policy but not the
-- underlying table grant -- the same class of gap as the original
-- anomaly_thresholds incident, mirrored (there it was grant-without-policy,
-- here it's policy-without-grant). Confirmed via the adversarial
-- verification this migration's own commit asked for: even the admin
-- account got "permission denied for table customer_block_access", not an
-- RLS-filtered empty result -- a table-level grant error, not a policy one.
grant select on customer_block_access to authenticated;
