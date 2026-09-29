-- insights-scan reads harvest_receipts_current (1fc61c2, merged 2026-09-20)
-- but that code was never deployed, and service_role was never granted the
-- view or the exclusion table under it -- deploying it would have failed the
-- yield query with "permission denied" (the two-gates pattern,
-- docs/SECURITY.md). harvest_receipts_current is security_invoker, so both
-- the view and every table it reads need the grant. service_role already has
-- SELECT on harvest_receipts itself (20260902211836).
grant select on public.harvest_receipts_current, public.harvest_receipts_excluded to service_role;
