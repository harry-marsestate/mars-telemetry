-- RLS on lot_analyses and vessels, stated in a migration (docs/SECURITY.md,
-- "Chat tool findings", "Not fixed": RLS on these two tables).
--
-- 20260811215238 created both tables with an operator-only SELECT policy
-- (lot_analyses_read, vessels_read) and a SELECT grant to authenticated, but
-- never enabled row level security: production has it on (pg_class.
-- relrowsecurity = true, relforcerowsecurity = false, checked 2026-10-07)
-- because Supabase enabled it on create. A database rebuilt from migrations
-- alone would have the policies but not RLS, so every authenticated user
-- (customers and pending accounts) could read every InnoVint lot analysis and
-- vessel.
--
-- On production this is a no-op: ENABLE on a table that already has RLS
-- enabled changes nothing, and FORCE is deliberately not set (production does
-- not force it; the table owner keeps bypassing RLS as today). P1
-- security.rls.enabled_on_every_table already checks the live state.
alter table public.lot_analyses enable row level security;
alter table public.vessels enable row level security;
