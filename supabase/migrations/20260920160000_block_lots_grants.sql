-- block_lots (varietal per block: B1's Cab Franc/Cab Sauvignon/Petit
-- Verdot split, B2/B3 as 100% Cabernet Sauvignon) has had RLS enabled
-- with ZERO policies AND no SELECT grant to any non-owner role since it
-- was created (20260805221617_core_schema.sql) -- confirmed live, not
-- assumed: information_schema.role_table_grants has no SELECT row for
-- authenticated/anon/service_role, and pg_policies has zero rows for
-- this table. Both gates fail closed independently (docs/SECURITY.md's
-- "RLS auto-enable gotcha" entry), so only the table owner has ever
-- been able to read it -- invisible to the dashboard, chat, and every
-- real account. Silent failure mode: a future join against this table
-- returns zero rows, not an error, so nothing so far has surfaced it.
--
-- Mirrors blocks' own grant+policy exactly, not a new/tighter shape:
-- confirmed live blocks grants SELECT to authenticated and has a single
-- open `using (true)` read policy, already visible to customers as well
-- as operators. Varietal-per-block is the same reference/geometry
-- character as block acreage/aspect/elevation already on that same
-- table -- nothing about "which grapes grow where" is more sensitive
-- than "where the block boundaries are," so no reason found to restrict
-- this beyond what blocks itself already allows.
grant select on block_lots to authenticated;
create policy block_lots_read on block_lots for select
  using (true);
