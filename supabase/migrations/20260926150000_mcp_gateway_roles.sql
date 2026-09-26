-- MCP agentic access, revised auth (Option B', 2026-09-26): two dedicated
-- roles replace the per-request signed JWT. See docs/SECURITY.md's MCP entries.
--
--   mcp_gateway  the ONLY role the mcp Edge Function logs in as (directly, via
--                the Supavisor pooler -- never PostgREST). Owns no data
--                privileges: it can resolve/log API keys (EXECUTE granted in
--                20260926150001) and switch to mcp_reader, nothing else.
--                Created NOLOGIN with no password: the owner enables it by hand
--                (`alter role mcp_gateway with login password '...'`), so no
--                credential ever lives in a migration or the repo.
--
--   mcp_reader   what every tool query runs as. Per request, inside ONE
--                read-only transaction, the function sets
--                request.jwt.claims.sub = the API key owner's real uid, then
--                `set local role mcp_reader`. Every RLS policy in public is
--                `to public`, so each applies unchanged, keyed off auth.uid() --
--                the key owner's own RLS context. SELECT only, and only on
--                the round-one allowlist below. No BYPASSRLS, no writes.
--
-- Neither role inherits anything (NOINHERIT); mcp_gateway's membership in
-- mcp_reader is SET-only, so gateway queries never silently gain reader's
-- grants without an explicit `set role`.

create role mcp_reader nologin noinherit nobypassrls;
create role mcp_gateway nologin noinherit nobypassrls connection limit 20;
grant mcp_reader to mcp_gateway with inherit false, set true;

-- Guard rails on every gateway session (role settings apply at login; the
-- function additionally sets per-transaction limits).
alter role mcp_gateway set statement_timeout = '15s';
alter role mcp_gateway set idle_in_transaction_session_timeout = '10s';

grant usage on schema public to mcp_reader;

-- Exactly the relations the five round-one tools query (mirrors
-- supabase/functions/mcp/allowlist.ts RELATIONS; the boundary check fails if
-- the two ever disagree).
grant select on
  public.lab_samples_current,
  public.lab_results_current,
  public.berry_maturity_by_block,
  public.ets_lot_analyses_reconciliation,
  public.labour_actuals_by_category,
  public.labour_actuals_by_month,
  public.labour_vintage_coverage,
  public.lot_analyses,
  public.lot_canonical_map
to mcp_reader;

-- View dependencies, NOT tool access: all seven views above are
-- security_invoker, so Postgres checks the caller's own privileges on the
-- tables beneath them. This is the complete dependency closure (computed from
-- pg_depend on 2026-09-26): without these, every view read fails with
-- `permission denied`. Each has RLS on, which applies to mcp_reader too. The
-- tool code never names these tables (the boundary check enforces that); only
-- the views do. mirrors allowlist.ts VIEW_DEPENDENCIES.
grant select on
  public.lab_samples,        -- under lab_samples_current, lab_results_current, berry_maturity_by_block, reconciliation
  public.lab_results,        -- under lab_results_current, berry_maturity_by_block, reconciliation
  public.labour_actuals,     -- under the three labour_* views
  public.ets_lot_bridge,     -- under ets_lot_analyses_reconciliation
  public.ets_analyte_bridge  -- under ets_lot_analyses_reconciliation
to mcp_reader;
