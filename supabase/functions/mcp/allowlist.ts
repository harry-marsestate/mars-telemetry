// The allowlists this function is held to, each enforced three ways:
//   - at runtime: handler.ts gates tools/list + tools/call on MCP_TOOLS, and
//     adapter.ts refuses any from()/rpc() target not listed here;
//   - in Postgres: mcp_reader's grants (20260926150000) are exactly
//     TABLES_AND_VIEWS + VIEW_DEPENDENCIES, SELECT only;
//   - statically: scripts/check-mcp-boundaries.mjs fails if any relation
//     reachable from these tools or this directory isn't listed, or if the
//     migration's grants and these lists disagree.

// Round one (docs/SECURITY.md, MCP entry). Deliberately NOT get_series,
// get_derived_series or get_anomalies (simulated-history risk: MOCK_NOW
// anchoring and real-only gating) and not get_vessels (deferred). runTool()
// can dispatch every one of those -- handler.ts rejects them before it's
// called.
export const MCP_TOOLS: readonly string[] = [
  "get_berry_maturity",
  "get_smoke_markers",
  "get_wine_lab_results",
  "get_lot_analyses",
  "get_labour_summary",
];

// Tables/views the tool code may name in from(). The standing rule is
// "*_current views, never base tables"; the two exceptions are named here
// rather than hidden in a looser grep.
export const TABLES_AND_VIEWS: Readonly<Record<string, string>> = {
  // --- views (all security_invoker = true, so the caller's own RLS applies) ---
  lab_samples_current: "*_current view: excludes superseded ETS reissue samples that lab_samples intentionally retains.",
  lab_results_current: "*_current view: excludes superseded ETS reissue results that lab_results intentionally retains.",
  berry_maturity_by_block: "View built on lab_samples_current/lab_results_current only (20260920140000), never the raw lab tables.",
  ets_lot_analyses_reconciliation: "View over lab_results_current/lab_samples_current joined to lot_analyses; reconciliation status only.",
  labour_actuals_by_category: "Aggregate view over labour_actuals; labour data has no reissue concept, so no *_current counterpart exists.",
  labour_actuals_by_month: "Aggregate view over labour_actuals, same reasoning as labour_actuals_by_category.",
  labour_vintage_coverage: "Coverage view over labour_actuals, same reasoning; feeds the tool's real-coverage note.",

  // --- base tables, named exceptions to the *_current rule ---
  lot_analyses:
    "Base table, exception: InnoVint lab rows have no reissue/superseded concept, so there is no *_current view to prefer; operator-only RLS. Duplicate lot objects are handled via lot_canonical_map instead (docs/SECURITY.md, 'get_lot_analyses duplicate-lot bug').",
  lot_canonical_map:
    "Base table, exception: the dedup map itself (duplicate_lot_code -> canonical_lot_code) that get_lot_analyses uses to exclude superseded InnoVint duplicates; no *_current counterpart by construction.",
};

// SELECT-granted to mcp_reader ONLY because the security_invoker views above
// read them with the caller's privileges (complete pg_depend closure,
// 2026-09-26). Never named by tool code -- the boundary check fails if one
// appears in a from().
export const VIEW_DEPENDENCIES: Readonly<Record<string, string>> = {
  lab_samples: "Beneath lab_samples_current, lab_results_current, berry_maturity_by_block, ets_lot_analyses_reconciliation.",
  lab_results: "Beneath lab_results_current, berry_maturity_by_block, ets_lot_analyses_reconciliation.",
  labour_actuals: "Beneath labour_actuals_by_category, labour_actuals_by_month, labour_vintage_coverage.",
  ets_lot_bridge: "Beneath ets_lot_analyses_reconciliation.",
  ets_analyte_bridge: "Beneath ets_lot_analyses_reconciliation.",
};

// Functions the tool path calls through the adapter's rpc() (as mcp_reader),
// and the two the gateway calls itself before switching roles.
export const RPCS: Readonly<Record<string, string>> = {
  current_data_mode: "SECURITY DEFINER, keyed off auth.uid(): the key owner's own data_mode, resolved exactly as chat does.",
  domain_reality: "SECURITY DEFINER, caller-independent real/simulated classification; resolved exactly as chat does.",
  mcp_authenticate: "SECURITY DEFINER key lookup; EXECUTE for mcp_gateway only. Returns (key_id, user_id) for an active key.",
  mcp_log_call: "SECURITY DEFINER audit append into agent_api_key_calls; EXECUTE for mcp_gateway only, gated on the key hash.",
};

// Everything the MCP path may reference, for the boundary check's reachability walk.
export const RELATIONS: Readonly<Record<string, string>> = { ...TABLES_AND_VIEWS, ...RPCS };
