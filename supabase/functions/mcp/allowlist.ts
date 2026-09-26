// The two allowlists this function is held to. Both are enforced, not just
// documented: MCP_TOOLS gates tools/list and tools/call in handler.ts, and
// scripts/check-mcp-boundaries.mjs fails if any relation reachable from these
// tools (in chat/tools.ts) or from this directory isn't in RELATIONS below.

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

// Every table, view and RPC the MCP path is permitted to touch, each with the
// reason it's allowed. The standing rule is "*_current views, never base
// tables"; the exceptions are named here rather than hidden in a looser grep.
export const RELATIONS: Readonly<Record<string, string>> = {
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

  // --- RPCs ---
  current_data_mode: "SECURITY DEFINER, keyed off auth.uid(): the calling user's own data_mode, resolved exactly as chat does.",
  domain_reality: "SECURITY DEFINER, caller-independent real/simulated classification; resolved exactly as chat does.",
  mcp_authenticate: "SECURITY DEFINER key lookup (anon-executable); returns only (key_id, user_id) for an active key.",
  mcp_log_call: "SECURITY DEFINER audit append into agent_api_key_calls (anon-executable, gated on the key hash).",
};
