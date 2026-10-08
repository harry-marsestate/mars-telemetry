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
  // Nightly-health round (docs/SECURITY.md, "Nightly health checks"): the
  // round-one deferral reversed on purpose, with guardrails -- per-key scopes,
  // data_status tags, explicit as_of for get_anomalies, column-level grants,
  // rate limits, total_count, parity tests. A key must be granted these
  // explicitly (agent_api_keys.allowed_tools); no existing key has them.
  "get_series",
  "get_derived_series",
  "get_anomalies",
  "get_vessels",
  // Health tools (health-tools.ts, not chat tools): operator-owned keys only
  // (key-scope trigger) and operator accounts only (inside each function).
  "get_system_health",
  "get_health_history",
  "get_health_baselines",
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
  ets_lot_bridge:
    "Base table, exception (2026-10-08, identifier sweep): the static ETS description -> InnoVint lot_code mapping, read directly by get_wine_lab_results to name InnoVint readings of the same analyte (cross-source variants). Open-read RLS (using true) and already SELECT-granted to mcp_reader as a dependency of ets_lot_analyses_reconciliation (20260926150000) -- no new grant; no *_current counterpart by construction.",
  daily_derived: "security_invoker view (get_derived_series, and the gateway's total_count); column-level grant only (20260930040000).",
  vessels: "Base table, operator-only RLS (get_vessels, and the gateway's total_count); column-level grant only, no capacity_suspect/current_lot_id.",
};

// SELECT-granted to mcp_reader ONLY because the security_invoker views above
// read them with the caller's privileges (complete pg_depend closure,
// 2026-09-26). Never named by tool code -- the boundary check fails if one
// appears in a from().
export const VIEW_DEPENDENCIES: Readonly<Record<string, string>> = {
  lab_samples: "Beneath lab_samples_current, lab_results_current, berry_maturity_by_block, ets_lot_analyses_reconciliation.",
  lab_results: "Beneath lab_results_current, berry_maturity_by_block, ets_lot_analyses_reconciliation.",
  labour_actuals: "Beneath labour_actuals_by_category, labour_actuals_by_month, labour_vintage_coverage.",
  ets_analyte_bridge: "Beneath ets_lot_analyses_reconciliation.",
  daily_weather: "Beneath daily_derived (all its columns are read by the view's first CTE); column-level grant.",
  vintage_climate_calibration: "Beneath daily_derived (vintage, scalar only).",
};

// Read by the SECURITY INVOKER functions the data tools call (series_bucketed,
// anomalies_eval) or by the RLS policy on one of those tables -- never named by
// tool code. Column-level grants only (20260930040000).
export const RPC_DEPENDENCIES: Readonly<Record<string, string>> = {
  sensor_readings: "Read by series_bucketed() and anomalies_eval(); RLS (sensor_read) applies under the key owner's identity.",
  real_data_sources: "Read by series_bucketed()'s real-over-mock precedence.",
  metric_registry: "Read by sensor_readings' RLS policy (metric_key, min_role).",
  anomaly_thresholds: "Read by anomalies_eval().",
};

// Functions the tool path calls through the adapter's rpc() (as mcp_reader),
// and the two the gateway calls itself before switching roles.
export const RPCS: Readonly<Record<string, string>> = {
  current_data_mode: "SECURITY DEFINER, keyed off auth.uid(): the key owner's own data_mode, resolved exactly as chat does.",
  domain_reality: "SECURITY DEFINER, caller-independent real/simulated classification; resolved exactly as chat does.",
  series_bucketed: "SECURITY INVOKER time-bucketed sensor series (get_series); caller's RLS applies.",
  anomalies_eval: "SECURITY INVOKER anomaly rule evaluation (get_anomalies); caller's RLS applies.",
  chat_lot_analyses_scope: "SECURITY INVOKER (20261007120000): get_lot_analyses' full match set -- per-lot counts/ranges, total, analysis types, ETS pointer -- as one jsonb value; reads lot_analyses, lot_canonical_map, lab_samples_current, lab_results_current, ets_lot_bridge under the caller's RLS.",
  chat_ets_winery_scope: "SECURITY INVOKER (20261007120000): get_wine_lab_results' full match set -- samples, result total, analysis codes, vineyard/InnoVint pointers -- as one jsonb value; reads lab_samples_current, lab_results_current, ets_lot_bridge, lot_analyses under the caller's RLS.",
  health_system_status: "SECURITY DEFINER, operator accounts only: latest run per producer + the P4 self-check (get_system_health). EXECUTE for mcp_reader only.",
  health_history: "SECURITY DEFINER, operator accounts only: runs in the last 1-30 days (get_health_history). EXECUTE for mcp_reader only.",
  health_baselines: "SECURITY DEFINER, operator accounts only: every P1 baseline (get_health_baselines). EXECUTE for mcp_reader only.",
  mcp_authenticate: "SECURITY DEFINER key lookup; EXECUTE for mcp_gateway only. Returns (key_id, user_id) for an active key.",
  mcp_log_call: "SECURITY DEFINER audit append into agent_api_key_calls; EXECUTE for mcp_gateway only, gated on the key hash.",
  mcp_key_scope: "SECURITY DEFINER: an active key's allowed_tools and rate limits; EXECUTE for mcp_gateway only (tools/list).",
  mcp_authorize_call: "SECURITY DEFINER per-key scope + rate-limit decision for one tools/call, auditing refusals; EXECUTE for mcp_gateway only.",
};

// Everything the MCP path may reference, for the boundary check's reachability walk.
export const RELATIONS: Readonly<Record<string, string>> = { ...TABLES_AND_VIEWS, ...RPCS };
