// The three gateway health tools (docs/SECURITY.md, "Nightly health checks").
// Not chat tools: the in-app chat never sees them. Each calls one SECURITY
// DEFINER read function (EXECUTE for mcp_reader only; operator accounts only)
// through the adapter, inside the same read-only, key-owner-scoped
// transaction as every other gateway call.
import type { GatewayResult } from "./data-tools.ts";
import { currentToolVintage } from "../chat/tools.ts";

const RANK: Record<string, number> = { pass: 1, warn: 2, fail: 3, error: 4 };

// P4 addition: the gateway's own answer to "which vintage is current" (the
// TypeScript harvest-year rule it uses for get_anomalies' default) must
// equal the database's (its harvest_vintage function) and exist in the vintages table.
// deno-lint-ignore no-explicit-any
export function withGatewayVintageCheck(status: any, gatewayVintage: number): any {
  if (!status || typeof status !== "object" || !Array.isArray(status.p4_gateway_self_check)) return status;
  const ok = status.current_vintage === gatewayVintage && status.current_vintage_in_table === true;
  const check = {
    check_id: "gateway.p4.current_vintage",
    status: ok ? "pass" : "fail",
    observed: { gateway: gatewayVintage, database: status.current_vintage, in_vintages_table: status.current_vintage_in_table },
    ...(ok ? {} : { detail: "the gateway and the database disagree on the current vintage, or it is missing from the vintages table" }),
  };
  const worst = [status.overall, check.status].reduce((a: string, b: string) => (RANK[b] > RANK[a] ? b : a), "pass");
  return { ...status, overall: worst, p4_gateway_self_check: [...status.p4_gateway_self_check, check] };
}

export const HEALTH_TOOLS = [
  {
    name: "get_system_health",
    description:
      "Latest nightly health status: for each producer (P1 database checks 12:00 UTC, P2 upstream probes 12:10, P3 frontend checks 12:17, with a 12:35 backup dispatch) the latest run, its status, whether it is stale (no run since its latest slot + 30 min, or older than 26 hours), result counts and every non-passing check with observed/expected values; plus a P4 self-check computed now (database reachable through the gateway, this key's expiry, its allowed tools, any write-capable tools, and the current vintage per the gateway vs the database). 'overall' is the worst of all of them.",
    input_schema: { type: "object" as const, properties: {}, required: [] as string[] },
  },
  {
    name: "get_health_history",
    description: "Every health run in the last N days (1-30, default 7), newest first, with each run's status, result counts and non-passing checks.",
    input_schema: {
      type: "object" as const,
      properties: { days: { type: "integer", description: "How many days back, 1-30. Default 7." } },
      required: [] as string[],
    },
  },
  {
    name: "get_health_baselines",
    description: "Every stored baseline the P1 database checks compare against (check_id, value, when and by whom it was set). Uncapped.",
    input_schema: { type: "object" as const, properties: {}, required: [] as string[] },
  },
];
export const HEALTH_TOOL_NAMES: readonly string[] = HEALTH_TOOLS.map((t) => t.name);

// deno-lint-ignore no-explicit-any
export async function runHealthTool(client: any, name: string, input: Record<string, unknown>): Promise<GatewayResult> {
  let r: { data: unknown; error: { message: string } | null };
  if (name === "get_system_health") r = await client.rpc("health_system_status");
  else if (name === "get_health_history") {
    // Checked here too (health_history() raises): a SQL error aborts the
    // scoped transaction and would surface only as a generic failure.
    const days = input.days ?? 7;
    if (!Number.isInteger(days) || (days as number) < 1 || (days as number) > 30) return { content: "days must be an integer between 1 and 30", isError: true };
    r = await client.rpc("health_history", { p_days: days });
  }
  else if (name === "get_health_baselines") r = await client.rpc("health_baselines");
  else return { content: `Unknown tool: ${name}`, isError: true };
  if (r.error) {
    const msg = /operator accounts only|between 1 and 30/.test(r.error.message) ? r.error.message : "The health query failed.";
    return { content: msg, isError: true };
  }
  const data = name === "get_system_health" ? withGatewayVintageCheck(r.data, currentToolVintage()) : r.data;
  return { content: JSON.stringify(data), isError: false, structuredContent: data as Record<string, unknown> };
}
