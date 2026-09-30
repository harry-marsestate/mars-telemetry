// The three gateway health tools (docs/SECURITY.md, "Nightly health checks").
// Not chat tools: the in-app chat never sees them. Each calls one SECURITY
// DEFINER read function (EXECUTE for mcp_reader only; operator accounts only)
// through the adapter, inside the same read-only, key-owner-scoped
// transaction as every other gateway call.
import type { GatewayResult } from "./data-tools.ts";

export const HEALTH_TOOLS = [
  {
    name: "get_system_health",
    description:
      "Latest nightly health status: for each producer (P1 database checks 12:00 UTC, P2 upstream probes 12:10, P3 frontend checks 12:20) the latest run, its status, whether it is stale (older than 26 hours), result counts and every non-passing check with observed/expected values; plus a P4 self-check computed now (database reachable through the gateway, this key's expiry, its allowed tools, any write-capable tools). 'overall' is the worst of all of them.",
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
  return { content: JSON.stringify(r.data), isError: false, structuredContent: r.data as Record<string, unknown> };
}
