// Gateway-only wrapper for the four nightly-health data tools (get_series,
// get_derived_series, get_anomalies, get_vessels). It runs chat/tools.ts
// runTool() UNCHANGED -- the in-app chat's behaviour and deployed code are
// untouched -- and adds, for gateway callers only (docs/SECURITY.md,
// "Nightly health checks", guardrails 2, 3 and 6):
//
//   * get_anomalies requires an explicit as_of. The chat default is the
//     frozen MOCK_NOW (2026-07-28); a gateway caller must say what instant it
//     means, and a missing/unparseable as_of is a clear error.
//   * data_status ('real' | 'mock' | 'unknown') on every row, from
//     domain_reality() -- the same server-side classification chat and the
//     dashboard use. 'unknown' = domain_reality() has no answer for that
//     domain (an unmapped anomaly metric, or the RPC failed); chat fails OPEN
//     there, the gateway says so instead of guessing. Real-only owners: the
//     tools' own real-only gate (unchanged chat code) already withholds
//     simulated domains/vintages whole; on top of that, the gateway refuses
//     (fails closed) if any row it would return to a real_only owner is not
//     classified 'real'. So real_only owners get EXCLUSION, everyone gets TAGS.
//     Row-level exclusion by source_system isn't possible here: series_bucketed
//     and daily_derived return aggregates with no source_system per row.
//   * total_count / truncated: how many rows the same filters match under the
//     same RLS identity, next to how many were returned.
//
// The text content is runTool()'s output byte for byte plus one appended
// "[gateway]" line; the tags and counts are also in MCP structuredContent.
// Parity tests compare the text minus that line against the chat path.
import { currentToolVintage, type DomainReality, type ToolResult, vesselFilters } from "../chat/tools.ts";
import { resolveDateBounds } from "../chat/query-rules.ts";

export const DATA_TOOLS: readonly string[] = ["get_series", "get_derived_series", "get_anomalies", "get_vessels"];

// The current vintage comes from chat/tools.ts's currentToolVintage() (the
// harvest-year rule, _shared/vintage.ts) -- get_anomalies' default vintage.

// Mirrors chat/tools.ts's RULE_METRIC_DOMAIN exactly (anomaly metric_key ->
// domain_reality() domain); scripts/check-mcp-boundaries.mjs fails if the two
// ever differ.
export const RULE_METRIC_DOMAIN: Readonly<Record<string, string>> = {
  air_temp: "air_temp", dtr: "dtr_f", humidity: "humidity", soil_moisture: "soil_moisture",
  vpd: "vpd_kpa", vpd_peak: "vpd_peak_kpa", wind_speed: "wind_speed",
  gdd: "gdd_cumulative_calibrated", et0: "et0_in",
};
const DERIVED_FIELDS = ["gdd_cumulative_calibrated", "dtr_f", "vpd_kpa", "vpd_peak_kpa", "et0_in"];

export const GATEWAY_NOTE_PREFIX = "\n\n[gateway] ";

export interface GatewayResult extends ToolResult {
  structuredContent?: Record<string, unknown>;
}

interface ToolDef {
  name: string;
  description?: string;
  input_schema: { type: "object"; properties?: Record<string, { type?: string; enum?: unknown[]; description?: string }>; required?: string[] };
}

// The schema the gateway exposes: identical to chat's, except that
// get_anomalies' as_of is required.
export function gatewayToolDef<T extends ToolDef>(t: T): T {
  if (t.name !== "get_anomalies") return t;
  const props = { ...(t.input_schema.properties ?? {}) };
  props.as_of = { ...(props.as_of ?? { type: "string" }), description: "REQUIRED through the gateway: ISO 8601 instant to evaluate as of (the in-app default is a frozen demo date)." };
  return { ...t, input_schema: { ...t.input_schema, properties: props, required: [...new Set([...(t.input_schema.required ?? []), "as_of"])] } };
}

// chat tools return JSON.stringify(value), optionally followed by "\n\n" and
// plain-text notes. Returns the parsed value and the notes, or null.
export function splitToolContent(content: string): { json: unknown; notes: string } | null {
  try { return { json: JSON.parse(content), notes: "" }; } catch { /* has notes */ }
  for (let i = content.indexOf("\n\n"); i >= 0; i = content.indexOf("\n\n", i + 1)) {
    try { return { json: JSON.parse(content.slice(0, i)), notes: content.slice(i) }; } catch { /* keep looking */ }
  }
  return null;
}

type Status = "real" | "mock" | "unknown";
const isReal = (reality: DomainReality, domain: string | undefined, vintage: number): Status =>
  !domain || !reality.has(domain) ? "unknown" : reality.get(domain)!.has(vintage) ? "real" : "mock";

// deno-lint-ignore no-explicit-any
function statusOf(name: string, row: any, input: Record<string, unknown>, reality: DomainReality): Status {
  switch (name) {
    case "get_series": {
      const vintage = typeof input.vintage === "number" ? input.vintage : new Date(row.t).getUTCFullYear();
      return isReal(reality, String(input.metric), vintage);
    }
    case "get_derived_series":
    {
      const each = DERIVED_FIELDS.map((f) => isReal(reality, f, Number(input.vintage)));
      return each.includes("unknown") ? "unknown" : each.every((x) => x === "real") ? "real" : "mock";
    }
    case "get_anomalies":
      return isReal(reality, RULE_METRIC_DOMAIN[row.metric_key], typeof input.vintage === "number" ? input.vintage : currentToolVintage());
    case "get_vessels":
      return isReal(reality, "vessels", currentToolVintage());
    default:
      return "unknown";
  }
}

export type Count = (sql: string, params: unknown[]) => Promise<number>;

// Rows the tool's own filters match (under the caller's RLS), ignoring its row
// cap. Mirrors the filters in chat/tools.ts getDerivedSeries/getVessels (params
// untyped so Postgres casts them to the column's type, as PostgREST does) by
// calling the SAME helpers chat uses -- resolveDateBounds() for the bare-date
// rule, vesselFilters() for case/whitespace normalisation -- so the two can't
// drift (they did: a bare end_date was `day <= D` here too). The other two
// tools can't truncate (get_series rejects >500 buckets instead,
// get_anomalies has no cap), so their total is what they returned.
async function totalCount(name: string, input: Record<string, unknown>, returned: number, count: Count): Promise<number> {
  if (name === "get_derived_series") {
    const where = ["vintage = $1"];
    const params: unknown[] = [String(input.vintage)];
    const b = resolveDateBounds("day", input.start_date, input.end_date, "wallclock");
    if (b.gte) { params.push(b.gte); where.push(`day >= $${params.length}`); }
    if (b.lt) { params.push(b.lt); where.push(`day < $${params.length}`); }
    if (b.lte) { params.push(b.lte); where.push(`day <= $${params.length}`); }
    return await count(`select count(*)::int as n from public.daily_derived where ${where.join(" and ")}`, params);
  }
  if (name === "get_vessels") {
    const where: string[] = [];
    const params: unknown[] = [];
    const f = vesselFilters(input);
    if (!input.include_archived) where.push("archived = false");
    if (f.vessel_type) { params.push(f.vessel_type); where.push(`vessel_type = $${params.length}`); }
    if (f.current_lot_name) { params.push(`%${f.current_lot_name}%`.replace(/\*/g, "%")); where.push(`current_lot_name ilike $${params.length}`); }
    return await count(`select count(*)::int as n from public.vessels${where.length ? ` where ${where.join(" and ")}` : ""}`, params);
  }
  return returned;
}

export async function runDataTool(
  name: string,
  input: Record<string, unknown>,
  run: () => Promise<ToolResult>,
  ctx: { dataMode: string; reality: DomainReality; count: Count },
): Promise<GatewayResult> {
  if (name === "get_anomalies" && (typeof input.as_of !== "string" || Number.isNaN(Date.parse(input.as_of)))) {
    return { content: "as_of is required through the gateway: pass an ISO 8601 instant (e.g. 2024-07-06T02:00:00Z). The in-app default is a frozen demo date and is not used here.", isError: true };
  }
  const result = await run();
  if (result.isError) return result;
  const split = splitToolContent(result.content);
  if (!split) return { content: "The gateway could not read this tool's result.", isError: true };

  // deno-lint-ignore no-explicit-any
  const blocked = split.json && !Array.isArray(split.json) && (split.json as any).real_only_mode_blocked === true;
  if (blocked) {
    return {
      content: `${result.content}${GATEWAY_NOTE_PREFIX}withheld whole by real-only mode; total_count: 0 (0 returned).`,
      isError: false,
      structuredContent: { tool: name, rows: [], returned_count: 0, total_count: 0, truncated: false, real_only_mode_blocked: true },
    };
  }
  if (!Array.isArray(split.json)) return { content: "The gateway could not read this tool's result.", isError: true };

  const rows = split.json.map((row) => ({ ...row, data_status: statusOf(name, row, input, ctx.reality) }));
  const mock = rows.filter((r) => r.data_status === "mock").length;
  const unknown = rows.filter((r) => r.data_status === "unknown").length;
  if (ctx.dataMode === "real_only" && mock + unknown > 0) {
    return { content: `Refused by the gateway: ${mock + unknown} row(s) not classified real would have reached a real-only account.`, isError: true };
  }
  const total = await totalCount(name, input, rows.length, ctx.count);
  const truncated = total > rows.length;
  const real = rows.length - mock - unknown;
  const statusText = rows.length === 0 ? "no rows"
    : real === rows.length ? "every row real"
    : mock === rows.length ? "every row simulated (mock)"
    : `${real} real, ${mock} simulated (mock)${unknown ? `, ${unknown} unclassified (unknown)` : ""} -- see each row's data_status`;
  return {
    content: `${result.content}${GATEWAY_NOTE_PREFIX}data_status: ${statusText}; total_count: ${total} (${rows.length} returned${truncated ? ", TRUNCATED -- narrow the filters" : ""}).`,
    isError: false,
    structuredContent: {
      tool: name, rows, returned_count: rows.length, total_count: total, truncated, data_status_source: "domain_reality()",
      // The vintage actually evaluated (get_anomalies defaults to the current
      // one) -- P3 compares it with the harvest-year rule.
      ...(name === "get_anomalies" ? { vintage_used: typeof input.vintage === "number" ? input.vintage : currentToolVintage() } : {}),
    },
  };
}
