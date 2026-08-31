import type Anthropic from "@anthropic-ai/sdk";

// series_bucketed's own aggregation is bounded by the caller's date range
// and bucket size, not by a fixed row limit -- a wide range with a tiny
// bucket can generate an enormous series. Reject before calling the RPC.
const MAX_SERIES_BUCKETS = 500;

const CURRENT_VINTAGE = 2026;
// Mirrors web/index.html's MOCK_NOW -- the app anchors "current" to this
// simulated timestamp, not the real wall clock, since real ingestion only
// covers data up to this point. Keep in sync with web/index.html's own
// MOCK_NOW until the Phase 7 TODO to remove the override is done.
const MOCK_NOW = "2026-07-28T14:20:00-07:00";

export const TOOLS: Anthropic.Tool[] = [
  {
    name: "get_series",
    description:
      "Time-bucketed real IoT sensor readings for vineyard blocks (air_temp, soil_moisture, soil_temp, humidity, wind, etc.). Averages (or sums, for precipitation/irrigation) readings into buckets across a time range. Block-scoped: a customer only sees blocks they have access to; RLS silently returns no data for inaccessible blocks rather than erroring.",
    input_schema: {
      type: "object",
      properties: {
        metric: { type: "string", description: "Metric key, e.g. 'air_temp', 'soil_moisture', 'soil_temp', 'humidity', 'wind_speed', 'precip'." },
        block: { type: "string", description: "Block id, e.g. 'B1'. Omit for all accessible blocks." },
        vintage: { type: "integer", description: "Year, e.g. 2026. Omit for all vintages." },
        start: { type: "string", description: "ISO 8601 start timestamp." },
        end: { type: "string", description: "ISO 8601 end timestamp." },
        bucket_hours: { type: "number", description: "Bucket width in hours, e.g. 1 for hourly, 24 for daily." },
        agg: { type: "string", enum: ["avg", "sum"], description: "Aggregation within each bucket. Use 'sum' for precip/irrigation volume, 'avg' otherwise." },
      },
      required: ["metric", "start", "end", "bucket_hours"],
    },
  },
  {
    name: "get_derived_series",
    description:
      "Real derived daily climate metrics for a vintage: growing degree days (gdd_cumulative), average-based vapor pressure deficit (vpd_kpa), peak-hour vapor pressure deficit (vpd_peak_kpa), diurnal temperature range (dtr_f), and reference evapotranspiration (et0_in). One row per day. Defaults to the current 2026 vintage's live-to-date range if start_date/end_date are omitted.",
    input_schema: {
      type: "object",
      properties: {
        vintage: { type: "integer", description: "Year, e.g. 2026." },
        start_date: { type: "string", description: "ISO date, e.g. '2026-04-01'. Defaults to the start of the growing season." },
        end_date: { type: "string", description: "ISO date. Defaults to today for the current vintage (2026-07-28), or end of season for an archived vintage." },
      },
      required: ["vintage"],
    },
  },
  {
    name: "get_anomalies",
    description:
      "Real-time evaluation of vineyard anomaly rules (soil moisture, DTR, VPD, humidity, wind) against current sensor and climate data, as of a given snapshot. Only vineyard-tab rules are wired to real data; winery/tank anomalies are not covered by this tool. Defaults to the current 2026 vintage as of the app's live snapshot date (2026-07-28) -- pass vintage/as_of explicitly to check an archived vintage (e.g. 'were there issues in 2022?').",
    input_schema: {
      type: "object",
      properties: {
        vintage: { type: "integer", description: "Year to evaluate. Defaults to the current vintage (2026)." },
        as_of: { type: "string", description: "ISO 8601 timestamp to evaluate as of. Defaults to the current live snapshot for the current vintage, or end-of-year for an archived vintage." },
      },
      required: [],
    },
  },
  {
    name: "get_lot_analyses",
    description:
      "Real winery lab analysis data per fermentation lot (Brix, pH, TA, and other chemistry), sourced from InnoVint. Operator access only -- returns no rows for customer or pending accounts. Returns at most 200 rows, most recent first; narrow with lot_name/analysis_type/date range for a specific question rather than relying on the default limit.",
    input_schema: {
      type: "object",
      properties: {
        lot_name: { type: "string", description: "Partial lot name match, e.g. 'Zinfandel'." },
        analysis_type: { type: "string", description: "Exact analysis type, e.g. 'brix', 'ph', 'ta'." },
        start_date: { type: "string", description: "ISO date lower bound on recorded_at." },
        end_date: { type: "string", description: "ISO date upper bound on recorded_at." },
        limit: { type: "integer", description: "Max rows to return, default 50, max 200." },
      },
      required: [],
    },
  },
  {
    name: "get_vessels",
    description:
      "Real winery tank/vessel inventory: type, capacity, current fill volume, and current lot assignment, sourced from InnoVint. Operator access only -- returns no rows for customer or pending accounts.",
    input_schema: {
      type: "object",
      properties: {
        vessel_type: { type: "string", description: "Filter by vessel type." },
        current_lot_name: { type: "string", description: "Partial match on the lot currently assigned to the vessel." },
        include_archived: { type: "boolean", description: "Include archived/decommissioned vessels. Default false." },
      },
      required: [],
    },
  },
  {
    name: "get_labour_summary",
    description:
      "Real vineyard labor hours and cost per block/work-type/vintage (e.g. harvest, leafing, pruning), sourced from actual work records. Operator access only -- returns no rows for customer or pending accounts.",
    input_schema: {
      type: "object",
      properties: {
        vintage: { type: "integer", description: "Year, e.g. 2026." },
        block_id: { type: "string", description: "Block id, e.g. 'B1'." },
      },
      required: [],
    },
  },
];

export interface ToolResult {
  content: string;
  isError: boolean;
}

function formatErrorForModel(error: { message: string }): ToolResult {
  return { content: `Query failed: ${error.message}`, isError: true };
}

// deno-lint-ignore no-explicit-any
export async function runTool(supabase: any, name: string, input: Record<string, unknown>): Promise<ToolResult> {
  try {
    switch (name) {
      case "get_series":
        return await getSeries(supabase, input);
      case "get_derived_series":
        return await getDerivedSeries(supabase, input);
      case "get_anomalies":
        return await getAnomalies(supabase, input);
      case "get_lot_analyses":
        return await getLotAnalyses(supabase, input);
      case "get_vessels":
        return await getVessels(supabase, input);
      case "get_labour_summary":
        return await getLabourSummary(supabase, input);
      default:
        return { content: `Unknown tool: ${name}`, isError: true };
    }
  } catch (err) {
    console.error(`chat: tool ${name} failed`, err);
    return { content: "Tool execution failed unexpectedly.", isError: true };
  }
}

// deno-lint-ignore no-explicit-any
async function getSeries(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { metric, block, vintage, start, end, bucket_hours, agg } = input as {
    metric: string; block?: string; vintage?: number; start: string; end: string; bucket_hours: number; agg?: string;
  };

  const startMs = Date.parse(start);
  const endMs = Date.parse(end);
  if (Number.isNaN(startMs) || Number.isNaN(endMs) || endMs <= startMs) {
    return { content: "Invalid or empty time range: 'end' must be after 'start'.", isError: true };
  }
  if (!(bucket_hours > 0)) {
    return { content: "bucket_hours must be a positive number.", isError: true };
  }
  const bucketCount = (endMs - startMs) / (bucket_hours * 3600_000);
  if (bucketCount > MAX_SERIES_BUCKETS) {
    return {
      content: `Requested range/bucket size would produce ${Math.ceil(bucketCount)} buckets, over the ${MAX_SERIES_BUCKETS} limit. Widen bucket_hours or narrow the time range.`,
      isError: true,
    };
  }

  const { data, error } = await supabase.rpc("series_bucketed", {
    p_metric: metric,
    p_block: block ?? null,
    p_vintage: vintage ?? null,
    p_start: start,
    p_end: end,
    p_bucket: `${bucket_hours} hours`,
    p_agg: agg ?? "avg",
  });
  if (error) return formatErrorForModel(error);
  return { content: JSON.stringify(data), isError: false };
}

// deno-lint-ignore no-explicit-any
async function getDerivedSeries(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { vintage, start_date, end_date } = input as { vintage: number; start_date?: string; end_date?: string };

  let query = supabase
    .from("daily_derived")
    .select("day, gdd_cumulative, dtr_f, vpd_kpa, vpd_peak_kpa, et0_in")
    .eq("vintage", vintage)
    .order("day", { ascending: true })
    .limit(400);
  if (start_date) query = query.gte("day", start_date);
  if (end_date) query = query.lte("day", end_date);

  const { data, error } = await query;
  if (error) return formatErrorForModel(error);
  return { content: JSON.stringify(data), isError: false };
}

// deno-lint-ignore no-explicit-any
async function getAnomalies(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { vintage, as_of } = input as { vintage?: number; as_of?: string };
  const p_vintage = vintage ?? CURRENT_VINTAGE;
  const p_as_of = as_of ?? (p_vintage === CURRENT_VINTAGE ? MOCK_NOW : `${p_vintage}-12-31T23:59:59Z`);

  const { data, error } = await supabase.rpc("anomalies_eval", { p_vintage, p_as_of });
  if (error) return formatErrorForModel(error);
  return { content: JSON.stringify(data), isError: false };
}

// deno-lint-ignore no-explicit-any
async function getLotAnalyses(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { lot_name, analysis_type, start_date, end_date, limit } = input as {
    lot_name?: string; analysis_type?: string; start_date?: string; end_date?: string; limit?: number;
  };
  const cappedLimit = Math.min(limit && limit > 0 ? limit : 50, 200);

  let query = supabase
    .from("lot_analyses")
    .select("lot_name, lot_code, block_id, analysis_type, value, unit, recorded_at")
    .order("recorded_at", { ascending: false })
    .limit(cappedLimit);
  if (lot_name) query = query.ilike("lot_name", `%${lot_name}%`);
  if (analysis_type) query = query.eq("analysis_type", analysis_type);
  if (start_date) query = query.gte("recorded_at", start_date);
  if (end_date) query = query.lte("recorded_at", end_date);

  const { data, error } = await query;
  if (error) return formatErrorForModel(error);
  const truncated = data.length === cappedLimit;
  const note = truncated
    ? `\n\n(Returned the maximum ${cappedLimit} rows -- there may be more. Narrow with lot_name, analysis_type, or a date range if this doesn't cover what you need.)`
    : "";
  return { content: JSON.stringify(data) + note, isError: false };
}

// deno-lint-ignore no-explicit-any
async function getVessels(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { vessel_type, current_lot_name, include_archived } = input as {
    vessel_type?: string; current_lot_name?: string; include_archived?: boolean;
  };

  let query = supabase
    .from("vessels")
    .select("vessel_id, code, vessel_type, capacity_gal, volume_gal, current_lot_name, current_lot_code, block_id, archived")
    .limit(500);
  if (!include_archived) query = query.eq("archived", false);
  if (vessel_type) query = query.eq("vessel_type", vessel_type);
  if (current_lot_name) query = query.ilike("current_lot_name", `%${current_lot_name}%`);

  const { data, error } = await query;
  if (error) return formatErrorForModel(error);
  return { content: JSON.stringify(data), isError: false };
}

// deno-lint-ignore no-explicit-any
async function getLabourSummary(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { vintage, block_id } = input as { vintage?: number; block_id?: string };

  let query = supabase
    .from("labour_summary")
    .select("vintage, block_id, block_label, acres, work_type, total_hours, total_cost, cost_per_acre")
    .limit(500);
  if (vintage) query = query.eq("vintage", vintage);
  if (block_id) query = query.eq("block_id", block_id);

  const { data, error } = await query;
  if (error) return formatErrorForModel(error);
  return { content: JSON.stringify(data), isError: false };
}
