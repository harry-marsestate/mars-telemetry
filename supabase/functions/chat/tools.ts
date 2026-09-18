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

// real-only-data-mode project (2026-09-13): every vintage this app knows
// about, mirroring web/index.html's own VINTAGES constant -- used to
// bulk-fetch domain_reality() once per chat request (see index.ts),
// covering every vintage a tool call could plausibly ask about.
export const ALL_VINTAGES = [2022, 2023, 2024, 2025, 2026];

// domain -> Set<real vintage>, built from domain_reality() -- the SAME
// server-side RPC web/index.html calls (see
// supabase/migrations/20260913150000_real_only_data_mode.sql), so this
// file and the frontend share one source of truth for "is X real" rather
// than maintaining a second, independent classification here.
export type DomainReality = Map<string, Set<number>>;

// deno-lint-ignore no-explicit-any
export async function fetchDomainReality(supabase: any, vintages: number[] = ALL_VINTAGES): Promise<DomainReality> {
  const { data, error } = await supabase.rpc("domain_reality", { p_vintages: vintages });
  if (error) {
    console.error("chat: domain_reality failed, real-only gating disabled this request", error);
    return new Map();
  }
  const byDomain: DomainReality = new Map();
  // deno-lint-ignore no-explicit-any
  (data as any[] ?? []).forEach((row) => {
    if (!byDomain.has(row.domain)) byDomain.set(row.domain, new Set());
    if (row.is_real) byDomain.get(row.domain)!.add(row.vintage);
  });
  return byDomain;
}

function isDomainReal(reality: DomainReality, domain: string, vintage: number): boolean {
  // Fails open (real=true) on a domain domain_reality() doesn't know
  // about, or when the RPC itself failed above -- same "don't silently
  // hide data from an 'all'-mode account" convention web/index.html's
  // isDomainReal() uses. A real-only account only loses gating for that
  // one request in a genuine RPC failure, never the reverse.
  return reality.get(domain)?.has(vintage) ?? true;
}

// The distinct, non-error result shape every gated tool returns instead
// of the actual (simulated) data, when real-only mode blocks a request --
// isError:false is deliberate: this isn't a query failure, it's a
// legitimate answer ("this exists, but it's simulated, and this account
// can't see simulated data"), and the model needs to explain it as such
// rather than reporting an error or claiming no data exists. See
// buildSystemPrompt()'s real-only-mode note in index.ts for how the
// model is told to read this field.
function realOnlyBlockedResult(description: string): ToolResult {
  return {
    content: JSON.stringify({
      real_only_mode_blocked: true,
      message: `This account is set to real-data-only mode. ${description} is simulated, not real, so it has been withheld rather than returned.`,
    }),
    isError: false,
  };
}

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
      "Real derived daily climate metrics for a vintage: cumulative growing degree days (gdd_cumulative_calibrated -- calibrated per-vintage against the Napa Valley Grapegrowers Growing Conditions Report figures for Angwin, and the authoritative GDD figure to quote), average-based vapor pressure deficit (vpd_kpa), peak-hour vapor pressure deficit (vpd_peak_kpa), uncalibrated diurnal temperature range (dtr_f), and reference evapotranspiration (et0_in). One row per day. Defaults to the current 2026 vintage's live-to-date range if start_date/end_date are omitted.",
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
      "Real vineyard labor hours and cost per operation category and vintage (e.g. Canopy Management, Irrigation, Harvest), sourced from actual Silverado hours invoices (2023, 2024) and the Mars Invoice Backup (2026, ingested month by month as new invoices arrive). No block dimension -- the source records are job-category/task/role, not per-block. Returns labor_cost and expense_cost SEPARATELY (some categories -- Fertilize, Disease Control, Irrigation, Other -- also carry folded-in invoice expenses that have cost but no hours); cost_per_hour is computed from labor_cost only, never the combined total. Coverage is uneven and NOT comparable across vintages: 2023 covers May-Dec (8 months), 2024 covers the full Jan-Dec season, 2026 is a partial, still-growing season -- the exact month range is NOT fixed here, always read it from this tool's own returned Coverage note rather than assuming a specific month or month count. 2022 and 2025 have no labour records of any kind -- returns empty for them, not simulated data. Pass period_month to scope the answer to ONE specific calendar month (e.g. 'what did we spend in August specifically') instead of the whole vintage -- without it, results are summed across every month on file for that vintage, which is almost certainly NOT what a month-specific question wants. Operator access only -- returns no rows for customer or pending accounts.",
    input_schema: {
      type: "object",
      properties: {
        vintage: { type: "integer", description: "Year, e.g. 2024." },
        job_category: { type: "string", description: "Partial match on operation category, e.g. 'Canopy' or 'Harvest'." },
        period_month: { type: "string", description: "Optional. Scopes the result to one calendar month instead of the whole vintage, format 'YYYY-MM' (e.g. '2026-08' for August 2026). When given, returned totals cover ONLY that month -- read this tool's Coverage note either way, since a month with no records returns empty plus that vintage's real range, not an error." },
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

// dataMode/domainReality: real-only-data-mode project (2026-09-13).
// Resolved ONCE per chat request in index.ts (not per tool call) and
// threaded through here -- domain_reality() is cheap but there's no
// reason to re-fetch it on every tool invocation within one turn, same
// "once per request/session, not per call" convention
// refreshRealClimateVintages()/refreshDataMode() already use client-side.
// deno-lint-ignore no-explicit-any
export async function runTool(
  supabase: any,
  name: string,
  input: Record<string, unknown>,
  dataMode: string,
  domainReality: DomainReality,
): Promise<ToolResult> {
  try {
    switch (name) {
      case "get_series":
        return await getSeries(supabase, input, dataMode, domainReality);
      case "get_derived_series":
        return await getDerivedSeries(supabase, input, dataMode, domainReality);
      case "get_anomalies":
        return await getAnomalies(supabase, input, dataMode, domainReality);
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
async function getSeries(supabase: any, input: Record<string, unknown>, dataMode: string, domainReality: DomainReality): Promise<ToolResult> {
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

  // Real-only-data-mode gate (2026-09-13). No explicit `vintage` param
  // doesn't mean "no vintage" -- start/end are real calendar timestamps,
  // so the vintage(s) touched are derived from their years. Checks EVERY
  // year the requested range spans (usually one, since a growing season
  // runs Apr-Oct within a single calendar year) -- if real-only mode is
  // on and ANY touched year is simulated for this metric, the whole
  // request is blocked rather than silently returning a partial series.
  if (dataMode === "real_only") {
    const years = vintage != null
      ? [vintage]
      : Array.from(
        { length: new Date(endMs).getUTCFullYear() - new Date(startMs).getUTCFullYear() + 1 },
        (_, i) => new Date(startMs).getUTCFullYear() + i,
      );
    const simulatedYears = years.filter((y) => !isDomainReal(domainReality, metric, y));
    if (simulatedYears.length) {
      return realOnlyBlockedResult(`${metric} for ${simulatedYears.join(", ")}`);
    }
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
  // series_bucketed's avg/sum aggregation returns full double precision
  // (e.g. 18.383333333333333) -- measured live, this alone accounts for a
  // meaningful share of a series call's token cost with zero benefit to the
  // model, which never needs more than display-grade precision to compare
  // buckets. Round to 2dp, matching this app's own fmt() display convention.
  // deno-lint-ignore no-explicit-any
  const rounded = (data as any[])?.map((row) => ({ ...row, v: row.v == null ? null : Math.round(row.v * 100) / 100 }));
  return { content: JSON.stringify(rounded), isError: false };
}

// deno-lint-ignore no-explicit-any
async function getDerivedSeries(supabase: any, input: Record<string, unknown>, dataMode: string, domainReality: DomainReality): Promise<ToolResult> {
  const { vintage, start_date, end_date } = input as { vintage: number; start_date?: string; end_date?: string };

  // Real-only-data-mode gate (2026-09-13). All five fields are checked
  // (not just gdd) since they're each independently classified by
  // domain_reality() -- gdd_cumulative_calibrated/dtr_f depend on
  // air_temp only, vpd_kpa/vpd_peak_kpa on air_temp AND humidity, et0_in
  // on air_temp only. All five happen to share the same real/mock status
  // per vintage today (their raw inputs move in lockstep), but this
  // doesn't assume that stays true. Whole-response block, not a per-
  // field strip -- matches web/index.html's own whole-panel granularity
  // rather than returning a JSON row array with some columns silently
  // missing.
  if (dataMode === "real_only") {
    const fields = ["gdd_cumulative_calibrated", "dtr_f", "vpd_kpa", "vpd_peak_kpa", "et0_in"];
    const simulatedFields = fields.filter((f) => !isDomainReal(domainReality, f, vintage));
    if (simulatedFields.length) {
      return realOnlyBlockedResult(`${simulatedFields.join(", ")} for ${vintage}`);
    }
  }

  let query = supabase
    .from("daily_derived")
    // gdd_cumulative_calibrated, NOT gdd_cumulative -- the raw column is the
    // uncorrected Open-Meteo sum and understates this site's real heat
    // accumulation (2023: 2853.5 raw vs 3576.0 calibrated, the latter exactly
    // matching the published Grapegrowers Angwin total). The chat was
    // reporting the raw figure as authoritative. dtr_f deliberately stays
    // raw, matching the dashboard -- see docs/SECURITY.md.
    .select("day, gdd_cumulative_calibrated, dtr_f, vpd_kpa, vpd_peak_kpa, et0_in")
    .eq("vintage", vintage)
    .order("day", { ascending: true })
    .limit(400);
  if (start_date) query = query.gte("day", start_date);
  if (end_date) query = query.lte("day", end_date);

  const { data, error } = await query;
  if (error) return formatErrorForModel(error);
  // Measured live: dtr_f/vpd_kpa/vpd_peak_kpa/et0_in come back at full double
  // precision (e.g. vpd_kpa: 0.2012390913710435). A single vintage's ~214-row
  // response is ~35KB, so a two-vintage comparison (2 calls in one turn) sent
  // ~43K input tokens and a four-vintage one ~86K -- the single largest
  // input-token cost in the tool set, and since input dominates this route's
  // bill, its largest cost lever too. Rounding cut two-vintage input by a
  // measured 14.2% (43,124 -> 36,987 tokens avg) at zero cost to the answers.
  // It is NOT a truncation fix and was measured not to be one: with rounding
  // alone at the old 2048 ceiling, 4/5 trials still hit max_tokens and 3/5
  // still returned blank -- see index.ts's `effort` comment for what actually
  // fixed that.
  //
  // gdd_cumulative_calibrated IS rounded here, unlike the raw gdd_cumulative
  // it replaced. The old comment said GDD was "already a clean running total"
  // and skipped it -- true of the raw sum (2853.4500000000000000) but NOT of
  // the calibrated column, which multiplies through a 6-decimal per-vintage
  // scalar and arrives as 3576.0006090000000000000000: 27 chars vs 21, ~26%
  // wider, on ~214 rows per vintage per call. 1dp keeps the exact
  // Grapegrowers match legible (3576.0) at a fraction of the tokens.
  // deno-lint-ignore no-explicit-any
  const rounded = (data as any[])?.map((row) => ({
    ...row,
    gdd_cumulative_calibrated: row.gdd_cumulative_calibrated == null
      ? null
      : Math.round(row.gdd_cumulative_calibrated * 10) / 10,
    dtr_f: row.dtr_f == null ? null : Math.round(row.dtr_f * 100) / 100,
    vpd_kpa: row.vpd_kpa == null ? null : Math.round(row.vpd_kpa * 100) / 100,
    vpd_peak_kpa: row.vpd_peak_kpa == null ? null : Math.round(row.vpd_peak_kpa * 100) / 100,
    et0_in: row.et0_in == null ? null : Math.round(row.et0_in * 1000) / 1000,
  }));
  return { content: JSON.stringify(rounded), isError: false };
}

// This tool never passes p_tab, so anomalies_eval() always runs its
// default 'vineyard' rule set -- these are exactly that rule set's
// metric_key values (see supabase/migrations/20260831000001_anomalies_eval_materialized_cte.sql's
// anomaly_thresholds join), bridged to domain_reality()'s domain names.
// Mirrors web/index.html's renderAnomalies() RULE_METRIC_DOMAIN exactly
// -- same reasoning: anomalies_eval()'s rule set isn't filtered upstream
// (wind_high is data_status='real' in anomaly_thresholds but confirmed
// 100% mock; see docs/SECURITY.md), so hits are filtered here, per-row,
// by metric_key, rather than blocking the whole tool.
const RULE_METRIC_DOMAIN: Record<string, string> = {
  air_temp: "air_temp", dtr: "dtr_f", humidity: "humidity", soil_moisture: "soil_moisture",
  vpd: "vpd_kpa", vpd_peak: "vpd_peak_kpa", wind_speed: "wind_speed",
  gdd: "gdd_cumulative_calibrated", et0: "et0_in",
};

// deno-lint-ignore no-explicit-any
async function getAnomalies(supabase: any, input: Record<string, unknown>, dataMode: string, domainReality: DomainReality): Promise<ToolResult> {
  const { vintage, as_of } = input as { vintage?: number; as_of?: string };
  const p_vintage = vintage ?? CURRENT_VINTAGE;
  const p_as_of = as_of ?? (p_vintage === CURRENT_VINTAGE ? MOCK_NOW : `${p_vintage}-12-31T23:59:59Z`);

  const { data, error } = await supabase.rpc("anomalies_eval", { p_vintage, p_as_of });
  if (error) return formatErrorForModel(error);
  // deno-lint-ignore no-explicit-any
  let rows = data as any[];
  let filteredNote = "";
  if (dataMode === "real_only") {
    const before = rows.length;
    rows = rows.filter((row) => {
      const domain = RULE_METRIC_DOMAIN[row.metric_key];
      return !domain || isDomainReal(domainReality, domain, p_vintage);
    });
    if (rows.length < before) {
      filteredNote = `\n\n(${before - rows.length} rule${before - rows.length === 1 ? "" : "s"} omitted: this account is real-only and that data is simulated for ${p_vintage}.)`;
    }
  }
  return { content: JSON.stringify(rows) + filteredNote, isError: false };
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

const MONTH_NAMES = ["January","February","March","April","May","June","July","August","September","October","November","December"];
// first_month/last_month/period_month are each the 1ST OF that calendar
// month (e.g. 2026-08-01 means "the month of August", not "August 1st" as
// a cutoff). Spelling a date out as a bare ISO string joined by "to"/"for"
// reads to a model like a narrow day-precision span, which produced a
// real, observed wrong answer during the August 2026 labour round: Kimi
// (and, checked side by side, Sonnet 5 too -- not a Kimi-specific
// weakness) read a genuine 2-month (Jul+Aug) coverage note as "a single
// July window" and claimed August data didn't exist yet, despite the same
// tool result's own rows already including it. Every place that reports a
// month back to the model -- the vintage-range note below AND the new
// single-month note in the period_month branch -- goes through this same
// helper so neither path can reintroduce that bug independently.
function monthLabel(isoDate: string): string {
  const [y, m] = isoDate.split("-");
  return `${MONTH_NAMES[Number(m) - 1]} ${y}`;
}

// Real-labour-ingestion project (2026-09-14): labour_summary/work_events
// (100% simulated) are gone entirely, replaced by labour_actuals. No
// real_only-mode gate here anymore -- unlike every other gated tool,
// there is no simulated version of this data left to withhold. 2022/2025
// genuinely have no labour records (never real, never mocked) and that's
// true regardless of dataMode, so it falls out of the query naturally
// (empty result + the coverage note below) rather than needing a block.
//
// Monthly-granularity project (2026-09-18): period_month was already a
// correct, row-level column on labour_actuals for every source ingested
// so far -- see docs/SECURITY.md's investigation entry -- so this adds a
// query path onto the new labour_actuals_by_month view (additive sibling
// to labour_actuals_by_category, same migration round) rather than
// changing any schema. Omitting period_month must behave EXACTLY as
// before this change -- that's the regression risk, guarded by keeping
// the original vintage/category query and coverage-note logic completely
// untouched in its own branch below, not restructured or merged with the
// new one.
// deno-lint-ignore no-explicit-any
async function getLabourSummary(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { vintage, job_category, period_month: periodMonthInput } = input as {
    vintage?: number; job_category?: string; period_month?: string;
  };

  // Accepts 'YYYY-MM' (e.g. '2026-08', the documented format) and also
  // tolerates a full 'YYYY-MM-DD' (a model sometimes passes a complete
  // date despite the schema asking for year-month only) -- the day part,
  // if present, is ignored, since every row's own period_month is already
  // normalized to the 1st. Anything else is treated the same as omitted
  // (falls through to the unfiltered vintage/category path) rather than
  // raising a validation error -- consistent with this tool's existing
  // style of never special-casing bad input.
  const periodMonthMatch = typeof periodMonthInput === "string" ? periodMonthInput.match(/^(\d{4})-(\d{2})(?:-\d{2})?$/) : null;
  const periodMonth = periodMonthMatch ? `${periodMonthMatch[1]}-${periodMonthMatch[2]}-01` : null;

  if (periodMonth) {
    let query = supabase
      .from("labour_actuals_by_month")
      .select("vintage, period_month, job_category, labor_hours, labor_cost, expense_cost, total_cost, cost_per_hour")
      .eq("period_month", periodMonth)
      .limit(500);
    if (vintage) query = query.eq("vintage", vintage);
    if (job_category) query = query.ilike("job_category", `%${job_category}%`);

    const { data, error } = await query;
    if (error) return formatErrorForModel(error);

    const label = monthLabel(periodMonth);
    let note: string;
    if ((data ?? []).length > 0) {
      // Scoped to THIS month, not the full vintage -- says so explicitly
      // so the model doesn't need to infer scope from the row shape alone.
      note = `\n\nCoverage: this result is scoped to ${label} only, not the full vintage -- ${data.length} job categor${data.length === 1 ? "y" : "ies"} with labour records that month.`;
    } else {
      // No rows for this specific month -- say so plainly (matching the
      // existing "not simulated, genuinely absent" framing below) and give
      // the vintage's real coverage range as context rather than a bare
      // zero, reusing the same month-name/inclusive phrasing.
      const impliedVintage = vintage ?? Number(periodMonth.slice(0, 4));
      const { data: cov } = await supabase
        .from("labour_vintage_coverage")
        .select("first_month, last_month, month_count")
        .eq("vintage", impliedVintage)
        .maybeSingle();
      const rangeNote = cov
        ? ` This vintage's actual coverage is ${cov.first_month === cov.last_month ? monthLabel(cov.first_month) : `${monthLabel(cov.first_month)} through ${monthLabel(cov.last_month)} INCLUSIVE`} (${cov.month_count} of 12 months).`
        : ` No labour records exist for vintage ${impliedVintage} at all -- not simulated, genuinely absent.`;
      note = `\n\nNo labour records exist for ${label} specifically.${rangeNote}`;
    }
    return { content: JSON.stringify(data) + note, isError: false };
  }

  // Unchanged from before period_month existed -- same query, same
  // coverage-note construction, byte-for-byte, so a caller that never
  // passes period_month sees identical behavior to the round-4 verified
  // response.
  let query = supabase
    .from("labour_actuals_by_category")
    .select("vintage, job_category, labor_hours, labor_cost, expense_cost, total_cost, cost_per_hour")
    .limit(500);
  if (vintage) query = query.eq("vintage", vintage);
  if (job_category) query = query.ilike("job_category", `%${job_category}%`);

  const { data, error } = await query;
  if (error) return formatErrorForModel(error);

  // Coverage caveat, per vintage actually present in the result -- the
  // model has no other way to know 2024's total is a full season while
  // 2026's is a couple of months, and get_labour_summary's own description
  // can't carry a caveat this specific to the rows actually returned.
  // deno-lint-ignore no-explicit-any
  const vintagesInResult = [...new Set((data ?? []).map((r: any) => r.vintage))] as number[];
  const coverageNotes: string[] = [];
  for (const v of vintagesInResult) {
    const { data: cov } = await supabase
      .from("labour_vintage_coverage")
      .select("first_month, last_month, month_count")
      .eq("vintage", v)
      .maybeSingle();
    if (cov) {
      const span = cov.first_month === cov.last_month
        ? monthLabel(cov.first_month)
        : `${monthLabel(cov.first_month)} through ${monthLabel(cov.last_month)} INCLUSIVE (both calendar months have real data, not just their first day)`;
      const partial = cov.month_count < 12
        ? " -- NOT a full season, do not compare this vintage's raw totals to a full-year vintage"
        : "";
      coverageNotes.push(`${v}: ${span} -- ${cov.month_count} distinct calendar month(s) of data out of 12${partial}`);
    }
  }
  const note = coverageNotes.length
    ? `\n\nCoverage: ${coverageNotes.join("; ")}.`
    : (vintage ? `\n\nNo labour records exist for ${vintage} -- not simulated, genuinely absent.` : "");
  return { content: JSON.stringify(data) + note, isError: false };
}
