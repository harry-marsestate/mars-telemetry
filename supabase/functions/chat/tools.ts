import { labourResult } from "./labour-totals.ts";
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
      "Real winery lab analysis data per fermentation lot (Brix, pH, TA, and other chemistry), sourced from InnoVint. Operator access only -- returns no rows for customer or pending accounts. Returns at most 200 rows, most recent first; narrow with lot_code/lot_name/analysis_type/date range for a specific question rather than relying on the default limit. InnoVint contains genuine duplicate lot objects for the same physical wine for a few 2023 lots (confirmed: byte-identical chemistry under two or three different lot_codes) -- pass lot_code when you already know it (exact match, unambiguous); a lot_name search (partial match) automatically excludes the known-superseded duplicates and, if it still matches more than one distinct lot_code (e.g. a name that's also a substring of a different vintage's lot name), says so explicitly rather than silently blending them. Querying a superseded lot_code directly still works (its own rows, not redirected) but the result notes which lot_code is canonical.",
    input_schema: {
      type: "object",
      properties: {
        lot_code: { type: "string", description: "Exact lot code, e.g. 'MA23CSV3'. Unambiguous -- prefer this over lot_name when known. Bypasses the duplicate-lot exclusion (an explicit request for a specific code, including a superseded one, is honored as asked)." },
        lot_name: { type: "string", description: "Partial lot name match, e.g. 'Zinfandel'. Known-superseded duplicate lot_codes are excluded automatically." },
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
      "Real vineyard labor hours and cost per operation category and vintage (e.g. Canopy Management, Irrigation, Harvest), sourced from actual Silverado hours invoices (2023, 2024) and the Mars Invoice Backup (2026, ingested month by month as new invoices arrive). No block dimension -- the source records are job-category/task/role, not per-block. Returns labor_cost and expense_cost SEPARATELY (some categories -- Fertilize, Disease Control, Irrigation, Other -- also carry folded-in invoice expenses that have cost but no hours); cost_per_hour is computed from labor_cost only, never the combined total. Coverage is uneven and NOT comparable across vintages: 2023 covers May-Dec (8 months), 2024 covers the full Jan-Dec season, 2026 is a partial, still-growing season -- the exact month range is NOT fixed here, always read it from this tool's own returned Coverage note rather than assuming a specific month or month count. 2022 and 2025 have no labour records of any kind -- returns empty for them, not simulated data. Pass period_month to scope the answer to ONE specific calendar month (e.g. 'what did we spend in August specifically') instead of the whole vintage -- without it, results are summed across every month on file for that vintage, which is almost certainly NOT what a month-specific question wants. Use the supplied totals.display values verbatim for headline totals and the total row; NEVER sum category rows yourself or average category rates. totals contains exact decimal sums; display rounds once to two decimals. Empty categories mean no records, NOT known zero spend. Operator access only -- returns no rows for customer or pending accounts.",
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
  {
    name: "get_berry_maturity",
    description:
      "Real vineyard berry-maturity sampling per block per collection date (brix, pH, titratable acidity, L-malic acid, glucose+fructose, berry weight, berry volume, berry volume variability, sugar per berry), sourced from ETS Labs. Reads berry_maturity_by_block, a view over CURRENT (non-superseded) samples only -- never the raw lab_samples/lab_results tables, which intentionally retain superseded reissue rows. Coverage is UNEVEN and NOT comparable across vintages: 2023 and 2024 each have exactly ONE collection date with only three analytes measured (brix/pH/titratable acidity) -- L-malic acid, glucose+fructose, and the three berry-size analytes are ABSENT those vintages because ETS ran a smaller panel then, not because the fruit had none or measurement failed; do not read those gaps as zero or as a real change in the vineyard. 2026 has the full nine-analyte Dyostem panel across four collection dates through late-season ripening. 2022 has no berry sampling of any kind. 2025 has smoke-taint screening only (see get_smoke_markers), no maturity/ripening panel. Always read this tool's own returned Coverage note rather than assuming a vintage's shape from another vintage's. Deliberately does NOT expose the underlying 20-bin Dyostem berry-size histogram -- that's raw instrument detail with no value in a chat answer; berry_volume_variability_pct already carries the same ripening-uniformity signal as one number. Operator access only (customer/pending accounts get no rows, enforced by the view's own RLS, not an application check here). Never gated by real-only mode -- this data has no simulated counterpart to withhold, same as get_labour_summary.",
    input_schema: {
      type: "object",
      properties: {
        vintage: { type: "integer", description: "Year, e.g. 2026. Omit for all vintages." },
        block_id: { type: "string", description: "Block id, e.g. 'B2' or 'B3'. Omit for all blocks." },
      },
      required: [],
    },
  },
  {
    name: "get_smoke_markers",
    description:
      "Real smoke-taint marker lab results per sample (the nine free volatile phenols -- guaiacol, 4-methylguaiacol, 4-methylsyringol, m-/o-/p-cresol, cresols (sum), phenol, syringol -- plus the six glycosylated conjugate markers of the same compounds), sourced from ETS Labs. Reads lab_results_current, filtered to just these analytes -- never lab_results directly, which intentionally retains superseded reissue rows (confirmed live: querying it directly for this exact data returned every value twice before this fix). Every row carries result_operator ('=' or '<') separately from result_numeric: a '<' row is a detection-limit censored result (e.g. '< 0.5'), and must be reported as below/under that limit, NEVER as a plain measured number. units differ by sample basis and are NEVER interchangeable: µg/kg is berry-mass basis, µg/L is liquid/juice basis -- always quote the unit given with the value, never convert or compare a µg/kg figure to a µg/L one as if equal. Coverage is concentrated in 2025: two berry-mass-basis samples, two juice-basis samples, and one trial micro-ferment (block unresolved -- see this tool's Coverage note). 2022/2023/2024/2026 have no vineyard-side smoke screening on file. Operator access only (RLS-enforced, not an application check). Never gated by real-only mode -- no simulated counterpart exists for this data.",
    input_schema: {
      type: "object",
      properties: {
        vintage: { type: "integer", description: "Year, e.g. 2025. Omit for all vintages." },
        block_id: { type: "string", description: "Block id, e.g. 'B2' or 'B3'. Omit for all blocks -- note the trial micro-ferment sample has no resolved block and is excluded by any block_id filter." },
      },
      required: [],
    },
  },
  {
    name: "get_wine_lab_results",
    description:
      "Real winery lab chemistry from ETS Labs (ethanol, VA, TA, pH, free/total SO2, YAN, ammonia, potassium, malic acid, glucose+fructose, brix, plus specialty QC panels -- microbial safety, heat/cold stability trials, fining trials, conductivity), sourced from the same CSV as get_berry_maturity/get_smoke_markers but covering wine/must/ferment/stability-trial samples instead of vineyard ones. Reads lab_results_current/lab_samples_current only -- never the raw lab_samples/lab_results tables, which intentionally retain superseded reissue rows. sample_description identifies the lot (e.g. 'MA23CS', '25CHMR-LF') -- partial match, and CAUTION: some codes are literal substrings of others in the SAME vintage (e.g. 'MA22CS' also matches 'MA22CSV2' and 'MA22CSV3' -- vintage alone does NOT disambiguate this case, since all three are 2022). The response always states which distinct sample_description values actually matched; read that before assuming a result is about one lot. Every result row carries result_operator ('=' or '<' -- a '<' row is a detection-limit censored result, never report it as a plain number), units, and a reconciliation status against InnoVint's own lot_analyses (lot_match: 'exact' = same lot/date/analyte/value already in lot_analyses, 'value_conflict' = same lot/date/analyte but a DIFFERENT value there, 'date_near' = matched within 3 days not same day, 'ets_only' = no InnoVint counterpart at all -- most rows are 'ets_only', that's expected, not a data quality problem). Date coverage per matched lot is precomputed server-side and spelled out in words in the response -- never infer a lot's date range from counting rows yourself. Operator access only (RLS-enforced). Never gated by real-only mode -- no simulated counterpart exists for this data. Two rows (MA25CH's conductivity-test disclaimer and its Heat Stability Trial protocol note) have result_numeric=null and only a free-text result_raw -- report their content as text, not as a missing number.",
    input_schema: {
      type: "object",
      properties: {
        sample_description: { type: "string", description: "Partial match on the ETS/InnoVint lot code, e.g. 'MA23CS' or '25CHMR-LF'. Omit for all winery samples." },
        vintage: { type: "integer", description: "Year, e.g. 2023. Omit for all vintages." },
        sample_type: { type: "string", enum: ["must", "wine", "ferment", "stability_trial"], description: "Narrow to one sample phase. Omit for all." },
        analysis_code: { type: "string", description: "Exact analysis code, e.g. 'ethanol_at_20c', 'volatile_acidity_acetic_acid', 'ph'." },
        start_date: { type: "string", description: "ISO date lower bound on analyzed_at." },
        end_date: { type: "string", description: "ISO date upper bound on analyzed_at." },
        limit: { type: "integer", description: "Max rows to return, default 100, max 300." },
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
      case "get_berry_maturity":
        return await getBerryMaturity(supabase, input);
      case "get_smoke_markers":
        return await getSmokeMarkers(supabase, input);
      case "get_wine_lab_results":
        return await getWineLabResults(supabase, input);
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

// lot_canonical_map (2026-09-20): InnoVint carries genuine duplicate lot
// objects for the same physical wine for a handful of 2023 lots --
// confirmed live (docs/SECURITY.md), not an ingest bug. lot_name search
// alone returned every duplicate as if it were an independent reading
// (8 real brix readings came back as 24 rows). This function now excludes
// known-superseded lot_codes on the lot_name/unfiltered path, and honors
// an explicit lot_code request as-is (including a superseded one) with a
// note identifying its canonical counterpart.
//
// The superseded-set read below is deliberately fail-CLOSED (an error
// here returns an error to the model, never an empty exclusion list) --
// the opposite of isDomainReal()'s deliberate fail-open elsewhere in this
// file. The risk direction is reversed: isDomainReal() failing open
// protects against hiding real data from an honest account; this read
// failing open would silently let the exact duplication bug this table
// exists to fix reappear, indistinguishable from "no duplicates exist."
// deno-lint-ignore no-explicit-any
async function fetchSupersededLotMap(supabase: any): Promise<{ map: Map<string, string> } | { error: { message: string } }> {
  const { data, error } = await supabase.from("lot_canonical_map").select("duplicate_lot_code, canonical_lot_code");
  if (error) return { error };
  // deno-lint-ignore no-explicit-any
  return { map: new Map((data as any[]).map((r) => [r.duplicate_lot_code, r.canonical_lot_code])) };
}

// deno-lint-ignore no-explicit-any
async function getLotAnalyses(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { lot_code, lot_name, analysis_type, start_date, end_date, limit } = input as {
    lot_code?: string; lot_name?: string; analysis_type?: string; start_date?: string; end_date?: string; limit?: number;
  };
  const cappedLimit = Math.min(limit && limit > 0 ? limit : 50, 200);

  const superseded = await fetchSupersededLotMap(supabase);
  if ("error" in superseded) return formatErrorForModel(superseded.error);

  // Shared filter conditions -- applied identically to the scope query
  // (below) and the main display query, so the two can never drift apart
  // and silently disagree about what "matches."
  // deno-lint-ignore no-explicit-any
  const applyFilters = (q: any) => {
    if (lot_code) {
      // Explicit exact request -- honored as asked, superseded or not;
      // the exclusion filter below is a default for fuzzy/unscoped
      // search, not a block on a direct query.
      q = q.eq("lot_code", lot_code);
    } else {
      if (lot_name) q = q.ilike("lot_name", `%${lot_name}%`);
      if (superseded.map.size > 0) {
        const list = [...superseded.map.keys()].map((c) => `"${c}"`).join(",");
        q = q.not("lot_code", "in", `(${list})`);
      }
    }
    if (analysis_type) q = q.eq("analysis_type", analysis_type);
    if (start_date) q = q.gte("recorded_at", start_date);
    if (end_date) q = q.lte("recorded_at", end_date);
    return q;
  };

  // Scope query: EVERY distinct lot_code the filters match, and each
  // one's true min/max recorded_at -- both computed independently of
  // the row cap below, for two separate reasons that happen to share
  // one query:
  //
  // (a) The multi-lot-code warning must be based on the true match set,
  // not on whichever lot_codes happen to survive the cap. Confirmed
  // live this distinction is load-bearing, not theoretical:
  // lot_name='Cabernet Sauvignon, V3' with no date filter returns 100%
  // MA24CSV3 rows (176 available, all more recent than MA23CSV3's) --
  // recency ordering plus the default 50-row cap fill the entire
  // window before MA22CSV3/MA23CSV3's genuinely-matching rows ever
  // appear, so a check against the returned `data` alone sees exactly
  // one lot_code and stays silent.
  //
  // (b) The per-lot date-RANGE has the identical exposure, and it's
  // what actually produced a wrong answer live: asked for "the
  // Cabernet Sauvignon V3 lot's history," Kimi correctly named all
  // three lots (the fix above), picked MA24CSV3 as primary, but then
  // separately stated MA23CSV3's own range as "Mar 2023-Jul 2024" --
  // real end date, wrong start. MA23CSV3 has 80 rows; a follow-up call
  // with the default 50-row cap and recency ordering would show only
  // its MOST RECENT 50 rows, silently hiding the true (older) start of
  // its history -- exactly the shape that produces a plausible-but-
  // wrong start date instead of an obviously-missing one. Same remedy
  // this project already applied to labour's arithmetic totals
  // (labour-totals.ts precomputes backend-side rather than asking the
  // model to sum capped/possibly-partial rows): compute the date range
  // server-side from every matching row, not from whatever fits in the
  // display window.
  //
  // lot_analyses is 1,405 rows total; any filtered subset is far
  // smaller, so one unordered, capped-generously-not-tightly query
  // (recorded_at only, no full row payload) is cheap regardless of
  // whether lot_code was given.
  const scopeQuery = applyFilters(supabase.from("lot_analyses").select("lot_code, lot_name, recorded_at")).limit(1000);
  const { data: scopeRows, error: scopeError } = await scopeQuery;
  if (scopeError) return formatErrorForModel(scopeError);

  const lotRanges = new Map<string, { name: string; min: string; max: string }>();
  // deno-lint-ignore no-explicit-any
  for (const r of scopeRows as any[]) {
    const existing = lotRanges.get(r.lot_code);
    if (!existing) {
      lotRanges.set(r.lot_code, { name: r.lot_name, min: r.recorded_at, max: r.recorded_at });
    } else {
      if (r.recorded_at < existing.min) existing.min = r.recorded_at;
      if (r.recorded_at > existing.max) existing.max = r.recorded_at;
    }
  }
  const rangeLabel = (min: string, max: string) => {
    const a = dayLabel(min.slice(0, 10));
    const b = dayLabel(max.slice(0, 10));
    return a === b ? a : `${a} through ${b}`;
  };

  const query = applyFilters(
    supabase
      .from("lot_analyses")
      .select("lot_name, lot_code, block_id, analysis_type, value, unit, recorded_at")
      .order("recorded_at", { ascending: false })
      .limit(cappedLimit),
  );

  const { data, error } = await query;
  if (error) return formatErrorForModel(error);

  const notes: string[] = [];

  if (lot_code && superseded.map.has(lot_code)) {
    notes.push(`(Note: ${lot_code} is a superseded duplicate lot_code -- InnoVint has two lot objects for this same physical wine. The canonical/complete record is ${superseded.map.get(lot_code)}.)`);
  }

  if (lotRanges.size > 1) {
    const matchedListing = [...lotRanges.entries()].map(([code, r]) => `${code} (${r.name})`).join(", ");
    notes.push(`(Note: this lot_name search matches ${lotRanges.size} distinct lots, not one -- ${matchedListing}. Treat these as separate lots/vintages unless you intend a cross-vintage comparison; narrow with lot_code for a single lot.)`);

    // deno-lint-ignore no-explicit-any
    const returnedLots = new Set((data as any[]).map((r) => r.lot_code));
    if (returnedLots.size < lotRanges.size) {
      const returnedListing = [...returnedLots].join(", ") || "none";
      const missingListing = [...lotRanges.keys()].filter((c) => !returnedLots.has(c)).join(", ");
      notes.push(`(This capped, most-recent-first result only actually CONTAINS rows from: ${returnedListing}. Rows from ${missingListing} matched the same search but were pushed entirely out of the ${cappedLimit}-row window by more recent data from another lot -- pass lot_code to see one specifically, or narrow analysis_type/date range.)`);
    }

    const rangeListing = [...lotRanges.entries()].map(([code, r]) => `${code}: ${rangeLabel(r.min, r.max)}`).join("; ");
    notes.push(`(Date ranges (computed from every matching row, not just what's shown above, so this is reliable even where the row cap isn't) -- ${rangeListing}.)`);
  } else if (lotRanges.size === 1) {
    const [[code, r]] = lotRanges;
    notes.push(`(${code} lab-analysis date range across every matching row: ${rangeLabel(r.min, r.max)}.)`);
  }

  // Multi-reading disclosure (2026-09-20): lot_analyses genuinely
  // contains more than one reading of the same analysis_type for the
  // same lot_code on the same date -- confirmed live, not a duplication
  // bug (see the within-lot-duplicates entry in docs/SECURITY.md): a
  // live InnoVint API call confirmed a distinct, populated `vesselId`
  // per reading for a multi-vessel case (MA24CSV3's three brix values
  // on one timestamp) and a distinct `actionId` per reading for a
  // same-day-different-submission case (MA22CS's two 2024-05-01
  // panels) -- both real, separate InnoVint records, not a sync
  // artifact. lot_analyses stores NEITHER field today (confirmed
  // against ingest-innovint's own InnoVintAnalysis interface, which
  // never declared them) -- the real fix is syncing one of them, not
  // built this round (see docs/SECURITY.md for the recommendation).
  // Until then, a model reading two identical values on one timestamp
  // can misread it as a duplicate record (and drop one), or divergent
  // values as measurement inconsistency (and average or pick one) --
  // neither matches reality. Disclosed explicitly, computed from the
  // rows actually returned (what the model can see), not the full
  // scope -- this is about explaining multiplicity already in the
  // response, not detecting rows hidden by the cap (the separate
  // concern the scope query above already covers).
  // deno-lint-ignore no-explicit-any
  const multiReadingGroups = new Map<string, { lot: string; type: string; date: string; values: number[] }>();
  // deno-lint-ignore no-explicit-any
  for (const r of data as any[]) {
    const dateKey = String(r.recorded_at).slice(0, 10);
    const key = `${r.lot_code}|${r.analysis_type}|${dateKey}`;
    if (!multiReadingGroups.has(key)) multiReadingGroups.set(key, { lot: r.lot_code, type: r.analysis_type, date: dateKey, values: [] });
    multiReadingGroups.get(key)!.values.push(r.value);
  }
  const multiGroups = [...multiReadingGroups.values()].filter((g) => g.values.length > 1);
  if (multiGroups.length > 0) {
    const listing = multiGroups.map((g) => `${g.lot} ${g.type} on ${dayLabel(g.date)} has ${g.values.length} readings (${g.values.join(", ")})`).join("; ");
    notes.push(`(Note: this result has more than one reading for the same lot/analyte/date in ${multiGroups.length} case(s) -- ${listing}. lot_analyses has no vessel or sample identifier to label these individually (InnoVint's own API exposes one, not yet synced -- see docs/SECURITY.md), but they are CONFIRMED real, separate InnoVint records -- different vessels or different lab submissions, not duplicate rows. Report every value; never average them, and never drop one as a suspected duplicate.)`);
  }

  const truncated = data.length === cappedLimit;
  if (truncated) {
    notes.push(`(Returned the maximum ${cappedLimit} rows -- there may be more. Narrow with lot_code, lot_name, analysis_type, or a date range if this doesn't cover what you need.)`);
  }

  return { content: JSON.stringify(data) + (notes.length ? "\n\n" + notes.join(" ") : ""), isError: false };
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
// changing any schema. Both paths now share exact decimal totals while
// retaining their own filter scope, category grain, and coverage notes.
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
      .select("vintage, period_month, job_category, labor_hours::text, labor_cost::text, expense_cost::text, total_cost::text, cost_per_hour::text")
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
      const { data: cov, error: coverageError } = await supabase
        .from("labour_vintage_coverage")
        .select("first_month, last_month, month_count")
        .eq("vintage", impliedVintage)
        .maybeSingle();
      if (coverageError) return formatErrorForModel(coverageError);
      const rangeNote = cov
        ? ` This vintage's actual coverage is ${cov.first_month === cov.last_month ? monthLabel(cov.first_month) : `${monthLabel(cov.first_month)} through ${monthLabel(cov.last_month)} INCLUSIVE`} (${cov.month_count} of 12 months).`
        : ` No labour records exist for vintage ${impliedVintage} at all -- not simulated, genuinely absent.`;
      note = `\n\nNo labour records match ${label} specifically${job_category ? ` with job category filter "${job_category}"` : ""}.${rangeNote}`;
    }
    return { content: labourResult(data ?? [], { vintage: vintage ?? null, period_month: periodMonth, job_category: job_category ?? null }) + note, isError: false };
  }

  // Vintage path retains its category grain and vintage-wide coverage.
  let query = supabase
    .from("labour_actuals_by_category")
    .select("vintage, job_category, labor_hours::text, labor_cost::text, expense_cost::text, total_cost::text, cost_per_hour::text")
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
    const { data: cov, error: coverageError } = await supabase
      .from("labour_vintage_coverage")
      .select("first_month, last_month, month_count")
      .eq("vintage", v)
      .maybeSingle();
    if (coverageError) return formatErrorForModel(coverageError);
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
    : (vintage ? `\n\nNo labour records match vintage ${vintage}${job_category ? ` with job category filter "${job_category}"` : ""} -- not simulated, genuinely absent for this scope.` : "");
  return { content: labourResult(data ?? [], { vintage: vintage ?? null, period_month: periodMonth, job_category: job_category ?? null }) + note, isError: false };
}

// Same day-precision-matters reasoning as monthLabel() above, one level
// finer: a berry-maturity/smoke-marker collection date IS the meaningful
// unit here (samples are taken on specific days, not aggregated by
// month), so this spells the full date out in words rather than
// reusing monthLabel() at month grain or falling back to a bare ISO
// string.
function dayLabel(isoDate: string): string {
  const [y, m, d] = isoDate.split("-");
  return `${MONTH_NAMES[Number(m) - 1]} ${Number(d)}, ${y}`;
}

// ETS berry-sampling ingestion (2026-09-20): lab_samples/lab_results/
// berry_volume_histogram are intentionally lossless (a reissued sample's
// superseded rows stay in the base tables -- see docs/SECURITY.md for the
// duplication bug that was live before lab_results_current/
// lab_samples_current existed). Both tools below read ONLY the *_current
// views/the berry_maturity_by_block view built on them -- never
// lab_samples/lab_results directly -- so a chat answer can't reintroduce
// that bug.
//
// Real-only-mode: deliberately NOT gated, same reasoning and same choice
// as get_labour_summary (see that function's own comment) -- ETS lab
// data has no mock/simulated generator that has ever existed for it (the
// domain_reality() berry_sampling clause is existence-based against this
// exact table, with nothing to distinguish "real" from "simulated" for
// this domain -- there is no simulated version to withhold). Operator
// access is enforced by each view's own RLS (security_invoker + an
// operator-only policy, mirroring lot_analyses/labour_actuals) -- not an
// application-level check in either function below.
const MATURITY_ANALYTE_LABELS: Record<string, string> = {
  brix: "brix", ph: "pH", titratable_acidity: "titratable acidity",
  l_malic_acid: "L-malic acid", glucose_fructose: "glucose+fructose",
  berry_weight_g: "berry weight", berry_volume_ml: "berry volume",
  berry_volume_variability_pct: "berry volume variability", sugar_per_berry_mg: "sugar per berry",
};
const MATURITY_ANALYTE_KEYS = Object.keys(MATURITY_ANALYTE_LABELS);

// deno-lint-ignore no-explicit-any
async function getBerryMaturity(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { vintage, block_id } = input as { vintage?: number; block_id?: string };

  let query = supabase
    .from("berry_maturity_by_block")
    .select("block_id, collected_on, vintage, brix, ph, titratable_acidity, l_malic_acid, glucose_fructose, berry_weight_g, berry_volume_ml, berry_volume_variability_pct, sugar_per_berry_mg")
    .order("block_id", { ascending: true })
    .order("collected_on", { ascending: true });
  if (vintage) query = query.eq("vintage", vintage);
  if (block_id) query = query.eq("block_id", block_id);

  const { data, error } = await query;
  if (error) return formatErrorForModel(error);

  // Coverage is computed from an UNFILTERED read of the same view plus
  // lab_samples_current's sample_type/vintage columns -- both tiny (12
  // and 17 rows total) -- so the returned note is honest about every
  // vintage's actual shape regardless of what this call filtered to,
  // rather than only describing whatever happened to survive the filter.
  const { data: allMaturity, error: allErr } = await supabase
    .from("berry_maturity_by_block")
    .select("vintage, collected_on, brix, ph, titratable_acidity, l_malic_acid, glucose_fructose, berry_weight_g, berry_volume_ml, berry_volume_variability_pct, sugar_per_berry_mg");
  if (allErr) return formatErrorForModel(allErr);
  const { data: allSamples, error: samplesErr } = await supabase
    .from("lab_samples_current")
    .select("vintage, sample_type");
  if (samplesErr) return formatErrorForModel(samplesErr);

  const SAMPLE_TYPE_LABEL: Record<string, string> = {
    berry_smoke: "smoke-taint screening", trial_ferment: "a trial micro-ferment",
  };
  const coverageLines: string[] = [];
  for (const v of [2022, 2023, 2024, 2025, 2026]) {
    // deno-lint-ignore no-explicit-any
    const rows = (allMaturity as any[]).filter((r) => r.vintage === v);
    if (rows.length === 0) {
      // deno-lint-ignore no-explicit-any
      const otherTypes = [...new Set((allSamples as any[]).filter((s) => s.vintage === v).map((s) => s.sample_type))];
      coverageLines.push(
        otherTypes.length === 0
          ? `${v}: no berry sampling of any kind -- genuinely absent, not simulated.`
          : `${v}: no maturity/ripening panel -- that vintage's only berry sampling was ${otherTypes.map((t) => SAMPLE_TYPE_LABEL[t as string] ?? t).join(" and ")} (see get_smoke_markers), not brix/pH/TA ripening tracking.`,
      );
      continue;
    }
    const dates = [...new Set(rows.map((r) => r.collected_on))].sort();
    const present = MATURITY_ANALYTE_KEYS.filter((k) => rows.some((r) => r[k] != null));
    const absent = MATURITY_ANALYTE_KEYS.filter((k) => !present.includes(k));
    const dateLabel = dates.length === 1 ? dayLabel(dates[0]) : `${dates.length} dates (${dates.map(dayLabel).join(", ")})`;
    coverageLines.push(
      absent.length === 0
        ? `${v}: full nine-analyte panel across ${dateLabel}.`
        : `${v}: only ${present.map((k) => MATURITY_ANALYTE_LABELS[k]).join("/")} measured, across ${dateLabel} -- ${absent.map((k) => MATURITY_ANALYTE_LABELS[k]).join(", ")} NOT measured that vintage (absent because a smaller panel ran, not zero or missing entry).`,
    );
  }
  const note = `\n\nCoverage (all vintages, regardless of this call's filters): ${coverageLines.join(" ")}`;
  return { content: JSON.stringify(data ?? []) + note, isError: false };
}

// The nine free volatile phenols (both ETS method-string variants
// normalize to these codes -- see ingestion/ets_labs/parse.py's
// analysis_code_for()) plus the six glycosylated conjugate markers.
//
// Verified exhaustively against the live database (2026-09-20), not just
// against the questions a re-ask happened to cite: `select distinct
// analysis_code from lab_results_current` returns exactly 24 codes --
// these 15 plus the 9 non-smoke maturity-panel codes get_berry_maturity
// already covers (brix, ph, titratable_acidity, l_malic_acid,
// glucose_fructose, berry_weight, berry_volume,
// berry_volume_variability, sugar_per_berry_by_volume). All 15 literals
// below match a live code exactly; none is a typo that would silently
// and permanently drop an analyte from this tool.
const SMOKE_ANALYSIS_CODES = [
  "guaiacol", "4_methylguaiacol", "4_methylsyringol", "m_cresol", "o_cresol", "p_cresol",
  "phenol", "syringol", "cresols_sum",
  "smoke_glycosylated_markers_lcms_ms_qqq_4_methylguaiacol_rutinoside",
  "smoke_glycosylated_markers_lcms_ms_qqq_4_methylsyringol_gentiobioside",
  "smoke_glycosylated_markers_lcms_ms_qqq_cresol_rutinoside",
  "smoke_glycosylated_markers_lcms_ms_qqq_guaiacol_rutinoside",
  "smoke_glycosylated_markers_lcms_ms_qqq_phenol_rutinoside",
  "smoke_glycosylated_markers_lcms_ms_qqq_syringol_gentiobioside",
];

// deno-lint-ignore no-explicit-any
async function getSmokeMarkers(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { vintage, block_id } = input as { vintage?: number; block_id?: string };

  // Samples first (not lab_results_current directly): lab_results_current
  // carries no block_id/vintage/collected_on of its own (it's `select
  // r.*` over lab_results, joined only to filter -- see
  // 20260920140000_lab_samples_current.sql), and it's a view, not a
  // table with a declared FK, so PostgREST embedding across it isn't
  // relied on here -- the join is done explicitly in this function
  // instead, against sample ids resolved from lab_samples_current.
  let sampleQuery = supabase
    .from("lab_samples_current")
    .select("id, lab_sample_no, sample_description_raw, sample_type, block_id, vintage, collected_on");
  if (vintage) sampleQuery = sampleQuery.eq("vintage", vintage);
  if (block_id) sampleQuery = sampleQuery.eq("block_id", block_id);
  const { data: samples, error: sampleErr } = await sampleQuery;
  if (sampleErr) return formatErrorForModel(sampleErr);

  // deno-lint-ignore no-explicit-any
  const sampleById = new Map((samples as any[]).map((s) => [s.id, s]));
  const sampleIds = [...sampleById.keys()];

  let rows: unknown[] = [];
  if (sampleIds.length > 0) {
    const { data: results, error: resultsErr } = await supabase
      .from("lab_results_current")
      .select("sample_id, analysis_name_raw, analysis_code, result_raw, result_numeric, result_operator, units, analyzed_at")
      .in("sample_id", sampleIds)
      .in("analysis_code", SMOKE_ANALYSIS_CODES);
    if (resultsErr) return formatErrorForModel(resultsErr);
    // deno-lint-ignore no-explicit-any
    rows = (results as any[]).map((r) => {
      const s = sampleById.get(r.sample_id);
      return {
        block_id: s?.block_id ?? null,
        vintage: s?.vintage,
        collected_on: s?.collected_on,
        lab_sample_no: s?.lab_sample_no,
        sample_description: s?.sample_description_raw,
        analysis_name_raw: r.analysis_name_raw,
        analysis_code: r.analysis_code,
        result_operator: r.result_operator,
        result_numeric: r.result_numeric,
        result_raw: r.result_raw,
        units: r.units,
        analyzed_at: r.analyzed_at,
      };
    });
  }

  // Coverage: unfiltered read of every sample this table has ever seen
  // (17 rows total via lab_samples_current), so the note is honest about
  // every vintage's smoke-screening status regardless of this call's own
  // vintage/block_id filters.
  const { data: allSamples, error: allSamplesErr } = await supabase
    .from("lab_samples_current")
    .select("vintage, block_id, collected_on, sample_type, sample_description_raw");
  if (allSamplesErr) return formatErrorForModel(allSamplesErr);
  const coverageLines: string[] = [];
  for (const v of [2022, 2023, 2024, 2025, 2026]) {
    // deno-lint-ignore no-explicit-any
    const smokeSamples = (allSamples as any[]).filter((s) => s.vintage === v && (s.sample_type === "berry_smoke" || s.sample_type === "trial_ferment"));
    if (smokeSamples.length === 0) {
      coverageLines.push(`${v}: no vineyard-side smoke-taint screening on file -- genuinely absent, not simulated.`);
      continue;
    }
    const parts = smokeSamples.map((s) =>
      `${s.block_id ?? "block unresolved"} (${dayLabel(s.collected_on)}${s.sample_type === "trial_ferment" ? ", trial micro-ferment" : ""})`
    );
    coverageLines.push(`${v}: ${parts.join(", ")}.`);
  }
  const note = `\n\nCoverage (all vintages, regardless of this call's filters): ${coverageLines.join(" ")} Units are basis-specific (µg/kg = berry mass, µg/L = liquid/juice) and are never interchangeable -- always read the units field on each row.`;
  return { content: JSON.stringify(rows) + note, isError: false };
}

const WINERY_SAMPLE_TYPES = ["must", "wine", "ferment", "stability_trial"];

// ETS winery ingestion (2026-09-20): lab_samples/lab_results are the same
// lossless base tables Phase 1's berry tools already guard against --
// this tool reads lab_samples_current/lab_results_current for the exact
// same reason (superseded reissue rows must never resurface). Never
// gated by real-only mode, same reasoning as the berry tools: no
// simulated counterpart has ever existed for ETS lab data.
//
// sample_description is a KNOWN substring-collision risk in this exact
// dataset -- confirmed live: 'MA22CS' is a literal substring of
// 'MA22CSV2'/'MA22CSV3', and all three are vintage 2022, so `vintage`
// does NOT disambiguate the way it might look like it should. This is
// the same class of bug get_lot_analyses had (confirmed live there
// too, docs/SECURITY.md) -- fixed here from the start rather than
// discovered later: every matching sample_description_raw is computed
// from the full (uncapped -- this dataset is 25 samples/93 rows total,
// nowhere near any row limit) sample set, not from whatever survives
// the results row cap, and reported explicitly whenever a search
// matches more than one.
// deno-lint-ignore no-explicit-any
async function getWineLabResults(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { sample_description, vintage, sample_type, analysis_code, start_date, end_date, limit } = input as {
    sample_description?: string; vintage?: number; sample_type?: string; analysis_code?: string;
    start_date?: string; end_date?: string; limit?: number;
  };
  const cappedLimit = Math.min(limit && limit > 0 ? limit : 100, 300);

  let sampleQuery = supabase
    .from("lab_samples_current")
    .select("id, lab_sample_no, sample_description_raw, sample_type, vintage, collected_on, fruit_source")
    .in("sample_type", sample_type ? [sample_type] : WINERY_SAMPLE_TYPES);
  if (sample_description) sampleQuery = sampleQuery.ilike("sample_description_raw", `%${sample_description}%`);
  if (vintage) sampleQuery = sampleQuery.eq("vintage", vintage);
  const { data: samples, error: sampleErr } = await sampleQuery;
  if (sampleErr) return formatErrorForModel(sampleErr);

  // deno-lint-ignore no-explicit-any
  const sampleById = new Map((samples as any[]).map((s) => [s.id, s]));
  const sampleIds = [...sampleById.keys()];

  let rows: unknown[] = [];
  if (sampleIds.length > 0) {
    let resultQuery = supabase
      .from("lab_results_current")
      .select("id, sample_id, analysis_name_raw, analysis_code, result_raw, result_numeric, result_operator, units, analyzed_at")
      .in("sample_id", sampleIds)
      .order("analyzed_at", { ascending: false })
      .limit(cappedLimit);
    if (analysis_code) resultQuery = resultQuery.eq("analysis_code", analysis_code);
    if (start_date) resultQuery = resultQuery.gte("analyzed_at", start_date);
    if (end_date) resultQuery = resultQuery.lte("analyzed_at", end_date);

    const { data: results, error: resultsErr } = await resultQuery;
    if (resultsErr) return formatErrorForModel(resultsErr);

    // Reconciliation status per result row -- the "flag overlaps" surface
    // the owner chose over skipping duplicated analytes. Fetched by id
    // (the view's own lab_result_id), not re-derived here.
    // deno-lint-ignore no-explicit-any
    const resultIds = (results as any[]).map((r) => r.id);
    const reconById = new Map<number, { status: string; lot: string | null; value: number | null }>();
    if (resultIds.length > 0) {
      const { data: recon, error: reconErr } = await supabase
        .from("ets_lot_analyses_reconciliation")
        .select("lab_result_id, match_status, matched_lot_code, matched_value")
        .in("lab_result_id", resultIds);
      if (reconErr) return formatErrorForModel(reconErr);
      // deno-lint-ignore no-explicit-any
      for (const r of recon as any[]) {
        reconById.set(r.lab_result_id, { status: r.match_status, lot: r.matched_lot_code, value: r.matched_value });
      }
    }

    // deno-lint-ignore no-explicit-any
    rows = (results as any[]).map((r) => {
      const s = sampleById.get(r.sample_id);
      const recon = reconById.get(r.id);
      return {
        sample_description: s?.sample_description_raw,
        sample_type: s?.sample_type,
        vintage: s?.vintage,
        collected_on: s?.collected_on,
        fruit_source: s?.fruit_source,
        lab_sample_no: s?.lab_sample_no,
        analysis_name_raw: r.analysis_name_raw,
        analysis_code: r.analysis_code,
        result_operator: r.result_operator,
        result_numeric: r.result_numeric,
        result_raw: r.result_raw,
        units: r.units,
        analyzed_at: r.analyzed_at,
        lot_analyses_match: recon?.status ?? "ets_only",
        lot_analyses_lot_code: recon?.lot ?? null,
        lot_analyses_value: recon?.value ?? null,
      };
    });
  }

  const notes: string[] = [];

  // Precomputed per-description date range (dayLabel()-formatted, in
  // words) -- same "don't let the model derive a range from a row set
  // it can't fully see" fix as get_lot_analyses, applied from the start
  // rather than discovered as a live bug.
  const byDescription = new Map<string, { type: string; vintage: number; dates: string[] }>();
  // deno-lint-ignore no-explicit-any
  for (const s of samples as any[]) {
    const key = s.sample_description_raw;
    if (!byDescription.has(key)) byDescription.set(key, { type: s.sample_type, vintage: s.vintage, dates: [] });
    byDescription.get(key)!.dates.push(s.collected_on);
  }
  if (byDescription.size === 0) {
    notes.push(`(No winery samples match this search${sample_description ? ` for sample_description "${sample_description}"` : ""}${vintage ? ` in ${vintage}` : ""} -- not simulated, genuinely absent for this scope.)`);
  } else {
    const lines = [...byDescription.entries()].map(([desc, d]) => {
      const sorted = [...new Set(d.dates)].sort();
      const range = sorted.length === 1 ? dayLabel(sorted[0]) : `${dayLabel(sorted[0])} through ${dayLabel(sorted[sorted.length - 1])}`;
      return `${desc} (${d.type}, ${d.vintage}): ${range}`;
    });
    if (byDescription.size > 1) {
      notes.push(`(Note: this search matches ${byDescription.size} distinct sample_description values, not one -- ${[...byDescription.keys()].join(", ")}. Treat these as separate lots unless a cross-lot comparison is intended.)`);
    }
    notes.push(`(Date coverage per matched lot, computed from every matching sample, not just the rows shown -- ${lines.join("; ")}.)`);
  }

  const truncated = rows.length === cappedLimit;
  if (truncated) {
    notes.push(`(Returned the maximum ${cappedLimit} rows -- there may be more. Narrow with sample_description, analysis_code, or a date range if this doesn't cover what you need.)`);
  }

  return { content: JSON.stringify(rows) + (notes.length ? "\n\n" + notes.join(" ") : ""), isError: false };
}
