import { labourResult } from "./labour-totals.ts";
import { currentVintage, vintagesThrough } from "../_shared/vintage.ts";
import {
  analyteFamily, applyBounds, dayLabel, describeChange, isBareDate, normLower, normText, normUpper,
  pacificDate, pacificMidnightUtc, addDays, type Point, resolveDateBounds, temperatureLabel,
} from "./query-rules.ts";
import type Anthropic from "@anthropic-ai/sdk";

// series_bucketed's own aggregation is bounded by the caller's date range
// and bucket size, not by a fixed row limit -- a wide range with a tiny
// bucket can generate an enormous series. Reject before calling the RPC.
const MAX_SERIES_BUCKETS = 500;

// "Current vintage" comes from the harvest-year rule (_shared/vintage.ts),
// never a year written here (docs/SECURITY.md, "Current vintage from the
// harvest-year rule"). The clock is replaceable ONLY by tests
// (setToolClockForTests); no request can change it.
let clock: () => Date = () => new Date();
export function setToolClockForTests(fn: () => Date): void { clock = fn; }
export function currentToolVintage(): number { return currentVintage(clock()); }
// Every vintage from the first to the current one (was a fixed
// [2022..2026]) -- used to bulk-fetch domain_reality() once per request.
export function allVintages(): number[] { return vintagesThrough(clock()); }

// A fact about the seeded MOCK data, not "the current vintage": the mock
// generator narrates MOCK_SEASON's in-progress season frozen at MOCK_NOW
// (mirrors web/index.html). While MOCK_SEASON is current, "now" for it is
// MOCK_NOW; any later current vintage uses the real clock.
const MOCK_SEASON = 2026;
const MOCK_NOW = "2026-07-28T14:20:00-07:00";

// domain -> Set<real vintage>, built from domain_reality() -- the SAME
// server-side RPC web/index.html calls (see
// supabase/migrations/20260913150000_real_only_data_mode.sql), so this
// file and the frontend share one source of truth for "is X real" rather
// than maintaining a second, independent classification here.
export type DomainReality = Map<string, Set<number>>;

// deno-lint-ignore no-explicit-any
export async function fetchDomainReality(supabase: any, vintages: number[] = allVintages()): Promise<DomainReality> {
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
      "Time-bucketed real IoT sensor readings for vineyard blocks (air_temp, soil_moisture, soil_temp, humidity, wind, etc.). Averages (or sums, for precipitation/irrigation) readings into buckets across a time range. Block-scoped: a customer only sees blocks they have access to; RLS silently returns no data for inaccessible blocks rather than erroring. The response ends with the effective interval used and a server-computed Changes note (first to last non-empty bucket, change per day, min/max) -- quote those figures rather than computing them.",
    input_schema: {
      type: "object",
      properties: {
        metric: { type: "string", description: "Metric key, e.g. 'air_temp', 'soil_moisture', 'soil_temp', 'humidity', 'wind_speed', 'precip'." },
        block: { type: "string", description: "Block id, e.g. 'B1' (case and surrounding spaces ignored). Omit for all accessible blocks." },
        vintage: { type: "integer", description: "Vintage (harvest year), e.g. 2024. Omit for all vintages." },
        start: { type: "string", description: "ISO 8601 start timestamp, or a calendar date 'YYYY-MM-DD' meaning the start of that Pacific (estate) day." },
        end: { type: "string", description: "ISO 8601 end timestamp, or a calendar date 'YYYY-MM-DD' meaning through the END of that Pacific day (start and end may be the same date)." },
        bucket_hours: { type: "number", description: "Bucket width in hours, e.g. 1 for hourly, 24 for daily." },
        agg: { type: "string", enum: ["avg", "sum"], description: "Aggregation within each bucket. Use 'sum' for precip/irrigation volume, 'avg' otherwise." },
      },
      required: ["metric", "start", "end", "bucket_hours"],
    },
  },
  {
    name: "get_derived_series",
    description:
      "Real derived daily climate metrics for a vintage: cumulative growing degree days (gdd_cumulative_calibrated -- calibrated per-vintage against the Napa Valley Grapegrowers Growing Conditions Report figures for Angwin, and the authoritative GDD figure to quote), average-based vapor pressure deficit (vpd_kpa), peak-hour vapor pressure deficit (vpd_peak_kpa), uncalibrated diurnal temperature range (dtr_f), and reference evapotranspiration (et0_in). One row per day. Defaults to the vintage's growing-season range if start_date/end_date are omitted; a bare end_date includes that whole day. The response ends with the effective interval and a server-computed Changes note (GDD gained and per day, min/max/mean of each other field) -- quote those figures rather than computing them.",
    input_schema: {
      type: "object",
      properties: {
        vintage: { type: "integer", description: "Vintage (harvest year), e.g. 2024." },
        start_date: { type: "string", description: "Calendar date, e.g. '2024-04-01' (inclusive). Defaults to the start of the growing season." },
        end_date: { type: "string", description: "Calendar date, inclusive of that whole day. Defaults to the latest data for the current vintage, or end of season for an archived vintage." },
      },
      required: ["vintage"],
    },
  },
  {
    name: "get_anomalies",
    description:
      "Real-time evaluation of vineyard anomaly rules (soil moisture, DTR, VPD, humidity, wind) against current sensor and climate data, as of a given snapshot. Only vineyard-tab rules are wired to real data; winery/tank anomalies are not covered by this tool. Defaults to the current vintage (see the date line in your instructions) as of its live snapshot -- pass vintage/as_of explicitly to check an archived vintage (e.g. 'were there issues in 2022?').",
    input_schema: {
      type: "object",
      properties: {
        vintage: { type: "integer", description: "Vintage (harvest year) to evaluate. Defaults to the current vintage." },
        as_of: { type: "string", description: "ISO 8601 timestamp to evaluate as of. Defaults to the current live snapshot for the current vintage, or end-of-year for an archived vintage." },
      },
      required: [],
    },
  },
  {
    name: "get_lot_analyses",
    description:
      "Real winery lab analyses recorded in InnoVint per lot (Brix, pH, TA, VA, SO2, YAN, malic, temperature, ethanol and other cellar chemistry), keyed by InnoVint lot_code/lot_name. SOURCE: InnoVint only. ETS Labs results by lab sample number (fermentation checks, wine chemistry, stability trials) are in get_wine_lab_results, not here -- a sample number (9 digits, e.g. '310310429') or an ETS sample description (e.g. 'T-7 V-2') will not match an InnoVint lot. When nothing matches, the response names any ETS samples the same identifier matches; follow that pointer before asking the user. Operator access only -- returns no rows for customer or pending accounts. Returns at most 200 rows, most recent first, with the exact total_count of matching rows and a truncated flag; per-lot row counts and first/last dates are computed in the database over every matching row (never from the capped rows). Dates are labelled in the estate's Pacific calendar day. InnoVint contains genuine duplicate lot objects for the same physical wine for a few 2023 lots (byte-identical chemistry under two or three different lot_codes) -- pass lot_code when you already know it (exact match, case-insensitive, unambiguous); a lot_name search (partial match) automatically excludes the known-superseded duplicates and, if it still matches more than one distinct lot_code (e.g. a name that's also a substring of a different vintage's lot name), says so explicitly rather than silently blending them. Querying a superseded lot_code directly still works (its own rows, not redirected) but the result notes which lot_code is canonical. The same analyte can be recorded at different reference temperatures (ethanol-20c, ethanol-60f, plus plain ethanol/alcohol) -- different measurements, never interchangeable; when you filter on one, the response lists the variants on file in InnoVint AND the matching ETS Labs results for the same lot (e.g. ethanol_at_20c / ethanol_at_60f), with values. When nothing matches, the response also names a superseded ETS sample number's reissue, or the vessel a lot code is assigned to (get_vessels). Each result ends with a server-computed Changes note per lot and analysis type (first to last reading, change per day) -- quote it rather than computing rates yourself.",
    input_schema: {
      type: "object",
      properties: {
        lot_code: { type: "string", description: "Exact InnoVint lot code, e.g. 'MA23CSV3' (case and surrounding spaces ignored). Unambiguous -- prefer this over lot_name when known. Bypasses the duplicate-lot exclusion (an explicit request for a specific code, including a superseded one, is honored as asked)." },
        lot_name: { type: "string", description: "Partial lot name match, e.g. 'Zinfandel'. Known-superseded duplicate lot_codes are excluded automatically." },
        analysis_type: { type: "string", description: "Exact InnoVint analysis type, e.g. 'brix', 'ph', 'titratable-acidity', 'ethanol-20c' (case ignored). Temperature variants of the same analyte are listed in the response." },
        start_date: { type: "string", description: "Lower bound on recorded_at: a calendar date 'YYYY-MM-DD' (start of that Pacific day) or an ISO 8601 timestamp." },
        end_date: { type: "string", description: "Upper bound on recorded_at: a calendar date 'YYYY-MM-DD' includes that WHOLE Pacific day (start_date = end_date gives one full day); an ISO 8601 timestamp is used exactly, inclusive." },
        limit: { type: "integer", description: "Max rows to return, default 50, max 200." },
      },
      required: [],
    },
  },
  {
    name: "get_vessels",
    description:
      "Real winery tank/vessel inventory: type, capacity, current fill volume, and current lot assignment, sourced from InnoVint. Operator access only -- returns no rows for customer or pending accounts. Returns at most 500 vessels with the total matching count and a truncated flag.",
    input_schema: {
      type: "object",
      properties: {
        vessel_type: { type: "string", description: "Filter by vessel type: 'tank', 'barrel', 'keg', 'steel_drum' (case ignored)." },
        current_lot_name: { type: "string", description: "Partial match on the lot currently assigned to the vessel." },
        include_archived: { type: "boolean", description: "Include archived/decommissioned vessels. Default false." },
      },
      required: [],
    },
  },
  {
    name: "get_labour_summary",
    description:
      "Real vineyard labor hours and cost per operation category and vintage (e.g. Canopy Management, Irrigation, Harvest), sourced from actual Silverado hours invoices (2023, 2024) and the Mars Invoice Backup (2026, ingested month by month as new invoices arrive). No block dimension -- the source records are job-category/task/role, not per-block. Returns labor_cost and expense_cost SEPARATELY (some categories -- Fertilize, Disease Control, Irrigation, Other -- also carry folded-in invoice expenses that have cost but no hours); cost_per_hour is computed from labor_cost only, never the combined total. Coverage is uneven and NOT comparable across vintages: some vintages cover only part of the year, some (the current one) grow month by month as invoices arrive, and some have no labour records of any kind (returns empty for them, not simulated data). The month range per vintage is NOT fixed here -- always read it from this tool's own returned Coverage note, computed from the data on every call, rather than assuming a specific month or month count. Pass period_month to scope the answer to ONE specific calendar month (e.g. 'what did we spend in August specifically') instead of the whole vintage -- without it, results are summed across every month on file for that vintage, which is almost certainly NOT what a month-specific question wants. Use the supplied totals.display values verbatim for headline totals and the total row; NEVER sum category rows yourself or average category rates. totals contains exact decimal sums; display rounds once to two decimals. Empty categories mean no records, NOT known zero spend. Operator access only -- returns no rows for customer or pending accounts.",
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
      "Real vineyard berry-maturity sampling per block per collection date (brix, pH, titratable acidity, L-malic acid, glucose+fructose, berry weight, berry volume, berry volume variability, sugar per berry), sourced from ETS Labs. Reads berry_maturity_by_block, a view over CURRENT (non-superseded) samples only -- never the raw lab_samples/lab_results tables, which intentionally retain superseded reissue rows. Every row carries its provenance: lab_sample_no (the ETS sample number), collected_on_source ('description' = date stated in the sample description, 'report' = date stated on the ETS report, 'inferred_from_receipt' = date inferred from the lab's receipt date) and collected_on_inferred (true when the date was inferred, not recorded) -- say so when you quote an inferred date. Coverage is UNEVEN and NOT comparable across vintages: early vintages ran a smaller panel (brix/pH/TA only), so absent analytes there mean not measured, never zero or a real change in the vineyard. The number of collection dates, the analytes measured and the vintages with no maturity sampling are NOT fixed here -- they change as new ETS reports arrive; always read this tool's own returned Coverage note, which is computed from the data on every call. Each result ends with a server-computed Changes note per block and vintage (first to last collection date, change per day, and every step between consecutive dates) -- quote it rather than computing rates yourself. Deliberately does NOT expose the underlying 20-bin Dyostem berry-size histogram -- that's raw instrument detail with no value in a chat answer; berry_volume_variability_pct already carries the same ripening-uniformity signal as one number. Operator access only (customer/pending accounts get no rows, enforced by the view's own RLS, not an application check here). Never gated by real-only mode -- this data has no simulated counterpart to withhold, same as get_labour_summary.",
    input_schema: {
      type: "object",
      properties: {
        vintage: { type: "integer", description: "Vintage (harvest year), e.g. 2024. Omit for all vintages." },
        block_id: { type: "string", description: "Block id, e.g. 'B2' or 'B3' (case and surrounding spaces ignored). Omit for all blocks." },
        start_date: { type: "string", description: "Earliest collection date, 'YYYY-MM-DD' (inclusive). Use with end_date to get the Changes note for exactly the window asked about." },
        end_date: { type: "string", description: "Latest collection date, 'YYYY-MM-DD' (inclusive)." },
      },
      required: [],
    },
  },
  {
    name: "get_smoke_markers",
    description:
      "Real smoke-taint marker lab results per sample (the nine free volatile phenols -- guaiacol, 4-methylguaiacol, 4-methylsyringol, m-/o-/p-cresol, cresols (sum), phenol, syringol -- plus the six glycosylated conjugate markers of the same compounds), sourced from ETS Labs. Reads lab_results_current, filtered to just these analytes -- never lab_results directly, which intentionally retains superseded reissue rows (confirmed live: querying it directly for this exact data returned every value twice before this fix). Every row carries result_operator ('=' or '<') separately from result_numeric: a '<' row is a detection-limit censored result (e.g. '< 0.5'), and must be reported as below/under that limit, NEVER as a plain measured number. units differ by sample basis and are NEVER interchangeable: µg/kg is berry-mass basis, µg/L is liquid/juice basis -- always quote the unit given with the value, never convert or compare a µg/kg figure to a µg/L one as if equal. Every row carries lab_sample_no and collected_on_source/collected_on_inferred (whether the collection date was recorded or inferred). Which vintages, blocks and sample bases have smoke screening is NOT fixed here (new ETS reports add samples) -- read this tool's returned Coverage note, computed from the data on every call. Operator access only (RLS-enforced, not an application check). Never gated by real-only mode -- no simulated counterpart exists for this data.",
    input_schema: {
      type: "object",
      properties: {
        vintage: { type: "integer", description: "Year, e.g. 2025. Omit for all vintages." },
        block_id: { type: "string", description: "Block id, e.g. 'B2' or 'B3' (case and surrounding spaces ignored). Omit for all blocks -- note a sample with no resolved block (e.g. a trial micro-ferment) is excluded by any block_id filter." },
        lab_sample_no: { type: "string", description: "Exact ETS lab sample number, e.g. '508260303'." },
      },
      required: [],
    },
  },
  {
    name: "get_wine_lab_results",
    description:
      "Real winery lab chemistry from ETS Labs, by lab sample: fermentation checks on fermenting must/ferments, finished-wine chemistry (ethanol, VA, TA, pH, free/total SO2, YAN, ammonia, potassium, malic acid, glucose+fructose, brix) and specialty QC panels (microbial safety, heat/cold stability trials, fining trials, conductivity). SOURCE: ETS only -- InnoVint's own per-lot cellar analyses are in get_lot_analyses. Find a sample by lab_sample_no (exact ETS sample number, e.g. '310310429'), by lot_code (exact lot code, also resolving an InnoVint lot_code that maps to an ETS description, e.g. 'MA23CSV3-AP' -> 'MA23CSV3'), or by sample_description (partial match on ETS's description, e.g. 'MA23CS', 'T-7 V-2'; a value that is exactly a sample number also matches that sample). When nothing matches, the response names matching vineyard samples (get_berry_maturity/get_smoke_markers) or InnoVint lots (get_lot_analyses); follow that pointer before asking the user. CAUTION: some descriptions are literal substrings of others in the SAME vintage (e.g. 'MA22CS' also matches 'MA22CSV2' and 'MA22CSV3'); the response always states which distinct sample_description values matched -- use lot_code or lab_sample_no for one lot or sample. The same analyte can be reported at different reference temperatures -- e.g. ethanol_at_20c AND ethanol_at_60f on the same sample: different measurements, never interchangeable; when you filter on one, the response lists every variant on file for those samples, with values, plus InnoVint's readings of the same analyte for the matching lot (get_lot_analyses). A superseded sample number (e.g. 511110861) is answered with its reissue (511110861A). Every result row carries lab_sample_no, collected_on_source/collected_on_inferred (whether the collection date was recorded or inferred), result_operator ('=' or '<' -- a '<' row is a detection-limit censored result, never report it as a plain number), units, and a reconciliation status against InnoVint's own lot_analyses (lot_match: 'exact' = same lot/date/analyte/value already in lot_analyses, 'value_conflict' = same lot/date/analyte but a DIFFERENT value there, 'date_near' = matched within 3 days not same day, 'ets_only' = no InnoVint counterpart at all -- most rows are 'ets_only', that's expected, not a data quality problem). Returns the exact total_count of matching results and a truncated flag; date coverage per matched lot is computed in the database over every matching sample -- never infer a lot's date range from counting rows yourself. Each result ends with a server-computed Changes note per lot and analyte -- quote it rather than computing rates yourself. Some rows (e.g. a conductivity-test disclaimer or a stability-trial protocol note) have result_numeric=null and only a free-text result_raw -- report their content as text, not as a missing number. Operator access only (RLS-enforced). Never gated by real-only mode -- no simulated counterpart exists for this data.",
    input_schema: {
      type: "object",
      properties: {
        lab_sample_no: { type: "string", description: "Exact ETS lab sample number, e.g. '310310429' or '511110861A'." },
        lot_code: { type: "string", description: "Exact lot code, e.g. 'MA24CS' (matches only that description, not MA24CSV2/V3) or an InnoVint lot_code such as 'MA23CSV3-AP'. Case ignored." },
        sample_description: { type: "string", description: "Partial match on the ETS sample description, e.g. 'MA23CS', '25CHMR-LF' or 'T-7 V-2'. Omit for all winery samples." },
        vintage: { type: "integer", description: "Year, e.g. 2023. Omit for all vintages." },
        sample_type: { type: "string", enum: ["must", "wine", "ferment", "stability_trial"], description: "Narrow to one sample phase. Omit for all." },
        analysis_code: { type: "string", description: "Exact analysis code, e.g. 'ethanol_at_20c', 'ethanol_at_60f', 'volatile_acidity_acetic_acid', 'ph' (case ignored). Other temperature variants of the same analyte are listed in the response." },
        start_date: { type: "string", description: "Lower bound on analyzed_at: a calendar date 'YYYY-MM-DD' (start of that day) or an ISO 8601 timestamp." },
        end_date: { type: "string", description: "Upper bound on analyzed_at: a calendar date 'YYYY-MM-DD' includes that WHOLE day (start_date = end_date gives one full day); an ISO 8601 timestamp is used exactly, inclusive." },
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
    // The gateway validates arguments against the schema (mcp/handler.ts
    // validateArgs); the in-app path must not silently ignore an unknown one
    // either. Colin's {lab_sample_no: "608140601"} -- before that parameter
    // existed -- returned every winery result (93 rows) unfiltered.
    const tool = TOOLS.find((t) => t.name === name);
    if (tool) {
      const known = Object.keys((tool.input_schema as { properties?: Record<string, unknown> }).properties ?? {});
      const unknown = Object.keys(input ?? {}).filter((k) => !known.includes(k));
      if (unknown.length) {
        return { content: `Unknown argument${unknown.length === 1 ? "" : "s"} for ${name}: ${unknown.join(", ")}. Valid arguments: ${known.join(", ")}.`, isError: true };
      }
    }
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
  const { metric, vintage, bucket_hours, agg } = input as {
    metric: string; vintage?: number; bucket_hours: number; agg?: string;
  };
  // series_bucketed compares block_id with '=' (case-sensitive): 'b2' used to
  // return all-null buckets, indistinguishable from "no readings".
  const block = normUpper(input.block);
  // A bare date is the Pacific (estate) calendar day -- sensor_readings holds
  // real instants. series_bucketed generates buckets from p_start THROUGH
  // p_end, so a bare end date D ends 1 ms before D+1's Pacific midnight: the
  // bucket starting at D+1 00:00 is excluded, every bucket within D included.
  const start = isBareDate(input.start) ? pacificMidnightUtc(input.start) : input.start as string;
  const end = isBareDate(input.end)
    ? new Date(Date.parse(pacificMidnightUtc(addDays(input.end, 1))) - 1).toISOString()
    : input.end as string;

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
  const notes = [`(Effective interval: buckets of ${bucket_hours} h starting from ${new Date(startMs).toISOString()} through ${new Date(endMs).toISOString()}${isBareDate(input.start) || isBareDate(input.end) ? " -- bare dates are whole Pacific calendar days (America/Los_Angeles)" : ""}; ${rounded.length} bucket(s), ${rounded.filter((r) => r.v != null).length} with readings.)`];
  const changes = seriesChanges(rounded.filter((r) => r.v != null).map((r) => ({ t: r.t, v: r.v })), metric);
  if (changes) notes.push(changes);
  if (block && rounded.length > 0 && rounded.every((r) => r.v == null)) {
    notes.push(`(Every bucket is empty for block ${block}: no ${metric} readings in this range for that block -- check the block id and the metric's date coverage.)`);
  }
  return { content: JSON.stringify(rounded) + "\n\n" + notes.join(" "), isError: false };
}

// Server-side summary of a bucketed series, so the model never does this
// arithmetic itself: first to last non-empty bucket, change per day (elapsed
// time between bucket starts), min and max.
function seriesChanges(points: { t: string; v: number }[], metric: string): string | null {
  if (points.length < 2) return null;
  const first = points[0], last = points[points.length - 1];
  const days = (Date.parse(last.t) - Date.parse(first.t)) / 86400000;
  const change = Math.round((last.v - first.v) * 100) / 100;
  const min = points.reduce((a, b) => (b.v < a.v ? b : a));
  const max = points.reduce((a, b) => (b.v > a.v ? b : a));
  const perDay = days > 0 ? `, ${change >= 0 ? "+" : ""}${Math.round((change / days) * 1000) / 1000}/day over ${Math.round(days * 100) / 100} days` : "";
  return `(Changes, computed server-side -- quote these, never recompute: ${metric} ${first.v} at ${first.t} -> ${last.v} at ${last.t}: ${change >= 0 ? "+" : ""}${change}${perDay}; min ${min.v} at ${min.t}, max ${max.v} at ${max.t}. A change over time is not evidence of its cause.)`;
}

// deno-lint-ignore no-explicit-any
async function getDerivedSeries(supabase: any, input: Record<string, unknown>, dataMode: string, domainReality: DomainReality): Promise<ToolResult> {
  const { vintage, start_date, end_date } = input as { vintage: number; start_date?: string; end_date?: string };
  // daily_derived.day is a Pacific day label stored at UTC midnight
  // (wall-clock), so [D 00:00Z, D+1 00:00Z) is exactly day D.
  const bounds = resolveDateBounds("day", start_date, end_date, "wallclock");
  if (bounds.error) return { content: bounds.error, isError: true };

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
    .limit(DERIVED_LIMIT + 1);
  query = applyBounds(query, "day", bounds);

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
  const truncated = rounded.length > DERIVED_LIMIT;
  const shown = truncated ? rounded.slice(0, DERIVED_LIMIT) : rounded;
  const notes = [
    `(${bounds.label} Returned ${shown.length} day(s); truncated: ${truncated}${truncated ? ` -- more than ${DERIVED_LIMIT} days match; narrow start_date/end_date` : ""}.)`,
  ];
  const changes = derivedChanges(shown);
  if (changes) notes.push(changes);
  return { content: JSON.stringify(shown) + "\n\n" + notes.join(" "), isError: false };
}

const DERIVED_LIMIT = 400;

// GDD is cumulative: report what was gained and per day. The other fields are
// daily values: mean, min and max with their dates. Computed here so the model
// never sums or differences daily rows itself.
// deno-lint-ignore no-explicit-any
function derivedChanges(rows: any[]): string | null {
  if (rows.length < 2) return null;
  const day = (r: { day: string }) => String(r.day).slice(0, 10);
  const parts: string[] = [];
  const gdd = rows.filter((r) => r.gdd_cumulative_calibrated != null);
  if (gdd.length >= 2) {
    const a = gdd[0], b = gdd[gdd.length - 1];
    const d = Math.round((Date.parse(day(b)) - Date.parse(day(a))) / 86400000);
    const gained = Math.round((b.gdd_cumulative_calibrated - a.gdd_cumulative_calibrated) * 10) / 10;
    parts.push(`GDD (calibrated) ${a.gdd_cumulative_calibrated} on ${dayLabel(day(a))} -> ${b.gdd_cumulative_calibrated} on ${dayLabel(day(b))}: +${gained} over ${d} days = +${d > 0 ? Math.round((gained / d) * 10) / 10 : gained}/day`);
  }
  for (const [field, dp] of [["vpd_kpa", 2], ["vpd_peak_kpa", 2], ["dtr_f", 2], ["et0_in", 3]] as const) {
    const vals = rows.filter((r) => r[field] != null);
    if (vals.length === 0) continue;
    const min = vals.reduce((x, y) => (y[field] < x[field] ? y : x));
    const max = vals.reduce((x, y) => (y[field] > x[field] ? y : x));
    const mean = Math.round((vals.reduce((t, r) => t + r[field], 0) / vals.length) * 10 ** dp) / 10 ** dp;
    parts.push(`${field} mean ${mean} over ${vals.length} days, min ${min[field]} (${dayLabel(day(min))}), max ${max[field]} (${dayLabel(day(max))})`);
  }
  return parts.length ? `(Changes, computed server-side over the rows above -- quote these, never recompute: ${parts.join("; ")}. Climate coinciding with a change elsewhere is not evidence that it caused it.)` : null;
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
  const current = currentToolVintage();
  const p_vintage = vintage ?? current;
  const p_as_of = as_of ?? (p_vintage === current
    ? (current === MOCK_SEASON ? MOCK_NOW : clock().toISOString())
    : `${p_vintage}-12-31T23:59:59Z`);

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
  // Stored lot codes are upper case and analysis types lower case (verified
  // 2026-10-07); 'ma24csv3', ' MA24CSV3 ' and 'Brix' used to return 0 rows.
  const lot_code = normUpper(input.lot_code);
  const lot_name = normText(input.lot_name);
  const analysis_type = normLower(input.analysis_type);
  const limit = input.limit as number | undefined;
  const cappedLimit = Math.min(limit && limit > 0 ? limit : 50, 200);
  // recorded_at holds real UTC instants: a bare date is the Pacific day.
  const bounds = resolveDateBounds("recorded_at", input.start_date, input.end_date, "instant");
  if (bounds.error) return { content: bounds.error, isError: true };

  const superseded = await fetchSupersededLotMap(supabase);
  if ("error" in superseded) return formatErrorForModel(superseded.error);

  // Shared filter conditions for the display query; chat_lot_analyses_scope
  // (20261007120000) applies the same ones in SQL.
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
    return applyBounds(q, "recorded_at", bounds);
  };

  // Scope: EVERY matching lot_code with its exact row count and first/last
  // recorded_at, the exact total, and every analysis_type on file for those
  // lots -- one jsonb value from the database, so no row cap applies.
  //
  // This replaced an unordered `.limit(1000)` scan of recorded_at. With 1,264
  // non-superseded rows that scan was short, and an arbitrary 1,000 rows
  // decided the "computed from every matching row" ranges: Colin's broad query
  // reported MA24CSV3 as ending March 27, 2025 while a targeted query showed
  // February 3, 2026, and every 2026 lot was missing from the lot list. The
  // two reasons a scope independent of the display cap exists still hold
  // (docs/SECURITY.md, get_lot_analyses): the multi-lot warning must reflect
  // the true match set, and a lot's date range must never be derived from the
  // most-recent-N rows on show.
  const { data: scope, error: scopeError } = await supabase.rpc("chat_lot_analyses_scope", {
    p_lot_code: lot_code ?? null,
    p_lot_name: lot_code ? null : lot_name ?? null,
    p_analysis_type: analysis_type ?? null,
    p_start: bounds.gte ?? null,
    p_end_exclusive: bounds.lt ?? null,
    p_end_inclusive: bounds.lte ?? null,
  });
  if (scopeError) return formatErrorForModel(scopeError);
  const lots: { lot_code: string; lot_name: string; n: number; first_at: string; last_at: string }[] = scope?.lots ?? [];
  const total = Number(scope?.total ?? 0);
  const rangeLabel = (min: string, max: string) => {
    const a = dayLabel(pacificDate(min));
    const b = dayLabel(pacificDate(max));
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
  // deno-lint-ignore no-explicit-any
  const rows = (data as any[]).map((r) => ({ ...r, recorded_on_pacific: pacificDate(r.recorded_at) }));

  const truncated = rows.length < total;
  const notes: string[] = [
    `(Source: InnoVint lot analyses. ${bounds.label} Result: returned ${rows.length} of ${total} matching row(s), most recent first; truncated: ${truncated}${truncated ? ` -- narrow with lot_code, analysis_type or a date range, or raise limit (max 200)` : ""}. recorded_on_pacific is each reading's estate (Pacific) calendar date.)`,
  ];

  if (lot_code && superseded.map.has(lot_code)) {
    notes.push(`(Note: ${lot_code} is a superseded duplicate lot_code -- InnoVint has two lot objects for this same physical wine. The canonical/complete record is ${superseded.map.get(lot_code)}.)`);
  }

  if (lots.length > 1) {
    notes.push(`(Note: this ${lot_name ? "lot_name search" : "query"} matches ${lots.length} distinct lots, not one -- ${lots.map((l) => `${l.lot_code} (${l.lot_name})`).join(", ")}. Treat these as separate lots/vintages unless you intend a cross-vintage comparison; narrow with lot_code for a single lot.)`);
    const returnedLots = new Set(rows.map((r) => r.lot_code));
    if (returnedLots.size < lots.length) {
      const missing = lots.filter((l) => !returnedLots.has(l.lot_code)).map((l) => l.lot_code).join(", ");
      notes.push(`(This capped, most-recent-first result only actually CONTAINS rows from: ${[...returnedLots].join(", ") || "none"}. Rows from ${missing} matched the same search but were pushed entirely out of the ${cappedLimit}-row window by more recent data from another lot -- pass lot_code to see one specifically, or narrow analysis_type/date range.)`);
    }
    notes.push(`(Per-lot row counts and date ranges, computed in the database over EVERY matching row, not just the rows shown -- ${lots.map((l) => `${l.lot_code}: ${l.n} row(s), ${rangeLabel(l.first_at, l.last_at)}`).join("; ")}.)`);
  } else if (lots.length === 1) {
    const [l] = lots;
    notes.push(`(${l.lot_code} lab-analysis date range across every matching row (${l.n}, computed in the database): ${rangeLabel(l.first_at, l.last_at)}.)`);
  } else if ((lot_code || lot_name) && total === 0 && rows.length === 0) {
    // Source selection (Colin 1a): "T-7 V-2" is an ETS ferment sample
    // (310310429), not an InnoVint lot. Point at the other source before the
    // model asks the user.
    const ets: { lab_sample_no: string; sample_description_raw: string; sample_type: string; vintage: number; collected_on: string; n_results: number; analysis_codes: string | null }[] = scope?.ets_samples ?? [];
    notes.push(ets.length
      ? `(No InnoVint lot matches ${lot_code ? `lot_code "${lot_code}"` : `lot_name "${lot_name}"`}, but ETS Labs holds ${ets.length} sample(s) this identifier names -- ${ets.map((e) => `${e.lab_sample_no} "${e.sample_description_raw}" (${e.sample_type}, ${e.vintage}, collected ${dayLabel(e.collected_on)}; ${e.n_results} result(s): ${e.analysis_codes ?? "none"})`).join("; ")}. Call ${ets.some((e) => ["berry_maturity", "berry_smoke", "trial_ferment"].includes(e.sample_type)) ? "get_berry_maturity / get_smoke_markers (vineyard samples) or " : ""}get_wine_lab_results with lab_sample_no for these before asking the user.)`
      : await (async () => {
        const extra = [await reissuePointer(supabase, lot_code ?? lot_name), await vesselPointer(supabase, lot_code, lot_code ? undefined : lot_name)].filter(Boolean);
        return extra.length
          ? `(No InnoVint lot matches ${lot_code ? `lot_code "${lot_code}"` : `lot_name "${lot_name}"`}, and no current ETS sample description or sample number matches it.) ${extra.join(" ")}`
          : `(No InnoVint lot matches ${lot_code ? `lot_code "${lot_code}"` : `lot_name "${lot_name}"`}, and no ETS Labs sample description or sample number matches it either -- not simulated, genuinely absent in both sources.)`;
      })());
  }

  // Temperature variants (Colin 1b): ethanol-20c and ethanol-60f are
  // different measurements; a request for one must surface the others.
  if (analysis_type) {
    const types: { analysis_type: string; n: number }[] = scope?.analysis_types ?? [];
    const fam = analyteFamily(analysis_type);
    const siblings = types.filter((t) => t.analysis_type !== analysis_type && analyteFamily(t.analysis_type) === fam);
    if (siblings.length) {
      notes.push(`(${total === 0 ? `No "${analysis_type}" rows match, but the` : "The"} same analyte is also on file for ${lots.length || "these"} lot(s) under ${siblings.map((t) => `"${t.analysis_type}" (${temperatureLabel(t.analysis_type)}, ${t.n} row(s))`).join(", ")}; "${analysis_type}" is ${temperatureLabel(analysis_type)}. These are different reference temperatures -- never interchange them; pass analysis_type to see one.)`);
    }
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
  // artifact. lot_analyses stores NEITHER field today. Grouped by the
  // reading's Pacific calendar date (was the UTC date, which put afternoon
  // and evening Pacific readings on the next day).
  const multiReadingGroups = new Map<string, { lot: string; type: string; date: string; values: number[] }>();
  for (const r of rows) {
    const key = `${r.lot_code}|${r.analysis_type}|${r.recorded_on_pacific}`;
    if (!multiReadingGroups.has(key)) multiReadingGroups.set(key, { lot: r.lot_code, type: r.analysis_type, date: r.recorded_on_pacific, values: [] });
    multiReadingGroups.get(key)!.values.push(r.value);
  }
  const multiGroups = [...multiReadingGroups.values()].filter((g) => g.values.length > 1);
  if (multiGroups.length > 0) {
    const listing = multiGroups.map((g) => `${g.lot} ${g.type} on ${dayLabel(g.date)} has ${g.values.length} readings (${g.values.join(", ")})`).join("; ");
    notes.push(`(Note: this result has more than one reading for the same lot/analyte/date in ${multiGroups.length} case(s) -- ${listing}. lot_analyses has no vessel or sample identifier to label these individually (InnoVint's own API exposes one, not yet synced -- see docs/SECURITY.md), but they are CONFIRMED real, separate InnoVint records -- different vessels or different lab submissions, not duplicate rows. Report every value; never average them, and never drop one as a suspected duplicate.)`);
  }

  // Across sources (identifier sweep): InnoVint has only "alcohol" for MA24CS
  // while ETS has ethanol_at_20c 15.22 and ethanol_at_60f 15.14 for the same
  // lot -- a request for one must name the other source's values too.
  if (analysis_type) {
    const lotCodes = lot_code ? [lot_code] : lots.map((l) => l.lot_code);
    // Auxiliary: a failure here notes itself rather than discarding the
    // InnoVint rows this call exists to return.
    const cross = await etsFamilyForLots(supabase, lotCodes, analyteFamily(analysis_type));
    if (cross.error) notes.push(`(Could not check ETS Labs for the same analyte: ${cross.error.message}. Call get_wine_lab_results with lot_code to check.)`);
    if (cross.lines.length) notes.push(crossSourceNote("ETS Labs (get_wine_lab_results)", cross.lines));
    if (lotCodes.length > CROSS_SOURCE_LOTS) notes.push(`(Cross-source check covered the first ${CROSS_SOURCE_LOTS} of ${lotCodes.length} lots; pass lot_code for one.)`);
  }

  const changes = lotChanges(rows, multiReadingGroups, truncated);
  if (changes) notes.push(changes);

  return { content: JSON.stringify(rows) + "\n\n" + notes.join(" "), isError: false };
}

const MAX_CHANGE_SERIES = 40;

// First-to-last change per lot and analysis type over the rows returned, in
// Pacific calendar days. Never averages: a date with several readings (real,
// separate vessels/submissions) can't be an endpoint of one change, so such a
// series reports its readings instead of a rate.
function lotChanges(
  // deno-lint-ignore no-explicit-any
  rows: any[],
  groups: Map<string, { lot: string; type: string; date: string; values: number[] }>,
  truncated: boolean,
): string | null {
  const series = new Map<string, { lot: string; type: string; unit: string | null; dates: string[] }>();
  for (const g of groups.values()) {
    const k = `${g.lot}|${g.type}`;
    if (!series.has(k)) series.set(k, { lot: g.lot, type: g.type, unit: rows.find((r) => r.lot_code === g.lot && r.analysis_type === g.type)?.unit ?? null, dates: [] });
    series.get(k)!.dates.push(g.date);
  }
  const lines: string[] = [];
  for (const sr of series.values()) {
    const dates = [...new Set(sr.dates)].sort();
    if (dates.length < 2) continue;
    const first = groups.get(`${sr.lot}|${sr.type}|${dates[0]}`)!, last = groups.get(`${sr.lot}|${sr.type}|${dates[dates.length - 1]}`)!;
    if (first.values.length > 1 || last.values.length > 1) {
      lines.push(`${sr.lot} ${sr.type}: not computed -- ${first.values.length > 1 ? dayLabel(first.date) : dayLabel(last.date)} has several separate readings (${(first.values.length > 1 ? first : last).values.join(", ")}), so there is no single endpoint; report the readings`);
      continue;
    }
    const pts: Point[] = [{ date: first.date, value: first.values[0] }, { date: last.date, value: last.values[0] }];
    lines.push(`${sr.lot} ${sr.type}: ${describeChange(pts, sr.unit ?? "", false)}`);
  }
  if (!lines.length) return null;
  const extra = lines.length > MAX_CHANGE_SERIES ? ` (${lines.length - MAX_CHANGE_SERIES} more series not summarised -- narrow the query)` : "";
  return `(Changes, computed server-side over the rows returned${truncated ? " -- the result is truncated, so a series' true first reading may be earlier than shown" : ""}; quote these, never recompute: ${lines.slice(0, MAX_CHANGE_SERIES).join("; ")}${extra}. A change is not evidence of its cause.)`;
}

// deno-lint-ignore no-explicit-any
async function getVessels(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { include_archived } = input as { include_archived?: boolean };
  // vessel_type is stored lower case ('Tank' used to return 0 rows). The
  // gateway's total_count mirrors this filter via vesselFilters().
  const { vessel_type, current_lot_name } = vesselFilters(input);

  // Fetch up to the scan cap, show VESSEL_LIMIT: the extra rows only count.
  let query = supabase
    .from("vessels")
    .select("vessel_id, code, vessel_type, capacity_gal, volume_gal, current_lot_name, current_lot_code, block_id, archived")
    .order("code", { ascending: true })
    .limit(SCAN_CAP);
  if (!include_archived) query = query.eq("archived", false);
  if (vessel_type) query = query.eq("vessel_type", vessel_type);
  if (current_lot_name) query = query.ilike("current_lot_name", `%${current_lot_name}%`);

  const { data, error } = await query;
  if (error) return formatErrorForModel(error);
  // deno-lint-ignore no-explicit-any
  const all = data as any[];
  const shown = all.slice(0, VESSEL_LIMIT);
  const totalText = all.length >= SCAN_CAP ? `at least ${SCAN_CAP} (the count itself reached the scan cap, so it is incomplete)` : String(all.length);
  return {
    content: JSON.stringify(shown) + `\n\n(Result: returned ${shown.length} of ${totalText} matching vessel(s); truncated: ${shown.length < all.length || all.length >= SCAN_CAP}.)`,
    isError: false,
  };
}

const VESSEL_LIMIT = 500;

// PostgREST's db-max-rows (and the MCP adapter's MAX_ROWS): a read with no
// explicit limit is silently capped here. Every scan that feeds a count or a
// coverage statement asks for exactly this many rows and reports itself
// INCOMPLETE if it gets them all, instead of presenting a partial set as
// exhaustive.
export const SCAN_CAP = 1000;

export function vesselFilters(input: Record<string, unknown>): { vessel_type?: string; current_lot_name?: string } {
  return { vessel_type: normLower(input.vessel_type), current_lot_name: normText(input.current_lot_name) };
}

function scanIncomplete(rows: unknown[] | null | undefined, what: string): string | null {
  return (rows?.length ?? 0) >= SCAN_CAP
    ? `(INCOMPLETE: the ${what} scan reached the ${SCAN_CAP}-row cap, so the coverage and counts below may be missing data -- say so; do not present them as complete.)`
    : null;
}

// ── Cross-tool pointers (identifier sweep, 2026-10-08) ─────────────────
// docs/SECURITY.md, "Identifier sweep: cross-source pointers".

const SAMPLE_TYPE_TOOL: Record<string, string> = {
  berry_maturity: "get_berry_maturity", berry_smoke: "get_smoke_markers", trial_ferment: "get_smoke_markers",
  must: "get_wine_lab_results", wine: "get_wine_lab_results", ferment: "get_wine_lab_results", stability_trial: "get_wine_lab_results",
};

// A superseded ETS sample number (e.g. 511110861) is excluded from every
// *_current view, so an exact lookup found nothing and said nothing. Its
// reissue carries reissue_of = the old number IN lab_samples_current, so this
// names it without reading the base table.
// deno-lint-ignore no-explicit-any
async function reissuePointer(supabase: any, ident: unknown): Promise<string | null> {
  const no = normUpper(ident);
  if (!no) return null;
  const { data, error } = await supabase
    .from("lab_samples_current")
    .select("lab_sample_no, sample_type, sample_description_raw, vintage, collected_on, reissue_of")
    .eq("reissue_of", no)
    .limit(20);
  if (error) return `(Could not check whether ${no} was reissued: ${error.message}.)`;
  // deno-lint-ignore no-explicit-any
  const rows = (data ?? []) as any[];
  if (!rows.length) return null;
  return `(${no} is a superseded ETS sample number: ETS reissued it as ${rows.map((r) => `${r.lab_sample_no} ("${r.sample_description_raw}", ${r.sample_type}, ${r.vintage}, collected ${dayLabel(r.collected_on)})`).join("; ")}. Superseded results are kept but never served -- look up ${rows.map((r) => `lab_sample_no "${r.lab_sample_no}" with ${SAMPLE_TYPE_TOOL[r.sample_type] ?? "get_wine_lab_results"}`).join(", ")} before asking the user.)`;
}

// A lot code that exists only as a vessel's current lot (e.g. XMAWHITELEES on
// TD-08) has no lab analyses in either source; point at get_vessels instead of
// calling it absent.
// deno-lint-ignore no-explicit-any
async function vesselPointer(supabase: any, lotCode: string | undefined, lotName?: string): Promise<string | null> {
  if (!lotCode && !lotName) return null;
  let q = supabase
    .from("vessels")
    .select("code, vessel_type, current_lot_name, current_lot_code, archived")
    .order("code", { ascending: true })
    .limit(20);
  q = lotCode ? q.eq("current_lot_code", lotCode) : q.ilike("current_lot_name", `%${lotName}%`);
  const { data, error } = await q;
  if (error) return `(Could not check vessels for this lot: ${error.message}.)`;
  // deno-lint-ignore no-explicit-any
  const rows = (data ?? []) as any[];
  if (!rows.length) return null;
  const names = [...new Set(rows.map((r) => r.current_lot_name).filter(Boolean))];
  return `(${lotCode ? `Lot code ${lotCode}` : `Lot name "${lotName}"`} has no lab analyses in InnoVint or ETS, but it is the current lot of ${rows.length} vessel(s): ${rows.map((r) => `${r.code} (${r.vessel_type}${r.archived ? ", archived" : ""}, current lot ${r.current_lot_code ?? "?"} "${r.current_lot_name ?? ""}")`).join("; ")}. Call get_vessels${names.length === 1 ? ` with current_lot_name "${names[0]}"` : ""}${rows.some((r) => r.archived) ? " and include_archived true" : ""} for its inventory.)`;
}

const CROSS_SOURCE_LOTS = 5;
const CROSS_SOURCE_ROWS = 20;

// InnoVint -> ETS: for these InnoVint lot codes, every ETS winery result in
// the same analyte family (ethanol_at_20c / ethanol_at_60f for alcohol/
// ethanol). Lot -> ETS sample resolution is chat_ets_winery_scope's own
// p_lot_code rule (exact description, or ets_lot_bridge), so this and
// get_wine_lab_results lot_code can never disagree.
// deno-lint-ignore no-explicit-any
async function etsFamilyForLots(supabase: any, lotCodes: string[], family: string): Promise<{ lines: string[]; error?: { message: string } }> {
  const lines: string[] = [];
  for (const code of lotCodes.slice(0, CROSS_SOURCE_LOTS)) {
    const { data: scope, error } = await supabase.rpc("chat_ets_winery_scope", { p_lot_code: code });
    if (error) return { lines, error };
    const samples: { id: number; lab_sample_no: string; sample_description_raw: string; sample_type: string; collected_on: string }[] = scope?.samples ?? [];
    const famCodes = ((scope?.analysis_codes ?? []) as { analysis_code: string }[]).map((c) => c.analysis_code).filter((c) => analyteFamily(c) === family);
    if (!samples.length || !famCodes.length) continue;
    const byId = new Map(samples.map((s) => [s.id, s]));
    const { data: res, error: resErr } = await supabase
      .from("lab_results_current")
      .select("sample_id, analysis_code, analysis_name_raw, result_raw, result_operator, units")
      .in("sample_id", [...byId.keys()])
      .in("analysis_code", famCodes)
      .order("analysis_code", { ascending: true })
      .limit(CROSS_SOURCE_ROWS);
    if (resErr) return { lines, error: resErr };
    const perSample = new Map<number, string[]>();
    // deno-lint-ignore no-explicit-any
    for (const r of (res ?? []) as any[]) {
      if (!perSample.has(r.sample_id)) perSample.set(r.sample_id, []);
      perSample.get(r.sample_id)!.push(`${r.analysis_code} (${temperatureLabel(r.analysis_code)}) ${r.result_operator === "<" ? "< " : ""}${r.result_raw}${r.units ? ` ${r.units}` : ""}`);
    }
    for (const [sid, values] of perSample) {
      const s = byId.get(sid)!;
      lines.push(`InnoVint ${code} <-> ETS ${s.lab_sample_no} "${s.sample_description_raw}" (${s.sample_type}, collected ${dayLabel(s.collected_on)}): ${values.join(", ")}`);
    }
  }
  return { lines };
}

// ETS -> InnoVint: for these ETS descriptions, every InnoVint reading in the
// same analyte family. Description -> lot code is the same rule reversed
// (exact code, or ets_lot_bridge); superseded duplicate lot codes are dropped
// (their chemistry is byte-identical to the canonical lot's).
// deno-lint-ignore no-explicit-any
async function innovintFamilyForDescriptions(supabase: any, descriptions: string[], family: string): Promise<{ lines: string[]; error?: { message: string } }> {
  const descs = [...new Set(descriptions)].slice(0, CROSS_SOURCE_LOTS);
  const { data: bridge, error: bridgeErr } = await supabase
    .from("ets_lot_bridge")
    .select("ets_description, lot_analyses_lot_code")
    .in("ets_description", descs);
  if (bridgeErr) return { lines: [], error: bridgeErr };
  const superseded = await fetchSupersededLotMap(supabase);
  if ("error" in superseded) return { lines: [], error: superseded.error };
  const pairs = new Map<string, string>(); // lot code -> description
  for (const d of descs) pairs.set(d.toUpperCase(), d);
  // deno-lint-ignore no-explicit-any
  for (const b of (bridge ?? []) as any[]) pairs.set(b.lot_analyses_lot_code, b.ets_description);
  for (const dup of superseded.map.keys()) pairs.delete(dup);
  const lines: string[] = [];
  for (const [code, desc] of pairs) {
    const { data: scope, error } = await supabase.rpc("chat_lot_analyses_scope", { p_lot_code: code });
    if (error) return { lines, error };
    const types = ((scope?.analysis_types ?? []) as { analysis_type: string }[]).map((t) => t.analysis_type).filter((t) => analyteFamily(t) === family);
    if (!types.length) continue;
    const { data: rows, error: rowsErr } = await supabase
      .from("lot_analyses")
      .select("lot_code, analysis_type, value, unit, recorded_at")
      .eq("lot_code", code)
      .in("analysis_type", types)
      .order("recorded_at", { ascending: false })
      .limit(CROSS_SOURCE_ROWS);
    if (rowsErr) return { lines, error: rowsErr };
    // deno-lint-ignore no-explicit-any
    const values = ((rows ?? []) as any[]).map((r) => `${r.analysis_type} (${temperatureLabel(r.analysis_type)}) ${r.value}${r.unit ? ` ${r.unit}` : ""} on ${dayLabel(pacificDate(r.recorded_at))}`);
    if (values.length) lines.push(`ETS "${desc}" <-> InnoVint ${code}: ${values.join(", ")}`);
  }
  return { lines };
}

const crossSourceNote = (other: string, lines: string[]) =>
  `(The same analyte is also on file in ${other} for the matching lot(s), all dates: ${lines.join("; ")}${lines.length >= CROSS_SOURCE_ROWS ? ` (first ${CROSS_SOURCE_ROWS} per lot)` : ""}. Different source and possibly a different reference temperature -- report each value with its source and label; never merge, average or interchange them.)`;

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
// dayLabel() itself now lives in query-rules.ts (shared with the gateway).

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
  const { vintage } = input as { vintage?: number };
  // Block ids are stored upper case: 'b2' used to return 0 rows (Colin 2c).
  const block_id = normUpper(input.block_id);
  // collected_on is a date: both bounds inclusive. Lets the Changes note cover
  // exactly the window asked about (the 2026-10-07 replay: asked for Aug 25 ->
  // Sep 22, the note covered the whole series, and the model -- correctly,
  // under the answer rules -- would not compute the window itself).
  const bounds = resolveDateBounds("collected_on", input.start_date, input.end_date, "date");
  if (bounds.error) return { content: bounds.error, isError: true };

  // lab_sample_no / collected_on_source / collected_on_inferred: provenance
  // columns added to the view by 20261007120000 (Colin 4).
  let query = supabase
    .from("berry_maturity_by_block")
    .select(`block_id, collected_on, vintage, ${MATURITY_ANALYTE_KEYS.join(", ")}, lab_sample_no, collected_on_source, collected_on_inferred`)
    .order("block_id", { ascending: true })
    .order("collected_on", { ascending: true })
    .limit(SCAN_CAP);
  if (vintage) query = query.eq("vintage", vintage);
  if (block_id) query = query.eq("block_id", block_id);
  query = applyBounds(query, "collected_on", bounds);

  const { data, error } = await query;
  if (error) return formatErrorForModel(error);

  // Coverage is computed from an UNFILTERED read of the same view plus
  // lab_samples_current's sample_type/vintage columns -- so the returned note
  // is honest about every vintage's actual shape regardless of what this call
  // filtered to. Each read asks for SCAN_CAP rows and says so if it hits it.
  const { data: allMaturity, error: allErr } = await supabase
    .from("berry_maturity_by_block")
    .select(`vintage, collected_on, ${MATURITY_ANALYTE_KEYS.join(", ")}`)
    .limit(SCAN_CAP);
  if (allErr) return formatErrorForModel(allErr);
  const { data: allSamples, error: samplesErr } = await supabase
    .from("lab_samples_current")
    .select("vintage, sample_type")
    .limit(SCAN_CAP);
  if (samplesErr) return formatErrorForModel(samplesErr);

  const SAMPLE_TYPE_LABEL: Record<string, string> = {
    berry_smoke: "smoke-taint screening", trial_ferment: "a trial micro-ferment",
  };
  const coverageLines: string[] = [];
  for (const v of allVintages()) {
    // deno-lint-ignore no-explicit-any
    const rows = (allMaturity as any[]).filter((r) => r.vintage === v);
    if (rows.length === 0) {
      // Vineyard sample types only: winery samples (wine, must, ferment,
      // stability_trial) share lab_samples_current since the ETS winery
      // ingest, and were being reported here as "berry sampling ... see
      // get_smoke_markers" (seen in the 2026-10-07 replay).
      // deno-lint-ignore no-explicit-any
      const otherTypes = [...new Set((allSamples as any[]).filter((s) => s.vintage === v && s.sample_type in SAMPLE_TYPE_LABEL).map((s) => s.sample_type))];
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
    const dateLabel = dates.length === 1 ? `1 collection date (${dayLabel(dates[0])})` : `${dates.length} collection dates (${dates.map(dayLabel).join(", ")})`;
    coverageLines.push(
      absent.length === 0
        ? `${v}: full nine-analyte panel across ${dateLabel}.`
        : `${v}: only ${present.map((k) => MATURITY_ANALYTE_LABELS[k]).join("/")} measured, across ${dateLabel} -- ${absent.map((k) => MATURITY_ANALYTE_LABELS[k]).join(", ")} NOT measured that vintage (absent because a smaller panel ran, not zero or missing entry).`,
    );
  }
  const notes = [
    scanIncomplete(data, "result"), scanIncomplete(allMaturity, "coverage"), scanIncomplete(allSamples, "sample"),
    `(Source: ETS Labs berry-maturity samples. ${bounds.label} Result: ${(data ?? []).length} block/date row(s); truncated: ${(data ?? []).length >= SCAN_CAP}. lab_sample_no is the ETS sample number; collected_on_inferred=true means the collection date was inferred from the lab's receipt date, not recorded -- say so when quoting it.)`,
    `Coverage (all vintages, regardless of this call's filters, computed from the data on this call): ${coverageLines.join(" ")}`,
    berryChanges(data ?? []),
  ].filter(Boolean);
  return { content: JSON.stringify(data ?? []) + "\n\n" + notes.join(" "), isError: false };
}

const MATURITY_UNITS: Record<string, string> = {
  brix: "Brix", ph: "", titratable_acidity: "g/L", l_malic_acid: "g/L", glucose_fructose: "g/L",
  berry_weight_g: "g", berry_volume_ml: "mL", berry_volume_variability_pct: "%", sugar_per_berry_mg: "mg",
};

// Per block and vintage, per analyte: first to last collection date, change
// per day, and every step between consecutive dates (Colin 5: 2.4 Brix over
// 28 days was reported as ~0.3/day; correct 0.086/day).
// deno-lint-ignore no-explicit-any
function berryChanges(rows: any[]): string | null {
  const groups = new Map<string, typeof rows>();
  for (const r of rows) {
    const k = `${r.block_id} ${r.vintage}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k)!.push(r);
  }
  const lines: string[] = [];
  for (const [k, rs] of groups) {
    for (const key of MATURITY_ANALYTE_KEYS) {
      const pts: Point[] = rs.filter((r) => r[key] != null).map((r) => ({ date: r.collected_on, value: Number(r[key]) }));
      const d = describeChange(pts, MATURITY_UNITS[key]);
      if (d) lines.push(`${k} ${MATURITY_ANALYTE_LABELS[key]}: ${d}`);
    }
  }
  return lines.length
    ? `(Changes, computed server-side -- quote these, never recompute: ${lines.join("; ")}. Inferred collection dates make the day counts approximate. A change is not evidence of its cause.)`
    : null;
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
  const { vintage } = input as { vintage?: number };
  // Stored upper case: 'b2' used to return 0 rows against 30 for 'B2' (Colin 2c).
  const block_id = normUpper(input.block_id);
  const lab_sample_no = normUpper(input.lab_sample_no);

  // Samples first (not lab_results_current directly): lab_results_current
  // carries no block_id/vintage/collected_on of its own (it's `select
  // r.*` over lab_results, joined only to filter -- see
  // 20260920140000_lab_samples_current.sql), and it's a view, not a
  // table with a declared FK, so PostgREST embedding across it isn't
  // relied on here -- the join is done explicitly in this function
  // instead, against sample ids resolved from lab_samples_current.
  let sampleQuery = supabase
    .from("lab_samples_current")
    .select("id, lab_sample_no, sample_description_raw, sample_type, block_id, vintage, collected_on, collected_on_source")
    .limit(SCAN_CAP);
  if (vintage) sampleQuery = sampleQuery.eq("vintage", vintage);
  if (block_id) sampleQuery = sampleQuery.eq("block_id", block_id);
  if (lab_sample_no) sampleQuery = sampleQuery.eq("lab_sample_no", lab_sample_no);
  const { data: samples, error: sampleErr } = await sampleQuery;
  if (sampleErr) return formatErrorForModel(sampleErr);

  // deno-lint-ignore no-explicit-any
  const sampleById = new Map((samples as any[]).map((s) => [s.id, s]));
  const sampleIds = [...sampleById.keys()];

  let rows: unknown[] = [];
  let resultsScan: unknown[] = [];
  if (sampleIds.length > 0) {
    const { data: results, error: resultsErr } = await supabase
      .from("lab_results_current")
      .select("sample_id, analysis_name_raw, analysis_code, result_raw, result_numeric, result_operator, units, analyzed_at")
      .in("sample_id", sampleIds)
      .in("analysis_code", SMOKE_ANALYSIS_CODES)
      .limit(SCAN_CAP);
    if (resultsErr) return formatErrorForModel(resultsErr);
    resultsScan = results;
    // deno-lint-ignore no-explicit-any
    rows = (results as any[]).map((r) => {
      const s = sampleById.get(r.sample_id);
      return {
        block_id: s?.block_id ?? null,
        vintage: s?.vintage,
        collected_on: s?.collected_on,
        collected_on_source: s?.collected_on_source,
        collected_on_inferred: s?.collected_on_source === "inferred_from_receipt",
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

  // Coverage: unfiltered read of every current sample, so the note is
  // honest about every vintage's smoke-screening status regardless of this
  // call's own filters; reported INCOMPLETE if it ever reaches the cap.
  const { data: allSamples, error: allSamplesErr } = await supabase
    .from("lab_samples_current")
    .select("vintage, block_id, collected_on, sample_type, sample_description_raw")
    .limit(SCAN_CAP);
  if (allSamplesErr) return formatErrorForModel(allSamplesErr);
  const coverageLines: string[] = [];
  for (const v of allVintages()) {
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
  const reissue = lab_sample_no && sampleIds.length === 0 ? await reissuePointer(supabase, lab_sample_no) : null;
  const notes = [
    scanIncomplete(samples, "sample"), scanIncomplete(resultsScan, "result"), scanIncomplete(allSamples, "coverage"), reissue,
    `(Source: ETS Labs smoke-marker results. Result: ${rows.length} row(s) from ${sampleIds.length} sample(s); truncated: ${resultsScan.length >= SCAN_CAP}.${lab_sample_no && sampleIds.length === 0 && !reissue ? ` No sample ${lab_sample_no} with these filters -- if it is a berry-maturity or winery sample, use get_berry_maturity or get_wine_lab_results.` : ""})`,
    `Coverage (all vintages, regardless of this call's filters, computed from the data on this call): ${coverageLines.join(" ")} Units are basis-specific (µg/kg = berry mass, µg/L = liquid/juice) and are never interchangeable -- always read the units field on each row.`,
  ].filter(Boolean);
  return { content: JSON.stringify(rows) + "\n\n" + notes.join(" "), isError: false };
}

// ETS winery ingestion (2026-09-20): lab_samples/lab_results are the same
// lossless base tables Phase 1's berry tools already guard against --
// this tool reads lab_samples_current/lab_results_current (through
// chat_ets_winery_scope, which lists the winery sample types) for the exact
// same reason: superseded reissue rows must never resurface. Never gated by
// real-only mode, same reasoning as the berry tools: no simulated
// counterpart has ever existed for ETS lab data.
//
// sample_description is a KNOWN substring-collision risk in this exact
// dataset -- confirmed live: 'MA22CS' is a literal substring of
// 'MA22CSV2'/'MA22CSV3', and all three are vintage 2022, so `vintage`
// does NOT disambiguate. Every matching sample_description_raw comes from
// the full sample set (one jsonb value from the database, no row cap), never
// from whatever survives the results row cap, and is reported explicitly
// whenever a search matches more than one. lot_code and lab_sample_no
// (2026-10-07) are the exact alternatives.
// deno-lint-ignore no-explicit-any
async function getWineLabResults(supabase: any, input: Record<string, unknown>): Promise<ToolResult> {
  const { vintage, sample_type, limit } = input as { vintage?: number; sample_type?: string; limit?: number };
  const sample_description = normText(input.sample_description);
  // Sample numbers and lot codes are stored upper case, analysis codes lower
  // case (verified 2026-10-07); 'Ethanol_At_20C' used to return 0 rows.
  const lab_sample_no = normUpper(input.lab_sample_no);
  const lot_code = normUpper(input.lot_code);
  const analysis_code = normLower(input.analysis_code);
  const cappedLimit = Math.min(limit && limit > 0 ? limit : 100, 300);
  // ETS analyzed_at is the lab's wall-clock time marked +00, so a bare date
  // is [D 00:00Z, D+1 00:00Z) -- the lab's own calendar day.
  const bounds = resolveDateBounds("analyzed_at", input.start_date, input.end_date, "wallclock");
  if (bounds.error) return { content: bounds.error, isError: true };

  // The full match set, in one jsonb value from the database (20261007120000):
  // matching samples, the exact result total, and every analysis_code on file
  // for them. The display query below fetches results for exactly these
  // sample ids, so display and coverage can never disagree.
  const { data: scope, error: scopeErr } = await supabase.rpc("chat_ets_winery_scope", {
    p_sample_type: sample_type ?? null,
    p_description: sample_description ?? null,
    p_lab_sample_no: lab_sample_no ?? null,
    p_lot_code: lot_code ?? null,
    p_vintage: vintage ?? null,
    p_analysis_code: analysis_code ?? null,
    p_start: bounds.gte ?? null,
    p_end_exclusive: bounds.lt ?? null,
    p_end_inclusive: bounds.lte ?? null,
  });
  if (scopeErr) return formatErrorForModel(scopeErr);
  const samples: { id: number; lab_sample_no: string; sample_description_raw: string; sample_type: string; vintage: number; collected_on: string; collected_on_source: string; fruit_source: string | null }[] = scope?.samples ?? [];
  const total = Number(scope?.total ?? 0);

  const sampleById = new Map(samples.map((s) => [s.id, s]));
  const sampleIds = [...sampleById.keys()];

  // deno-lint-ignore no-explicit-any
  const fetchResults = async (codes: string[] | null, max: number): Promise<{ data?: any[]; error?: { message: string } }> => {
    let q = supabase
      .from("lab_results_current")
      .select("id, sample_id, analysis_name_raw, analysis_code, result_raw, result_numeric, result_operator, units, analyzed_at")
      .in("sample_id", sampleIds)
      .order("analyzed_at", { ascending: false })
      .limit(max);
    if (codes) q = q.in("analysis_code", codes);
    q = applyBounds(q, "analyzed_at", bounds);
    const { data, error } = await q;
    return error ? { error } : { data };
  };

  let rows: Record<string, unknown>[] = [];
  if (sampleIds.length > 0) {
    const fetched = await fetchResults(analysis_code ? [analysis_code] : null, cappedLimit);
    if (fetched.error) return formatErrorForModel(fetched.error);
    const results = fetched.data!;

    // Reconciliation status per result row -- the "flag overlaps" surface
    // the owner chose over skipping duplicated analytes. Fetched by id
    // (the view's own lab_result_id), not re-derived here.
    const resultIds = results.map((r) => r.id);
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

    rows = results.map((r) => {
      const s = sampleById.get(r.sample_id);
      const recon = reconById.get(r.id);
      return {
        sample_description: s?.sample_description_raw,
        sample_type: s?.sample_type,
        vintage: s?.vintage,
        collected_on: s?.collected_on,
        collected_on_source: s?.collected_on_source,
        collected_on_inferred: s?.collected_on_source === "inferred_from_receipt",
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

  const truncated = rows.length < total;
  const notes: string[] = [
    `(Source: ETS Labs winery samples. ${bounds.label} Result: returned ${rows.length} of ${total} matching result(s), most recent first; truncated: ${truncated}${truncated ? " -- narrow with lab_sample_no, lot_code, analysis_code or a date range, or raise limit (max 300)" : ""}.)`,
  ];

  const searched = [
    lab_sample_no && `lab_sample_no "${lab_sample_no}"`, lot_code && `lot_code "${lot_code}"`,
    sample_description && `sample_description "${sample_description}"`, vintage && `vintage ${vintage}`, sample_type && `sample_type ${sample_type}`,
  ].filter(Boolean).join(", ");

  // Precomputed per-description date range (dayLabel()-formatted, in
  // words) over EVERY matching sample -- the sample set comes from the
  // database in full, never from the capped result rows.
  const byDescription = new Map<string, { type: string; vintage: number; dates: string[]; nos: string[] }>();
  for (const s of samples) {
    const key = s.sample_description_raw;
    if (!byDescription.has(key)) byDescription.set(key, { type: s.sample_type, vintage: s.vintage, dates: [], nos: [] });
    byDescription.get(key)!.dates.push(s.collected_on);
    byDescription.get(key)!.nos.push(s.lab_sample_no);
  }
  if (byDescription.size === 0) {
    // Source selection: point at the other tool/source before the model asks
    // the user (Colin 1a).
    const vineyard: { lab_sample_no: string; sample_description_raw: string; sample_type: string; block_id: string | null; vintage: number; collected_on: string }[] = scope?.vineyard_samples ?? [];
    const lots: { lot_code: string; lot_name: string; n: number; first_at: string; last_at: string }[] = scope?.innovint_lots ?? [];
    const pointers: string[] = [];
    if (vineyard.length) {
      pointers.push(`ETS vineyard sample(s) match: ${vineyard.map((v) => `${v.lab_sample_no} "${v.sample_description_raw}" (${v.sample_type}, ${v.block_id ?? "block unresolved"}, ${v.vintage}, ${dayLabel(v.collected_on)})`).join("; ")} -- call ${vineyard.some((v) => v.sample_type === "berry_maturity") ? "get_berry_maturity" : ""}${vineyard.some((v) => v.sample_type === "berry_maturity") && vineyard.some((v) => v.sample_type !== "berry_maturity") ? " / " : ""}${vineyard.some((v) => v.sample_type !== "berry_maturity") ? "get_smoke_markers" : ""} for them`);
    }
    const reissue = await reissuePointer(supabase, lab_sample_no ?? sample_description);
    const clause = (note: string) => note.slice(1, -1).replace(/ before asking the user\.$/, "").replace(/\.$/, "");
    if (reissue) pointers.push(clause(reissue));
    if (!lots.length) {
      const vessel = await vesselPointer(supabase, lot_code ?? normUpper(sample_description));
      if (vessel) pointers.push(clause(vessel));
    }
    if (lots.length) {
      pointers.push(`InnoVint lot(s) match: ${lots.map((l) => `${l.lot_code} (${l.lot_name}, ${l.n} analyses, ${dayLabel(pacificDate(l.first_at))} through ${dayLabel(pacificDate(l.last_at))})`).join("; ")} -- call get_lot_analyses with lot_code for InnoVint's own analyses`);
    }
    notes.push(pointers.length
      ? `(No ETS winery sample matches ${searched || "this search"}. ${pointers.join(". ")}. Do this before asking the user.)`
      : `(No winery samples match this search${searched ? ` for ${searched}` : ""}, and no ETS vineyard sample or InnoVint lot matches it either -- not simulated, genuinely absent for this scope.)`);
  } else {
    const lines = [...byDescription.entries()].map(([desc, d]) => {
      const sorted = [...new Set(d.dates)].sort();
      const range = sorted.length === 1 ? dayLabel(sorted[0]) : `${dayLabel(sorted[0])} through ${dayLabel(sorted[sorted.length - 1])}`;
      return `${desc} (${d.type}, ${d.vintage}; sample(s) ${d.nos.join(", ")}): ${range}`;
    });
    if (byDescription.size > 1) {
      notes.push(`(Note: this search matches ${byDescription.size} distinct sample_description values, not one -- ${[...byDescription.keys()].join(", ")}. Treat these as separate lots unless a cross-lot comparison is intended; pass lot_code or lab_sample_no for one.)`);
    }
    notes.push(`(Collection-date coverage per matched lot, computed in the database over every matching sample, not just the rows shown -- ${lines.join("; ")}.)`);
  }

  // Temperature variants (Colin 1b): ethanol_at_20c and ethanol_at_60f are
  // both on file for 602250939; a request for one must surface the other,
  // with its values, so a model never reports one as "the" ethanol.
  const codes: { analysis_code: string; n: number }[] = scope?.analysis_codes ?? [];
  if (analysis_code && sampleIds.length > 0) {
    const fam = analyteFamily(analysis_code);
    const siblings = codes.filter((c) => c.analysis_code !== analysis_code && analyteFamily(c.analysis_code) === fam);
    if (siblings.length) {
      const sib = await fetchResults(siblings.map((c) => c.analysis_code), VARIANT_ROWS);
      if (sib.error) return formatErrorForModel(sib.error);
      const values = sib.data!.map((r) => `${sampleById.get(r.sample_id)?.lab_sample_no} ${sampleById.get(r.sample_id)?.sample_description_raw}: ${r.analysis_name_raw} ${r.result_operator === "<" ? "< " : ""}${r.result_raw} ${r.units ?? ""}`.trim());
      notes.push(`(${total === 0 ? `No "${analysis_code}" results match, but the` : "The"} same analyte is also on file for these samples at another reference temperature: ${siblings.map((c) => `${c.analysis_code} (${temperatureLabel(c.analysis_code)}, ${c.n} result(s))`).join(", ")}; ${analysis_code} is ${temperatureLabel(analysis_code)}. Values: ${values.join("; ")}${sib.data!.length >= VARIANT_ROWS ? ` (first ${VARIANT_ROWS} shown)` : ""}. Different reference temperatures -- report each with its own label, never interchange them.)`);
    } else if (total === 0 && codes.length) {
      notes.push(`(analysis_code "${analysis_code}" matches nothing for these samples. Codes on file for them: ${codes.map((c) => c.analysis_code).join(", ")}.)`);
    }
  }

  // Across sources (identifier sweep): the InnoVint readings of the same
  // analyte family for the matching lot(s), via ets_lot_bridge.
  if (analysis_code && samples.length > 0) {
    const cross = await innovintFamilyForDescriptions(supabase, samples.map((s) => s.sample_description_raw), analyteFamily(analysis_code));
    if (cross.error) notes.push(`(Could not check InnoVint for the same analyte: ${cross.error.message}. Call get_lot_analyses with lot_code to check.)`);
    if (cross.lines.length) notes.push(crossSourceNote("InnoVint (get_lot_analyses)", cross.lines));
  }

  const changes = wineChanges(rows, truncated);
  if (changes) notes.push(changes);

  return { content: JSON.stringify(rows) + "\n\n" + notes.join(" "), isError: false };
}

const VARIANT_ROWS = 50;

// Per lot (sample_description) and analysis_code over the rows returned,
// by collection date. Censored '<' and text-only results are left out (and
// counted); a date with more than one sample has no single endpoint.
function wineChanges(rows: Record<string, unknown>[], truncated: boolean): string | null {
  const series = new Map<string, { desc: string; code: string; units: string; byDate: Map<string, number[]>; censored: number }>();
  for (const r of rows) {
    const k = `${r.sample_description}|${r.analysis_code}`;
    if (!series.has(k)) series.set(k, { desc: String(r.sample_description), code: String(r.analysis_code), units: String(r.units ?? ""), byDate: new Map(), censored: 0 });
    const sr = series.get(k)!;
    if (r.result_operator !== "=" || r.result_numeric == null) { sr.censored++; continue; }
    const d = String(r.collected_on);
    if (!sr.byDate.has(d)) sr.byDate.set(d, []);
    sr.byDate.get(d)!.push(Number(r.result_numeric));
  }
  const lines: string[] = [];
  for (const sr of series.values()) {
    const dates = [...sr.byDate.keys()].sort();
    if (dates.length < 2) continue;
    const multi = dates.filter((d) => sr.byDate.get(d)!.length > 1);
    if (multi.length) {
      lines.push(`${sr.desc} ${sr.code}: not computed -- ${multi.map(dayLabel).join(", ")} ha${multi.length === 1 ? "s" : "ve"} several samples; report them individually`);
      continue;
    }
    const d = describeChange(dates.map((date) => ({ date, value: sr.byDate.get(date)![0] })), sr.units);
    lines.push(`${sr.desc} ${sr.code}: ${d}${sr.censored ? ` (${sr.censored} censored or text-only result(s) left out)` : ""}`);
  }
  if (!lines.length) return null;
  const extra = lines.length > MAX_CHANGE_SERIES ? ` (${lines.length - MAX_CHANGE_SERIES} more series not summarised -- narrow the query)` : "";
  return `(Changes by collection date, computed server-side over the rows returned${truncated ? " -- the result is truncated, so a series may start earlier than shown" : ""}; quote these, never recompute: ${lines.slice(0, MAX_CHANGE_SERIES).join("; ")}${extra}. A change is not evidence of its cause.)`;
}
