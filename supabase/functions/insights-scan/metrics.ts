// metrics.ts — data-gathering for the insights scanner. All lag/effect
// math happens in-memory in index.ts against the series this module
// fetches; this file is purely "get real, daily, real/mock-precedence-
// resolved data out of Postgres" using existing project infrastructure
// (series_bucketed(), daily_derived, real_data_sources) rather than
// reimplementing that precedence logic a third time.

import type { SupabaseClient } from "@supabase/server";

export const TIER_A_METRICS = [
  "air_temp", "humidity", "precipitation", "soil_moisture", "soil_temp", "solar",
  "gdd_day", "dtr", "vpd_kpa", "vpd_peak_kpa", "et0_in",
] as const;
export type TierAMetric = typeof TIER_A_METRICS[number];

const RAW_METRIC_KEYS = ["air_temp", "humidity", "precipitation", "soil_moisture", "soil_temp", "solar"];
const SUM_METRICS = new Set(["precipitation"]); // everything else averages

// Coarse existence check ("does any real data exist for this metric/
// vintage at all") -- distinct from MIN_N_TIER_A in index.ts, which
// gates the actual bucketed daily-pairs count used in a correlation.
const MIN_RAW_ROWS_FOR_REAL_EXISTENCE = 100;

const SEASON_START_MONTH_DAY = "04-01";
const SEASON_END_MONTH_DAY = "11-01"; // exclusive upper bound -> through Oct 31

function dayIndex(isoDate: string, vintage: number): number {
  const start = Date.parse(`${vintage}-${SEASON_START_MONTH_DAY}T00:00:00Z`);
  return Math.round((Date.parse(isoDate) - start) / 86400000);
}

/** metric -> vintage -> Map<dayIndex, value>, only for vintages where
 *  that metric is real (per realVintagesByMetric). Fetches each metric's
 *  full season exactly once per real vintage -- lag search over this is
 *  pure in-memory work in index.ts, not repeated queries. */
export async function fetchTierAMetrics(
  sb: SupabaseClient,
  realByMetric: Map<string, Set<number>>,
): Promise<Record<string, Record<number, Map<number, number>>>> {
  const series: Record<string, Record<number, Map<number, number>>> = {};

  for (const metric of TIER_A_METRICS) {
    series[metric] = {};
    const vintages = [...(realByMetric.get(metric) ?? [])];
    for (const v of vintages) {
      const start = `${v}-${SEASON_START_MONTH_DAY}T00:00:00Z`;
      const end = `${v}-${SEASON_END_MONTH_DAY}T00:00:00Z`;
      const map = new Map<number, number>();

      if (RAW_METRIC_KEYS.includes(metric)) {
        const { data, error } = await sb.rpc("series_bucketed", {
          p_metric: metric, p_block: null, p_vintage: v,
          p_start: start, p_end: end, p_bucket: "1 day",
          p_agg: SUM_METRICS.has(metric) ? "sum" : "avg",
        });
        if (error) { console.error(`fetchTierAMetrics: series_bucketed(${metric}, ${v})`, error); continue; }
        for (const row of data ?? []) {
          if (row.v != null) map.set(dayIndex(row.t, v), Number(row.v));
        }
      } else {
        // Derived metrics: one query per vintage covers all 5 at once.
        if (!series.__derivedFetched) series.__derivedFetched = {};
        // (fetched below, once per vintage, shared across the 5 derived metrics)
      }
      series[metric][v] = map;
    }
  }

  // Derived metrics: fetch once per distinct vintage across all 5,
  // instead of once per (metric, vintage) -- daily_derived carries all
  // five in one row.
  const derivedMetrics = TIER_A_METRICS.filter(m => !RAW_METRIC_KEYS.includes(m));
  const derivedVintages = new Set<number>();
  for (const m of derivedMetrics) for (const v of realByMetric.get(m) ?? []) derivedVintages.add(v);

  for (const v of derivedVintages) {
    const { data, error } = await sb
      .from("daily_derived")
      .select("day, gdd_day_calibrated, dtr_f_calibrated, vpd_kpa, vpd_peak_kpa, et0_in")
      .eq("vintage", v);
    if (error) { console.error(`fetchTierAMetrics: daily_derived(${v})`, error); continue; }
    const cols: Record<string, string> = {
      gdd_day: "gdd_day_calibrated", dtr: "dtr_f_calibrated",
      vpd_kpa: "vpd_kpa", vpd_peak_kpa: "vpd_peak_kpa", et0_in: "et0_in",
    };
    for (const m of derivedMetrics) {
      if (!(realByMetric.get(m) ?? new Set()).has(v)) continue;
      const map = new Map<number, number>();
      for (const row of data ?? []) {
        const val = (row as Record<string, unknown>)[cols[m]];
        if (val != null) map.set(dayIndex(row.day as string, v), Number(val));
      }
      series[m][v] = map;
    }
  }

  return series;
}

/** metric -> Set<real vintage>, derived live from real_data_sources +
 *  metric_derivation -- no hardcoded vintage list anywhere. Raw metrics
 *  checked directly against sensor_readings; derived metrics real for a
 *  vintage iff ALL their declared metric_derivation inputs are real for
 *  that vintage. */
export async function realVintagesByMetric(
  sb: SupabaseClient,
  allMetrics: readonly string[],
): Promise<Map<string, Set<number>>> {
  // These two reads are foundational -- every downstream eligibility
  // decision depends on them. A permission/connectivity failure here must
  // abort loudly, not silently degrade into "every metric has zero real
  // vintages," which would look identical to a genuine all-mock dataset
  // in the resulting insights rows (all excluded_low_n) and be very hard
  // to tell apart from a real infrastructure problem after the fact.
  const { data: vintageRows, error: vintageErr } = await sb.from("vintages").select("vintage").eq("is_current", false).order("vintage");
  if (vintageErr) throw new Error(`realVintagesByMetric: could not read vintages: ${vintageErr.message}`);
  const vintages = (vintageRows ?? []).map((r: { vintage: number }) => r.vintage);

  const { data: counts, error: countsErr } = await sb.rpc("real_metric_vintage_counts", {
    p_metrics: RAW_METRIC_KEYS, p_vintages: vintages,
  });
  if (countsErr) throw new Error(`realVintagesByMetric: real_metric_vintage_counts failed: ${countsErr.message}`);

  const rawReal = new Map<string, Set<number>>(RAW_METRIC_KEYS.map(m => [m, new Set<number>()]));
  for (const row of counts ?? []) {
    if (Number(row.n) >= MIN_RAW_ROWS_FOR_REAL_EXISTENCE) rawReal.get(row.metric_key)?.add(row.vintage);
  }

  const { data: derivation, error: derivationErr } = await sb.from("metric_derivation").select("*");
  if (derivationErr) throw new Error(`realVintagesByMetric: could not read metric_derivation: ${derivationErr.message}`);

  const result = new Map<string, Set<number>>();
  for (const m of allMetrics) {
    if (RAW_METRIC_KEYS.includes(m)) { result.set(m, rawReal.get(m) ?? new Set()); continue; }
    const inputs = (derivation ?? []).filter((d: { metric_key: string }) => d.metric_key === m)
      .map((d: { derived_from: string }) => d.derived_from);
    const real = new Set<number>(vintages.filter((v: number) => inputs.every((inp: string) => rawReal.get(inp)?.has(v))));
    result.set(m, real);
  }
  return result;
}

// ── Tier B: the single hardcoded join (see migration comment) ────────
export interface TierBPoint { block_id: string; vintage: number; irrigation: number; yield: number }

export async function fetchTierBPairs(sb: SupabaseClient): Promise<TierBPoint[]> {
  const [{ data: irrRows, error: irrErr }, { data: yieldRows, error: yieldErr }] = await Promise.all([
    sb.from("sensor_readings")
      .select("block_id, vintage, value")
      .eq("metric_key", "irrigation_volume")
      .eq("source_system", "farm_irrigation_log")
      .not("block_id", "is", null),
    sb.from("harvest_receipts")
      .select("block_id, vintage, weight_tons")
      .eq("source_system", "innovint")
      .not("block_id", "is", null),
  ]);
  if (irrErr) { console.error("fetchTierBPairs: irrigation query failed", irrErr); return []; }
  if (yieldErr) { console.error("fetchTierBPairs: harvest query failed", yieldErr); return []; }

  const irrByKey = new Map<string, number>();
  for (const r of irrRows ?? []) {
    const key = `${r.block_id}|${r.vintage}`;
    irrByKey.set(key, (irrByKey.get(key) ?? 0) + Number(r.value));
  }
  const yieldByKey = new Map<string, number>();
  for (const r of yieldRows ?? []) {
    const key = `${r.block_id}|${r.vintage}`;
    yieldByKey.set(key, (yieldByKey.get(key) ?? 0) + Number(r.weight_tons));
  }

  const points: TierBPoint[] = [];
  for (const [key, irrigation] of irrByKey) {
    const yieldVal = yieldByKey.get(key);
    if (yieldVal === undefined) continue; // real irrigation but no real yield for this block/vintage -- not joinable
    const [block_id, vintageStr] = key.split("|");
    points.push({ block_id, vintage: Number(vintageStr), irrigation, yield: yieldVal });
  }
  return points;
}
