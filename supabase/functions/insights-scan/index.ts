import "@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "@supabase/server";
import { spearman, fisherCombine, benjaminiHochberg, rankConcordance, Pair } from "./stats.ts";
import { fetchTierAMetrics, fetchTierBPairs, realVintagesByMetric, TIER_A_METRICS } from "./metrics.ts";
import { narrateFindings } from "./narrate.ts";

const MIN_N_TIER_A = 100;
const MIN_N_TIER_B = 4;
const MIN_EFFECT = 0.30;
// Materially stricter than MIN_EFFECT: single_season findings have no
// cross-season replication to lean on, so the bar moves from
// conventional "moderate" (0.30) to conventional "strong" (0.50) rather
// than an arbitrary bump.
const MIN_EFFECT_SINGLE_SEASON = 0.50;
const FDR_Q = 0.10;
const SURFACE_CAP = 5;
const MAX_LAG = 21;

interface PendingRow {
  row: Record<string, unknown>;
  p?: number;
}

// pg_cron-only: no real user is ever behind this call. Same auth mode as
// notify-admin-approval, for the same reason (server-to-server, secret
// key only -- see docs/SECURITY.md's two-key-system note).
export default {
  fetch: withSupabase({ auth: ["secret"] }, async (_req, ctx) => {
    try {
      const runId = crypto.randomUUID();
      const pending: PendingRow[] = [];

      // Foundational read -- a permission/connectivity failure here must
      // abort loudly (see the matching comment in metrics.ts), not
      // silently treat every pair as non-tautological.
      const { data: derivation, error: derivationErr } = await ctx.supabaseAdmin.from("metric_derivation").select("*");
      if (derivationErr) throw new Error(`could not read metric_derivation: ${derivationErr.message}`);
      const isDerived = (a: string, b: string) =>
        (derivation ?? []).some((d: { metric_key: string; derived_from: string }) =>
          (d.metric_key === a && d.derived_from === b) || (d.metric_key === b && d.derived_from === a));

      // ── Tier A ──────────────────────────────────────────────────────
      // Real-vintage coverage derived live from real_data_sources +
      // metric_derivation -- no hardcoded vintage list (see
      // docs/SECURITY.md's addendum and the migration comment on this
      // table for why hardcoding it here would have reproduced the same
      // "two independent implementations kept in sync by hand" risk
      // already documented for daily_weather.sql/series_bucketed()).
      const realByMetric = await realVintagesByMetric(ctx.supabaseAdmin, TIER_A_METRICS);
      const series = await fetchTierAMetrics(ctx.supabaseAdmin, realByMetric);

      const tierAPairs: { a: string; b: string }[] = [];
      for (let i = 0; i < TIER_A_METRICS.length; i++)
        for (let j = i + 1; j < TIER_A_METRICS.length; j++) {
          const [a, b] = [TIER_A_METRICS[i], TIER_A_METRICS[j]].sort();
          tierAPairs.push({ a, b });
        }

      for (const { a, b } of tierAPairs) {
        if (isDerived(a, b)) {
          pending.push({ row: baseRow(runId, "A", a, b, "excluded_derived",
            "metric_derivation declares one as computed from the other") });
          continue;
        }

        const jointVintages = [...(realByMetric.get(a) ?? [])].filter(v => realByMetric.get(b)?.has(v));
        if (jointVintages.length === 0) {
          pending.push({ row: baseRow(runId, "A", a, b, "excluded_low_n",
            "no vintage has real data for both metrics") });
          continue;
        }

        let bestReproduced: BestCandidate | null = null;
        let bestSingleSeason: BestCandidate | null = null;

        // Bidirectional: lag_days>0 means metric_b lags metric_a
        // (metric_a[t] paired with metric_b[t+lag]); lag_days<0 means
        // metric_a lags metric_b. metric_a/metric_b order is alphabetical
        // (storage canonicalization only, not a claim about which metric
        // is physically upstream), so a real relationship running either
        // direction is searched, not assumed.
        for (let lag = -MAX_LAG; lag <= MAX_LAG; lag++) {
          const perVintage: { vintage: number; r: { rho: number; p: number; n: number } }[] = [];
          for (const v of jointVintages) {
            const pairs = buildLaggedPairs(series[a]?.[v], series[b]?.[v], lag);
            if (pairs.length < MIN_N_TIER_A) continue;
            const r = spearman(pairs);
            if (r) perVintage.push({ vintage: v, r });
          }
          if (perVintage.length === 0) continue;

          if (perVintage.length >= 3) {
            // Reproduced path: >=3/4 sign agreement among vintages
            // actually tested at this lag.
            const positive = perVintage.filter(x => x.r.rho > 0);
            const negative = perVintage.filter(x => x.r.rho < 0);
            const agreeing = positive.length >= negative.length ? positive : negative;
            if (agreeing.length < 3) continue;
            const effect = mean(agreeing.map(x => x.r.rho));
            const p = fisherCombine(agreeing.map(x => x.r.p));
            const n = sum(agreeing.map(x => x.r.n));
            if (!bestReproduced || Math.abs(effect) > Math.abs(bestReproduced.effect))
              bestReproduced = { lag, effect, p, agreeing: agreeing.length, tested: perVintage.length, n };
          } else {
            // 1-2 real vintages: single_season candidate, evaluated (not
            // discarded pre-evaluation) but gated separately, more
            // strictly, below. A 2-vintage split decision is worse
            // evidence than 1, not better -- skip this lag if they
            // disagree in sign rather than averaging away the contradiction.
            if (perVintage.length === 2 && Math.sign(perVintage[0].r.rho) !== Math.sign(perVintage[1].r.rho)) continue;
            const effect = mean(perVintage.map(x => x.r.rho));
            const p = fisherCombine(perVintage.map(x => x.r.p));
            const n = sum(perVintage.map(x => x.r.n));
            if (!bestSingleSeason || Math.abs(effect) > Math.abs(bestSingleSeason.effect))
              bestSingleSeason = { lag, effect, p, agreeing: perVintage.length, tested: perVintage.length, n };
          }
        }

        // Reproduced beats single_season unconditionally when both exist
        // for the same pair -- independent cross-season corroboration is
        // strictly better evidence than a single season's larger number,
        // and this keeps the later rank-by-effect-size step from
        // accidentally rewarding the less-corroborated candidate.
        if (bestReproduced) {
          pending.push({
            row: {
              ...baseRow(runId, "A", a, b, "below_threshold", null),
              scope_kind: "estate", scope_vintages: jointVintages,
              method: "spearman_lag", effect: bestReproduced.effect, lag_days: bestReproduced.lag,
              n_observations: bestReproduced.n, vintages_agreeing: bestReproduced.agreeing,
              vintages_tested: bestReproduced.tested, confidence_label: "reproduced",
            },
            p: bestReproduced.p,
          });
        } else if (bestSingleSeason) {
          pending.push({
            row: {
              ...baseRow(runId, "A", a, b, "below_threshold", null),
              scope_kind: "estate", scope_vintages: jointVintages,
              method: "spearman_lag", effect: bestSingleSeason.effect, lag_days: bestSingleSeason.lag,
              n_observations: bestSingleSeason.n, vintages_agreeing: bestSingleSeason.agreeing,
              vintages_tested: bestSingleSeason.tested, confidence_label: "single_season",
            },
            p: bestSingleSeason.p,
          });
        } else {
          pending.push({ row: baseRow(runId, "A", a, b, "excluded_low_n",
            `no lag in -${MAX_LAG}..${MAX_LAG} reached the minimum evidence bar for either path`) });
        }
      }

      // BH-FDR across every Tier A pair that actually produced a p-value
      // (excluded/low-n pairs never entered the test family) -- both
      // reproduced and single_season candidates share one family, per
      // "across all Tier A pairs tested per run."
      const withP = pending.filter(x => x.p !== undefined);
      const adjusted = benjaminiHochberg(withP.map(x => x.p!));
      withP.forEach((x, i) => { x.row.p_value = x.p; x.row.p_adjusted = adjusted[i]; });

      // ── Tier B (single hardcoded join -- see migration comment) ────
      const tierB = await fetchTierBPairs(ctx.supabaseAdmin);
      const tierBBase = baseRow(runId, "B", "harvest_yield_tons", "irrigation_volume", "below_threshold", null);
      if (tierB.length < MIN_N_TIER_B) {
        tierBBase.status = "excluded_low_n";
        tierBBase.rejection_reason = `only ${tierB.length} real, jointly-available block-vintage pairs (need >=${MIN_N_TIER_B})`;
        pending.push({ row: tierBBase });
      } else {
        const rc = rankConcordance(tierB.map(x => ({ a: x.irrigation, b: x.yield })));
        if (rc) {
          Object.assign(tierBBase, {
            scope_kind: "block", scope_vintages: [...new Set(tierB.map(x => x.vintage))],
            method: "rank_concordance", effect: rc.effect, n_observations: rc.n,
            confidence_label: "directional_only", // n<=5 is always <6
          });
        }
        pending.push({ row: tierBBase });
      }

      // ── Eligibility gate + cap ───────────────────────────────────────
      const eligible = pending.filter(x => {
        const r = x.row;
        if (r.status === "excluded_derived" || r.status === "excluded_low_n") return false;
        const minEffect = r.confidence_label === "single_season" ? MIN_EFFECT_SINGLE_SEASON : MIN_EFFECT;
        if (Math.abs(r.effect as number) < minEffect) return false;
        if (r.tier === "A" && (r.p_adjusted as number) > FDR_Q) return false;
        return true;
      });
      eligible.sort((x, y) => Math.abs(y.row.effect as number) - Math.abs(x.row.effect as number));
      eligible.slice(0, SURFACE_CAP).forEach(x => x.row.status = "surfaced");
      eligible.slice(SURFACE_CAP).forEach(x => {
        x.row.status = "below_threshold";
        x.row.rejection_reason = "cut by top-5-per-run cap despite clearing gates";
      });
      pending.filter(x => x.row.status === "below_threshold" && !x.row.rejection_reason).forEach(x => {
        const r = x.row;
        const minEffect = r.confidence_label === "single_season" ? MIN_EFFECT_SINGLE_SEASON : MIN_EFFECT;
        r.rejection_reason = (r.tier === "A" && x.p !== undefined && (r.p_adjusted as number) > FDR_Q)
          ? `BH-FDR adjusted p=${(r.p_adjusted as number).toFixed(4)} exceeds q=${FDR_Q}`
          : `|effect|=${Math.abs(r.effect as number).toFixed(3)} below minimum ${minEffect} for confidence_label=${r.confidence_label}`;
      });

      const rows = pending.map(x => x.row);
      const { error: insertErr } = await ctx.supabaseAdmin.from("insights").insert(rows);
      if (insertErr) {
        console.error("insights-scan: failed to persist run", runId, insertErr);
        return Response.json({ ok: false, reason: "insert failed", detail: insertErr.message }, { status: 500 });
      }

      // ── Narration: query by status, not run_id -- picks up this run's
      // fresh surfaced rows AND any prior run's surfaced-but-unnarrated
      // rows left over from a narration failure, satisfying "leave rows
      // un-narrated, retry next run" without a separate retry schedule. ─
      const { data: toNarrate, error: toNarrateErr } = await ctx.supabaseAdmin
        .from("insights").select("*")
        .eq("status", "surfaced").is("narrated_at", null)
        .order("computed_at", { ascending: true });
      // Logged, not thrown: the scan itself already succeeded and
      // persisted above -- a failure fetching the narration queue
      // shouldn't turn a successful scan into a 500. It's surfaced in the
      // response instead of silently swallowed.
      if (toNarrateErr) console.error("insights-scan: could not fetch narration queue", toNarrateErr);

      if (toNarrate?.length) await narrateFindings(ctx.supabaseAdmin, toNarrate);

      return Response.json({
        ok: true, run_id: runId, tested: rows.length, surfaced: eligible.slice(0, SURFACE_CAP).length,
        narrated_this_run: toNarrate?.length ?? 0, narration_queue_error: toNarrateErr?.message ?? null,
      }, { status: 200 });
    } catch (err) {
      console.error("insights-scan: unexpected error", err);
      return Response.json({ ok: false, reason: "unexpected error", detail: String(err) }, { status: 500 });
    }
  }),
};

interface BestCandidate { lag: number; effect: number; p: number; agreeing: number; tested: number; n: number }

function baseRow(runId: string, tier: "A" | "B", a: string, b: string, status: string, reason: string | null) {
  return { run_id: runId, tier, metric_a: a, metric_b: b, status, rejection_reason: reason,
    scope_kind: "estate", scope_vintages: [], method: tier === "A" ? "spearman_lag" : "rank_concordance",
    effect: 0, n_observations: 0, confidence_label: "directional_only" };
}

function buildLaggedPairs(a: Map<number, number> | undefined, b: Map<number, number> | undefined, lag: number): Pair[] {
  if (!a || !b) return [];
  const out: Pair[] = [];
  for (const [day, av] of a) {
    const bv = b.get(day + lag);
    if (bv !== undefined) out.push({ a: av, b: bv });
  }
  return out;
}

function mean(xs: number[]): number { return xs.reduce((s, x) => s + x, 0) / xs.length; }
function sum(xs: number[]): number { return xs.reduce((s, x) => s + x, 0); }
