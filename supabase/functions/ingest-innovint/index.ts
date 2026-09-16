import "@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "@supabase/server";

// Daily InnoVint sync. Ports ingestion/innovint/{client,db,assets,capacity,
// weights}.py's three Dagster assets (analyses_sync, vessels_sync,
// harvest_receipts_sync) into a scheduled Edge Function -- those assets'
// own ScheduleDefinition (0 6 * * * America/Los_Angeles,
// ingestion/innovint/definitions.py) was never actually deployed anywhere
// persistent (no Dockerfile/CI/Dagster Cloud config in this repo; git
// history confirms the Dagster/Python path was designed then abandoned
// for the same reason insights-scan was -- see docs/SECURITY.md, "Daily
// InnoVint sync investigation"). This is the always-on daily counterpart.
//
// Combined into ONE function for all three assets, unlike the three
// independent Dagster assets: this lets `lots`, `block_innovint_map`, and
// the per-lot blockComponents cache be fetched ONCE and shared across all
// three phases instead of being re-fetched by each asset independently --
// a real reduction in call count (see the pacing comment below), not just
// a code-organization convenience.
//
// pg_cron-only, same auth mode as insights-scan/notify-admin-approval/
// ingest-climate-2026 (server-to-server, secret key only).
//
// Deliberately NOT full pydantic-style "extra field fails the response"
// strictness (contracts.py's approach): no schema-validation library is
// already loaded in this Deno runtime, and adding one is a bigger call
// than this port needs to make on its own. What IS preserved exactly,
// because these are the correctness-critical properties the investigation
// flagged, not style choices: block_innovint_map's time-scoped resolution
// and its overlap-raises behavior, capacity_suspect's two-signal
// heuristic, to_short_tons's loud-fail-on-unrecognized-unit behavior, the
// pagination-boundary dedup, and harvest_receipts's reconcile-delete
// invariants (fetch-everything-before-any-write; explicit vintage list,
// never derived from fetched rows).
export default {
  fetch: withSupabase({ auth: ["secret"] }, async (_req, ctx) => {
    const token = Deno.env.get("INNOVINT_TOKEN");
    const wineryId = Deno.env.get("INNOVINT_WINERY_ID") ?? "wnry_2PW0KJ93L726WKKG54OQE1RY";
    if (!token) {
      console.error("ingest-innovint: INNOVINT_TOKEN is not set");
      return Response.json({ ok: false, reason: "INNOVINT_TOKEN is not set" }, { status: 500 });
    }

    const runStartedAt = Date.now();
    let httpCallCount = 0;
    const countedFetch = async (url: string): Promise<Response> => {
      httpCallCount++;
      const resp = await fetch(url, { headers: { Authorization: `Access-Token ${token}` } });
      await sleep(REQUEST_PAUSE_MS);
      return resp;
    };

    try {
      // Two preconditions every phase depends on, either directly (lots)
      // or via block resolution (block_innovint_map). Both fetched ONCE
      // and treated as fatal-abort-everything on failure -- deliberately
      // NOT "proceed with an empty map/list on error," which would
      // silently blank out every row's block_id on a transient DB hiccup
      // (an UPDATE that erases a previously-correct value is exactly the
      // silent-not-loud failure shape docs/SECURITY.md warns about
      // repeatedly, not a safe no-op like a skipped upsert would be).
      const { data: mapRows, error: mapErr } = await ctx.supabaseAdmin
        .from("block_innovint_map")
        .select("innovint_block_id, valid_from_vintage, valid_to_vintage, block_id");
      if (mapErr) throw new Error(`could not read block_innovint_map: ${mapErr.message}`);
      const blockMap = loadBlockMap(mapRows ?? []);

      const lots = await fetchLots(countedFetch, wineryId);
      const lotsById = new Map(lots.map((l) => [l.id, l]));

      const blockCache = new Map<string, string | null>();
      const danglingLotRefs = new Set<string>();
      const resolveForLot = (lotId: string) =>
        resolveBlockIdForLot(countedFetch, wineryId, blockMap, lotId, blockCache, danglingLotRefs);

      const results: Record<string, unknown> = {};

      // ── analyses_sync ──────────────────────────────────────────────
      try {
        const rows: LotAnalysisRow[] = [];
        let skippedDeletedOrSkipped = 0;
        let skippedNullValue = 0;
        for (const lot of lots) {
          const analyses = await fetchAnalyses(countedFetch, wineryId, lot.id);
          for (const a of analyses) {
            if (a.deleted || a.skipped) { skippedDeletedOrSkipped++; continue; }
            if (a.value == null) { skippedNullValue++; continue; }
            const blockId = await resolveForLot(a.lotId);
            rows.push({
              source_system: "innovint", source_id: a.id, lot_id: a.lotId,
              lot_name: lot.name, lot_code: lot.code, block_id: blockId,
              analysis_type: a.analysisType.slug, value: a.value, unit: a.unit.unit,
              recorded_at: a.recordedAt, ingested_at: new Date().toISOString(),
            });
          }
        }
        const fetchedCount = rows.length;
        const deduped = dedupeByKey(rows, (r) => `${r.source_system}::${r.source_id}`);
        const { error } = await ctx.supabaseAdmin.from("lot_analyses")
          .upsert(deduped, { onConflict: "source_system,source_id" });
        if (error) throw new Error(error.message);
        await markSynced(ctx, "lot_analyses");
        results.analyses = {
          lots_processed: lots.length,
          rows_upserted: deduped.length,
          rows_deduped: fetchedCount - deduped.length,
          rows_with_block_id: deduped.filter((r) => r.block_id != null).length,
          rows_skipped_deleted_or_skipped: skippedDeletedOrSkipped,
          rows_skipped_null_value: skippedNullValue,
        };
      } catch (err) {
        console.error("ingest-innovint: analyses_sync failed", err);
        results.analyses = { error: String(err) };
      }

      // ── vessels_sync ───────────────────────────────────────────────
      try {
        const vessels = await fetchVessels(countedFetch, wineryId);
        const capacities = vessels.map((v) => v.capacity?.value).filter((v): v is number => v != null);
        const threshold = outlierThreshold(capacities);

        const rows: VesselRow[] = [];
        let suspectCount = 0;
        let resolvedCount = 0;
        for (const v of vessels) {
          const capVal = v.capacity?.value ?? null;
          const volVal = v.volume?.value ?? null;
          const suspect = computeCapacitySuspect(capVal, threshold);
          if (suspect) suspectCount++;

          let blockId: string | null = null;
          if (v.lotId != null) {
            blockId = await resolveForLot(v.lotId);
            if (blockId != null) resolvedCount++;
          }
          const currentLot = v.lotId != null ? lotsById.get(v.lotId) : undefined;

          if (!VESSEL_TYPES.has(v.vesselType)) {
            throw new Error(`unrecognized vessel_type ${JSON.stringify(v.vesselType)} on vessel ${v.id} -- refusing to ingest rather than guess a lowercase mapping`);
          }
          rows.push({
            vessel_id: v.id, source_system: "innovint", vessel_type: v.vesselType.toLowerCase(),
            code: v.code, capacity_gal: capVal, volume_gal: volVal, capacity_suspect: suspect,
            current_lot_id: v.lotId, current_lot_name: currentLot?.name ?? null,
            current_lot_code: currentLot?.code ?? null, block_id: blockId, archived: v.archived,
            updated_at: new Date().toISOString(),
          });
        }
        const fetchedCount = rows.length;
        const deduped = dedupeByKey(rows, (r) => r.vessel_id);
        const { error } = await ctx.supabaseAdmin.from("vessels")
          .upsert(deduped, { onConflict: "vessel_id" });
        if (error) throw new Error(error.message);
        await markSynced(ctx, "vessels");
        results.vessels = {
          vessels_processed: vessels.length,
          rows_upserted: deduped.length,
          rows_deduped: fetchedCount - deduped.length,
          rows_capacity_suspect: suspectCount,
          rows_with_block_id: resolvedCount,
          outlier_threshold_gal: threshold,
        };
      } catch (err) {
        console.error("ingest-innovint: vessels_sync failed", err);
        results.vessels = { error: String(err) };
      }

      // ── harvest_receipts_sync ──────────────────────────────────────
      // Every fetch (across every vintage) completes before a single write
      // happens -- a throw anywhere in this loop (network error, or
      // toShortTons rejecting an unrecognized/volume unit) propagates to
      // the catch below with nothing upserted and nothing deleted.
      try {
        const now = new Date().toISOString();
        const currentYear = new Date().getUTCFullYear();
        const vintages: number[] = [];
        for (let v = HARVEST_RECEIPTS_FIRST_VINTAGE; v <= currentYear + 1; v++) vintages.push(v);

        const rows: (HarvestReceiptRow & { varietal_id: string })[] = [];
        let unmapped = 0;
        for (const vintage of vintages) {
          const receipts = await fetchGrowerReceipts(countedFetch, wineryId, vintage);
          for (const r of receipts) {
            const blockId = resolveBlockId(blockMap, r.blockId, r.vintage);
            if (blockId == null) unmapped++;
            const lot = lotsById.get(r.lotId);
            rows.push({
              innovint_receipt_id: r.id, innovint_action_id: r.actionId, innovint_lot_id: r.lotId,
              innovint_block_id: r.blockId, block_id: blockId, vintage: r.vintage,
              weight_value: r.totalWeight.value, weight_unit: r.totalWeight.unit,
              // Raises rather than coercing -- a volume unit here is a
              // source data error, matching weights.py exactly.
              weight_tons: toShortTons(r.totalWeight.value, r.totalWeight.unit),
              receipt_date: r.receiptDate, weigh_tag_number: r.weighTagNumber,
              varietal_id: r.varietalId, lot_code: lot?.code ?? null, lot_name: lot?.name ?? null,
              grower_id: r.growerId, vineyard_id: r.vineyardId, appellation_id: r.appellationId,
              source_system: "innovint", synced_at: now,
            });
          }
        }

        const varietalNames = await fetchVarietalNames(countedFetch, new Set(rows.map((r) => r.varietal_id)));
        let unnamed = 0;
        const finalRows: HarvestReceiptRow[] = rows.map(({ varietal_id, ...rest }) => {
          const name = varietalNames.get(varietal_id) ?? null;
          if (name == null) unnamed++;
          return { ...rest, varietal_name: name };
        });

        const deduped = dedupeByKey(finalRows, (r) => r.innovint_receipt_id);

        // Reconciliation, not pure upsert: /growerReceipts exposes neither
        // a `deleted` field nor a `state` filter, so a removed receipt
        // simply vanishes from the response -- the only way to notice is
        // to delete whatever's stored for these exact vintages that isn't
        // in this run's payload. `vintages` is the loop variable computed
        // above, NEVER derived from `deduped` -- a vintage that
        // legitimately returned zero receipts is still reconciled (its
        // stale rows get deleted), while a vintage this run never
        // attempted to fetch is never touched.
        if (deduped.length > 0) {
          const { error } = await ctx.supabaseAdmin.from("harvest_receipts")
            .upsert(deduped, { onConflict: "innovint_receipt_id" });
          if (error) throw new Error(error.message);
        }
        let delQuery = ctx.supabaseAdmin.from("harvest_receipts")
          .delete({ count: "exact" }).eq("source_system", "innovint").in("vintage", vintages);
        const keepIds = deduped.map((r) => r.innovint_receipt_id);
        if (keepIds.length > 0) {
          // InnoVint ids are always ^[a-z]+_[0-9A-Z]{24}$ (confirmed
          // against the OpenAPI spec's own path-parameter patterns) --
          // no quote/comma ever appears, so this literal-list form of
          // PostgREST's negated `in` is safe here.
          delQuery = delQuery.not("innovint_receipt_id", "in", `(${keepIds.join(",")})`);
        }
        const { error: delErr, count: deletedCount } = await delQuery;
        if (delErr) throw new Error(delErr.message);
        await markSynced(ctx, "harvest_receipts");

        results.harvest_receipts = {
          vintages_swept: `${vintages[0]}-${vintages[vintages.length - 1]}`,
          receipts_upserted: deduped.length,
          stale_deleted: deletedCount ?? 0,
          unmapped_block: unmapped,
          unnamed_varietal: unnamed,
        };
      } catch (err) {
        console.error("ingest-innovint: harvest_receipts_sync failed", err);
        results.harvest_receipts = { error: String(err) };
      }

      const durationMs = Date.now() - runStartedAt;
      const anyError = Object.values(results).some((r) => r && typeof r === "object" && "error" in r);
      return Response.json({
        ok: !anyError,
        results,
        dangling_lot_refs: Array.from(danglingLotRefs).sort(),
        http_call_count: httpCallCount,
        duration_ms: durationMs,
      }, { status: anyError ? 207 : 200 });
    } catch (err) {
      // Whatever failed, however early -- log it and leave the DB exactly
      // as the last successful run left it. Nothing above ever deletes
      // before every fetch for that phase has already succeeded.
      console.error("ingest-innovint: unexpected error", err);
      return Response.json({
        ok: false, reason: "unexpected error", detail: String(err),
        http_call_count: httpCallCount, duration_ms: Date.now() - runStartedAt,
      }, { status: 500 });
    }
  }),
};

const BASE_URL = "https://sutter.innovint.us/api/v1";
const HARVEST_RECEIPTS_FIRST_VINTAGE = 2022;

// InnoVint's OpenAPI spec (fetched live during the investigation, GET
// /api/v1/schema) documents 120 requests/minute (429 + Retry-After on
// excess). The Python ingestion's REQUEST_PAUSE_SECONDS=0.1 predates that
// discovery -- at 0.1s pacing this job would run at up to ~600
// requests/minute, 5x over the documented limit. Corrected to 600ms
// (~100 req/min sustained), a deliberate ~17% margin under the documented
// 120 req/min rather than pacing exactly at the boundary, since this job
// now runs unattended on a schedule with nobody watching for a 429 the
// way an interactive backfill run would be. See docs/SECURITY.md, "Daily
// InnoVint sync investigation" for the full reasoning and the timing
// consequence this has for the combined-vs-split function decision.
const REQUEST_PAUSE_MS = 600;

const VESSEL_TYPES = new Set(["TANK", "BARREL", "KEG", "STEEL_DRUM"]);

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}

// Records that THIS resource's phase just succeeded -- called once per
// phase, only from that phase's own success path (never from a catch
// block), so a failed phase never advances its freshness marker. Failure
// to write this is logged but never thrown: the actual data sync for
// this phase already committed by the time this runs, and a freshness-
// marker hiccup shouldn't be reported as if the sync itself failed.
async function markSynced(ctx: { supabaseAdmin: { from: (t: string) => any } }, resource: string): Promise<void> {
  const { error } = await ctx.supabaseAdmin.from("innovint_sync_status")
    .upsert({ resource, last_success_at: new Date().toISOString() }, { onConflict: "resource" });
  if (error) console.error(`ingest-innovint: could not record sync status for ${resource}`, error);
}

// ── Pagination envelope ─────────────────────────────────────────────────

interface Pagination { count: number; next: string | null; previous: string | null }
interface EnvelopeItem<T> { data: T }
interface PaginatedResponse<T> { results: EnvelopeItem<T>[]; pagination: Pagination }

async function fetchAllPages<T>(
  fetcher: (url: string) => Promise<Response>, initialUrl: string,
): Promise<T[]> {
  const out: T[] = [];
  let url: string | null = initialUrl;
  while (url) {
    const resp = await fetcher(url);
    if (!resp.ok) throw new Error(`InnoVint ${resp.status} for ${url}: ${await resp.text()}`);
    const parsed: PaginatedResponse<T> = await resp.json();
    out.push(...parsed.results.map((r) => r.data));
    url = parsed.pagination.next;
  }
  return out;
}

// ── Resource shapes (only the fields this ingestion consumes) ──────────

interface Measurement { value: number | null; unit: string }
interface Lot { id: string; name: string; code: string }
interface AnalysisType { name: string; abbreviation: string; slug: string }
interface AnalysisUnit { name: string; unit: string }
interface InnoVintAnalysis {
  id: string; analysisType: AnalysisType; deleted: boolean; lotId: string;
  recordedAt: string; skipped: boolean; value: number | null; unit: AnalysisUnit;
}
interface NamedRef { id: string; name: string }
interface BlockComponent { block: NamedRef; vintage: number; percentage: number }
interface InnoVintVessel {
  id: string; capacity: Measurement | null; code: string | null; vesselType: string;
  lotId: string | null; volume: Measurement | null; archived: boolean;
}
interface FloatUnit { value: number; unit: string }
interface GrowerReceipt {
  id: string; actionId: string; lotId: string; growerId: string; blockId: string;
  vineyardId: string; varietalId: string; appellationId: string; vintage: number;
  weighTagNumber: string; receiptDate: string; totalWeight: FloatUnit;
}
interface Varietal { id: string; name: string }

function fetchLots(fetcher: (url: string) => Promise<Response>, wineryId: string): Promise<Lot[]> {
  return fetchAllPages<Lot>(fetcher, `${BASE_URL}/wineries/${wineryId}/lots?limit=100`);
}

function fetchAnalyses(
  fetcher: (url: string) => Promise<Response>, wineryId: string, lotId: string,
): Promise<InnoVintAnalysis[]> {
  return fetchAllPages<InnoVintAnalysis>(
    fetcher, `${BASE_URL}/wineries/${wineryId}/lots/${lotId}/analyses?limit=50`,
  );
}

async function fetchBlockComponents(
  fetcher: (url: string) => Promise<Response>, wineryId: string, lotId: string,
  danglingLotRefs: Set<string>,
): Promise<BlockComponent[]> {
  const url = `${BASE_URL}/wineries/${wineryId}/lots/${lotId}/blockComponents`;
  const resp = await fetcher(url);
  if (resp.status === 404) {
    // Confirmed live (Python inventory): a vessel's current lotId (or, in
    // principle, an analysis's) can point to a lot that doesn't exist at
    // all -- not "no components," genuinely absent. Treated as "no
    // resolvable block components," tracked rather than silently blended
    // into the ordinary zero-component case.
    danglingLotRefs.add(lotId);
    return [];
  }
  if (!resp.ok) throw new Error(`InnoVint ${resp.status} for ${url}: ${await resp.text()}`);
  const parsed: PaginatedResponse<BlockComponent> = await resp.json();
  return parsed.results.map((r) => r.data);
}

function fetchVessels(fetcher: (url: string) => Promise<Response>, wineryId: string): Promise<InnoVintVessel[]> {
  return fetchAllPages<InnoVintVessel>(fetcher, `${BASE_URL}/wineries/${wineryId}/vessels?limit=100`);
}

function fetchGrowerReceipts(
  fetcher: (url: string) => Promise<Response>, wineryId: string, vintage: number,
): Promise<GrowerReceipt[]> {
  return fetchAllPages<GrowerReceipt>(
    fetcher, `${BASE_URL}/wineries/${wineryId}/growerReceipts/${vintage}?limit=100`,
  );
}

const VARIETAL_ID_CHUNK = 50;

async function fetchVarietalNames(
  fetcher: (url: string) => Promise<Response>, varietalIds: Set<string>,
): Promise<Map<string, string>> {
  const names = new Map<string, string>();
  if (varietalIds.size === 0) return names;
  const ordered = Array.from(varietalIds).sort();
  for (let start = 0; start < ordered.length; start += VARIETAL_ID_CHUNK) {
    const chunk = ordered.slice(start, start + VARIETAL_ID_CHUNK);
    // /varietals is GLOBAL, not winery-scoped -- confirmed against the
    // spec, matches client.py's fetch_varietal_names exactly.
    const rows = await fetchAllPages<Varietal>(
      fetcher, `${BASE_URL}/varietals?idIn=${chunk.join(",")}&limit=100`,
    );
    for (const v of rows) names.set(v.id, v.name);
  }
  return names;
}

// ── block_innovint_map resolution (correctness-critical, ported exactly) ─

type BlockMapEntry = { validFrom: number | null; validTo: number | null; blockId: string };
type BlockMap = Map<string, BlockMapEntry[]>;

function loadBlockMap(
  rows: { innovint_block_id: string; valid_from_vintage: number | null; valid_to_vintage: number | null; block_id: string }[],
): BlockMap {
  const out: BlockMap = new Map();
  for (const r of rows) {
    const list = out.get(r.innovint_block_id) ?? [];
    list.push({ validFrom: r.valid_from_vintage, validTo: r.valid_to_vintage, blockId: r.block_id });
    out.set(r.innovint_block_id, list);
  }
  return out;
}

class AmbiguousBlockMapping extends Error {}

// Raises rather than picking a winner when two windows overlap for the
// same vintage -- a silent wrong answer here would attribute another
// block's history to a local block with no error, exactly the failure
// docs/SECURITY.md's block_innovint_map entry warns against. Matches
// db.py's resolve_block_id exactly, including which case it does NOT
// catch (the partial unique indexes on block_innovint_map prevent two
// simultaneously-open windows; this is the backstop for overlapping
// closed windows, which they cannot prevent).
function resolveBlockId(blockMap: BlockMap, innovintBlockId: string, vintage: number): string | null {
  const hits = (blockMap.get(innovintBlockId) ?? [])
    .filter((e) => (e.validFrom == null || vintage >= e.validFrom) && (e.validTo == null || vintage <= e.validTo))
    .map((e) => e.blockId);
  if (hits.length > 1) {
    throw new AmbiguousBlockMapping(
      `${innovintBlockId} maps to ${JSON.stringify([...hits].sort())} for vintage ${vintage}; ` +
      `fix the overlapping windows in block_innovint_map`,
    );
  }
  return hits[0] ?? null;
}

// Only resolves lots with exactly one blockComponents entry at
// (effectively) 100% -- matches assets.py's _resolve_block_id exactly.
// Cached by lot_id alone (not vintage): a lot's block composition doesn't
// depend on which caller is asking, only the component's OWN vintage
// field does, which resolveBlockId already accounts for.
async function resolveBlockIdForLot(
  fetcher: (url: string) => Promise<Response>, wineryId: string, blockMap: BlockMap,
  lotId: string, cache: Map<string, string | null>, danglingLotRefs: Set<string>,
): Promise<string | null> {
  if (cache.has(lotId)) return cache.get(lotId)!;
  const components = await fetchBlockComponents(fetcher, wineryId, lotId, danglingLotRefs);
  let resolved: string | null = null;
  if (components.length === 1) {
    const comp = components[0];
    if (Math.abs(comp.percentage - 1.0) < 1e-6) {
      resolved = resolveBlockId(blockMap, comp.block.id, comp.vintage);
    }
  }
  cache.set(lotId, resolved);
  return resolved;
}

// ── capacity_suspect heuristic (correctness-critical, ported exactly) ───

const KNOWN_PLACEHOLDER_VALUES = new Set([500_000.0]);
const OUTLIER_MULTIPLE = 10;
const MIN_SAMPLE_FOR_OUTLIER_CHECK = 5;

// p99 via linear-interpolation percentile (numpy/"linear" convention).
// capacity.py uses Python's statistics.quantiles(n=100)[98] ("exclusive"
// method) -- a slightly different interpolation rule than this. Noted
// explicitly rather than claimed identical: with a x10 multiplier this
// heuristic is meant to catch "obviously not real," not draw a precise
// statistical line, so the two methods' typically sub-1%-of-value
// disagreement on the same sample doesn't change what gets flagged in
// practice. The heuristic's STRUCTURE (exclude known placeholders from
// the baseline before computing p99, x10 multiplier, min-sample-5
// fallback to exact-match-only) is preserved exactly.
function percentile(sorted: number[], p: number): number {
  const idx = (sorted.length - 1) * p;
  const lo = Math.floor(idx), hi = Math.ceil(idx);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}

function outlierThreshold(capacities: number[]): number | null {
  const baseline = capacities.filter((c) => !KNOWN_PLACEHOLDER_VALUES.has(c)).sort((a, b) => a - b);
  if (baseline.length < MIN_SAMPLE_FOR_OUTLIER_CHECK) return null;
  const p99 = percentile(baseline, 0.99);
  return p99 > 0 ? OUTLIER_MULTIPLE * p99 : null;
}

function computeCapacitySuspect(capacityGal: number | null, threshold: number | null): boolean {
  if (capacityGal == null) return false;
  if (KNOWN_PLACEHOLDER_VALUES.has(capacityGal)) return true;
  return threshold != null && capacityGal > threshold;
}

// ── weight-unit normalization (correctness-critical, ported exactly) ────

const TO_SHORT_TONS: Record<string, number> = {
  tons: 1.0, ton: 1.0, tonne: 1.10231, tonnes: 1.10231,
  kg: 0.00110231, kilograms: 0.00110231, lbs: 0.0005,
};
const VOLUME_UNITS = new Set(["gal", "gallons", "gallon", "hl", "hL", "liters", "litres", "L", "pg", "PG"]);

class UnrecognizedWeightUnit extends Error {}

// Kept as a function that THROWS on an unrecognized/volume unit --
// deliberately not a silent null or a best-guess conversion, matching
// weights.py's own reasoning: an unrecognized unit is a source-data
// error, not a conversion gap to paper over.
function toShortTons(value: number, unit: string): number {
  if (VOLUME_UNITS.has(unit)) {
    throw new UnrecognizedWeightUnit(
      `volume unit ${JSON.stringify(unit)} on a fruit intake weight -- refusing to coerce; this is a source data error, not a conversion gap`,
    );
  }
  const factor = TO_SHORT_TONS[unit];
  if (factor == null) {
    throw new UnrecognizedWeightUnit(
      `no short-ton conversion for unit ${JSON.stringify(unit)}; add it to TO_SHORT_TONS deliberately rather than defaulting`,
    );
  }
  return value * factor;
}

// ── pagination-boundary dedup (correctness-critical, ported exactly) ────

// Postgres rejects a single INSERT...ON CONFLICT DO UPDATE batch
// containing the same conflict key twice (CardinalityViolation) --
// confirmed against live data for InnoVint analyses on lots large enough
// to span multiple /analyses pages (offset-pagination returning the same
// row across adjacent page boundaries, byte-identical both times). Same
// last-write-wins semantics as db.py's _dedupe_by_key (a plain dict
// comprehension keeps the LAST occurrence of a repeated key, not the
// first) -- Map.set here does the same.
function dedupeByKey<T>(rows: T[], keyFn: (row: T) => string): T[] {
  const deduped = new Map<string, T>();
  for (const row of rows) deduped.set(keyFn(row), row);
  return Array.from(deduped.values());
}

// ── Row shapes written to Postgres ───────────────────────────────────────

interface LotAnalysisRow {
  source_system: string; source_id: string; lot_id: string; lot_name: string; lot_code: string;
  block_id: string | null; analysis_type: string; value: number; unit: string;
  recorded_at: string; ingested_at: string;
}
interface VesselRow {
  vessel_id: string; source_system: string; vessel_type: string; code: string | null;
  capacity_gal: number | null; volume_gal: number | null; capacity_suspect: boolean;
  current_lot_id: string | null; current_lot_name: string | null; current_lot_code: string | null;
  block_id: string | null; archived: boolean; updated_at: string;
}
interface HarvestReceiptRow {
  innovint_receipt_id: string; innovint_action_id: string; innovint_lot_id: string;
  innovint_block_id: string; block_id: string | null; vintage: number; weight_value: number;
  weight_unit: string; weight_tons: number; receipt_date: string; weigh_tag_number: string;
  varietal_name: string | null; lot_code: string | null; lot_name: string | null;
  grower_id: string; vineyard_id: string; appellation_id: string; source_system: string; synced_at: string;
}
