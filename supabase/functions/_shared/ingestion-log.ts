// Durable per-run record for the ingest functions
// (system_health.ingestion_runs, via public.log_ingestion_run -- service_role
// only). Before this, a failed run was recorded nowhere durable: pg_cron only
// knows the HTTP request was queued, and net._http_response keeps the
// function's answer for ~6 hours.
//
// withIngestionLog() runs the function's own handler unchanged and, in a
// finally block, writes one row for EVERY run it sees: success, a partial
// (207) run, an error response, a thrown exception, or an upstream failure the
// handler reported. The handler's response is returned untouched. A logging
// failure is console.error'd and never changes the response -- the data sync
// already happened. A request rejected by withSupabase's key check never
// reaches this code; the nightly health check catches that as a stale/missing
// run instead.

export type RunStatus = "success" | "partial" | "error";

export interface RunSummary {
  rows_written?: number | null;
  error?: string | null;
  detail?: Record<string, unknown> | null;
}

// deno-lint-ignore no-explicit-any
type Rpc = (fn: string, args: Record<string, unknown>) => PromiseLike<{ error: { message: string } | null } | any>;

export function runStatus(httpStatus: number, body: unknown): RunStatus {
  // deno-lint-ignore no-explicit-any
  const ok = (body as any)?.ok;
  if (httpStatus === 200 && ok !== false) return "success";
  if (httpStatus === 207) return "partial";
  return "error";
}

export async function withIngestionLog(
  ctx: { supabaseAdmin: { rpc: Rpc } },
  asset: "ingest-innovint" | "ingest-climate-2026" | "ingest-ets-report",
  run: () => Promise<Response>,
  summarize: (body: unknown) => RunSummary,
): Promise<Response> {
  const startedAt = new Date();
  let response: Response | undefined;
  let thrown: unknown;
  try {
    response = await run();
    return response;
  } catch (err) {
    thrown = err;
    console.error(`${asset}: unhandled error`, err);
    response = Response.json({ ok: false, reason: "unexpected error", detail: String(err) }, { status: 500 });
    return response;
  } finally {
    try {
      const httpStatus = response?.status ?? 500;
      let body: unknown = null;
      try { body = await response?.clone().json(); } catch { /* not JSON */ }
      let summary: RunSummary = {};
      try { summary = summarize(body) ?? {}; } catch (e) { summary = { error: `summarize failed: ${String(e)}` }; }
      const error = summary.error ?? (thrown ? String(thrown) : null);
      const result = await ctx.supabaseAdmin.rpc("log_ingestion_run", {
        p_asset: asset,
        p_started_at: startedAt.toISOString(),
        p_status: runStatus(httpStatus, body),
        p_http_status: httpStatus,
        p_rows_written: summary.rows_written ?? null,
        p_error: error ? String(error).slice(0, 2000) : null,
        p_detail: summary.detail ?? null,
      });
      if (result?.error) console.error(`${asset}: could not write ingestion_runs`, result.error.message);
    } catch (e) {
      console.error(`${asset}: could not write ingestion_runs`, e instanceof Error ? e.message : String(e));
    }
  }
}

// ingest-innovint's JSON response -> a run summary. rows_written is the number
// of rows UPSERTED (a full pull re-writes every row every run), not the number
// that changed -- the health check treats it accordingly.
export function summarizeInnovint(body: unknown): RunSummary {
  // deno-lint-ignore no-explicit-any
  const b = body as any;
  if (!b || typeof b !== "object") return { error: "no JSON response body" };
  const r = b.results ?? {};
  const phaseErrors = Object.entries(r).filter(([, v]) => v && typeof v === "object" && "error" in (v as object))
    // deno-lint-ignore no-explicit-any
    .map(([k, v]) => `${k}: ${(v as any).error}`);
  const rows = [r.analyses?.rows_upserted, r.vessels?.rows_upserted, r.harvest_receipts?.receipts_upserted]
    .filter((n) => typeof n === "number");
  return {
    rows_written: rows.length ? rows.reduce((a: number, n: number) => a + n, 0) : null,
    error: b.reason ? `${b.reason}${b.detail ? `: ${b.detail}` : ""}` : (phaseErrors.join("; ") || null),
    detail: {
      phases: Object.fromEntries(Object.entries(r).map(([k, v]) => [k, v && typeof v === "object" && "error" in (v as object) ? "error" : "ok"])),
      rows_upserted: { analyses: r.analyses?.rows_upserted ?? null, vessels: r.vessels?.rows_upserted ?? null, harvest_receipts: r.harvest_receipts?.receipts_upserted ?? null },
      stale_deleted: r.harvest_receipts?.stale_deleted ?? null,
      capacity_suspect: r.vessels?.rows_capacity_suspect ?? null,
      dangling_lot_refs: Array.isArray(b.dangling_lot_refs) ? b.dangling_lot_refs.length : null,
      http_call_count: b.http_call_count ?? null,
      duration_ms: b.duration_ms ?? null,
    },
  };
}

// ingest-climate-2026's JSON response -> a run summary.
export function summarizeClimate(body: unknown): RunSummary {
  // deno-lint-ignore no-explicit-any
  const b = body as any;
  if (!b || typeof b !== "object") return { error: "no JSON response body" };
  const r = b.results ?? {};
  // deno-lint-ignore no-explicit-any
  const metrics = Object.entries(r) as [string, any][];
  const errors = metrics.filter(([, v]) => v?.error).map(([k, v]) => `${k}: ${v.error}`);
  if (b.refresh_error) errors.push(`daily_weather refresh: ${b.refresh_error}`);
  return {
    rows_written: metrics.length ? metrics.reduce((a, [, v]) => a + (Number(v?.written) || 0), 0) : null,
    error: b.reason ? `${b.reason}${b.detail ? `: ${b.detail}` : ""}` : (errors.join("; ") || null),
    detail: {
      window: b.window ?? null,
      per_metric: Object.fromEntries(metrics.map(([k, v]) => [k, { written: v?.written ?? 0, nulls: v?.nulls ?? 0, future_skipped: v?.future_skipped ?? 0, unknown_vintage: v?.unknown_vintage ?? 0, vintages: v?.vintages ?? undefined, error: v?.error ? true : undefined }])),
      daily_weather_refreshed: b.daily_weather_refreshed ?? null,
      real_as_of: b.real_as_of ?? null,
      requested_models: b.requested_models ?? null,
    },
  };
}

// ingest-ets-report's JSON response -> a run summary. One run is one report
// sample (or a heartbeat); rows_written counts analytes written, quarantined
// ones are in detail.
export function summarizeEtsReport(body: unknown): RunSummary {
  // deno-lint-ignore no-explicit-any
  const b = body as any;
  if (!b || typeof b !== "object") return { error: "no JSON response body" };
  return {
    rows_written: typeof b.written === "number" ? b.written : null,
    error: b.ok === false ? String(b.reason ?? "refused") : null,
    detail: {
      heartbeat: b.heartbeat === true || undefined,
      report_no: b.report_no ?? null,
      sample_id: b.sample_id ?? null,
      sample_status: b.sample?.status ?? null,
      sample_reason: b.sample?.reason ?? null,
      written: b.written ?? null,
      quarantined: b.quarantined ?? null,
    },
  };
}
