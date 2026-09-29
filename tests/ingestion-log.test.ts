// withIngestionLog / summarizers (supabase/functions/_shared/ingestion-log.ts).
//   npx deno test --no-lock tests/ingestion-log.test.ts
import { assertEquals, assertMatch } from "jsr:@std/assert@1";
import { runStatus, summarizeClimate, summarizeInnovint, withIngestionLog } from "../supabase/functions/_shared/ingestion-log.ts";

function fakeCtx(rpcBehaviour: "ok" | "error" | "throw" = "ok") {
  const calls: Record<string, unknown>[] = [];
  return {
    calls,
    ctx: {
      supabaseAdmin: {
        rpc: (fn: string, args: Record<string, unknown>) => {
          calls.push({ fn, ...args });
          if (rpcBehaviour === "throw") return Promise.reject(new Error("network down"));
          return Promise.resolve({ error: rpcBehaviour === "error" ? { message: "permission denied" } : null });
        },
      },
    },
  };
}

// Shapes copied from real production responses (2026-09-29, requests 316/317).
const INNOVINT_OK = {
  ok: true,
  results: {
    analyses: { rows_deduped: 6, rows_upserted: 1405, lots_processed: 50 },
    vessels: { rows_upserted: 241, rows_capacity_suspect: 63 },
    harvest_receipts: { vintages_swept: "2022-2026", receipts_upserted: 7, stale_deleted: 0 },
  },
  dangling_lot_refs: ["lot_a", "lot_b"], http_call_count: 97, duration_ms: 76500,
};
const CLIMATE_OK = {
  ok: true,
  window: { start: "2026-09-15", end: "2026-09-29", stored_through: "2026-09-29T23:00:00.000Z", daily_weather_through: "2026-09-28", fetch_end_fallback: false },
  results: {
    air_temp: { written: 359, nulls: 0, future_skipped: 1 }, humidity: { written: 359, nulls: 0, future_skipped: 1 },
    precipitation: { written: 359, nulls: 0, future_skipped: 1 }, soil_moisture: { written: 216, nulls: 143, future_skipped: 1 },
    soil_temp: { written: 216, nulls: 143, future_skipped: 1 },
  },
  daily_weather_refreshed: true, refresh_error: null, real_as_of: "2026-09-23",
};

Deno.test("runStatus: 200 ok -> success, 207 -> partial, anything else or ok:false -> error", () => {
  assertEquals(runStatus(200, { ok: true }), "success");
  assertEquals(runStatus(200, { ok: false }), "error");
  assertEquals(runStatus(207, { ok: false }), "partial");
  assertEquals(runStatus(500, null), "error");
  assertEquals(runStatus(401, null), "error");
});

Deno.test("success: one row, response returned untouched", async () => {
  const { ctx, calls } = fakeCtx();
  const res = await withIngestionLog(ctx, "ingest-innovint", async () => Response.json(INNOVINT_OK), summarizeInnovint);
  assertEquals(res.status, 200);
  assertEquals(await res.json(), INNOVINT_OK);
  assertEquals(calls.length, 1);
  const c = calls[0];
  assertEquals([c.fn, c.p_asset, c.p_status, c.p_http_status, c.p_rows_written, c.p_error], ["log_ingestion_run", "ingest-innovint", "success", 200, 1653, null]);
  // deno-lint-ignore no-explicit-any
  const d = c.p_detail as any;
  assertEquals([d.capacity_suspect, d.dangling_lot_refs, d.http_call_count, d.phases.vessels], [63, 2, 97, "ok"]);
});

Deno.test("partial: a phase error is recorded as partial with the phase's message", async () => {
  const { ctx, calls } = fakeCtx();
  const body = { ...INNOVINT_OK, ok: false, results: { ...INNOVINT_OK.results, vessels: { error: "InnoVint 503 Service Unavailable" } } };
  const res = await withIngestionLog(ctx, "ingest-innovint", async () => Response.json(body, { status: 207 }), summarizeInnovint);
  assertEquals(res.status, 207);
  assertEquals([calls[0].p_status, calls[0].p_http_status, calls[0].p_rows_written], ["partial", 207, 1412]);
  assertMatch(String(calls[0].p_error), /vessels: InnoVint 503/);
});

Deno.test("error response (e.g. missing token) is recorded as error with its reason", async () => {
  const { ctx, calls } = fakeCtx();
  await withIngestionLog(ctx, "ingest-innovint", async () => Response.json({ ok: false, reason: "INNOVINT_TOKEN is not set" }, { status: 500 }), summarizeInnovint);
  assertEquals([calls[0].p_status, calls[0].p_error], ["error", "INNOVINT_TOKEN is not set"]);
});

Deno.test("a thrown exception becomes a 500 response AND an error row", async () => {
  const { ctx, calls } = fakeCtx();
  const res = await withIngestionLog(ctx, "ingest-climate-2026", async () => { throw new Error("boom"); }, summarizeClimate);
  assertEquals(res.status, 500);
  assertEquals((await res.json()).reason, "unexpected error");
  assertEquals(calls[0].p_status, "error");
  assertMatch(String(calls[0].p_error), /boom/);
});

Deno.test("a failing logger never changes the function's response", async () => {
  for (const mode of ["error", "throw"] as const) {
    const { ctx, calls } = fakeCtx(mode);
    const res = await withIngestionLog(ctx, "ingest-climate-2026", async () => Response.json(CLIMATE_OK), summarizeClimate);
    assertEquals(res.status, 200, mode);
    assertEquals((await res.json()).ok, true, mode);
    assertEquals(calls.length, 1, mode);
  }
});

Deno.test("non-JSON response body still yields a row", async () => {
  const { ctx, calls } = fakeCtx();
  await withIngestionLog(ctx, "ingest-climate-2026", async () => new Response("gateway timeout", { status: 504 }), summarizeClimate);
  assertEquals([calls[0].p_status, calls[0].p_http_status, calls[0].p_error], ["error", 504, "no JSON response body"]);
});

Deno.test("summarizeClimate: rows, per-metric detail, errors incl. refresh", () => {
  const s = summarizeClimate(CLIMATE_OK);
  assertEquals([s.rows_written, s.error], [1509, null]);
  // deno-lint-ignore no-explicit-any
  assertEquals((s.detail as any).per_metric.soil_moisture, { written: 216, nulls: 143, future_skipped: 1, wrong_vintage: 0, error: undefined });
  const bad = summarizeClimate({ ...CLIMATE_OK, ok: false, results: { ...CLIMATE_OK.results, soil_temp: { written: 0, nulls: 0, error: "Open-Meteo 400" } }, refresh_error: "timeout" });
  assertEquals(bad.error, "soil_temp: Open-Meteo 400; daily_weather refresh: timeout");
});
