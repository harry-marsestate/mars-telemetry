// ingest-ets-report's request flow (supabase/functions/ingest-ets-report/handler.ts)
// against a fake PostgREST rpc. The SQL itself is tested in ets-ingest-sql.test.mjs.
//   npx deno test --no-lock tests/ingest-ets-report.test.ts
import { assert, assertEquals, assertMatch } from "jsr:@std/assert@1";
import { createHandler, KEY_HEADER, sha256Hex } from "../supabase/functions/ingest-ets-report/handler.ts";
import { summarizeEtsReport } from "../supabase/functions/_shared/ingestion-log.ts";

const KEY = "ets_ingest_TESTKEY_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const migration = await Deno.readTextFile(new URL("../supabase/migrations/20261006120000_ets_report_ingest.sql", import.meta.url));
const SIGNATURES: Record<string, string[]> = {};
for (const m of migration.matchAll(/create function public\.(\w+)\(([^)]*)\)/g)) {
  SIGNATURES[m[1]] = m[2].split(",").map((a) => a.trim().split(/\s+/)[0]).filter(Boolean);
}

type Call = { fn: string; args: Record<string, unknown> };
function harness(apply: (payload: unknown) => unknown = () => ({ ok: true, http_status: 200, written: 3, quarantined: 0, rows: [] }), opts: { authError?: boolean } = {}) {
  const calls: Call[] = [];
  const ctx = {
    supabaseAdmin: {
      rpc: async (fn: string, args: Record<string, unknown>) => {
        calls.push({ fn, args });
        if (fn !== "log_ingestion_run") assertEquals(Object.keys(args).sort(), [...SIGNATURES[fn]].sort(), `${fn} argument names match the SQL`);
        if (fn === "ets_ingest_key_ok") {
          if (opts.authError) return { data: null, error: { message: "boom" } };
          return { data: args.p_key_sha256 === await sha256Hex(KEY), error: null };
        }
        if (fn === "ets_ingest_apply") return { data: apply(args.p_payload), error: null };
        return { data: 1, error: null };
      },
    },
  };
  return { handler: createHandler(ctx), calls };
}
const post = (body: unknown, key: string | null = KEY, method = "POST") =>
  new Request("http://x/ingest-ets-report", {
    method, headers: { "content-type": "application/json", ...(key === null ? {} : { [KEY_HEADER]: key }) },
    body: method === "POST" ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined,
  });

Deno.test("header name is x-ets-ingest-key", () => assertEquals(KEY_HEADER, "x-ets-ingest-key"));

Deno.test("no key / wrong key: 401, the database sees only a hash, no run logged", async () => {
  const { handler, calls } = harness();
  assertEquals((await handler(post({}, null))).status, 401);
  assertEquals(calls.length, 0);
  const r = await handler(post({}, "sb_secret_wrong"));
  assertEquals(r.status, 401);
  assertEquals(calls.map((c) => c.fn), ["ets_ingest_key_ok"]);
  assertMatch(String(calls[0].args.p_key_sha256), /^[0-9a-f]{64}$/);
  assert(!JSON.stringify(calls).includes("sb_secret_wrong"));
});

Deno.test("key check unavailable: 503, not 401 or 200", async () => {
  const { handler } = harness(undefined, { authError: true });
  assertEquals((await handler(post({}))).status, 503);
});

Deno.test("GET: 405", async () => {
  const { handler, calls } = harness();
  assertEquals((await handler(post(null, KEY, "GET"))).status, 405);
  assertEquals(calls.length, 0);
});

Deno.test("valid key: payload passed through unchanged, status from the SQL, one run logged, key never sent", async () => {
  const payload = { report_no: "R1", sample_id: "609290801", analytes: [{ name: "brix" }] };
  const { handler, calls } = harness((p) => ({ ok: true, http_status: 207, report_no: "R1", sample_id: "609290801", written: 1, quarantined: 2, sample: { status: "written" }, rows: [] }));
  const r = await handler(post(payload));
  assertEquals(r.status, 207);
  const body = await r.json();
  assertEquals(body.http_status, undefined);
  assertEquals([body.written, body.quarantined], [1, 2]);
  assertEquals(calls.map((c) => c.fn), ["ets_ingest_key_ok", "ets_ingest_apply", "log_ingestion_run"]);
  assertEquals(calls[1].args.p_payload, payload);
  const log = calls[2].args;
  assertEquals([log.p_asset, log.p_status, log.p_http_status, log.p_rows_written], ["ingest-ets-report", "partial", 207, 1]);
  assert(!JSON.stringify(calls).includes(KEY));
});

Deno.test("refused payload (400 from SQL) is logged as an error run with its reason", async () => {
  const { handler, calls } = harness(() => ({ ok: false, http_status: 400, reason: "sample_date must be YYYY-MM-DD" }));
  const r = await handler(post({ x: 1 }));
  assertEquals(r.status, 400);
  const log = calls.at(-1)!.args;
  assertEquals([log.p_status, log.p_error], ["error", "sample_date must be YYYY-MM-DD"]);
});

Deno.test("not JSON: 400, logged; heartbeat: 200 and logged as a success with 0 rows", async () => {
  const a = harness();
  assertEquals((await a.handler(post("{not json"))).status, 400);
  assertEquals(a.calls.map((c) => c.fn), ["ets_ingest_key_ok", "log_ingestion_run"]);
  const b = harness();
  const r = await b.handler(post({ heartbeat: true, source: "ets_pdf_email" }));
  assertEquals(r.status, 200);
  assertEquals(b.calls.map((c) => c.fn), ["ets_ingest_key_ok", "log_ingestion_run"]);
  assertEquals([b.calls[1].args.p_status, b.calls[1].args.p_rows_written], ["success", 0]);
  assertEquals((await b.handler(post({ heartbeat: true }))).status, 400);
});

Deno.test("oversized body: 413", async () => {
  const { handler } = harness();
  assertEquals((await handler(post("x".repeat(300 * 1024)))).status, 413);
});

Deno.test("summarizeEtsReport", () => {
  assertEquals(summarizeEtsReport({ ok: true, report_no: "R", sample_id: "S", written: 4, quarantined: 1, sample: { status: "written" } }).rows_written, 4);
  assertEquals(summarizeEtsReport({ ok: false, reason: "bad" }).error, "bad");
  assertEquals(summarizeEtsReport(null).error, "no JSON response body");
});
