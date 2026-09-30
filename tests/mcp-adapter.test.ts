// Unit tests for the MCP PostgREST-compatible adapter and the scoped
// transaction wrapper. SQL generation and behaviour only -- output fidelity
// against the live REST API is scripts/mcp-parity.mjs's job.
//   npx deno test --no-lock --config supabase/functions/mcp/deno.json tests/mcp-adapter.test.ts
import { assert, assertEquals, assertMatch, assertRejects, assertThrows } from "jsr:@std/assert@1";
import { MAX_ROWS, parsePostgrestList, PostgrestAdapter } from "../supabase/functions/mcp/adapter.ts";
import { runAsKeyOwner, type Tx } from "../supabase/functions/mcp/gateway.ts";

const TYPES: Record<string, Record<string, string>> = {
  lot_analyses: { lot_code: "text", lot_name: "text", analysis_type: "text", value: "numeric", recorded_at: "timestamp with time zone", vintage: "integer" },
  labour_actuals_by_month: { vintage: "integer", period_month: "date", job_category: "text", labor_hours: "numeric" },
};

function fakeDb(body: unknown = []) {
  const seen: { text: string; params: unknown[] }[] = [];
  const query = (text: string, params: unknown[]) => {
    seen.push({ text, params });
    if (text.includes("from pg_attribute")) {
      const rel = String(params[0]).replace("public.", "");
      return Promise.resolve(Object.entries(TYPES[rel] ?? {}).map(([name, type]) => ({ name, type })));
    }
    return Promise.resolve([{ body: JSON.stringify(body) }]);
  };
  return { adapter: new PostgrestAdapter(query), seen, main: () => seen.filter((s) => !s.text.includes("pg_attribute")) };
}

Deno.test("builds the same select PostgREST would, with typed parameters and the max-rows cap", async () => {
  const db = fakeDb([{ lot_code: "MA23CSV3" }]);
  const { data, error } = await db.adapter.from("lot_analyses")
    .select("lot_name, lot_code, value, recorded_at")
    .order("recorded_at", { ascending: false })
    .limit(50)
    .eq("lot_code", "MA23CSV3")
    .gte("recorded_at", "2023-01-01")
    .lte("vintage", 2024);
  assertEquals(error, null);
  assertEquals(data, [{ lot_code: "MA23CSV3" }]);
  const [q] = db.main();
  assertEquals(
    q.text,
    `select coalesce(json_agg(mcp_row), '[]'::json)::text as body from (select "lot_name", "lot_code", "value", "recorded_at" from public."lot_analyses" where "lot_code" = $1::text and "recorded_at" >= $2::timestamp with time zone and "vintage" <= $3::integer order by "recorded_at" desc limit 50) mcp_row`,
  );
  assertEquals(q.params, ["MA23CSV3", "2023-01-01", "2024"]);
});

Deno.test("no limit -> MAX_ROWS; a limit above MAX_ROWS is capped, never raised", async () => {
  for (const [lim, want] of [[undefined, MAX_ROWS], [5000, MAX_ROWS], [200, 200]] as const) {
    const db = fakeDb();
    let q = db.adapter.from("lot_analyses").select("lot_code");
    if (lim !== undefined) q = q.limit(lim);
    await q;
    assertMatch(db.main()[0].text, new RegExp(` limit ${want}\\) mcp_row$`));
  }
  assertEquals(MAX_ROWS, 1000);
});

Deno.test("casts in select keep the column name as the JSON key; ilike maps * to %", async () => {
  const db = fakeDb();
  await db.adapter.from("labour_actuals_by_month").select("vintage, labor_hours::text").ilike("job_category", "%Canopy*");
  const [q] = db.main();
  assertMatch(q.text, /select "vintage", "labor_hours"::text as "labor_hours" from/);
  assertMatch(q.text, /"job_category" ilike \$1/);
  assertEquals(q.params, ["%Canopy%"]);
});

Deno.test("in / not-in use typed arrays; not() parses PostgREST list syntax", async () => {
  const db = fakeDb();
  await db.adapter.from("lot_analyses").select("lot_code").in("vintage", [2023, 2024]).not("lot_code", "in", '("MA23CSV1","A,B","q\\"x")');
  const [q] = db.main();
  assertMatch(q.text, /"vintage" = any\(\$1::integer\[\]\) and not \("lot_code" = any\(\$2::text\[\]\)\)/);
  assertEquals(q.params, [["2023", "2024"], ["MA23CSV1", "A,B", 'q"x']]);
  assertEquals(parsePostgrestList("(A,B)"), ["A", "B"]);
  assertEquals(parsePostgrestList("()"), []);
});

Deno.test("maybeSingle: 0 -> null, 1 -> row, >1 -> PGRST116 (as postgrest-js)", async () => {
  assertEquals((await fakeDb([]).adapter.from("lot_analyses").select("lot_code").maybeSingle()).data, null);
  assertEquals((await fakeDb([{ lot_code: "X" }]).adapter.from("lot_analyses").select("lot_code").maybeSingle()).data, { lot_code: "X" });
  const two = await fakeDb([{ lot_code: "X" }, { lot_code: "Y" }]).adapter.from("lot_analyses").select("lot_code").maybeSingle();
  assertEquals(two.data, null);
  assertEquals(two.error?.code, "PGRST116");
});

Deno.test("refuses relations outside the allowlist, view dependencies included", () => {
  const { adapter } = fakeDb();
  for (const rel of ["sensor_readings", "user_profiles", "lab_samples", "labour_actuals", "agent_api_keys", "daily_weather", "real_data_sources", "vessel_snapshots", 'lot_analyses"; drop table x; --']) {
    assertThrows(() => adapter.from(rel), Error, "not in the MCP allowlist");
  }
});

Deno.test("refuses unsupported builder usage loudly instead of mis-translating", async () => {
  const { adapter } = fakeDb();
  assertThrows(() => adapter.from("lot_analyses").select("*"), Error, "unsupported");
  assertThrows(() => adapter.from("lot_analyses").select("lot_code").not("lot_code", "eq", "x"), Error, "unsupported");
  assertThrows(() => adapter.from("lot_analyses").select("lot_code").order("lot_code", { nullsFirst: true }), Error, "unsupported");
  await assertRejects(() => adapter.rpc("accessible_blocks", {}), Error, "not callable");
  await assertRejects(() => adapter.rpc("mcp_key_scope", {}), Error, "not callable");
  await assertRejects(() => adapter.rpc("mcp_authenticate", {}), Error, "not callable");
});

Deno.test("unknown column -> an error result (42703), not a throw", async () => {
  const { error, data } = await fakeDb().adapter.from("lot_analyses").select("nope");
  assertEquals(data, null);
  assertEquals(error?.code, "42703");
});

Deno.test("rpc: current_data_mode scalar and domain_reality rows, capped", async () => {
  const db = fakeDb("real_only");
  assertEquals((await db.adapter.rpc("current_data_mode")).data, "real_only");
  const db2 = fakeDb([{ domain: "air_temp", vintage: 2026, is_real: true }]);
  const r = await db2.adapter.rpc("domain_reality", { p_vintages: [2025, 2026] });
  assertEquals(r.data, [{ domain: "air_temp", vintage: 2026, is_real: true }]);
  assertEquals(db2.main()[0].params, [["2025", "2026"]]);
  assertMatch(db2.main()[0].text, / limit 1000\) mcp_row$/);
});

Deno.test("rpc: series_bucketed / anomalies_eval use named, typed arguments; omitted ones take the function default", async () => {
  const db = fakeDb([{ t: "2024-07-01T00:00:00+00:00", v: 1.5 }]);
  const r = await db.adapter.rpc("series_bucketed", { p_metric: "air_temp", p_block: null, p_vintage: 2024, p_start: "2024-07-01", p_end: "2024-07-02", p_bucket: "1 hours", p_agg: "avg" });
  assertEquals(r, { data: [{ t: "2024-07-01T00:00:00+00:00", v: 1.5 }], error: null });
  assertEquals(db.main()[0].text,
    "select coalesce(json_agg(mcp_row), '[]'::json)::text as body from (select * from public.series_bucketed(p_metric => $1::text, p_block => $2::text, p_vintage => $3::integer, p_start => $4::timestamptz, p_end => $5::timestamptz, p_bucket => $6::interval, p_agg => $7::text) limit 1000) mcp_row");
  assertEquals(db.main()[0].params, ["air_temp", null, "2024", "2024-07-01", "2024-07-02", "1 hours", "avg"]);

  const db2 = fakeDb([]);
  await db2.adapter.rpc("anomalies_eval", { p_vintage: 2024, p_as_of: "2024-07-06T02:00:00Z" });
  assertMatch(db2.main()[0].text, /public\.anomalies_eval\(p_vintage => \$1::integer, p_as_of => \$2::timestamptz\) limit 1000\) mcp_row$/);
  await assertRejects(() => db2.adapter.rpc("anomalies_eval", { p_vintage: 2024, "p_as_of) ; drop": 1 }), Error, "unsupported");
  await assertRejects(() => db2.adapter.rpc("mcp_authorize_call", {}), Error, "not callable");
});

Deno.test("runAsKeyOwner: read-only, claims, role switch, then asserts before running the tool", async () => {
  const statements: string[] = [];
  const makeSql = (whoami: Record<string, unknown>) => ({
    begin: async <T>(fn: (tx: Tx) => Promise<T>) => {
      const tx: Tx = {
        unsafe: (text: string, params?: unknown[]) => {
          statements.push(params?.length ? `${text} ${JSON.stringify(params)}` : text);
          return Promise.resolve(text.startsWith("select current_user") ? [whoami] : [{ body: "[]" }]);
        },
      };
      return await fn(tx);
    },
  });
  const ok = await runAsKeyOwner(makeSql({ role: "mcp_reader", sub: "u1", ro: "on" }), "u1", "k1", async (q) => { await q("select 1", []); return "done"; });
  assertEquals(ok, "done");
  assertEquals(statements.slice(0, 4), [
    "set transaction read only",
    "set local statement_timeout = '10s'",
    `select set_config('request.jwt.claims', $1, true) ["{\\"sub\\":\\"u1\\",\\"role\\":\\"mcp_reader\\",\\"mcp_key_id\\":\\"k1\\"}"]`,
    "set local role mcp_reader",
  ]);
  assert(statements.includes("select 1"));

  for (const bad of [{ role: "authenticated", sub: "u1", ro: "on" }, { role: "mcp_reader", sub: "u2", ro: "on" }, { role: "mcp_reader", sub: "u1", ro: "off" }]) {
    let ran = false;
    await assertRejects(() => runAsKeyOwner(makeSql(bad), "u1", "k1", async () => { ran = true; }), Error, "scope assertion failed");
    assertEquals(ran, false);
  }
});
