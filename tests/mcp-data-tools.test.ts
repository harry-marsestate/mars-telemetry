// Deno tests for supabase/functions/mcp/data-tools.ts (the gateway wrapper
// around the four nightly-health data tools) and its handler wiring:
//   npx deno test --config supabase/functions/mcp/deno.json tests/mcp-data-tools.test.ts
import { assert, assertEquals, assertMatch } from "jsr:@std/assert@1";
import { type DomainReality, TOOLS } from "../supabase/functions/chat/tools.ts";
import { MCP_TOOLS } from "../supabase/functions/mcp/allowlist.ts";
import { HEALTH_TOOLS } from "../supabase/functions/mcp/health-tools.ts";
import { sha256Hex } from "../supabase/functions/mcp/auth.ts";
import { gatewayToolDef, runDataTool, splitToolContent } from "../supabase/functions/mcp/data-tools.ts";
import { createMcpHandler, type McpDeps, validateArgs } from "../supabase/functions/mcp/handler.ts";

const reality: DomainReality = new Map([
  ["air_temp", new Set([2023, 2024, 2025, 2026])],
  ["humidity", new Set([2024])],
  ["vessels", new Set([2026])],
  ...["gdd_cumulative_calibrated", "dtr_f", "vpd_kpa", "vpd_peak_kpa", "et0_in"].map((d) => [d, new Set([2024])] as [string, Set<number>]),
]);
const ok = (v: unknown, notes = "") => () => Promise.resolve({ content: JSON.stringify(v) + notes, isError: false });
const noCount = () => Promise.reject(new Error("count must not run"));

Deno.test("splitToolContent separates JSON from trailing notes", () => {
  assertEquals(splitToolContent('[{"a":1}]'), { json: [{ a: 1 }], notes: "" });
  assertEquals(splitToolContent('[{"a":"x\\n\\ny"}]\n\n(note)'), { json: [{ a: "x\n\ny" }], notes: "\n\n(note)" });
  assertEquals(splitToolContent("not json"), null);
});

Deno.test("get_anomalies requires an explicit, parseable as_of through the gateway (tool never runs)", async () => {
  let ran = 0;
  const run = () => { ran++; return Promise.resolve({ content: "[]", isError: false }); };
  for (const input of [{}, { as_of: "" }, { as_of: "yesterday" }, { as_of: 5 }]) {
    const r = await runDataTool("get_anomalies", input, run, { dataMode: "all", reality, count: noCount });
    assertEquals(r.isError, true);
    assertMatch(r.content, /as_of is required/);
  }
  assertEquals(ran, 0);
  const def = gatewayToolDef(TOOLS.find((t) => t.name === "get_anomalies")! as never) as { input_schema: { required?: string[] } };
  assert(def.input_schema.required?.includes("as_of"));
  assertMatch(validateArgs(def as never, { vintage: 2024 }) ?? "", /as_of/);
  assertEquals(validateArgs(def as never, { vintage: 2024, as_of: "2024-07-06T02:00:00Z" }), null);
  // chat's own schema is untouched
  assert(!(TOOLS.find((t) => t.name === "get_anomalies")!.input_schema as { required?: string[] }).required?.includes("as_of"));
});

Deno.test("get_series rows tagged by metric and year; text is runTool's byte for byte plus one [gateway] line", async () => {
  const rows = [{ t: "2022-12-31T23:00:00Z", v: 1 }, { t: "2023-01-01T00:00:00Z", v: 2 }];
  const r = await runDataTool("get_series", { metric: "air_temp" }, ok(rows), { dataMode: "all", reality, count: noCount });
  assertEquals(r.isError, false);
  assert(r.content.startsWith(JSON.stringify(rows) + "\n\n[gateway] "));
  assertEquals(r.content.split("\n\n[gateway] ").length, 2);
  const s = r.structuredContent as { rows: { data_status: string }[]; total_count: number; returned_count: number; truncated: boolean };
  assertEquals(s.rows.map((x) => x.data_status), ["mock", "real"]);
  assertEquals([s.total_count, s.returned_count, s.truncated], [2, 2, false]);
  assertMatch(r.content, /1 real, 1 simulated/);
  // explicit vintage wins over the timestamp's year
  const v = await runDataTool("get_series", { metric: "air_temp", vintage: 2024 }, ok(rows), { dataMode: "all", reality, count: noCount });
  assertEquals((v.structuredContent as { rows: { data_status: string }[] }).rows.map((x) => x.data_status), ["real", "real"]);
});

Deno.test("real_only: any row classified mock is refused (fail closed); chat's own block passes through as zero rows", async () => {
  const rows = [{ t: "2022-06-01T00:00:00Z", v: 1 }];
  const r = await runDataTool("get_series", { metric: "air_temp" }, ok(rows), { dataMode: "real_only", reality, count: noCount });
  assertEquals(r.isError, true);
  assertMatch(r.content, /Refused by the gateway: 1 row/);
  // domain_reality() failed (empty map): unknown, and real_only still refuses
  const u = await runDataTool("get_series", { metric: "air_temp" }, ok(rows), { dataMode: "real_only", reality: new Map(), count: noCount });
  assertEquals(u.isError, true);
  const ua = await runDataTool("get_series", { metric: "air_temp" }, ok(rows), { dataMode: "all", reality: new Map(), count: noCount });
  assertEquals((ua.structuredContent as { rows: { data_status: string }[] }).rows[0].data_status, "unknown");
  assertMatch(ua.content, /unclassified/);
  assert(!r.content.includes('"v"'), "no data in the refusal");

  const blocked = { real_only_mode_blocked: true, message: "withheld" };
  const b = await runDataTool("get_derived_series", { vintage: 2022 }, ok(blocked), { dataMode: "real_only", reality, count: noCount });
  assertEquals(b.isError, false);
  assertEquals((b.structuredContent as { total_count: number; real_only_mode_blocked: boolean }).real_only_mode_blocked, true);
});

Deno.test("get_anomalies tags each hit by its rule's domain; unmapped metric or unknown domain is tagged unknown", async () => {
  const hits = [{ rule_key: "a", metric_key: "air_temp" }, { rule_key: "b", metric_key: "humidity" }, { rule_key: "c", metric_key: "brand_new" }];
  const r = await runDataTool("get_anomalies", { vintage: 2024, as_of: "2024-07-06T02:00:00Z" }, ok(hits), { dataMode: "all", reality, count: noCount });
  assertEquals((r.structuredContent as { rows: { data_status: string }[] }).rows.map((x) => x.data_status), ["real", "real", "unknown"]);
  const r25 = await runDataTool("get_anomalies", { vintage: 2025, as_of: "2025-07-06T02:00:00Z" }, ok(hits.slice(0, 2)), { dataMode: "all", reality, count: noCount });
  assertEquals((r25.structuredContent as { rows: { data_status: string }[] }).rows.map((x) => x.data_status), ["real", "mock"]);
});

Deno.test("get_derived_series: real only if all five fields are real for the vintage; total_count from the same filters", async () => {
  const seen: [string, unknown[]][] = [];
  const count = (sql: string, params: unknown[]) => { seen.push([sql, params]); return Promise.resolve(450); };
  const rows = Array.from({ length: 400 }, (_, i) => ({ day: `d${i}` }));
  const r = await runDataTool("get_derived_series", { vintage: 2024, start_date: "2024-04-01", end_date: "2025-04-01" }, ok(rows), { dataMode: "all", reality, count });
  const s = r.structuredContent as { rows: { data_status: string }[]; total_count: number; truncated: boolean };
  assert(s.rows.every((x) => x.data_status === "real"));
  assertEquals([s.total_count, s.truncated], [450, true]);
  assertMatch(r.content, /TRUNCATED/);
  assertEquals(seen, [["select count(*)::int as n from public.daily_derived where vintage = $1 and day >= $2 and day <= $3", ["2024", "2024-04-01", "2025-04-01"]]]);
  const r23 = await runDataTool("get_derived_series", { vintage: 2023 }, ok(rows.slice(0, 1)), { dataMode: "all", reality, count: () => Promise.resolve(1) });
  assertEquals((r23.structuredContent as { rows: { data_status: string }[] }).rows[0].data_status, "mock");
});

Deno.test("get_vessels count mirrors the tool's filters (archived default, type, lot-name ilike)", async () => {
  const seen: [string, unknown[]][] = [];
  const count = (sql: string, params: unknown[]) => { seen.push([sql, params]); return Promise.resolve(3); };
  await runDataTool("get_vessels", {}, ok([{ code: "T1" }]), { dataMode: "all", reality, count });
  await runDataTool("get_vessels", { include_archived: true, vessel_type: "tank", current_lot_name: "CS*23" }, ok([]), { dataMode: "all", reality, count });
  assertEquals(seen, [
    ["select count(*)::int as n from public.vessels where archived = false", []],
    ["select count(*)::int as n from public.vessels where vessel_type = $1 and current_lot_name ilike $2", ["tank", "%CS%23%"]],
  ]);
});

Deno.test("tool errors pass through untouched; unreadable output is an error, never raw", async () => {
  const err = await runDataTool("get_vessels", {}, () => Promise.resolve({ content: "Tool execution failed unexpectedly.", isError: true }), { dataMode: "all", reality, count: noCount });
  assertEquals(err, { content: "Tool execution failed unexpectedly.", isError: true });
  const bad = await runDataTool("get_vessels", {}, () => Promise.resolve({ content: "garbage", isError: false }), { dataMode: "all", reality, count: noCount });
  assertEquals(bad.isError, true);
});

Deno.test("handler: get_anomalies without as_of is rejected before any transaction; structuredContent is passed through", async () => {
  const GOOD_KEY = "mtk_" + "A".repeat(43);
  const calls: string[] = [];
  const deps: McpDeps = {
    authenticate: async (h) => h === await sha256Hex(GOOD_KEY) ? { keyId: "k", userId: "u" } : null,
    logCall: async () => {},
    scope: async () => [...MCP_TOOLS],
    authorize: async () => ({ allowed: true, httpStatus: 200, reason: "ok", retryAfterSeconds: null }),
    runScoped: async (_u, _k, fn) => await fn({ rpc: async () => ({ data: "all", error: null }) }),
    runTool: async (_sb, name) => { calls.push(name); return { content: "[]\n\n[gateway] x", isError: false, structuredContent: { rows: [], total_count: 0 } }; },
    fetchDomainReality: async () => new Map(),
    tools: [...TOOLS, ...HEALTH_TOOLS] as never,
  };
  const handler = createMcpHandler(deps);
  const req = (name: string, args: unknown) => new Request("http://local/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: `Bearer ${GOOD_KEY}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
  const missing = await (await handler(req("get_anomalies", { vintage: 2024 }))).json();
  assertEquals(missing.result.isError, true);
  assertMatch(missing.result.content[0].text, /as_of/);
  assertEquals(calls, []);
  const good = await (await handler(req("get_vessels", {}))).json();
  assertEquals(good.result.structuredContent, { rows: [], total_count: 0 });
  const list = await (await handler(new Request("http://local/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: `Bearer ${GOOD_KEY}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
  }))).json();
  const anomalies = list.result.tools.find((t: { name: string }) => t.name === "get_anomalies");
  assert(anomalies.inputSchema.required.includes("as_of"));
});
