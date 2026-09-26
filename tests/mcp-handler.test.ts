// Deno tests for supabase/functions/mcp (the function imports npm: packages
// through its own import map, so these run under Deno, not node:test):
//   npx deno test --config supabase/functions/mcp/deno.json tests/mcp-handler.test.ts
import { assert, assertEquals, assertMatch } from "jsr:@std/assert@1";
import { TOOLS } from "../supabase/functions/chat/tools.ts";
import { MCP_TOOLS } from "../supabase/functions/mcp/allowlist.ts";
import { parseBearerKey, sha256Hex } from "../supabase/functions/mcp/auth.ts";
import { createMcpHandler, type McpDeps, validateArgs } from "../supabase/functions/mcp/handler.ts";

const GOOD_KEY = "mtk_" + "A".repeat(43);
const USER = "00000000-0000-4000-8000-000000000001";
const KEY_ID = "00000000-0000-4000-8000-0000000000aa";

function harness(overrides: Partial<McpDeps> = {}) {
  const calls = { authenticate: [] as string[], scoped: [] as [string, string][], runTool: [] as string[], log: [] as [string, boolean][] };
  const deps: McpDeps = {
    async authenticate(hash) {
      calls.authenticate.push(hash);
      return hash === await sha256Hex(GOOD_KEY) ? { keyId: KEY_ID, userId: USER } : null;
    },
    async logCall(_hash, tool, _args, isError) { calls.log.push([tool, isError]); },
    async runScoped(userId, keyId, fn) {
      calls.scoped.push([userId, keyId]);
      return await fn({ rpc: async () => ({ data: "all", error: null }) });
    },
    async runTool(_sb, name) { calls.runTool.push(name); return { content: `rows for ${name}`, isError: false }; },
    async fetchDomainReality() { return new Map(); },
    tools: TOOLS as never,
    ...overrides,
  };
  return { handler: createMcpHandler(deps), calls };
}

function rpc(body: unknown, auth: string | null = `Bearer ${GOOD_KEY}`): Request {
  const headers: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
  if (auth !== null) headers.Authorization = auth;
  return new Request("http://local/mcp", { method: "POST", headers, body: JSON.stringify(body) });
}
const call = (name: string, args: unknown = {}) => rpc({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name, arguments: args } });

Deno.test("parseBearerKey accepts only the issued key shape", () => {
  assertEquals(parseBearerKey(`Bearer ${GOOD_KEY}`), GOOD_KEY);
  assertEquals(parseBearerKey(null), null);
  assertEquals(parseBearerKey(GOOD_KEY), null);
  assertEquals(parseBearerKey(`Basic ${GOOD_KEY}`), null);
  assertEquals(parseBearerKey("Bearer mtk_short"), null);
  assertEquals(parseBearerKey(`Bearer ${GOOD_KEY}x`), null);
  assertEquals(parseBearerKey("Bearer eyJhbGciOiJIUzI1NiJ9.e30.x"), null);
});

Deno.test("missing or malformed key -> 401 without touching the database", async () => {
  const { handler, calls } = harness();
  for (const auth of [null, "Bearer nope", `Token ${GOOD_KEY}`]) {
    const res = await handler(rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, auth));
    assertEquals(res.status, 401);
    assertMatch(res.headers.get("WWW-Authenticate") ?? "", /^Bearer /);
  }
  assertEquals(calls.authenticate.length, 0);
});

Deno.test("well-formed but unknown key -> 401 after the lookup; lookup failure -> 500", async () => {
  const { handler, calls } = harness();
  const res = await handler(rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, `Bearer mtk_${"B".repeat(43)}`));
  assertEquals(res.status, 401);
  assertEquals(calls.authenticate.length, 1);
  assertMatch(calls.authenticate[0], /^[0-9a-f]{64}$/);

  const broken = harness({ authenticate: () => Promise.reject(new Error("db down")) });
  assertEquals((await broken.handler(rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }))).status, 500);
});

Deno.test("initialize, then tools/list returns exactly the round-one allowlist", async () => {
  const { handler, calls } = harness();
  const init = await handler(rpc({
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } },
  }));
  assertEquals(init.status, 200);
  assertEquals((await init.json()).result.serverInfo.name, "mars-telemetry");

  const list = await handler(rpc({ jsonrpc: "2.0", id: 2, method: "tools/list" }));
  const names = (await list.json()).result.tools.map((t: { name: string }) => t.name).sort();
  assertEquals(names, [...MCP_TOOLS].sort());
  assertEquals(calls.scoped.length, 0, "no scoped transaction is opened for list/initialize");
});

Deno.test("non-allowlisted tools are rejected before any scoped transaction or runTool, and are audited", async () => {
  const { handler, calls } = harness();
  for (const name of ["get_series", "get_derived_series", "get_anomalies", "get_vessels", "drop_everything"]) {
    const body = await (await handler(call(name))).json();
    assertEquals(body.error.code, -32602);
    assertMatch(body.error.message, /Unknown tool/);
  }
  assertEquals(calls.runTool, []);
  assertEquals(calls.scoped.length, 0);
  assertEquals(calls.log.map(([t, e]) => `${t}:${e}`), [
    "get_series:true", "get_derived_series:true", "get_anomalies:true", "get_vessels:true", "drop_everything:true",
  ]);
});

Deno.test("allowlisted call: one scoped transaction per call, as the key's owner", async () => {
  const { handler, calls } = harness();
  for (const name of MCP_TOOLS) {
    const body = await (await handler(call(name))).json();
    assertEquals(body.result.content[0].text, `rows for ${name}`);
  }
  assertEquals(calls.runTool, [...MCP_TOOLS]);
  assertEquals(calls.scoped, MCP_TOOLS.map(() => [USER, KEY_ID]));
  assertEquals(calls.log.map(([, e]) => e), MCP_TOOLS.map(() => false));
});

Deno.test("a failed scoped transaction is a tool error, audited, never a leak of the cause", async () => {
  const { handler, calls } = harness({ runScoped: () => Promise.reject(new Error("mcp gateway: transaction scope assertion failed")) });
  const body = await (await handler(call("get_berry_maturity"))).json();
  assertEquals(body.result.isError, true);
  assertEquals(body.result.content[0].text, "Tool execution failed unexpectedly.");
  assertEquals(calls.log, [["get_berry_maturity", true]]);
});

Deno.test("arguments are schema-checked before runTool", async () => {
  const lot = TOOLS.find((t) => t.name === "get_lot_analyses")! as never;
  const wine = TOOLS.find((t) => t.name === "get_wine_lab_results")! as never;
  assertEquals(validateArgs(lot, { lot_code: "MA23CSV3", limit: 20 }), null);
  assertEquals(validateArgs(lot, undefined), null);
  assertMatch(validateArgs(lot, { lot_code: 5 })!, /lot_code/);
  assertMatch(validateArgs(lot, { limit: 1.5 })!, /integer/);
  assertMatch(validateArgs(lot, { select: "*" })!, /unknown argument/);
  assertMatch(validateArgs(lot, ["x"])!, /object/);
  assertMatch(validateArgs(lot, { lot_name: "x".repeat(201) })!, /at most 200/);
  assertMatch(validateArgs(wine, { sample_type: "tank" })!, /one of/);

  const { handler, calls } = harness();
  const body = await (await handler(call("get_lot_analyses", { lot_code: 5 }))).json();
  assertEquals(body.result.isError, true);
  assertEquals(calls.runTool, []);
  assertEquals(calls.scoped.length, 0);
});
