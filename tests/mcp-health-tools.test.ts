// Deno tests for supabase/functions/mcp/health-tools.ts and its wiring:
//   npx deno test --no-lock --config supabase/functions/mcp/deno.json tests/mcp-health-tools.test.ts
import { assert, assertEquals, assertMatch, assertRejects } from "jsr:@std/assert@1";
import { TOOLS } from "../supabase/functions/chat/tools.ts";
import { PostgrestAdapter } from "../supabase/functions/mcp/adapter.ts";
import { MCP_TOOLS } from "../supabase/functions/mcp/allowlist.ts";
import { sha256Hex } from "../supabase/functions/mcp/auth.ts";
import { createMcpHandler, type McpDeps, validateArgs } from "../supabase/functions/mcp/handler.ts";
import { HEALTH_TOOL_NAMES, HEALTH_TOOLS, runHealthTool } from "../supabase/functions/mcp/health-tools.ts";

Deno.test("health tools are exposed, not chat tools", () => {
  for (const n of HEALTH_TOOL_NAMES) {
    assert(MCP_TOOLS.includes(n));
    assert(!TOOLS.some((t) => t.name === n), `${n} must not reach the in-app chat`);
  }
  const hist = HEALTH_TOOLS.find((t) => t.name === "get_health_history")!;
  assertEquals(validateArgs(hist as never, { days: 7 }), null);
  assertMatch(validateArgs(hist as never, { days: 1.5 }) ?? "", /integer/);
  assertMatch(validateArgs(hist as never, { hours: 1 }) ?? "", /unknown argument/);
});

Deno.test("runHealthTool calls exactly one function each; errors are generic unless they're the operator/bounds messages", async () => {
  const calls: [string, unknown][] = [];
  const client = { rpc: (n: string, p?: unknown) => { calls.push([n, p]); return Promise.resolve({ data: { overall: "pass" }, error: null }); } };
  const r = await runHealthTool(client, "get_system_health", {});
  assertEquals([r.isError, r.structuredContent], [false, { overall: "pass" }]);
  await runHealthTool(client, "get_health_history", {});
  await runHealthTool(client, "get_health_history", { days: 30 });
  await runHealthTool(client, "get_health_baselines", {});
  assertEquals(calls, [["health_system_status", undefined], ["health_history", { p_days: 7 }], ["health_history", { p_days: 30 }], ["health_baselines", undefined]]);
  for (const days of [0, 31, 2.5, "7"]) {
    const bad = await runHealthTool(client, "get_health_history", { days });
    assertEquals([bad.isError, bad.content], [true, "days must be an integer between 1 and 30"]);
  }
  assertEquals(calls.length, 4, "out-of-range days never reach SQL");
  const deny = await runHealthTool({ rpc: () => Promise.resolve({ data: null, error: { message: "health tools are available to operator accounts only" } }) }, "get_system_health", {});
  assertEquals([deny.isError, deny.content], [true, "health tools are available to operator accounts only"]);
  const leak = await runHealthTool({ rpc: () => Promise.resolve({ data: null, error: { message: 'relation "system_health.x" secret detail' } }) }, "get_system_health", {});
  assertEquals(leak.content, "The health query failed.");
});

Deno.test("adapter: scalar health RPCs are typed and named; unknown params refused", async () => {
  const seen: { text: string; params: unknown[] }[] = [];
  const adapter = new PostgrestAdapter((text, params) => { seen.push({ text, params }); return Promise.resolve([{ body: '{"runs":[]}' }]); });
  assertEquals((await adapter.rpc("health_history", { p_days: 7 })).data, { runs: [] });
  assertEquals(seen[0], { text: "select public.health_history(p_days => $1::integer)::text as body", params: ["7"] });
  await adapter.rpc("health_system_status");
  assertEquals(seen[1].text, "select public.health_system_status()::text as body");
  await assertRejects(() => adapter.rpc("health_history", { p_days: 1, x: 2 }), Error, "unsupported");
  await assertRejects(() => adapter.rpc("health_run_summary", {}), Error, "not callable");
});

Deno.test("handler lists health tools only for keys that have them; calls pass structuredContent", async () => {
  const KEY = "mtk_" + "A".repeat(43);
  let keyTools = ["get_series"];
  const deps: McpDeps = {
    authenticate: async (h) => h === await sha256Hex(KEY) ? { keyId: "k", userId: "u" } : null,
    logCall: async () => {},
    scope: async () => keyTools,
    authorize: async (_h, tool) => keyTools.includes(tool)
      ? { allowed: true, httpStatus: 200, reason: "ok", retryAfterSeconds: null }
      : { allowed: false, httpStatus: 403, reason: "no", retryAfterSeconds: null },
    runScoped: async (_u, _k, fn) => await fn({ rpc: async () => ({ data: "all", error: null }) }),
    runTool: async (_c, name, input) => HEALTH_TOOL_NAMES.includes(name) ? { content: "{}", isError: false, structuredContent: { tool: name, input } } : { content: "[]", isError: false },
    fetchDomainReality: async () => new Map(),
    tools: [...TOOLS, ...HEALTH_TOOLS] as never,
  };
  const handler = createMcpHandler(deps);
  const post = (body: unknown) => handler(new Request("http://local/mcp", {
    method: "POST", body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: `Bearer ${KEY}` },
  }));
  const names = async () => (await (await post({ jsonrpc: "2.0", id: 1, method: "tools/list" })).json()).result.tools.map((t: { name: string }) => t.name);
  assertEquals(await names(), ["get_series"]);
  keyTools = ["get_system_health", "get_health_history"];
  assertEquals(await names(), ["get_system_health", "get_health_history"]);
  const r = await (await post({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "get_health_history", arguments: { days: 3 } } })).json();
  assertEquals(r.result.structuredContent, { tool: "get_health_history", input: { days: 3 } });
  const denied = await (await post({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "get_health_baselines", arguments: {} } })).json();
  assertEquals(denied.error.code, -32602);
});
