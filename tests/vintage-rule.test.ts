// "Current vintage" is one rule everywhere (docs/SECURITY.md, "Current vintage
// from the harvest-year rule"): the shared module, the dashboard's copy, P3's
// copy, chat's and the gateway's defaults, and the P4 check -- at the three
// simulated dates plus today.
//   npx deno test --no-lock --config supabase/functions/mcp/deno.json -A tests/vintage-rule.test.ts
import { assert, assertEquals, assertMatch } from "jsr:@std/assert@1";
import { currentVintage, harvestVintage, latestCompleteVintage, seasonStarted, vintageContext, vintagesThrough } from "../supabase/functions/_shared/vintage.ts";
import { runTool, setToolClockForTests } from "../supabase/functions/chat/tools.ts";
import { runDataTool } from "../supabase/functions/mcp/data-tools.ts";
import { withGatewayVintageCheck } from "../supabase/functions/mcp/health-tools.ts";

const D = { today: new Date("2026-09-30T19:00:00Z"), nov1: new Date("2026-11-01T12:00:00Z"), dec15: new Date("2026-12-15T20:00:00Z"), apr2: new Date("2027-04-02T18:00:00Z") };

Deno.test("shared rule at the simulated dates", () => {
  assertEquals([D.today, D.nov1, D.dec15, D.apr2].map((d) => currentVintage(d)), [2026, 2027, 2027, 2027]);
  assertEquals(vintagesThrough(D.dec15), [2022, 2023, 2024, 2025, 2026, 2027]);
  assertEquals(vintagesThrough(D.today), [2022, 2023, 2024, 2025, 2026]);
  assertEquals([seasonStarted(2027, D.nov1), seasonStarted(2027, D.dec15), seasonStarted(2027, D.apr2), seasonStarted(2026, D.today)], [false, false, true, true]);
  assertEquals(latestCompleteVintage(D.dec15), 2026);
  assertMatch(vintageContext(D.dec15), /current vintage is 2027.*off-season.*2027 growing season begins April 1.*2026 is the latest complete season/);
  assertMatch(vintageContext(D.apr2), /current vintage is 2027.*in progress/);
  assertMatch(vintageContext(D.today), /Today is 2026-09-30.*current vintage is 2026/);
});

function extract(src: string, names: string[]): string {
  return names.map((n) => {
    const i = src.indexOf(`function ${n}(`);
    assert(i >= 0, `function ${n} not found`);
    let depth = 0, j = src.indexOf("{", i);
    for (let k = j; k < src.length; k++) { if (src[k] === "{") depth++; if (src[k] === "}" && --depth === 0) return src.slice(i, k + 1); }
    throw new Error(n);
  }).join("\n");
}

Deno.test("the dashboard's and P3's copies of the rule equal the shared one, hour by hour across both boundaries", async () => {
  const web = await Deno.readTextFile(new URL("../web/index.html", import.meta.url));
  const webRule = new Function(`${extract(web, ["pacificYearMonth", "harvestVintage", "seasonStarted"])}; return { harvestVintage, seasonStarted };`)();
  const p3 = await Deno.readTextFile(new URL("../scripts/p3-frontend.mjs", import.meta.url));
  const p3Rule = new Function(`${extract(p3, ["harvestVintage"])}; return harvestVintage;`)();
  let n = 0;
  for (const [from, to] of [["2026-10-30T00:00:00Z", "2026-11-03T00:00:00Z"], ["2026-12-30T00:00:00Z", "2027-01-03T00:00:00Z"], ["2027-03-30T00:00:00Z", "2027-04-03T00:00:00Z"]]) {
    for (let t = Date.parse(from); t < Date.parse(to); t += 3600_000, n++) {
      const d = new Date(t);
      assertEquals(webRule.harvestVintage(d), harvestVintage(t), d.toISOString());
      assertEquals(p3Rule(d), harvestVintage(t), d.toISOString());
      assertEquals(webRule.seasonStarted(2027, d), seasonStarted(2027, d), d.toISOString());
    }
  }
  assert(n > 250);
});

Deno.test("chat get_anomalies default vintage / as_of follow the rule (MOCK_NOW only while the mock season is current)", async () => {
  const seen: Record<string, unknown>[] = [];
  const stub = { rpc: (_n: string, p: Record<string, unknown>) => { seen.push(p); return Promise.resolve({ data: [], error: null }); } };
  for (const d of [D.today, D.nov1, D.apr2]) { setToolClockForTests(() => d); await runTool(stub, "get_anomalies", {}, "all", new Map()); }
  setToolClockForTests(() => D.nov1); await runTool(stub, "get_anomalies", { vintage: 2026 }, "all", new Map());
  setToolClockForTests(() => new Date());
  assertEquals(seen.map((p) => p.p_vintage), [2026, 2027, 2027, 2026]);
  assertEquals(seen.map((p) => p.p_as_of), ["2026-07-28T14:20:00-07:00", D.nov1.toISOString(), D.apr2.toISOString(), "2026-12-31T23:59:59Z"]);
});

Deno.test("gateway get_anomalies reports vintage_used from the rule", async () => {
  const run = () => Promise.resolve({ content: "[]", isError: false });
  const ctx = { dataMode: "all", reality: new Map(), count: () => Promise.resolve(0) };
  for (const [d, want] of [[D.today, 2026], [D.dec15, 2027]] as const) {
    setToolClockForTests(() => d);
    const r = await runDataTool("get_anomalies", { as_of: d.toISOString() }, run, ctx);
    assertEquals((r.structuredContent as { vintage_used: number }).vintage_used, want);
  }
  const explicit = await runDataTool("get_anomalies", { vintage: 2024, as_of: "2024-07-06T02:00:00Z" }, run, ctx);
  assertEquals((explicit.structuredContent as { vintage_used: number }).vintage_used, 2024);
  setToolClockForTests(() => new Date());
});

Deno.test("P4: gateway.p4.current_vintage passes only when gateway == database and the vintage exists", () => {
  const base = { overall: "pass", p4_gateway_self_check: [{ check_id: "x", status: "pass" }] };
  const ok = withGatewayVintageCheck({ ...base, current_vintage: 2027, current_vintage_in_table: true }, 2027);
  assertEquals([ok.overall, ok.p4_gateway_self_check.at(-1).status], ["pass", "pass"]);
  const disagree = withGatewayVintageCheck({ ...base, current_vintage: 2027, current_vintage_in_table: true }, 2026);
  assertEquals([disagree.overall, disagree.p4_gateway_self_check.at(-1).status], ["fail", "fail"]);
  const missing = withGatewayVintageCheck({ ...base, current_vintage: 2027, current_vintage_in_table: false }, 2027);
  assertEquals(missing.overall, "fail");
  assertEquals(withGatewayVintageCheck({ error: "x" }, 2027), { error: "x" }, "non-status payloads pass through");
});
