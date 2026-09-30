#!/usr/bin/env node
// P3: nightly frontend checks (docs/SECURITY.md, "Nightly health checks").
// Run by .github/workflows/nightly-health-p3.yml at 12:20 UTC.
//
// For each synthetic user (operator; HEALTH-CUST, all blocks; HEALTH-CUST-B2,
// B2 only), in a FRESH browser context (no cache, no stored session):
//   - log in through the real sign-in form, load both data tabs, and read what
//     every panel rendered from the dashboard's window.__panelData hook;
//   - check role visibility (operator-only panels) and, in-page as that user,
//     the RLS boundary (which blocks' rows the REST API returns);
//   - operator only: compare what panels show with what the MCP gateway
//     returns for the same query (data fidelity / chat-path tools), using the
//     P3 gateway key (owner: svc-nightly-checks).
// Results go to system_health as health_writer (record_run/record_result only).
//
// Secrets come from the environment only and are never printed:
//   P3_OPERATOR_PASSWORD, P3_CUSTOMER_PASSWORD, P3_CUSTOMER_B2_PASSWORD,
//   P3_MCP_KEY, HEALTH_WRITER_DB_URL.
// Local testing without passwords: --magic-link signs in with an
// admin-generated magic link (needs .env's service key; synthetic users only;
// nothing is emailed) and --dry-run prints results instead of recording them.
//
//   node scripts/p3-frontend.mjs [--dashboard <url>] [--magic-link] [--dry-run] [--chrome <path>]
import { readFileSync } from "node:fs";
import { chromium } from "playwright-core";
import pg from "pg";

const arg = (name) => { const i = process.argv.indexOf(`--${name}`); return i > -1 ? process.argv[i + 1] : undefined; };
const flag = (name) => process.argv.includes(`--${name}`);
const DASHBOARD = arg("dashboard") ?? process.env.P3_DASHBOARD_URL ?? "https://telemetry.marsestates.com/";
const MCP_URL = "https://wwdpunaefaiazsjamrkc.supabase.co/functions/v1/mcp";
const DRY = flag("dry-run");
const MAGIC = flag("magic-link");

const USERS = [
  { key: "operator", email: "harry.c+health-operator@marscap.investments", pw: "P3_OPERATOR_PASSWORD", role: "operator", blocks: ["B1", "B2", "B3"] },
  { key: "customer", email: "harry.c+health-customer@marscap.investments", pw: "P3_CUSTOMER_PASSWORD", role: "customer", blocks: ["B1", "B2", "B3"] },
  { key: "customer_b2", email: "harry.c+health-customer-b2@marscap.investments", pw: "P3_CUSTOMER_B2_PASSWORD", role: "customer", blocks: ["B2"] },
];
// Panels only an operator may see (PANELS minRole 'operator', both tabs).
const OPERATOR_ONLY_SAMPLE = ["tanks", "fruit"];

const secrets = [process.env.P3_OPERATOR_PASSWORD, process.env.P3_CUSTOMER_PASSWORD, process.env.P3_CUSTOMER_B2_PASSWORD, process.env.P3_MCP_KEY, process.env.HEALTH_WRITER_DB_URL].filter((s) => s && s.length >= 8);
const scrub = (s) => { let t = String(s ?? ""); for (const x of secrets) t = t.split(x).join("[REDACTED]"); return t; };
const log = (...a) => console.log(scrub(a.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(" ")));

const results = [];
const record = (layer, check_id, status, observed = {}, expected = {}, detail = null) => {
  results.push({ layer, check_id, status, observed, expected, detail: detail ? scrub(detail).slice(0, 1900) : null });
  log(`${status.padEnd(5)} ${check_id} ${detail ?? ""}${status === "pass" ? "" : ` ${JSON.stringify(observed).slice(0, 600)}`}`);
};

// ---- gateway (the P3 key; owner svc-nightly-checks) ------------------------
let rpcId = 0;
async function gateway(name, args) {
  const key = process.env.P3_MCP_KEY;
  if (!key) throw new Error("P3_MCP_KEY is not set");
  const r = await fetch(MCP_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method: "tools/call", params: { name, arguments: args } }),
    signal: AbortSignal.timeout(30_000),
  });
  const body = await r.json().catch(() => null);
  if (!r.ok || body?.error) throw new Error(`gateway ${name}: HTTP ${r.status} ${body?.error?.message ?? ""}`);
  if (body.result?.isError) throw new Error(`gateway ${name}: ${String(body.result.content?.[0]?.text ?? "").slice(0, 200)}`);
  return body.result.structuredContent;
}

// ---- browser ------------------------------------------------------------------
async function magicLinkTokenHash(email) {
  const env = Object.fromEntries(readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
    .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "")]));
  if (!/^harry\.c\+health-[a-z0-9-]+@marscap\.investments$/.test(email)) throw new Error("magic links are for the synthetic health users only");
  const origin = new URL(env.SUPABASE_URL).origin;
  const r = await fetch(`${origin}/auth/v1/admin/generate_link`, {
    method: "POST",
    headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ type: "magiclink", email }),
  });
  const j = await r.json().catch(() => ({}));
  const h = j.hashed_token ?? j.properties?.hashed_token;
  if (!r.ok || !h) throw new Error(`generate_link failed: HTTP ${r.status}`);
  return h;
}

// Waits until every panel the hook knows about has left 'rendering' and the
// set has been stable for 3s.
async function settle(page, timeoutMs = 90_000) {
  const t0 = Date.now();
  let last = "", stableSince = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const snap = await page.evaluate(() => JSON.stringify(Object.entries(window.__panelData || {}).map(([k, v]) => [k, v.status])));
    const busy = JSON.parse(snap).some(([, s]) => s === "rendering");
    if (snap !== last) { last = snap; stableSince = Date.now(); }
    if (!busy && JSON.parse(snap).length && Date.now() - stableSince > 3000) return JSON.parse(snap);
    await page.waitForTimeout(500);
  }
  throw new Error("panels did not settle within 90s");
}

async function runUser(browser, u) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  const consoleErrors = [];
  page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text().slice(0, 200)); });
  page.on("pageerror", (e) => consoleErrors.push(`pageerror: ${String(e.message).slice(0, 200)}`));
  const snapshot = { panels: {} };
  try {
    await page.goto(DASHBOARD, { waitUntil: "domcontentloaded", timeout: 60_000 });
    await page.waitForFunction(() => typeof sb !== "undefined", null, { timeout: 30_000 });
    if (MAGIC) {
      const tokenHash = await magicLinkTokenHash(u.email);
      const err = await page.evaluate(async (th) => (await sb.auth.verifyOtp({ token_hash: th, type: "magiclink" })).error?.message ?? null, tokenHash);
      if (err) throw new Error(`verifyOtp: ${err}`);
    } else {
      const pw = process.env[u.pw];
      if (!pw) throw new Error(`${u.pw} is not set`);
      await page.waitForSelector("#auth-email", { state: "visible", timeout: 30_000 });
      await page.fill("#auth-email", u.email);
      await page.fill("#auth-password", pw);
      await page.click("#auth-submit");
    }
    await page.waitForSelector("button.tab[data-tab='vineyard']", { state: "visible", timeout: 60_000 });
    const who = await page.evaluate(async () => (await sb.auth.getUser()).data.user?.email ?? null);
    if (who !== u.email) throw new Error("signed in as a different user");
    // Count only errors from here on: the page's pre-login work runs as anon
    // (e.g. the thresholds prefetch, docs/SECURITY.md) and is not a render fault.
    consoleErrors.length = 0;
    record("frontend", `frontend.${u.key}.login`, "pass", { user: u.key });
  } catch (err) {
    record("frontend", `frontend.${u.key}.login`, "fail", { user: u.key }, {}, err.message);
    await context.close();
    return null;
  }

  // Both data tabs, as the user would open them.
  for (const tab of ["vineyard", "winery"]) {
    try {
      const btn = page.locator(`button.tab[data-tab='${tab}']`);
      if (!(await btn.isVisible())) { snapshot.panels[tab] = { __hidden: true }; continue; }
      await btn.click();
      const states = await settle(page);
      snapshot.panels[tab] = Object.fromEntries(states);
    } catch (err) {
      snapshot.panels[tab] = { __error: err.message };
    }
  }
  const all = await page.evaluate(() => Object.fromEntries(Object.entries(window.__panelData || {}).map(([k, v]) => [k, { status: v.status, tab: v.tab, error: v.error ?? null }])));
  const byStatus = (s) => Object.entries(all).filter(([, v]) => v.status === s).map(([k]) => k).sort();
  const errored = byStatus("error");
  const settleErrors = Object.entries(snapshot.panels).filter(([, v]) => v.__error).map(([t, v]) => `${t}: ${v.__error}`);
  const observed = { ok: byStatus("ok").length, blocked: byStatus("blocked"), error: errored, still_rendering: byStatus("rendering"), console_errors: consoleErrors.length };
  if (errored.length || settleErrors.length || byStatus("rendering").length) {
    record("frontend", `frontend.${u.key}.panels`, "fail", observed, { error: [], still_rendering: [] }, [...errored.map((id) => `${id}: ${all[id].error}`), ...settleErrors].join("; "));
  } else if (consoleErrors.length) {
    record("frontend", `frontend.${u.key}.panels`, "warn", { ...observed, first_console_errors: consoleErrors.slice(0, 5) }, { console_errors: 0 }, "console errors while rendering");
  } else {
    record("frontend", `frontend.${u.key}.panels`, "pass", observed, { error: [], console_errors: 0 });
  }

  // Role visibility: operator-only panels exist for the operator, never for a customer.
  const present = OPERATOR_ONLY_SAMPLE.filter((id) => id in all);
  const roleOk = u.role === "operator" ? present.length === OPERATOR_ONLY_SAMPLE.length : present.length === 0;
  record("frontend", `frontend.${u.key}.role_visibility`, roleOk ? "pass" : "fail",
    { operator_only_panels_present: present }, { operator_only_panels_present: u.role === "operator" ? OPERATOR_ONLY_SAMPLE : [] });

  // RLS boundary, in-page through the user's own REST session.
  try {
    const rls = await page.evaluate(async () => {
      const count = async (q) => { const { count, error } = await q; return error ? `error: ${error.message}` : count; };
      const out = {};
      for (const b of ["B1", "B2", "B3"]) {
        out[`soil_${b}`] = await count(sb.from("sensor_readings").select("id", { count: "exact", head: true }).eq("metric_key", "soil_moisture").eq("block_id", b).eq("vintage", 2026));
      }
      out.vessels = await count(sb.from("vessels").select("vessel_id", { count: "exact", head: true }));
      out.user_profiles = await count(sb.from("user_profiles").select("id", { count: "exact", head: true }));
      return out;
    });
    const visibleBlocks = ["B1", "B2", "B3"].filter((b) => typeof rls[`soil_${b}`] === "number" && rls[`soil_${b}`] > 0);
    const expectVessels = u.role === "operator" ? "> 0" : 0;
    const ok = JSON.stringify(visibleBlocks) === JSON.stringify(u.blocks)
      && (u.role === "operator" ? rls.vessels > 0 : rls.vessels === 0)
      && (u.role === "operator" || rls.user_profiles === 1);
    record("frontend", `frontend.${u.key}.rls_boundary`, ok ? "pass" : "fail",
      { blocks_with_rows: visibleBlocks, vessels_rows: rls.vessels, user_profiles_rows: rls.user_profiles },
      { blocks_with_rows: u.blocks, vessels_rows: expectVessels, user_profiles_rows: u.role === "operator" ? "any" : 1 },
      ok ? null : "the REST API returned rows outside this user's access");
  } catch (err) {
    record("frontend", `frontend.${u.key}.rls_boundary`, "error", {}, {}, err.message);
  }

  if (u.role === "operator") { await fidelity(page); await currentVintageChecks(page); }
  await context.close();
  return snapshot;
}

// ---- current vintage: the rule, and what the apps say --------------------------
// Vintage = harvest year from Nov 1 Pacific (same rule as _shared/vintage.ts,
// public.harvest_vintage and the dashboard; tests/vintage-rule.test.ts keeps
// this copy equal).
function harvestVintage(d) {
  const parts = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Los_Angeles", year: "numeric", month: "2-digit" }).formatToParts(d);
  const y = Number(parts.find((x) => x.type === "year").value), m = Number(parts.find((x) => x.type === "month").value);
  return m >= 11 ? y + 1 : y;
}
async function currentVintageChecks(page) {
  const rule = harvestVintage(new Date());
  try {
    const dash = await page.evaluate(() => ({ current: CURRENT, vintages: VINTAGES }));
    const ok = dash.current === rule && dash.vintages[dash.vintages.length - 1] === rule;
    record("frontend", "frontend.current_vintage", ok ? "pass" : "fail", { dashboard: dash.current, dashboard_vintages: dash.vintages, rule }, { dashboard: rule },
      ok ? null : "the dashboard's current vintage disagrees with the harvest-year rule");
  } catch (err) { record("frontend", "frontend.current_vintage", "error", {}, {}, err.message); }
  try {
    const g = await gateway("get_anomalies", { as_of: new Date().toISOString() });
    const ok = g.vintage_used === rule;
    record("gateway", "gateway.current_vintage", ok ? "pass" : "fail", { gateway: g.vintage_used, rule }, { gateway: rule },
      ok ? null : "the gateway's default (current) vintage disagrees with the harvest-year rule");
  } catch (err) { record("gateway", "gateway.current_vintage", "error", {}, {}, err.message); }
}

// ---- operator: panels vs the gateway --------------------------------------------
const r1 = (x) => (x == null ? null : Math.round(Number(x) * 10) / 10);
const r2 = (x) => (x == null ? null : Math.round(Number(x) * 100) / 100);

async function fidelity(page) {
  // GDD panel: its newest non-null day vs get_derived_series for that day.
  try {
    const last = await page.evaluate(() => {
      const pts = window.__panelData?.gdd?.charts?.find((c) => c.kind === "line")?.sets?.[0]?.pts ?? [];
      const p = [...pts].reverse().find((x) => x.v != null);
      return p ? { day: new Date(p.t).toISOString().slice(0, 10), v: p.v, vintage: window.__panelData.gdd.vintage } : null;
    });
    if (!last) throw new Error("gdd panel has no data");
    const g = await gateway("get_derived_series", { vintage: last.vintage, start_date: last.day, end_date: last.day });
    const gv = g.rows[0]?.gdd_cumulative_calibrated ?? null;
    record("frontend", "frontend.fidelity.gdd", r1(last.v) === r1(gv) ? "pass" : "fail",
      { day: last.day, panel: r1(last.v), gateway: r1(gv), gateway_data_status: g.rows[0]?.data_status ?? null }, { panel: "= gateway" },
      r1(last.v) === r1(gv) ? null : "the GDD panel and get_derived_series disagree");
  } catch (err) {
    record("frontend", "frontend.fidelity.gdd", "error", {}, {}, err.message);
  }

  // Air temperature panel: replay the dashboard's own series_bucketed call through get_series.
  try {
    const call = await page.evaluate(() => [...(window.__seriesCalls || [])].reverse().find((c) => c.metric === "air_temp" && c.block === null && c.vintage));
    if (!call) throw new Error("no air_temp series call recorded");
    const hours = { "1 hour": 1, "3 hours": 3, "1 day": 24 }[call.bucket];
    if (!hours) throw new Error(`unsupported bucket ${call.bucket}`);
    const g = await gateway("get_series", { metric: "air_temp", vintage: call.vintage, start: call.start, end: call.end, bucket_hours: hours, agg: call.agg });
    const panel = call.points.map((p) => [p.t, r2(p.v)]);
    const gw = g.rows.map((p) => [p.t, r2(p.v)]);
    const same = JSON.stringify(panel) === JSON.stringify(gw);
    record("frontend", "frontend.fidelity.air_temp_series", same ? "pass" : "fail",
      { buckets_panel: panel.length, buckets_gateway: gw.length, first_diff: same ? null : panel.findIndex((p, i) => JSON.stringify(p) !== JSON.stringify(gw[i])), data_status: [...new Set(g.rows.map((x) => x.data_status))] },
      { series: "identical (2 dp)" }, same ? null : "the air temperature panel and get_series disagree");
  } catch (err) {
    record("frontend", "frontend.fidelity.air_temp_series", "error", {}, {}, err.message);
  }

  // Chat-path tools vs the operator's own REST reads.
  try {
    const inPage = await page.evaluate(async () => {
      const { count } = await sb.from("vessels").select("vessel_id", { count: "exact", head: true }).eq("archived", false);
      const { data } = await sb.rpc("anomalies_eval", { p_vintage: 2024, p_as_of: "2024-07-06T02:00:00Z" });
      return { active_vessels: count, anchor_rules: (data ?? []).map((r) => r.rule_key).sort() };
    });
    const v = await gateway("get_vessels", {});
    record("gateway", "gateway.tools.vessels_vs_rest", v.total_count === inPage.active_vessels ? "pass" : "fail",
      { gateway_total_count: v.total_count, rest_active_vessels: inPage.active_vessels }, { equal: true });
    const a = await gateway("get_anomalies", { vintage: 2024, as_of: "2024-07-06T02:00:00Z" });
    const rules = a.rows.map((r) => r.rule_key).sort();
    const ok = JSON.stringify(rules) === JSON.stringify(inPage.anchor_rules) && rules.length === 3;
    record("gateway", "gateway.tools.anomaly_anchor_vs_rest", ok ? "pass" : "fail",
      { gateway_rules: rules, rest_rules: inPage.anchor_rules }, { hits: 3, equal: true });
  } catch (err) {
    record("gateway", "gateway.tools.vessels_vs_rest", "error", {}, {}, err.message);
  }
}

// ---- main ------------------------------------------------------------------------
const startedAt = new Date();
const executablePath = arg("chrome") ?? process.env.CHROME_PATH;
const browser = await chromium.launch(executablePath ? { executablePath, headless: true } : { channel: "chrome", headless: true });
try {
  for (const u of USERS) await runUser(browser, u);
} finally {
  await browser.close();
}

if (DRY) {
  log(`dry run: ${results.length} results, not recorded`);
} else {
  const url = process.env.HEALTH_WRITER_DB_URL;
  if (!url) throw new Error("HEALTH_WRITER_DB_URL is not set");
  const db = new pg.Client({ connectionString: url, statement_timeout: 15_000 });
  await db.connect();
  try {
    const { rows: [{ id }] } = await db.query("select system_health.record_run('p3_frontend', $1) as id", [startedAt.toISOString()]);
    for (const r of results) {
      await db.query("select system_health.record_result($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7)",
        [id, r.layer, r.check_id, r.status, JSON.stringify(r.observed), JSON.stringify(r.expected), r.detail]);
    }
    log(`recorded run ${id}: ${results.length} results`);
  } finally {
    await db.end();
  }
}
if (results.some((r) => r.status === "fail" || r.status === "error")) process.exitCode = 1;
