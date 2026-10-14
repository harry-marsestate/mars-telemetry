#!/usr/bin/env node
// Mars Telemetry daily systems check. Self-contained: Node >= 22.21, no npm packages.
// Usage: node mars-check.mjs [--subject-out FILE] [--html-out FILE]
//   --subject-out  where to write the email subject (without any [TEST] prefix)
//   --html-out     where to write the report as an HTML email body
// stdout: the plain-text report ending with the BASELINES-JSON line, nothing else.
// "Changes since last run" compares against the gateway's own run history
// (get_health_history) and the baselines below, so no earlier report is needed.
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Node's fetch ignores HTTPS_PROXY unless NODE_USE_ENV_PROXY=1; re-exec once with it set.
if (process.env.HTTPS_PROXY && process.env.NODE_USE_ENV_PROXY !== '1') {
  const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url), ...process.argv.slice(2)], {
    stdio: 'inherit',
    env: { ...process.env, NODE_USE_ENV_PROXY: '1', NODE_NO_WARNINGS: '1' },
  });
  process.exit(r.status ?? 1);
}

const URL_ = 'https://wwdpunaefaiazsjamrkc.supabase.co/functions/v1/mcp';
const HEADERS = {
  'Content-Type': 'application/json',
  Accept: 'application/json, text/event-stream',
  'MCP-Protocol-Version': '2025-06-18',
}; // No Authorization header: the agent proxy injects the credential.
const EXPECTED_TOOLS = [
  'get_system_health', 'get_health_history', 'get_health_baselines', 'get_series', 'get_derived_series',
  'get_anomalies', 'get_vessels', 'get_lot_analyses', 'get_labour_summary', 'get_berry_maturity',
  'get_smoke_markers', 'get_wine_lab_results',
];
const PRODUCER_LAYERS = { p1_database: ['ingestion', 'database', 'security'], p2_probes: ['sources'], p3_frontend: ['dashboard'] };
const PRODUCER_NAMES = { p1_database: 'Database self-check (P1)', p2_probes: 'Data-source check (P2)', p3_frontend: 'Dashboard test (P3)', p3_backup: 'Dashboard test backup start' };
const LAYERS = ['sources', 'ingestion', 'database', 'gateway', 'dashboard', 'security'];
const LAYER_NAMES = { sources: 'Sources', ingestion: 'Ingestion', database: 'Database', gateway: 'Gateway', dashboard: 'Dashboard', security: 'Security' };
const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

// ---------- plain language ----------
// The report is read by people who don't remember check IDs or what P1-P4
// mean, so every name is explained where it appears. Check IDs stay in the
// report only as a "Technical ID" for looking things up in docs/SECURITY.md.
const PRODUCER_WHAT = {
  p1_database: 'the database checks itself: new data arrived, past seasons are unchanged, values are sensible, and access/security settings match the approved setup',
  p2_probes: 'each outside service the platform relies on (InnoVint, Open-Meteo weather, the AI chat models, Resend email) is contacted to confirm it answers with our key',
  p3_frontend: 'a robot web browser signs in to the live dashboard as three test users (a staff operator, a customer with all blocks, a customer with only Block 2), opens every panel, and checks each one sees only what they should',
};
const LAYER_WHAT = {
  sources: 'the outside services our data comes from',
  ingestion: 'the daily jobs that pull new weather, InnoVint and lab data in',
  database: 'the stored data itself: complete, sensible, and past seasons unchanged',
  gateway: 'the read-only connection Claude and other AI agents use to look up data',
  dashboard: 'the website people sign in to',
  security: 'who can see or change what',
};
const TEST_USERS = { operator: 'the staff (operator) test account', customer: 'the customer test account (all blocks)', customer_b2: 'the Block 2-only customer test account' };
const LAB_PLAIN = { get_berry_maturity: 'berry maturity samples', get_smoke_markers: 'smoke-taint marker samples', get_wine_lab_results: 'wine lab results' };
// What each health check confirms, as a short sentence.
const CHECK_PLAIN = [
  [/^ingestion\.climate\.last_run$/, 'The daily weather import ran successfully in the last 26 hours'],
  [/^ingestion\.innovint\.last_run$/, 'The daily InnoVint (winery system) import ran successfully in the last 26 hours'],
  [/^ingestion\.climate\.freshness$/, 'The newest weather reading is less than 26 hours old'],
  [/^ingestion\.climate\.daily_weather_through$/, 'The daily weather summaries are up to date (through two days ago)'],
  [/^ingestion\.climate\.current_vintage$/, 'New weather data is filed under the right harvest year, and next year is set up before 1 November'],
  [/^ingestion\.climate\.model_pinned$/, 'The weather import used the approved weather models'],
  [/^ingestion\.ets_report\.last_run$/, 'The weekly ETS Labs report import ran in the last 10 days without errors'],
  [/^ingestion\.ets_report\.quarantine$/, 'No ETS Labs report rows are held back for review'],
  [/^database\.insights_estate_inputs_estate_wide$/, 'Weather and soil inputs to the Insights panel are recorded estate-wide, not per block'],
  [/^database\.integrity\.soil_moisture_range$/, 'Every soil moisture reading is between 0 and 100%'],
  [/^database\.integrity\.gdd_calibrated_2022_2025$/, "Each finished season's growing-degree-day (heat) total is in the normal 3,000-4,400 range"],
  [/^database\.integrity\.mock_real_precedence$/, 'Where both real and sample data exist, the dashboard shows the real data'],
  [/^database\.integrity\.daily_weather_pacific_days$/, 'Daily weather is split into days on Pacific time'],
  [/^database\.integrity\.no_b1_2024_irrigation$/, 'Block 1 has no 2024 irrigation records (none should exist)'],
  [/^database\.integrity\.sensor_readings_unique$/, 'The database blocks duplicate sensor readings'],
  [/^database\.integrity\.no_future_real_rows$/, 'No real reading is dated in the future'],
  [/^database\.integrity\.climate_source_labels$/, 'Weather data is labelled with its true source'],
  [/^database\.vintage\.current_consistent$/, 'The database, dashboard and gateway agree on the current vintage (harvest year)'],
  [/^database\.checksum\.winery_closed_vintages$/, "Finished seasons' (2022-2025) winery records (harvest, lab, labour) are unchanged"],
  [/^database\.checksum\./, "Finished seasons' (2022-2025) sensor and weather data are unchanged"],
  [/^database\.anomalies\.anchor_/, 'The alert rules still flag a known test day correctly'],
  [/^database\.vessels\.counts$/, 'Tank and vessel counts look normal'],
  [/^database\.backup\.retention_decision$/, 'No old backup table is overdue for a keep-or-delete decision'],
  [/^security\.structure\.daily_derived$/, 'The daily summary table keeps its access settings (a data rebuild can strip them)'],
  [/^security\.rls\.enabled_on_every_table$/, 'Every table has its row-level access rules switched on'],
  [/^security\.anon\./, 'Signed-out visitors have no access to any data'],
  [/^security\.policies\.baseline$/, 'The access rules match the approved set'],
  [/^security\.functions\.required_present$/, 'The database functions the platform depends on all exist'],
  [/^security\.definer\.search_path_pinned$/, 'Privileged database functions are protected against hijacking'],
  [/^security\.mcp_reader\.grants$/, "The gateway's database account can read only what it should"],
  [/^security\.health_writer\.privileges$/, 'The health-check account can only record results'],
  [/^security\.no_embedded_keys$/, 'No password or API key is stored in plain text in the database'],
  [/^security\.pg_net\.queue_not_stale$/, "The database's outgoing web-request queue isn't stuck"],
  [/^source\.innovint\.api$/, 'The InnoVint winery system answers with our key'],
  [/^source\.open_meteo\./, "The Open-Meteo weather service returns yesterday's data"],
  [/^source\.anthropic\.model$/, 'The Anthropic (Claude) chat model is available with our key'],
  [/^source\.fireworks\.model$/, 'The optional Kimi chat model is available'],
  [/^source\.resend\.api$/, 'The Resend email service accepts our key'],
  [/^frontend\.([a-z0-9_]+)\.login$/, (m) => `Signing in to the dashboard as ${TEST_USERS[m[1]] || m[1]}`],
  [/^frontend\.([a-z0-9_]+)\.panels$/, (m) => `Every dashboard panel loads without errors for ${TEST_USERS[m[1]] || m[1]}`],
  [/^frontend\.([a-z0-9_]+)\.role_visibility$/, (m) => `Staff-only panels appear only for staff (checked as ${TEST_USERS[m[1]] || m[1]})`],
  [/^frontend\.([a-z0-9_]+)\.rls_boundary$/, (m) => `${(TEST_USERS[m[1]] || m[1]).replace(/^t/, 'T')} sees only its own blocks' data`],
  [/^frontend\.([a-z0-9_]+)\.insights_scope$/, (m) => `The Insights panel for ${TEST_USERS[m[1]] || m[1]} covers only its own blocks`],
  [/^frontend\.current_vintage$/, 'The dashboard shows the right current vintage'],
  [/^gateway\.current_vintage$/, 'The gateway uses the right current vintage'],
  [/^frontend\.fidelity\.gdd$/, "The dashboard's growing-degree-day figure matches the gateway's"],
  [/^frontend\.fidelity\.air_temp_series$/, "The dashboard's air temperature chart matches the gateway's data"],
  [/^gateway\.tools\.vessels_vs_rest$/, "The gateway's vessel count matches the database"],
  [/^gateway\.tools\.anomaly_anchor_vs_rest$/, "The gateway's alerts for a known test day match the database"],
  [/^frontend\.latest\.consistent$/, 'Each dashboard panel\'s "latest" value matches its chart and overview tile'],
  [/^frontend\.tab_cache$/, 'Switching dashboard tabs reuses already-loaded data correctly'],
  [/^(frontend\.p3\.schedule_backup|p3_backup)/, 'The backup that starts the dashboard test (P3) when GitHub runs it late'],
  [/^gateway\.p4\.database_reachable$/, 'The gateway can reach the database'],
  [/^gateway\.p4\.key_expiry$/, "The gateway access key isn't about to expire"],
  [/^gateway\.p4\.allowed_tools$/, "The gateway key's allowed tools are as expected"],
  [/^gateway\.p4\.write_capable_tools$/, "The gateway key can't change any data"],
  [/^gateway\.p4\.current_vintage$/, 'The gateway and database agree on the current vintage'],
];
// Why a problem in each area matters to the business, in one sentence.
const WHY_PLAIN = [
  [/^ingestion\./, "If new data stops arriving, the dashboard and Claude's answers go out of date."],
  [/^(database\.vintage\.|frontend\.current_vintage$|gateway\.current_vintage$|gateway\.p4\.current_vintage$)/, 'If parts of the system disagree on the current harvest year, pages and answers can show the wrong season.'],
  [/^database\.anomalies\./, 'Vineyard alerts (frost, heat, humidity and so on) could be missed or raised wrongly.'],
  [/^database\.vessels\.|^spot\.vessels/, 'Tank and vessel information from InnoVint may be incomplete or wrong.'],
  [/^database\.backup\./, 'Housekeeping only; users are not affected.'],
  [/^(database\.|spot\.)/, "Wrong or altered data would show wrong numbers on the dashboard and in Claude's answers."],
  [/^security\.|^frontend\.[a-z0-9_]+\.(rls_boundary|role_visibility|insights_scope)$/, "These settings keep each customer's data private; a problem could let someone see or change data they shouldn't."],
  [/^source\./, 'If this outside service cannot be reached, the data or feature that depends on it stops updating.'],
  [/^frontend\.[a-z0-9_]+\.login$/, 'If this is happening to real users too, they could be unable to sign in or reach the dashboard.'],
  [/^frontend\.[a-z0-9_]+\.panels$/, 'Part of the dashboard may be broken for users.'],
  [/^(frontend\.fidelity\.|frontend\.latest\.|gateway\.tools\.)/, 'The dashboard and Claude could give different numbers for the same thing.'],
  [/^frontend\.tab_cache$/, 'The dashboard may show out-of-date figures or load slowly.'],
  [/^gateway\.p4\.write_capable_tools$|^inventory\.unexpected/, 'Claude must never be able to change data; this would allow it.'],
  [/^(gateway|inventory|get_system_health|check\.script)/, "Claude's data lookups may fail, so it could not answer questions about the estate."],
  [/^lab\./, "Lab results on the dashboard and in Claude's answers may be incomplete or wrong."],
  [/^(p3_backup|frontend\.p3\.)/, 'Without it, the daily dashboard test may not run on days GitHub is late.'],
];
const whyPlain = (id) => (WHY_PLAIN.find(([re]) => re.test(id)) || [null, ''])[1];
const TODO_PLAIN = {
  CRITICAL: 'Ask Claude to investigate and fix this today; the technical step below is where to start.',
  HIGH: 'Ask Claude to investigate and fix this today; the technical step below is where to start.',
  MEDIUM: 'Worth a look this week: ask Claude to check it, starting from the technical step below.',
  LOW: 'No action needed unless it keeps happening.',
};
function checkPlain(id) {
  for (const [re, d] of CHECK_PLAIN) { const m = re.exec(id); if (m) return typeof d === 'function' ? d(m) : d; }
  return `Health check ${id}`;
}
// Spell out bare "P1".."P4" in text that came from the platform.
const plainify = (t) => String(t ?? '').replace(/(?<![(\w.-])P([1-4])\b(?![)\w-])/gi, (_, n) =>
  ({ 1: 'database self-check (P1)', 2: 'data-source check (P2)', 3: 'dashboard test (P3)', 4: 'gateway self-check (P4)' })[n]);
const STATE_PLAIN = { fail: 'failed', warn: 'warning', error: 'could not run' };
// A recorded observed/expected value as "key: value; ..." rather than raw JSON.
// Upstream errors sometimes carry a whole HTML error page; keep just its text.
const stripHtml = (t) => String(t).replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ').replace(/<\/?[a-z][^>]*>?/gi, ' ')
  .replace(/(\b[\w ]{3,60}\b)(\s+\1)+/g, '$1').replace(/\s+/g, ' ').trim();
function plainValue(v) {
  if (v == null || v === '') return '(none recorded)';
  if (typeof v !== 'object') return plainify(stripHtml(v));
  const one = (x) => x == null ? 'none' : typeof x === 'boolean' ? (x ? 'yes' : 'no') : Array.isArray(x) ? (x.length ? x.map(one).join(', ') : 'none')
    : typeof x === 'object' ? (Object.keys(x).length ? JSON.stringify(x) : 'none') : stripHtml(x);
  if (Array.isArray(v)) return one(v);
  const e = Object.entries(v);
  return e.length ? plainify(e.map(([k, x]) => `${k.replace(/_/g, ' ')}: ${one(x)}`).join('; ')) : '(none recorded)';
}
const KNOWN_ISSUES = { 'source.anthropic.model': 'known: Anthropic key pending replacement' };
// Items that are structurally not checkable; anything else becoming NOT CHECKABLE turns the report YELLOW.
const EXPECTED_UNCHECKABLE = new Set(['spot.soil_b2']);
// Lab field lists recorded 2026-09-30, plus the provenance fields added
// deliberately on 2026-10-07 (docs/SECURITY.md, "Chat tool findings"):
// lab_sample_no / collected_on_source / collected_on_inferred. Any other change
// is schema drift.
const LAB_FIELDS = {
  get_berry_maturity: ['berry_volume_ml', 'berry_volume_variability_pct', 'berry_weight_g', 'block_id', 'brix', 'collected_on', 'collected_on_inferred', 'collected_on_source', 'glucose_fructose', 'l_malic_acid', 'lab_sample_no', 'ph', 'sugar_per_berry_mg', 'titratable_acidity', 'vintage'],
  get_smoke_markers: ['analysis_code', 'analysis_name_raw', 'analyzed_at', 'block_id', 'collected_on', 'collected_on_inferred', 'collected_on_source', 'lab_sample_no', 'result_numeric', 'result_operator', 'result_raw', 'sample_description', 'units', 'vintage'],
  get_wine_lab_results: ['analysis_code', 'analysis_name_raw', 'analyzed_at', 'collected_on', 'collected_on_inferred', 'collected_on_source', 'fruit_source', 'lab_sample_no', 'lot_analyses_lot_code', 'lot_analyses_match', 'lot_analyses_value', 'result_numeric', 'result_operator', 'result_raw', 'sample_description', 'sample_type', 'units', 'vintage'],
};

// ---------- args ----------
const args = {};
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a.startsWith('--')) args[a.slice(2)] = process.argv[i + 1]?.startsWith('--') ? true : process.argv[++i];
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = new Date();
const findings = [];
const notChecked = []; // {id, reason, short}
const obs = { spot: {}, lab: {}, ops: {} }; // observed values
const changes = [];
const add = (severity, layer, check_id, title, observed, expected, next) =>
  findings.push({ severity, layer, check_id, title, observed, expected, next });
const nc = (id, reason, short = reason) => notChecked.push({ id, reason, short });
const fmt = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
const clip = (s, n = 400) => (s.length > n ? s.slice(0, n) + '...' : s);
const firstLine = (s) => String(s ?? '').split('\n')[0].trim();

// ---------- transport ----------
let rpcId = 1;
let authFailure = null;
async function post(body) {
  // Returns {status, json, retryAfter} or throws {kind:'timeout'|'network', code}
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 60_000);
  try {
    const r = await fetch(URL_, { method: 'POST', headers: HEADERS, body: JSON.stringify(body), signal: ctrl.signal });
    const text = await r.text();
    let json = null;
    if (r.ok && text) {
      try { json = JSON.parse(text); } catch {
        const line = text.split('\n').filter((l) => l.startsWith('data:')).pop();
        if (line) { try { json = JSON.parse(line.slice(5).trim()); } catch {} }
      }
    }
    return { status: r.status, json, retryAfter: r.headers.get('retry-after') };
  } catch (e) {
    throw { kind: e?.name === 'AbortError' ? 'timeout' : 'network', code: e?.cause?.code || e?.code || e?.name || 'error' };
  } finally { clearTimeout(t); }
}

// One JSON-RPC request with the retry rules. Returns {ok, result, failure}
async function rpc(method, params, { first = false } = {}) {
  const body = { jsonrpc: '2.0', id: rpcId++, method, ...(params ? { params } : {}) };
  let retried = false;
  let throttles = 0;
  for (;;) {
    let r;
    try { r = await post(body); } catch (e) {
      if (first && e.kind === 'network') return { ok: false, failure: `network error (${e.code}) before reaching the gateway` };
      if (!retried) { retried = true; await sleep(30_000); continue; }
      return { ok: false, failure: e.kind === 'timeout' ? 'TIMEOUT (60 s, retried once)' : `TIMEOUT (network error ${e.code}, retried once)` };
    }
    if (r.status === 429) {
      if (++throttles > 5) return { ok: false, failure: 'HTTP 429 (rate limited, gave up after 5 waits)' };
      const wait = Math.min(Math.max(Number(r.retryAfter) || 60, 1), 300);
      await sleep(wait * 1000); continue;
    }
    if (r.status >= 500) {
      if (!retried) { retried = true; await sleep(30_000); continue; }
      return { ok: false, failure: `TIMEOUT (HTTP ${r.status}, retried once)` };
    }
    if (r.status === 401 || r.status === 403) {
      if (first) authFailure = r.status;
      return { ok: false, failure: `HTTP ${r.status}` };
    }
    if (r.status < 200 || r.status >= 300) return { ok: false, failure: `HTTP ${r.status}` };
    if (!r.json) return r.status === 202 ? { ok: true, result: null } : { ok: false, failure: `HTTP ${r.status} with unparseable body` };
    if (r.json.error) return { ok: false, failure: `JSON-RPC error ${r.json.error.code}: ${clip(String(r.json.error.message || ''), 160)}` };
    return { ok: true, result: r.json.result };
  }
}

// tools/call -> {ok, data, failure}. data = structuredContent, else the leading JSON of the text.
async function tool(name, a = {}) {
  if (!allowedToCall.has(name)) return { ok: false, failure: 'not in tools/list' };
  const r = await rpc('tools/call', { name, arguments: a });
  if (!r.ok) return r;
  const res = r.result || {};
  const text = (res.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
  if (res.isError) return { ok: false, failure: `tool error: ${clip(text.split('\n')[0] || 'isError', 160)}` };
  let data = res.structuredContent ?? null;
  if (data == null) {
    try { data = JSON.parse(text); } catch {
      const s = text.trimStart();
      try { data = s ? jsonPrefix(s) : null; } catch { data = null; }
    }
  }
  return { ok: true, data };
}
function jsonPrefix(s) {
  // Parse the leading JSON value of s (tools append prose notes after the JSON).
  const open = s[0], close = open === '[' ? ']' : open === '{' ? '}' : null;
  if (!close) throw new Error('no json');
  let depth = 0, inStr = false, esc = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) { if (esc) esc = false; else if (c === '\\') esc = true; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true;
    else if (c === '[' || c === '{') depth++;
    else if (c === ']' || c === '}') { if (--depth === 0) return JSON.parse(s.slice(0, i + 1)); }
  }
  throw new Error('unterminated json');
}
const rowsOf = (d) => (Array.isArray(d) ? d : Array.isArray(d?.rows) ? d.rows : null);

// ---------- next steps (from docs/SECURITY.md "Every check_id") ----------
function nextStep(id) {
  const rules = [
    [/^ingestion\.climate\.last_run$/, 'Read the newest ingestion_runs row for climate (status, http_status, error) and the ingest-climate-2026 Edge Function logs; re-run the ingest once fixed.'],
    [/^ingestion\.innovint\.last_run$/, 'Read the newest ingestion_runs row for InnoVint and the ingest-innovint logs; check INNOVINT_TOKEN and source.innovint.api.'],
    [/^ingestion\.ets_report\.last_run$/, 'Weekly ETS cloud task: read the newest ingest-ets-report ingestion_runs rows (error, detail) and the function logs; check the task still runs and sends x-ets-ingest-key (docs/ETS-INGEST.md).'],
    [/^ingestion\.ets_report\.quarantine$/, 'Read public.ets_ingest_quarantine (reason per analyte); fix the PDF parser or ets_analyte_spec and re-send the report, or delete the row once handled (docs/ETS-INGEST.md).'],
    [/^ingestion\.climate\.freshness$/, 'Newest real ERA5 hour is over 26 h old: confirm the climate ingest cron ran and the Open-Meteo probes (source.open_meteo.*) pass.'],
    [/^ingestion\.climate\.daily_weather_through$/, 'daily_weather is behind: run refresh_daily_weather_range() for the missing days and check the daily_weather build.'],
    [/^ingestion\.climate\.current_vintage$/, 'Compare stored vintage with public.harvest_vintage(recorded_at); add the next vintage to public.vintages before 1 November Pacific.'],
    [/^ingestion\.climate\.model_pinned$/, 'Check CLIMATE_SOURCES in ingest-climate-2026 still pins weather=ecmwf_ifs and soil=era5_land.'],
    [/^database\.integrity\.soil_moisture_range$/, 'Find soil readings outside 0-100 in sensor_readings and the ingest run that wrote them.'],
    [/^database\.integrity\.gdd_calibrated_2022_2025$/, 'Inspect vintage_climate_calibration and daily_derived for the out-of-range vintage.'],
    [/^database\.integrity\.mock_real_precedence$/, 'Compare no-vintage vs vintage-scoped series_bucketed for the named pair (see the 20260930045000 fix); re-baseline only if the pair set changed deliberately.'],
    [/^database\.integrity\.daily_weather_pacific_days$/, 'daily_weather newest day must match Pacific-bucketed hourly ERA5 (tmax_f and tavg_f); check migration 20260930050100 and recompute the day.'],
    [/^database\.integrity\.no_b1_2024_irrigation$/, 'Remove the B1 2024 irrigation rows (B1 had no 2024 irrigation; see Track 2 Phase 3 notes).'],
    [/^database\.integrity\.sensor_readings_unique$/, 'Restore UNIQUE (metric_key, sensor_id, recorded_at) on sensor_readings.'],
    [/^database\.integrity\.no_future_real_rows$/, 'Find future-dated real rows; check ingest-climate-2026 is not storing forecast hours (2026-09-29 incident).'],
    [/^database\.integrity\.climate_source_labels$/, 'Relabel per the 2026-09-30 rule: atmospheric = ECMWF IFS, soil = ERA5-Land, no legacy open_meteo_era5/OM-ERA5.'],
    [/^database\.checksum\.(sensor_readings|daily_weather)_closed_vintages$/, 'Closed-vintage (2022-2025) data changed: find what wrote to it. If deliberate, re-baseline with system_health.set_baseline().'],
    [/^database\.checksum\.winery_closed_vintages$/, 'Likely an upstream InnoVint/ETS correction: confirm it upstream, then re-baseline.'],
    [/^database\.vintage\.current_consistent$/, 'If the dashboard test (P3) did not run in the last day, this clears after its next run. Otherwise compare vintages.is_current, harvest_vintage(now()) and the latest frontend.current_vintage / gateway.current_vintage results.'],
    [/^database\.anomalies\.anchor_/, 'Check recent anomaly_thresholds changes and anomalies_eval() under svc-nightly-checks via RLS.'],
    [/^database\.vessels\.counts$/, 'Check the InnoVint vessel sync; review new placeholder capacities; re-baseline if intended.'],
    [/^database\.backup\.retention_decision$/, 'Decide whether to drop the old table in schema backup (never dropped automatically).'],
    [/^security\.structure\.daily_derived$/, 'daily_derived grants/columns differ from baseline: a dbt full-refresh drops grants. Restore them, or re-baseline if intended.'],
    [/^security\.rls\.enabled_on_every_table$/, 'Enable RLS on the named table and add its policy + grant pair.'],
    [/^security\.anon\./, 'Revoke the listed privileges from anon and check postgres default privileges.'],
    [/^security\.policies\.baseline$/, 'Review the added/removed/changed RLS policy; if intended, re-baseline security.policies.baseline.'],
    [/^security\.functions\.required_present$/, 'Restore the missing function or signature.'],
    [/^security\.definer\.search_path_pinned$/, 'Add SET search_path to the named SECURITY DEFINER function.'],
    [/^security\.mcp_reader\.grants$/, "Compare mcp_reader's grants with the baseline, revoke extras, run check-mcp-boundaries.mjs."],
    [/^security\.health_writer\.privileges$/, 'Revoke extra privileges from health_writer (only record_run/record_result).'],
    [/^security\.no_embedded_keys$/, 'A secret appears in a database object: remove it from the named object and rotate that secret now.'],
    [/^security\.pg_net\.queue_not_stale$/, 'Inspect the pg_net request queue for the stuck request.'],
    [/^source\.innovint\.api$/, 'Check INNOVINT_TOKEN validity and InnoVint API status.'],
    [/^source\.open_meteo\./, 'Check Open-Meteo archive status; a short IFS day is often transient, re-check tomorrow.'],
    [/^source\.anthropic\.model$/, 'Replace ANTHROPIC_API_KEY (Anthropic console, then the Supabase secret).'],
    [/^source\.fireworks\.model$/, 'Set KIMI_API_KEY or unset CHAT_MODEL_PROVIDER=kimi.'],
    [/^source\.resend\.api$/, 'Check RESEND_API_KEY.'],
    [/^frontend\.[a-z0-9_]+\.login$/, "Check the synthetic user's GitHub secret password and Supabase Auth; see the P3 Actions run log."],
    [/^frontend\.[a-z0-9_]+\.panels$/, 'Open the P3 GitHub Actions run log for the failing panel; reproduce with a hard reload.'],
    [/^frontend\.[a-z0-9_]+\.role_visibility$/, 'Operator-only panel reached a customer, or vice versa: fix panel role gating now.'],
    [/^frontend\.[a-z0-9_]+\.rls_boundary$/, 'Possible data leak across the RLS boundary: review the sensor_readings/vessels/user_profiles policies now.'],
    [/^frontend\.fidelity\./, "Dashboard disagrees with the gateway: compare the panel's series_bucketed call with get_series/get_derived_series."],
    [/^gateway\.tools\./, 'Adapter disagrees with REST: run scripts/mcp-parity.mjs.'],
    [/^gateway\.p4\.write_capable_tools$/, "Remove the tool from the key's allowed_tools now (agent-keys.mjs set-tools) and review the key's audit log for misuse."],
    [/^gateway\.p4\./, 'Check the mcp Edge Function logs and the gateway role password.'],
    [/^p3_backup/, 'P3 schedule was missed: check nightly-health-p3.yml runs and github_p3_dispatch_token in Vault.'],
  ];
  for (const [re, s] of rules) if (re.test(id)) return s;
  return 'See docs/SECURITY.md "Every check_id" for this check.';
}
const layerOf = (l, id) => {
  const x = String(l || '').toLowerCase();
  if (x === 'source' || x === 'sources' || id.startsWith('source.')) return 'sources';
  if (x === 'frontend' || x === 'dashboard' || id.startsWith('frontend.')) return 'dashboard';
  if (LAYERS.includes(x)) return x;
  if (id.startsWith('gateway.')) return 'gateway';
  if (id.startsWith('security.')) return 'security';
  if (id.startsWith('ingestion.')) return 'ingestion';
  return 'database';
};

// ---------- main ----------
let allowedToCall = new Set();
const producers = {}; // producer -> {run_id, started_at, finished_at, status, stale, counts, schedule_utc}
let overall = null, currentVintage = null, health = null;
const stale = new Set();

async function main() {
  // 1. initialize (first call: auth failures stop the run)
  const init = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'mars-daily-check', version: '2.0' } }, { first: true });
  if (!init.ok) {
    if (authFailure || /network error/.test(init.failure)) {
      add('CRITICAL', 'gateway', 'gateway.auth', 'Gateway auth failed: credential missing, key revoked/expired, or service account disabled',
        authFailure ? `HTTP ${authFailure} on MCP initialize` : `${init.failure} (a proxy 403 means the domain/credential is not set up for this environment)`,
        'HTTP 200 on initialize', 'Check the key in User Management (revoked/expired?) and the service account; if the key was replaced, delete and re-add the environment credential.');
      for (const l of LAYERS) nc(`layer.${l}`, 'gateway auth failed on the first call', `${LAYER_NAMES[l]} layer (gateway auth failed)`);
      return;
    }
    add('HIGH', 'gateway', 'gateway.initialize', 'MCP initialize failed', init.failure, 'HTTP 200 with a result', 'Check the mcp Edge Function logs.');
    for (const l of LAYERS) nc(`layer.${l}`, 'MCP initialize failed', `${LAYER_NAMES[l]} layer (gateway unavailable)`);
    return;
  }
  await rpc('notifications/initialized'); // notification; response ignored

  // 2. tool inventory
  const tl = await rpc('tools/list');
  if (!tl.ok) {
    add('HIGH', 'gateway', 'gateway.tools_list', 'tools/list failed', tl.failure, '12 tools', 'Check the mcp Edge Function logs.');
    nc('inventory', 'tools/list failed', 'tool inventory (tools/list failed)');
    return;
  }
  const tools = tl.result?.tools || [];
  const names = tools.map((t) => t.name).sort();
  obs.tools = names;
  obs.missing = EXPECTED_TOOLS.filter((t) => !names.includes(t));
  obs.unexpected = names.filter((t) => !EXPECTED_TOOLS.includes(t));
  for (const t of obs.missing)
    add('HIGH', 'gateway', 'inventory.missing', `Tool missing from the gateway: ${t}`, `${names.length} tools listed`, 'all 12 expected tools',
      "Add the tool back to the key's allowed_tools (scripts/agent-keys.mjs set-tools).");
  for (const t of tools) if (!EXPECTED_TOOLS.includes(t.name)) {
    const a = t.annotations || {};
    const writes = !/^get_/.test(t.name) || a.readOnlyHint === false || a.destructiveHint === true;
    add(writes ? 'CRITICAL' : 'MEDIUM', 'gateway', 'inventory.unexpected', `Unexpected tool on the gateway: ${t.name}${writes ? ' (can write)' : ''}`,
      `tool "${t.name}" exposed to svc-nightly-checks`, 'exactly the 12 read-only tools',
      writes ? "Remove it from the key's allowed_tools immediately, check mcp_tool_catalogue, and review the key's audit log for misuse." : 'Confirm it is intended; otherwise remove it from allowed_tools.');
  }
  allowedToCall = new Set(names.filter((n) => EXPECTED_TOOLS.includes(n))); // never call anything unexpected

  // 3. system health
  const sh = await tool('get_system_health');
  if (!sh.ok) {
    add('HIGH', 'gateway', 'get_system_health', 'get_system_health failed', sh.failure, 'a health summary', 'Check the mcp Edge Function logs.');
    for (const l of ['sources', 'ingestion', 'database', 'dashboard', 'security']) nc(`layer.${l}`, 'get_system_health unavailable', `${LAYER_NAMES[l]} layer (health summary unavailable)`);
  } else {
    health = sh.data;
    overall = health.overall;
    currentVintage = health.current_vintage ?? null;
    for (const p of health.producers || []) {
      producers[p.producer] = { run_id: p.run_id, started_at: p.started_at, finished_at: p.finished_at, status: p.status, stale: !!p.stale, counts: p.summary?.counts || {}, schedule_utc: p.schedule_utc };
      if (p.stale) {
        stale.add(p.producer);
        add('HIGH', (PRODUCER_LAYERS[p.producer] || ['database'])[0], `stale.${p.producer}`, `${PRODUCER_NAMES[p.producer] || p.producer} did not run on schedule`,
          `latest run #${p.run_id} started ${et(p.started_at)}`, `a run after the ${p.schedule_utc} UTC slot (+30 min grace), under 26 h old`,
          { p1_database: 'Check pg_cron job health-p1-database (cron.job_run_details).', p2_probes: 'Check pg_cron job health-p2-probes and the health-probe Edge Function logs.', p3_frontend: 'Check the nightly-health-p3.yml GitHub Actions runs and the P3 backup dispatch.' }[p.producer] || 'Check the producer schedule.');
        for (const l of PRODUCER_LAYERS[p.producer] || []) nc(`layer.${l}`, `${p.producer} is stale, so its results are not current`, `${LAYER_NAMES[l]} layer (${PRODUCER_NAMES[p.producer] || p.producer} did not run)`);
        continue;
      }
      for (const pr of p.summary?.problems || []) healthProblem(pr, p.producer);
    }
    // GitHub starts the 12:17 P3 schedule late most days, so the 12:35 backup
    // dispatch usually starts P3; it records itself as "warn" by design. That
    // is GitHub's scheduling, not a fault: note it, and raise only a dispatch
    // that failed (a stale P3 is already its own HIGH finding above).
    const backups = health.p3_backup_dispatches || [];
    obs.p3_backup = backups.map((d) => ({ at: d.started_at, status: d.status }));
    const failedBackup = backups.find((b) => (b.summary?.problems || []).some((pr) => pr.status === 'fail') || b.status === 'fail' || b.status === 'error');
    if (failedBackup && !stale.has('p3_frontend')) {
      add('MEDIUM', 'dashboard', 'p3_backup.dispatch', 'The P3 backup dispatch could not start P3',
        `backup run at ${et(failedBackup.started_at)}: ${failedBackup.status}`, 'a dispatched P3 run', nextStep('p3_backup.dispatch'));
    }
    for (const c of health.p4_gateway_self_check || []) p4(c);
    obs.p4 = (health.p4_gateway_self_check || []).map((c) => c.status);
  }

  // 4. history: repeated failures, and changes versus each producer's previous run
  const hh = await tool('get_health_history', { days: 7 });
  if (!hh.ok) nc('health_history', `get_health_history failed: ${hh.failure}`, 'health history (tool failed)');
  else {
    const runs = hh.data?.runs || [];
    const fails = {};
    for (const r of runs) for (const pr of r.summary?.problems || [])
      if (pr.status === 'fail') (fails[pr.check_id] ||= { n: 0, layer: pr.layer, producer: r.producer, last: r.started_at }).n++;
    const currentProblems = new Set(findings.map((f) => f.check_id));
    for (const [id, f] of Object.entries(fails)) {
      if (f.n < 2 || currentProblems.has(id) || stale.has(f.producer) || !producers[f.producer]) continue;
      if (KNOWN_ISSUES[id]) continue; // known issue now passing: stop mentioning it
      add('LOW', layerOf(f.layer, id), id, `Fixed for now, but failed ${f.n} times in the last 7 days: ${checkPlain(id)}`,
        `${f.n} failed runs in 7 days, most recently ${et(f.last)}; passing in run #${producers[f.producer].run_id}`, 'no failures', nextStep(id) + ' Watch for recurrence.');
    }
    for (const [p, cur] of Object.entries(producers)) {
      const mine = runs.filter((r) => r.producer === p).sort((a, b) => String(b.started_at).localeCompare(String(a.started_at)));
      const i = mine.findIndex((r) => r.run_id === cur.run_id);
      const before = i >= 0 ? mine[i + 1] : mine[0];
      const label = PRODUCER_NAMES[p] || p;
      if (!before) { changes.push(`${label}: no earlier run in the last 7 days to compare with`); continue; }
      const ids = (list) => new Set((list || []).map((x) => `${checkPlain(x.check_id)} (${STATE_PLAIN[x.status] || x.status})`));
      const a = ids(before.summary?.problems), b = ids(health.producers.find((x) => x.producer === p)?.summary?.problems);
      const added = [...b].filter((x) => !a.has(x)), gone = [...a].filter((x) => !b.has(x));
      const parts = [];
      if (before.status !== cur.status) parts.push(`overall result went from ${before.status} to ${cur.status}`);
      if (added.length) parts.push(`new problem${added.length > 1 ? 's' : ''}: ${added.join('; ')}`);
      if (gone.length) parts.push(`fixed since last time: ${gone.join('; ')}`);
      changes.push(`${label}: ${parts.length ? parts.join('. ') : 'no change'} (compared with its previous run, ${et(before.started_at)})`);
    }
  }

  // 5. baselines
  const hb = await tool('get_health_baselines');
  const baselines = {};
  if (!hb.ok) nc('health_baselines', `get_health_baselines failed: ${hb.failure}`, 'stored baselines (tool failed)');
  else for (const b of hb.data?.baselines || []) baselines[b.check_id] = b.value;
  const p1ok = producers.p1_database && !stale.has('p1_database');
  const p3ok = producers.p3_frontend && !stale.has('p3_frontend');
  const passes = (id, prod) => (prod === 'p1' ? p1ok : p3ok) && !findings.some((f) => f.check_id === id && f.severity !== 'LOW');
  const disagree = (id, prod, observed, expected) => {
    if (passes(id, prod)) add('HIGH', 'gateway', id, `The platform's own check passed, but this report's spot check disagrees: ${checkPlain(id)}`, observed, expected,
      `${nextStep(id)} Also check whether the health check itself is still testing what it should.`);
  };

  // 6. spot-checks
  // 6a. soil moisture B2
  const soilArgs = { metric: 'soil_moisture', block: 'B2', vintage: 2024, start: '2024-07-01T00:00:00Z', end: '2024-07-08T00:00:00Z', bucket_hours: 24 };
  const s1 = await tool('get_series', soilArgs);
  if (!s1.ok) { nc('spot.soil_b2', `get_series failed: ${s1.failure}`, 'B2 soil moisture (tool failed)'); add('HIGH', 'gateway', 'spot.soil_moisture', 'Soil moisture spot-check failed to run', s1.failure, 'data', 'Check the mcp Edge Function logs.'); }
  else {
    const vals = (rowsOf(s1.data) || []).map((r) => r.v).filter((v) => v != null);
    obs.spot.soil_b2 = { total: s1.data?.total_count ?? null, non_null: vals.length, min: vals.length ? Math.min(...vals) : null, max: vals.length ? Math.max(...vals) : null };
    let checkVals = vals, where = 'B2';
    if (!vals.length) {
      nc('spot.soil_b2', `The weather service (ERA5-Land) provides soil moisture for the whole estate, not per block, so all ${s1.data?.total_count ?? 0} days came back empty for Block 2; the estate-wide values were checked instead`,
        'Block 2 soil moisture (soil data is recorded for the whole estate, not per block)');
      const s2 = await tool('get_series', { ...soilArgs, block: undefined });
      if (s2.ok) {
        checkVals = (rowsOf(s2.data) || []).map((r) => r.v).filter((v) => v != null);
        where = 'estate-wide';
        obs.spot.soil_estate = { total: s2.data?.total_count ?? null, non_null: checkVals.length, min: checkVals.length ? Math.min(...checkVals) : null, max: checkVals.length ? Math.max(...checkVals) : null };
      }
    }
    const bad = checkVals.filter((v) => v < 0 || v > 100);
    if (bad.length) {
      add('CRITICAL', 'database', 'spot.soil_moisture', `Soil moisture outside 0-100% (${where}, 1-8 Jul 2024)`, `${bad.length} bucket(s) out of range: ${bad.slice(0, 5).join(', ')}`, 'every value 0-100', nextStep('database.integrity.soil_moisture_range'));
      disagree('database.integrity.soil_moisture_range', 'p1', `get_series shows ${bad.length} out-of-range bucket(s)`, 'no out-of-range soil readings');
    }
  }
  // 6b. derived GDD
  const d = await tool('get_derived_series', { vintage: 2024 });
  if (!d.ok) { nc('spot.gdd_2024', `get_derived_series failed: ${d.failure}`, '2024 GDD (tool failed)'); add('HIGH', 'gateway', 'spot.gdd', 'GDD spot-check failed to run', d.failure, 'data', 'Check the mcp Edge Function logs.'); }
  else {
    const rows = (rowsOf(d.data) || []).filter((r) => r.gdd_cumulative_calibrated != null).sort((a, b) => String(a.day).localeCompare(String(b.day)));
    const last = rows.at(-1);
    obs.spot.gdd_2024 = last ? { value: last.gdd_cumulative_calibrated, day: String(last.day).slice(0, 10) } : null;
    if (!last) nc('spot.gdd_2024', 'get_derived_series 2024 returned no gdd_cumulative_calibrated values', '2024 GDD (no values returned)');
    else if (!(last.gdd_cumulative_calibrated >= 3000 && last.gdd_cumulative_calibrated <= 4400)) {
      add('CRITICAL', 'database', 'spot.gdd', 'Final 2024 calibrated GDD out of range', `${last.gdd_cumulative_calibrated} on ${String(last.day).slice(0, 10)}`, '3,000-4,400 (about 4,058)', nextStep('database.integrity.gdd_calibrated_2022_2025'));
      disagree('database.integrity.gdd_calibrated_2022_2025', 'p1', `2024 final = ${last.gdd_cumulative_calibrated}`, '3,000-4,400');
    }
  }
  // 6c. anomaly anchors
  for (const [asOf, want, id] of [['2024-07-06T02:00:00Z', 3, 'database.anomalies.anchor_2024_07_06'], ['2024-04-06T14:00:00Z', 2, 'database.anomalies.anchor_2024_04_06']]) {
    const key = `anomalies_${asOf.slice(0, 10)}`;
    const a = await tool('get_anomalies', { vintage: 2024, as_of: asOf });
    if (!a.ok) { nc(`spot.${key}`, `get_anomalies failed: ${a.failure}`, `anomaly anchor ${asOf.slice(0, 10)} (tool failed)`); add('HIGH', 'gateway', `spot.${key}`, 'Anomaly spot-check failed to run', a.failure, `${want} hits`, 'Check the mcp Edge Function logs.'); continue; }
    const n = a.data?.total_count ?? rowsOf(a.data)?.length ?? null;
    obs.spot[key] = { total: n, want, rules: (rowsOf(a.data) || []).map((r) => r.rule_key).sort() };
    if (n !== want) {
      add('HIGH', 'database', `spot.${key}`, `Anomaly anchor ${asOf.slice(0, 10)} returned ${n} alert(s) instead of ${want}`, `total_count ${n} (${obs.spot[key].rules.join(', ')})`, `${want} hits`, nextStep(id));
      disagree(id, 'p1', `get_anomalies total_count ${n}`, `${want} hits`);
    }
  }
  // 6d. vessels
  const v = await tool('get_vessels', { include_archived: true });
  if (!v.ok) { nc('spot.vessels', `get_vessels failed: ${v.failure}`, 'vessel counts (tool failed)'); add('HIGH', 'gateway', 'spot.vessels', 'Vessel spot-check failed to run', v.failure, 'data', 'Check the mcp Edge Function logs.'); }
  else {
    const total = v.data?.total_count ?? null;
    const rows = rowsOf(v.data) || [];
    const truncated = v.data?.truncated === true || (total != null && rows.length < total);
    const suspect = truncated ? null : rows.filter((r) => Number(r.capacity_gal) >= 500000).length;
    const active = rows.filter((r) => r.archived === false).length;
    const vb = baselines['database.vessels.counts'] || {};
    const baseSuspect = vb.capacity_suspect ?? null;
    obs.spot.vessels = { total, capacity_suspect: suspect, base_suspect: baseSuspect, active: truncated ? null : active, base_total: vb.total ?? null, base_active: vb.active ?? null };
    // Same rule as the platform's own vessel check: new tanks are normal
    // operations, so the total only informs; a problem is no tanks in use,
    // or the number in use moving more than 25% from the baseline.
    if (!truncated && active === 0) {
      add('HIGH', 'database', 'spot.vessels_active', 'No tanks or vessels are marked as in use', '0 in use', 'at least 1', nextStep('database.vessels.counts'));
      disagree('database.vessels.counts', 'p1', '0 vessels in use', 'at least 1');
    } else if (!truncated && vb.active && Math.abs(active - vb.active) / vb.active > 0.25) {
      add('MEDIUM', 'database', 'spot.vessels_active', `Tanks in use moved more than 25% from the baseline (${vb.active} to ${active})`, `${active} in use`, `within 25% of ${vb.active}`, nextStep('database.vessels.counts'));
      disagree('database.vessels.counts', 'p1', `${active} vessels in use`, `within 25% of ${vb.active}`);
    }
    if (suspect == null) nc('spot.vessels_capacity_suspect', 'get_vessels rows were capped, so the placeholder-capacity count is unreliable', 'placeholder-capacity vessel count (results capped)');
    else if (baseSuspect == null) nc('spot.vessels_capacity_suspect', 'no database.vessels.counts baseline available', 'placeholder-capacity vessel count (no baseline)');
    else if (suspect !== baseSuspect) {
      add('MEDIUM', 'database', 'spot.vessels_capacity_suspect', `Vessels with placeholder capacity changed to ${suspect}`, `${suspect} vessels at the 500000 gal placeholder`, `${baseSuspect} (baseline)`, nextStep('database.vessels.counts'));
      if (suspect > baseSuspect) disagree('database.vessels.counts', 'p1', `${suspect} placeholder-capacity vessels`, `<= ${baseSuspect}`);
    }
  }

  // 7. lab sanity
  const BOUNDS = {
    brix: [0, 35, 'Brix'], ph: [2.8, 4.2, 'pH'], titratable_acidity: [2, 15, 'TA g/L'], yeast_assimilable_nitrogen: [0, 600, 'YAN mg/L'],
    volatile_acidity_acetic_acid: [0, 2, 'VA g/L'], ethanol_at_20c: [0, 17, 'alcohol %'], ethanol_at_60f: [0, 17, 'alcohol %'], free_sulfur_dioxide: [0, 100, 'free SO2 mg/L'],
  };
  const tomorrow = new Date(now.getTime() + 86400_000).toISOString().slice(0, 10);
  for (const [name, a] of [['get_berry_maturity', {}], ['get_smoke_markers', {}], ['get_wine_lab_results', { limit: 300 }]]) {
    const r = await tool(name, a);
    const rows = r.ok ? rowsOf(r.data) : null;
    if (!r.ok || !rows) {
      nc(`lab.${name}`, r.ok ? 'response was not a row list' : `${name} failed: ${r.failure}`, `${name} (no usable rows)`);
      add('MEDIUM', 'gateway', `lab.${name}`, `Lab data (${LAB_PLAIN[name]}) could not be read through the gateway`, r.ok ? 'unparseable response' : r.failure, 'a JSON row list', 'Check the mcp Edge Function logs.');
      continue;
    }
    const fields = [...new Set(rows.flatMap((x) => Object.keys(x)))].sort();
    const issues = [];
    const oob = [];
    const check = (label, val, lo, hi, ref) => { if (typeof val === 'number' && (val < lo || val > hi)) oob.push(`${ref}: ${label}=${val} (allowed ${lo}-${hi})`); };
    for (const x of rows) {
      const ref = [x.lab_sample_no, x.sample_description, x.block_id, x.collected_on].filter(Boolean).join(' ');
      if (name === 'get_berry_maturity') for (const k of ['brix', 'ph', 'titratable_acidity']) check(BOUNDS[k][2], x[k], BOUNDS[k][0], BOUNDS[k][1], ref);
      if (name === 'get_wine_lab_results' && BOUNDS[x.analysis_code]) { const b = BOUNDS[x.analysis_code]; check(b[2], x.result_numeric, b[0], b[1], ref); }
      if (name === 'get_smoke_markers' && typeof x.result_numeric === 'number' && x.result_numeric < 0) oob.push(`${ref}: ${x.analysis_code}=${x.result_numeric} (negative)`);
    }
    if (oob.length) issues.push(['some values are outside the normal range', `${oob.length}: ${oob.slice(0, 5).join('; ')}`, 'values inside the sanity bounds']);
    const fut = rows.filter((x) => (x.collected_on && String(x.collected_on).slice(0, 10) > tomorrow) || (x.analyzed_at && new Date(x.analyzed_at) > new Date(now.getTime() + 86400_000)));
    if (fut.length) issues.push(['some samples are dated in the future', `${fut.length} row(s), e.g. ${fut.slice(0, 3).map((x) => x.collected_on || x.analyzed_at).join(', ')}`, 'no dates after today']);
    const seen = new Set(); let dups = 0;
    for (const x of rows) { const k = JSON.stringify(Object.keys(x).sort().map((f) => [f, x[f]])); if (seen.has(k)) dups++; seen.add(k); }
    if (dups) issues.push(['some samples appear twice', `${dups} exact duplicate row(s)`, 'no exact duplicates']);
    const allNull = rows.length ? fields.filter((f) => rows.every((x) => x[f] == null)) : [];
    if (allNull.length) issues.push(['some fields are empty on every sample', allNull.join(', '), 'each field populated on at least one row']);
    const pf = LAB_FIELDS[name];
    const added = fields.filter((f) => !pf.includes(f)), removed = pf.filter((f) => !fields.includes(f));
    if (added.length || removed.length) {
      issues.push(['the set of data fields changed (schema drift), which can break anything that reads this data', `${added.length ? 'new fields: ' + added.join(', ') : ''}${added.length && removed.length ? '; ' : ''}${removed.length ? 'missing fields: ' + removed.join(', ') : ''}`, `the ${pf.length} known fields`]);
      changes.push(`Lab data (${LAB_PLAIN[name]}): data fields changed (${added.length} added, ${removed.length} removed)`);
    }
    for (const [t, o, e] of issues) add('MEDIUM', 'database', `lab.${name}`, `Lab data (${LAB_PLAIN[name]}): ${t}`, o, e, 'Compare with the ETS Labs report / InnoVint record and correct the import if it is wrong; if the change was deliberate, update the expected list in this check.');
    obs.lab[name] = { rows: rows.length, issues: issues.length, fields };
    if (name === 'get_wine_lab_results' && rows.length >= 300) nc('lab.get_wine_lab_results.complete', 'returned the 300-row maximum, so later rows were not checked', 'wine lab rows beyond the first 300');
    if (name === 'get_smoke_markers' && currentVintage != null) {
      const hits = rows.filter((x) => x.vintage === currentVintage && typeof x.result_numeric === 'number' && x.result_numeric > 0 && x.result_operator !== '<');
      obs.lab.smoke_current = hits.length;
      if (hits.length) add('LOW', 'database', 'lab.smoke_current_vintage', `Smoke markers detected in the ${currentVintage} vintage`,
        `${hits.length} value(s) above zero, e.g. ${hits.slice(0, 3).map((x) => `${x.analysis_code}=${x.result_numeric} ${x.units || ''}`.trim()).join('; ')}`, 'none detected', 'Review with the winemaker; compare against smoke-taint thresholds for the sample basis.');
    }
  }

  // 8. lot analyses + labour
  for (const [name, a] of [['get_lot_analyses', {}], ['get_labour_summary', {}]]) {
    const r = await tool(name, a);
    const rows = r.ok ? rowsOf(r.data) : null;
    const hasData = r.ok && (rows ? rows.length > 0 : r.data && (r.data.record_status === 'records_present' || (r.data.categories || []).length > 0));
    obs.ops[name] = hasData;
    if (!hasData) add('HIGH', 'gateway', name, `${name} returned no data`, r.ok ? 'empty result' : r.failure, 'data without error', 'Check the mcp Edge Function logs and the underlying table grants/RLS.');
  }
}

function healthProblem(pr, producer) {
  const id = pr.check_id || 'unknown';
  const layer = layerOf(pr.layer, id);
  const st = pr.status;
  let sev;
  if (st === 'fail') sev = (/^frontend\..*(rls_boundary)$/.test(id) || /^frontend\.fidelity\./.test(id) || layer === 'security') ? 'CRITICAL' : 'HIGH';
  else if (st === 'warn' || st === 'error') sev = 'MEDIUM';
  else return;
  if (/^frontend\.[a-z0-9_]+\.login$/.test(id)) return loginProblem(pr, layer);
  const known = KNOWN_ISSUES[id];
  add(sev, layer, id, `${st === 'fail' ? 'Failed' : st === 'warn' ? 'Warning' : 'Could not run'}: ${checkPlain(id)}${pr.detail ? ` (${clip(plainify(firstLine(pr.detail)), 200)})` : ''}${known ? ` (${known})` : ''}`,
    clip(plainValue(pr.observed), 600), clip(plainValue(pr.expected), 600), nextStep(id));
}

// P3 signs each synthetic user in through the real form in a headless browser.
// Its diagnosis (scripts/p3-frontend.mjs) says whether sign-in itself worked:
//   - real sign-in failure (error shown, no session, or the database won't
//     answer the user's session): HIGH;
//   - signed in, but the dashboard page stalled in the test browser even
//     after a reload: MEDIUM (users can sign in; the page load is suspect);
//   - dashboard appeared after one reload: LOW.
// Runs from before that diagnosis existed can't tell these apart: MEDIUM.
function loginProblem(pr, layer) {
  const id = pr.check_id, o = (pr.observed && typeof pr.observed === 'object') ? pr.observed : {};
  const who = TEST_USERS[o.user || id.split('.')[1]] || o.user || id.split('.')[1];
  const diag = (d) => [d.screen && `screen: ${d.screen}`, d.session && `session: ${d.session}`, d.role_probe && `database: ${d.role_probe}`,
    d.pending_requests?.length && `open requests: ${d.pending_requests.slice(0, 3).join(', ')}`].filter(Boolean).join('; ');
  const step = 'Open the latest "nightly-health-p3" run in GitHub Actions: its "diagnosis" line shows which sign-in step stalled.';
  const tag = (short) => Object.assign(findings[findings.length - 1], { short, who });
  if (pr.status === 'warn') {
    add('LOW', layer, id, `Dashboard test (P3), ${who}: signed in fine, but the page needed a reload to appear`,
      clip(diag(o.first_attempt || {}) || 'recovered after one reload', 400), 'dashboard within 60s of sign-in', step);
    tag('the dashboard test needed a page reload after sign-in');
    return;
  }
  if (pr.status !== 'fail') return;
  const signedIn = o.session === 'signed in';
  const dbOk = /^ok \(/.test(o.role_probe || '');
  const authBroken = !!o.auth_error || o.session === 'no session' || (signedIn && o.role_probe && !dbOk);
  if (authBroken) {
    add('HIGH', layer, id, `Dashboard test (P3): signing in failed for ${who}${o.auth_error ? `: ${clip(o.auth_error, 120)}` : ''}`,
      clip(diag(o), 400), 'signed in, dashboard shown', "Check the synthetic user's GitHub secret password and Supabase Auth; see the P3 Actions run log.");
    tag('dashboard sign-in failed');
  } else if (signedIn) {
    add('MEDIUM', layer, id, `Dashboard test (P3), ${who}: signed in and the database answered, but the page did not finish loading in the robot browser, even after a reload`,
      clip(diag(o), 400), 'dashboard within 60s of sign-in', step);
    tag('the dashboard page stalled in the test browser after sign-in (sign-in itself worked)');
  } else {
    add('MEDIUM', layer, id, `Dashboard test (P3), ${who}: the dashboard did not appear within 60 seconds of signing in (cause not recorded)`,
      clip(firstLine(pr.detail || ''), 200), 'dashboard within 60s of sign-in',
      'Usually a stalled page load in the test browser rather than a sign-in failure; if it repeats, sign in as a real user to confirm, and see the P3 Actions run log.');
    tag('the dashboard test page did not appear after sign-in');
  }
}

// One phrase per kind of finding for the executive summary: the per-user
// dashboard sign-in findings collapse into one, naming the users.
function summarize(list) {
  const out = [], byShort = new Map();
  for (const f of list) {
    if (!f.short) { out.push(f.title); continue; }
    if (!byShort.has(f.short)) { byShort.set(f.short, []); out.push(f.short); }
    byShort.get(f.short).push(f.who);
  }
  const text = out.map((t) => byShort.has(t) ? `${t} (${byShort.get(t).join('; ')})` : t);
  return `${text.slice(0, 3).join('; ')}${text.length > 3 ? '; ...' : ''}`;
}

function p4(c) {
  const id = c.check_id;
  if (id === 'gateway.p4.key_expiry') {
    // Informational only: key rotation is routine. An expired key shows up as a RED gateway auth failure.
    obs.key = { prefix: c.observed?.key_prefix ?? null, expires_at: c.observed?.expires_at ?? null, days_left: c.observed?.days_left ?? null };
    return;
  }
  if (id === 'gateway.p4.write_capable_tools') {
    const w = c.observed?.write_capable_tools || [];
    if (w.length || c.status === 'fail') add('CRITICAL', 'gateway', id, 'The gateway key allows a tool that can write data', w.join(', ') || c.status, 'no write-capable tools', nextStep(id));
    return;
  }
  if (c.status === 'fail') add('HIGH', 'gateway', id, `Gateway self-check ${id} failed`, clip(fmt(c.observed ?? c.detail ?? ''), 400), 'pass', nextStep(id));
  else if (c.status === 'warn' || c.status === 'error') add('MEDIUM', 'gateway', id, `Gateway self-check ${id} returned "${c.status}"`, clip(fmt(c.observed ?? c.detail ?? ''), 400), 'pass', nextStep(id));
}

// ---------- report ----------
function et(iso) {
  if (!iso) return 'n/a';
  return new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short' }).format(new Date(iso));
}
const plural = (n, one, many = one + 's') => `${n} ${n === 1 ? one : many}`;
const countsText = (c) => {
  const total = Object.values(c || {}).reduce((a, b) => a + b, 0);
  const bad = Object.entries(c || {}).filter(([k]) => k !== 'pass').map(([k, n]) => `${n} ${k}`);
  return bad.length ? `${c.pass || 0} of ${total} passed (${bad.join(', ')})` : `all ${total} passed`;
};

function build() {
  findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.layer.localeCompare(b.layer));
  const worst = findings[0]?.severity;
  const unexpectedNC = notChecked.filter((n) => !EXPECTED_UNCHECKABLE.has(n.id));
  let status = 'GREEN';
  if (worst === 'CRITICAL' || worst === 'HIGH') status = 'RED';
  else if (findings.length || unexpectedNC.length) status = 'YELLOW';
  const n = findings.length + (findings.length ? 0 : unexpectedNC.length);
  const dateET = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/New_York' }).format(now);
  const subject = `Mars Telemetry ${status} - ${dateET}${status === 'GREEN' ? '' : `: ${n} issue(s)`}`;
  const serious = findings.filter((f) => SEV_ORDER[f.severity] <= 1);
  const minor = findings.filter((f) => SEV_ORDER[f.severity] > 1);
  const sections = []; // {title, paras: [], items: [{text, sub: []}]}

  // EXECUTIVE SUMMARY
  const ex = [];
  const authFailed = findings.some((f) => f.check_id === 'gateway.auth');
  if (authFailed) {
    ex.push('Action needed: the check could not sign in to the Mars Telemetry gateway, so nothing else could be checked today.');
    ex.push('The key may have been revoked or replaced, or the service account disabled; the finding below says what to look at.');
  } else {
    if (status === 'RED') ex.push(`Action needed: ${plural(serious.length, 'serious issue')} found (${summarize(serious)}).`);
    else if (status === 'YELLOW' && findings.length) ex.push(`No urgent problems. ${plural(minor.length, 'lower-priority item')} to be aware of: ${summarize(minor)}.`);
    else if (status === 'YELLOW') ex.push(`No problems found, but ${plural(unexpectedNC.length, 'item')} could not be checked today (${unexpectedNC.map((x) => x.short).join('; ')}).`);
    else ex.push('Everything looks healthy: no issues found.');
    const all = Object.values(producers).reduce((m, p) => { for (const [k, v] of Object.entries(p.counts)) m[k] = (m[k] || 0) + v; return m; }, {});
    const total = Object.values(all).reduce((a, b) => a + b, 0);
    if (health) ex.push(`The platform's own early-morning self-checks (the database self-check, the data-source check and the robot dashboard test) passed ${all.pass || 0} of ${total} checks; their overall result is "${overall}", and ${stale.size ? `${plural(stale.size, 'of them', 'of them')} did not run on schedule (${[...stale].map((p) => PRODUCER_NAMES[p] || p).join(', ')})` : 'all three ran on schedule'}.`);
    const spotBad = findings.filter((f) => /^(spot\.|lab\.|inventory\.|get_lot|get_labour)/.test(f.check_id) || /disagrees/.test(f.title));
    ex.push(`This report's own spot checks of the data (gateway tools, season heat totals, alert rules, tank counts, lab data) ${spotBad.length ? `found ${plural(spotBad.length, 'discrepancy', 'discrepancies')}` : 'all matched expectations'}.`);
    const expectedNC = notChecked.filter((x) => EXPECTED_UNCHECKABLE.has(x.id));
    if (expectedNC.length) ex.push(`As usual, ${expectedNC.map((x) => x.short).join('; ')} could not be checked.`);
  }
  sections.push({ title: 'EXECUTIVE SUMMARY', paras: [ex.join(' ')] });

  // SUMMARY
  sections.push({ title: 'SUMMARY', items: [
    { text: `Overall status: ${status}${n && status !== 'GREEN' ? ` (${plural(n, 'issue')})` : ''} - ${{ RED: 'something needs attention now (you are emailed)', YELLOW: 'nothing urgent; items worth knowing about', GREEN: 'all clear' }[status]}` },
    { text: `Findings: ${findings.length ? Object.entries(findings.reduce((m, f) => ((m[f.severity] = (m[f.severity] || 0) + 1), m), {})).sort((a, b) => SEV_ORDER[a[0]] - SEV_ORDER[b[0]]).map(([k, c]) => `${c} ${k}`).join(', ') : 'none'}` },
    { text: `Severity levels: CRITICAL or HIGH = broken or at risk now (makes the report RED and sends an email); MEDIUM = look at it soon; LOW = worth knowing, no action needed yet` },
    { text: `Platform's own overall verdict: ${overall ?? 'unknown'} (pass, warn or fail across its self-checks)${overall === 'warn' && obs.p3_backup?.length && Object.values(producers).every((p) => p.status === 'pass') ? '; the "warn" is only the routine note that the dashboard test was started by its backup trigger' : ''}` },
    { text: `Could not be checked: ${notChecked.length ? notChecked.length : 'none'}` },
    { text: `Report run: ${et(now.toISOString())}` },
  ] });

  // LAYER STATUS
  const layerInfo = {
    sources: ['p2_probes'], ingestion: ['p1_database'], database: ['p1_database'], security: ['p1_database'], dashboard: ['p3_frontend'],
  };
  const layerItems = LAYERS.map((l) => {
    const lf = findings.filter((f) => f.layer === l);
    const ncl = notChecked.find((x) => x.id === `layer.${l}`);
    const st = ncl ? 'NOT CHECKED' : lf.length ? lf[0].severity : 'OK';
    let detail;
    if (l === 'gateway') detail = health ? `Checked by the gateway's own self-check (P4) and this report's spot checks, ${et(health.generated_at)}` : 'gateway unavailable';
    else {
      const p = producers[layerInfo[l][0]];
      detail = p ? `Checked by the ${PRODUCER_NAMES[layerInfo[l][0]].replace(/^D/, 'd')}, last run ${et(p.finished_at || p.started_at)}: ${countsText(p.counts)}${l !== 'sources' && l !== 'dashboard' ? ' (one run covers ingestion, database and security)' : ''}` : 'no run reported';
    }
    const sub = [`Covers: ${LAYER_WHAT[l]}`, detail + (lf.length ? `; ${plural(lf.length, 'finding')} below` : '')];
    if (l === 'dashboard' && obs.p3_backup?.length && !lf.some((f) => f.check_id === 'p3_backup.dispatch'))
      sub.push(`The dashboard test was started by its backup trigger because GitHub ran its own schedule late, which is normal; not a problem`);
    return { text: `${LAYER_NAMES[l]}: ${st}`, sub };
  });
  sections.push({ title: 'LAYER STATUS', items: layerItems });

  // FINDINGS
  sections.push({ title: 'FINDINGS', items: findings.length ? findings.map((f) => ({
    text: `[${f.severity}] ${LAYER_NAMES[f.layer] || f.layer} - ${f.title}`,
    sub: [`What was found: ${f.observed}`, `What was expected: ${f.expected}`, whyPlain(f.check_id) && `Why it matters: ${whyPlain(f.check_id)}`,
      `What to do: ${TODO_PLAIN[f.severity]}`, `Technical next step: ${plainify(f.next)}`, `Technical ID: ${f.check_id}`].filter(Boolean),
  })) : [{ text: 'None.' }] });

  // INDEPENDENT CHECKS
  const s = obs.spot, ic = [];
  if (obs.tools) ic.push({ text: `Gateway tools (what Claude can look up): ${obs.tools.length} offered; ${obs.missing.length ? `missing ${obs.missing.join(', ')}` : 'all 12 expected read-only tools present'}${obs.unexpected.length ? `; unexpected ${obs.unexpected.join(', ')}` : ', and none that could change data'}` });
  if (s.soil_b2) ic.push({ text: s.soil_b2.non_null ? `Soil moisture, Block 2, 1-8 Jul 2024: ${s.soil_b2.min}-${s.soil_b2.max}% (expected 0-100%)`
    : `Soil moisture, 1-8 Jul 2024: no Block 2 values (soil is recorded for the whole estate)${s.soil_estate ? `; estate-wide ${s.soil_estate.min}-${s.soil_estate.max}% across ${s.soil_estate.non_null} days, within the possible 0-100%` : ''}` });
  if (s.gdd_2024) ic.push({ text: `2024 growing degree days (the season's total heat, calibrated, final): ${s.gdd_2024.value.toLocaleString('en-US')} on ${s.gdd_2024.day} (expected 3,000-4,400, about 4,058)` });
  for (const k of Object.keys(s).filter((k) => k.startsWith('anomalies_'))) ic.push({ text: `Vineyard alerts on a known test day (${k.slice(10)}): ${s[k].total} (expected ${s[k].want}) - ${s[k].rules.map((r) => r.replace(/_/g, ' ')).join(', ')}` });
  if (s.vessels) ic.push({ text: `Tanks and vessels (from InnoVint): ${s.vessels.total} total${s.vessels.base_total != null && s.vessels.base_total !== s.vessels.total ? ` (${s.vessels.base_total} when the baseline was set; new tanks are normal)` : ''}, ${s.vessels.active} in use${s.vessels.base_active != null ? ` (baseline ${s.vessels.base_active}; a move of more than 25% is flagged)` : ''}, ${s.vessels.capacity_suspect} still showing the 500,000-gallon placeholder capacity (baseline ${s.vessels.base_suspect})` });
  const labNames = { get_berry_maturity: 'berry maturity', get_smoke_markers: 'smoke marker', get_wine_lab_results: 'wine lab result' };
  if (Object.keys(obs.lab).length) {
    ic.push({ text: `ETS Labs data: ${Object.entries(labNames).filter(([k]) => obs.lab[k]).map(([k, v]) => `${obs.lab[k].rows} ${v} samples`).join(', ')}`, sub: [
      Object.values(obs.lab).some((x) => x.issues) ? 'Some problems found (see Findings)' : 'No out-of-range values, future dates, duplicates, empty fields or changed data fields',
      obs.lab.smoke_current != null ? (obs.lab.smoke_current ? `${obs.lab.smoke_current} smoke-marker value(s) above zero in the ${currentVintage} vintage` : `No smoke markers detected in the ${currentVintage} vintage`) : null,
    ].filter(Boolean) });
  }
  if (Object.keys(obs.ops).length) ic.push({ text: `InnoVint lot analyses and labour summary: ${Object.entries(obs.ops).map(([k, ok]) => `${k.replace('get_', '').replace('_', ' ')} ${ok ? 'returned data' : 'FAILED'}`).join('; ')}` });
  if (obs.key) ic.push({ text: `Gateway access key ${obs.key.prefix}: valid until ${String(obs.key.expires_at).slice(0, 10)} (information only)` });
  sections.push({ title: 'INDEPENDENT CHECKS', paras: ['Spot checks this report makes itself through the gateway (the read-only connection Claude uses), as a second opinion alongside the platform\'s own self-checks.'], items: ic.length ? ic : [{ text: 'None could run.' }] });

  // NOT CHECKED
  sections.push({ title: 'NOT CHECKED', items: notChecked.length ? notChecked.map((x) => ({ text: `${x.short}${EXPECTED_UNCHECKABLE.has(x.id) ? ' - expected, not a problem' : ''}`, sub: [x.reason] })) : [{ text: 'Nothing.' }] });

  // CHANGES
  sections.push({ title: 'CHANGES SINCE LAST RUN', paras: ["Each of the platform's self-checks compared with its own previous run."], items: changes.length ? changes.map((c) => ({ text: c })) : [{ text: 'No history available to compare.' }] });

  const baselines = {
    v: 2, at: now.toISOString(), status, overall, tools: obs.tools || [],
    producers: Object.fromEntries(Object.entries(producers).map(([k, p]) => [k, { run_id: p.run_id, finished_at: p.finished_at, status: p.status, stale: p.stale }])),
    spot: s, lab_fields: Object.fromEntries(Object.entries(obs.lab).map(([k, x]) => [k, x.fields])),
    not_checked: notChecked.map((x) => x.id), finding_ids: [...new Set(findings.map((f) => `${f.severity}:${f.check_id}`))],
  };
  return { subject, status, sections, baselinesLine: 'BASELINES-JSON: ' + JSON.stringify(baselines) };
}

function renderText({ subject, sections, baselinesLine }) {
  const L = [subject, ''];
  for (const sec of sections) {
    L.push(sec.title);
    for (const p of sec.paras || []) L.push(p);
    for (const it of sec.items || []) {
      L.push(`• ${it.text}`);
      for (const sub of it.sub || []) L.push(`    – ${sub}`);
    }
    L.push('');
  }
  L.push('TECHNICAL DATA (used to compare future runs; safe to ignore)');
  L.push(baselinesLine);
  return L.join('\n');
}

function renderHtml({ subject, status, sections, baselinesLine }) {
  const e = (t) => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const colour = { RED: '#b42318', YELLOW: '#b54708', GREEN: '#067647' }[status];
  const h = [`<div style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5;color:#1f2328;max-width:760px">`,
    `<h2 style="margin:0 0 12px;font-size:18px;color:${colour}">${e(subject)}</h2>`];
  for (const sec of sections) {
    h.push(`<h3 style="margin:18px 0 6px;font-size:13px;letter-spacing:.04em;color:#57606a">${e(sec.title)}</h3>`);
    for (const p of sec.paras || []) h.push(`<p style="margin:0 0 8px">${e(p)}</p>`);
    if (sec.items?.length) {
      h.push('<ul style="margin:0 0 8px;padding-left:20px">');
      for (const it of sec.items) {
        h.push(`<li style="margin:2px 0">${e(it.text)}`);
        if (it.sub?.length) h.push(`<ul style="padding-left:18px;color:#57606a">${it.sub.map((x) => `<li>${e(x)}</li>`).join('')}</ul>`);
        h.push('</li>');
      }
      h.push('</ul>');
    }
  }
  h.push(`<p style="margin-top:20px;font-size:11px;color:#8c959f">Technical data (used to compare future runs; safe to ignore)</p>`);
  h.push(`<p style="margin-top:4px;font-family:Menlo,Consolas,monospace;font-size:10px;color:#8c959f;word-break:break-all">${e(baselinesLine)}</p></div>`);
  return h.join('\n');
}

try { await main(); } catch (e) {
  add('HIGH', 'gateway', 'check.script', 'The check script hit an unexpected error', clip(String(e?.message || e), 200), 'a complete run', 'Re-run; if it repeats, the response format may have changed.');
}
const report = build();
if (args['subject-out']) writeFileSync(args['subject-out'], report.subject + '\n');
if (args['html-out']) writeFileSync(args['html-out'], renderHtml(report));
process.stdout.write(renderText(report) + '\n');
