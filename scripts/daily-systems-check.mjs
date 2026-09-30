#!/usr/bin/env node
// Mars Telemetry daily systems check. Self-contained: Node >= 22.21, no npm packages.
// Usage: node mars-check.mjs [--prev FILE] [--subject-out FILE] [--html-out FILE]
//   --prev         file holding the previous report email body (or just its BASELINES-JSON line)
//   --subject-out  where to write the email subject (without any [TEST] prefix)
//   --html-out     where to write the report wrapped as HTML <pre> for the mail client
// stdout: the plain-text report followed by the BASELINES-JSON line, nothing else.
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
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
const LAYERS = ['sources', 'ingestion', 'database', 'gateway', 'dashboard', 'security'];
const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const KNOWN_ISSUES = { 'source.anthropic.model': 'known: Anthropic key pending replacement' };

// ---------- args ----------
const args = {};
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a.startsWith('--')) args[a.slice(2)] = process.argv[i + 1]?.startsWith('--') ? true : process.argv[++i];
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = new Date();
const findings = [];
const notChecked = []; // {id, reason}
const obs = {}; // observed values for the baselines line
const add = (severity, layer, check_id, title, observed, expected, next) =>
  findings.push({ severity, layer, check_id, title, observed, expected, next });
const nc = (id, reason) => notChecked.push({ id, reason });
const fmt = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
const clip = (s, n = 400) => (s.length > n ? s.slice(0, n) + '...' : s);

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

// One JSON-RPC request with the retry rules. Returns {ok, result, error, failure}
async function rpc(method, params, { first = false } = {}) {
  const body = { jsonrpc: '2.0', id: rpcId++, method, ...(params ? { params } : {}) };
  let retried = false;
  let throttles = 0;
  for (;;) {
    let r;
    const t0 = Date.now();
    try { r = await post(body); } catch (e) {
      if (process.env.MARS_DEBUG) console.error(`${method} ${params?.name || ''} error ${e.kind} ${Date.now() - t0}ms`);
      if (first && e.kind === 'network') return { ok: false, failure: `network error (${e.code}) before reaching the gateway` };
      if (!retried) { retried = true; await sleep(30_000); continue; }
      return { ok: false, failure: e.kind === 'timeout' ? 'TIMEOUT (60 s, retried once)' : `TIMEOUT (network error ${e.code}, retried once)` };
    }
    if (process.env.MARS_DEBUG) console.error(`${method} ${params?.name || ''} HTTP ${r.status} ${Date.now() - t0}ms`);
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

// tools/call -> {ok, data, text, failure}. data = structuredContent, else leading JSON of the text.
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
  return { ok: true, data, text };
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

// ---------- previous baselines ----------
let prev = null;
let prevNote = null;
if (args.prev && existsSync(args.prev)) {
  const raw = readFileSync(args.prev, 'utf8');
  const m = raw.match(/BASELINES-JSON:\s*(.*)/);
  if (m) {
    const unesc = m[1].replace(/<[^>]*>.*$/s, '').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').trim();
    try { prev = jsonPrefix(unesc); } catch { prev = null; }
  }
  if (!prev) prevNote = 'Previous report found but it has no parseable BASELINES-JSON line; treated as first run, baselines recorded.';
}

// ---------- next steps (from docs/SECURITY.md "Every check_id") ----------
function nextStep(id) {
  const rules = [
    [/^ingestion\.climate\.last_run$/, 'Read the newest ingestion_runs row for climate (status, http_status, error) and the ingest-climate-2026 Edge Function logs; re-run the ingest once fixed.'],
    [/^ingestion\.innovint\.last_run$/, 'Read the newest ingestion_runs row for InnoVint and the ingest-innovint logs; check INNOVINT_TOKEN and source.innovint.api.'],
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
    [/^security\.no_embedded_keys$/, 'Remove the key from the named object and rotate that key immediately.'],
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
    [/^gateway\.p4\.key_expiry$/, 'Issue a replacement svc-nightly-checks key, then delete and re-add the environment credential, then revoke the old key.'],
    [/^gateway\.p4\.write_capable_tools$/, "Remove the tool from the key's allowed_tools now (agent-keys.mjs set-tools)."],
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
const producerTimes = {};
let overall = null, currentVintage = null, health = null;
const stale = new Set();

async function main() {
  // 1. initialize (first call: auth failures stop the run)
  const init = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'mars-daily-check', version: '1.0' } }, { first: true });
  if (!init.ok) {
    if (authFailure || /network error/.test(init.failure)) {
      add('CRITICAL', 'gateway', 'gateway.auth', 'Gateway auth failed: credential missing, key revoked/expired, or service account disabled',
        authFailure ? `HTTP ${authFailure} on MCP initialize` : `${init.failure} (a proxy 403 means the domain/credential is not set up for this environment)`,
        'HTTP 200 on initialize', 'Check the key in User Management (revoked/expired?) and the service account; if rotated, delete and re-add the environment credential.');
      for (const l of LAYERS) nc(`layer.${l}`, 'gateway auth failed on the first call');
      return;
    }
    add('HIGH', 'gateway', 'gateway.initialize', 'MCP initialize failed', init.failure, 'HTTP 200 with a result', 'Check the mcp Edge Function logs.');
    for (const l of LAYERS) nc(`layer.${l}`, 'MCP initialize failed');
    return;
  }
  await rpc('notifications/initialized'); // notification; response ignored

  // 2. tool inventory
  const tl = await rpc('tools/list');
  if (!tl.ok) {
    add('HIGH', 'gateway', 'gateway.tools_list', 'tools/list failed', tl.failure, '12 tools', 'Check the mcp Edge Function logs.');
    nc('inventory', 'tools/list failed');
    return;
  }
  const tools = tl.result?.tools || [];
  const names = tools.map((t) => t.name).sort();
  obs.tools = names;
  for (const t of EXPECTED_TOOLS) if (!names.includes(t))
    add('HIGH', 'gateway', 'inventory.missing', `Tool missing from tools/list: ${t}`, `${names.length} tools listed`, 'all 12 expected tools',
      "Add the tool back to the key's allowed_tools (scripts/agent-keys.mjs set-tools).");
  for (const t of tools) if (!EXPECTED_TOOLS.includes(t.name)) {
    const a = t.annotations || {};
    const writes = !/^get_/.test(t.name) || a.readOnlyHint === false || a.destructiveHint === true;
    add(writes ? 'CRITICAL' : 'MEDIUM', 'gateway', 'inventory.unexpected', `Unexpected tool in tools/list: ${t.name}${writes ? ' (write-capable)' : ''}`,
      `tool "${t.name}" exposed to svc-nightly-checks`, 'exactly the 12 read-only tools',
      writes ? "Remove it from the key's allowed_tools immediately and check the catalogue (mcp_tool_catalogue)." : 'Confirm it is intended; otherwise remove it from allowed_tools.');
  }
  allowedToCall = new Set(names.filter((n) => EXPECTED_TOOLS.includes(n))); // never call anything unexpected

  // 3. system health
  const sh = await tool('get_system_health');
  if (!sh.ok) {
    add('HIGH', 'gateway', 'get_system_health', 'get_system_health failed', sh.failure, 'a health summary', 'Check the mcp Edge Function logs.');
    for (const l of ['sources', 'ingestion', 'database', 'dashboard', 'security']) nc(`layer.${l}`, 'get_system_health unavailable');
  } else {
    health = sh.data;
    overall = health.overall;
    currentVintage = health.current_vintage ?? null;
    obs.overall = overall;
    for (const p of health.producers || []) {
      producerTimes[p.producer] = { run_id: p.run_id, started_at: p.started_at, finished_at: p.finished_at, status: p.status, stale: !!p.stale };
      if (p.stale) {
        stale.add(p.producer);
        add('HIGH', (PRODUCER_LAYERS[p.producer] || ['database'])[0], `stale.${p.producer}`, `Producer ${p.producer} is stale`,
          `latest run ${p.run_id} started ${p.started_at}`, `a run after the ${p.schedule_utc} UTC slot (+30 min grace), under 26 h old`,
          { p1_database: 'Check pg_cron job health-p1-database (cron.job_run_details).', p2_probes: 'Check pg_cron job health-p2-probes and the health-probe Edge Function logs.', p3_frontend: 'Check the nightly-health-p3.yml GitHub Actions runs and the P3 backup dispatch.' }[p.producer] || 'Check the producer schedule.');
        for (const l of PRODUCER_LAYERS[p.producer] || []) nc(`layer.${l}`, `${p.producer} is stale, so its results are not current`);
        continue;
      }
      for (const pr of p.summary?.problems || []) healthProblem(pr, p.producer);
    }
    // P3 backup dispatches count toward overall
    for (const d of health.p3_backup_dispatches || []) {
      const st = d.status || 'warn';
      if (st !== 'pass') healthProblem({ ...d, check_id: d.check_id || 'p3_backup.dispatch', layer: 'dashboard', status: st }, 'p3_backup');
    }
    // P4 self-check
    for (const c of health.p4_gateway_self_check || []) p4(c);
  }

  // 4. history
  const hh = await tool('get_health_history', { days: 7 });
  if (!hh.ok) nc('health_history', `get_health_history failed: ${hh.failure}`);
  else {
    const fails = {};
    for (const r of hh.data?.runs || []) for (const pr of r.summary?.problems || [])
      if (pr.status === 'fail') (fails[pr.check_id] ||= { n: 0, layer: pr.layer, producer: r.producer, last: r.started_at }).n++;
    const currentProblems = new Set(findings.map((f) => f.check_id));
    for (const [id, f] of Object.entries(fails)) {
      if (f.n < 2 || currentProblems.has(id) || stale.has(f.producer) || !producerTimes[f.producer]) continue;
      if (KNOWN_ISSUES[id]) continue; // known issue now passing: stop mentioning it
      add('LOW', layerOf(f.layer, id), id, 'Failed repeatedly in the last 7 days, passes today',
        `${f.n} failed runs in 7 days (latest failure ${f.last}); passing in run ${producerTimes[f.producer].run_id}`, 'no failures', nextStep(id) + ' Watch for recurrence.');
    }
  }

  // 5. baselines
  const hb = await tool('get_health_baselines');
  const baselines = {};
  if (!hb.ok) nc('health_baselines', `get_health_baselines failed: ${hb.failure}`);
  else for (const b of hb.data?.baselines || []) baselines[b.check_id] = b.value;
  const p1ok = producerTimes.p1_database && !stale.has('p1_database');
  const p3ok = producerTimes.p3_frontend && !stale.has('p3_frontend');
  const passes = (id, prod) => (prod === 'p1' ? p1ok : p3ok) && !findings.some((f) => f.check_id === id && f.severity !== 'LOW');
  const disagree = (id, prod, observed, expected) => {
    if (passes(id, prod)) add('HIGH', 'gateway', id, `health check ${id} disagrees with direct observation`, observed, expected,
      `${nextStep(id)} Also check whether the health check itself is still testing what it should.`);
  };

  // 6. spot-checks
  obs.spot = {};
  // 6a. soil moisture B2
  const soilArgs = { metric: 'soil_moisture', block: 'B2', vintage: 2024, start: '2024-07-01T00:00:00Z', end: '2024-07-08T00:00:00Z', bucket_hours: 24 };
  const s1 = await tool('get_series', soilArgs);
  if (!s1.ok) { nc('spot.soil_b2', `get_series failed: ${s1.failure}`); add('HIGH', 'gateway', 'spot.soil_moisture', 'get_series spot-check failed', s1.failure, 'data', 'Check the mcp Edge Function logs.'); }
  else {
    const vals = (rowsOf(s1.data) || []).map((r) => r.v).filter((v) => v != null);
    obs.spot.soil_b2 = { total: s1.data?.total_count ?? null, non_null: vals.length, min: vals.length ? Math.min(...vals) : null, max: vals.length ? Math.max(...vals) : null };
    let checkVals = vals, where = 'B2';
    if (!vals.length) {
      nc('spot.soil_b2', `get_series soil_moisture B2 2024-07-01..08 returned ${s1.data?.total_count ?? 0} buckets, all null (real ERA5-Land soil is estate-level, not per block)`);
      const s2 = await tool('get_series', { ...soilArgs, block: undefined });
      if (s2.ok) {
        checkVals = (rowsOf(s2.data) || []).map((r) => r.v).filter((v) => v != null);
        where = 'estate-wide';
        obs.spot.soil_estate = { total: s2.data?.total_count ?? null, non_null: checkVals.length, min: checkVals.length ? Math.min(...checkVals) : null, max: checkVals.length ? Math.max(...checkVals) : null };
      }
    }
    const bad = checkVals.filter((v) => v < 0 || v > 100);
    if (bad.length) {
      add('CRITICAL', 'database', 'spot.soil_moisture', `Soil moisture out of 0-100 (${where}, 2024-07-01..08)`, `${bad.length} bucket(s) out of range: ${bad.slice(0, 5).join(', ')}`, 'every value 0-100', nextStep('database.integrity.soil_moisture_range'));
      disagree('database.integrity.soil_moisture_range', 'p1', `get_series shows ${bad.length} out-of-range bucket(s)`, 'no out-of-range soil readings');
    }
  }
  // 6b. derived GDD
  const d = await tool('get_derived_series', { vintage: 2024 });
  if (!d.ok) { nc('spot.gdd_2024', `get_derived_series failed: ${d.failure}`); add('HIGH', 'gateway', 'spot.gdd', 'get_derived_series spot-check failed', d.failure, 'data', 'Check the mcp Edge Function logs.'); }
  else {
    const rows = (rowsOf(d.data) || []).filter((r) => r.gdd_cumulative_calibrated != null).sort((a, b) => String(a.day).localeCompare(String(b.day)));
    const last = rows.at(-1);
    obs.spot.gdd_2024 = last ? { value: last.gdd_cumulative_calibrated, day: String(last.day).slice(0, 10) } : null;
    if (!last) nc('spot.gdd_2024', 'get_derived_series 2024 returned no gdd_cumulative_calibrated values');
    else if (!(last.gdd_cumulative_calibrated >= 3000 && last.gdd_cumulative_calibrated <= 4400)) {
      add('CRITICAL', 'database', 'spot.gdd', 'Final 2024 calibrated GDD out of range', `${last.gdd_cumulative_calibrated} on ${String(last.day).slice(0, 10)}`, '3,000-4,400 (about 4,058)', nextStep('database.integrity.gdd_calibrated_2022_2025'));
      disagree('database.integrity.gdd_calibrated_2022_2025', 'p1', `2024 final = ${last.gdd_cumulative_calibrated}`, '3,000-4,400');
    }
  }
  // 6c. anomaly anchors
  for (const [asOf, want, id] of [['2024-07-06T02:00:00Z', 3, 'database.anomalies.anchor_2024_07_06'], ['2024-04-06T14:00:00Z', 2, 'database.anomalies.anchor_2024_04_06']]) {
    const key = `anomalies_${asOf.slice(0, 10)}`;
    const a = await tool('get_anomalies', { vintage: 2024, as_of: asOf });
    if (!a.ok) { nc(`spot.${key}`, `get_anomalies failed: ${a.failure}`); add('HIGH', 'gateway', `spot.${key}`, 'get_anomalies spot-check failed', a.failure, `${want} hits`, 'Check the mcp Edge Function logs.'); continue; }
    const n = a.data?.total_count ?? rowsOf(a.data)?.length ?? null;
    obs.spot[key] = { total: n, rules: (rowsOf(a.data) || []).map((r) => r.rule_key).sort() };
    if (n !== want) {
      add('HIGH', 'database', `spot.${key}`, `Anomaly anchor ${asOf} returned ${n} hit(s)`, `total_count ${n} (${obs.spot[key].rules.join(', ')})`, `${want} hits`, nextStep(id));
      disagree(id, 'p1', `get_anomalies total_count ${n}`, `${want} hits`);
    }
  }
  // 6d. vessels
  const v = await tool('get_vessels', { include_archived: true });
  if (!v.ok) { nc('spot.vessels', `get_vessels failed: ${v.failure}`); add('HIGH', 'gateway', 'spot.vessels', 'get_vessels spot-check failed', v.failure, 'data', 'Check the mcp Edge Function logs.'); }
  else {
    const total = v.data?.total_count ?? null;
    const rows = rowsOf(v.data) || [];
    const truncated = v.data?.truncated === true || (total != null && rows.length < total);
    const suspect = truncated ? null : rows.filter((r) => Number(r.capacity_gal) >= 500000).length;
    const active = rows.filter((r) => r.archived === false).length;
    const baseSuspect = baselines['database.vessels.counts']?.capacity_suspect ?? null;
    obs.spot.vessels = { total, capacity_suspect: suspect, active: truncated ? null : active };
    if (total !== 241) {
      add('MEDIUM', 'database', 'spot.vessels_total', 'Vessel total_count changed', `total_count ${total}`, '241', nextStep('database.vessels.counts'));
      disagree('database.vessels.counts', 'p1', `get_vessels total_count ${total}`, '241');
      disagree('gateway.tools.vessels_vs_rest', 'p3', `get_vessels total_count ${total}`, '241');
    }
    if (suspect == null) nc('spot.vessels_capacity_suspect', 'get_vessels rows were capped, so the placeholder-capacity count is unreliable');
    else if (baseSuspect == null) nc('spot.vessels_capacity_suspect', 'no database.vessels.counts baseline available');
    else if (suspect !== baseSuspect) {
      add('MEDIUM', 'database', 'spot.vessels_capacity_suspect', 'Placeholder-capacity vessel count changed', `${suspect} vessels at the 500000 gal placeholder`, `${baseSuspect} (baseline)`, nextStep('database.vessels.counts'));
      if (suspect > baseSuspect) disagree('database.vessels.counts', 'p1', `${suspect} placeholder-capacity vessels`, `<= ${baseSuspect}`);
    }
  }

  // 7. lab sanity
  obs.lab_fields = {};
  const BOUNDS = {
    brix: [0, 35, 'Brix'], ph: [2.8, 4.2, 'pH'], titratable_acidity: [2, 15, 'TA g/L'], yeast_assimilable_nitrogen: [0, 600, 'YAN mg/L'],
    volatile_acidity_acetic_acid: [0, 2, 'VA g/L'], ethanol_at_20c: [0, 17, 'alcohol %'], ethanol_at_60f: [0, 17, 'alcohol %'], free_sulfur_dioxide: [0, 100, 'free SO2 mg/L'],
  };
  const tomorrow = new Date(now.getTime() + 86400_000).toISOString().slice(0, 10);
  for (const [name, a] of [['get_berry_maturity', {}], ['get_smoke_markers', {}], ['get_wine_lab_results', { limit: 300 }]]) {
    const r = await tool(name, a);
    const rows = r.ok ? rowsOf(r.data) : null;
    if (!r.ok || !rows) {
      nc(`lab.${name}`, r.ok ? 'response was not a row list' : `${name} failed: ${r.failure}`);
      add('MEDIUM', 'gateway', `lab.${name}`, `${name} did not return usable rows`, r.ok ? 'unparseable response' : r.failure, 'a JSON row list', 'Check the mcp Edge Function logs.');
      continue;
    }
    const fields = [...new Set(rows.flatMap((x) => Object.keys(x)))].sort();
    obs.lab_fields[name] = fields;
    const issues = [];
    const oob = [];
    const check = (label, val, lo, hi, ref) => { if (typeof val === 'number' && (val < lo || val > hi)) oob.push(`${ref}: ${label}=${val} (allowed ${lo}-${hi})`); };
    for (const x of rows) {
      const ref = [x.lab_sample_no, x.sample_description, x.block_id, x.collected_on].filter(Boolean).join(' ');
      if (name === 'get_berry_maturity') for (const k of ['brix', 'ph', 'titratable_acidity']) check(BOUNDS[k][2], x[k], BOUNDS[k][0], BOUNDS[k][1], ref);
      if (name === 'get_wine_lab_results' && BOUNDS[x.analysis_code]) { const b = BOUNDS[x.analysis_code]; check(b[2], x.result_numeric, b[0], b[1], ref); }
      if (name === 'get_smoke_markers' && typeof x.result_numeric === 'number' && x.result_numeric < 0) oob.push(`${ref}: ${x.analysis_code}=${x.result_numeric} (negative)`);
    }
    if (oob.length) issues.push(['Out-of-bounds lab values', `${oob.length}: ${oob.slice(0, 5).join('; ')}`, 'values inside the sanity bounds']);
    const fut = rows.filter((x) => (x.collected_on && String(x.collected_on).slice(0, 10) > tomorrow) || (x.analyzed_at && new Date(x.analyzed_at) > new Date(now.getTime() + 86400_000)));
    if (fut.length) issues.push(['Future-dated lab rows', `${fut.length} row(s), e.g. ${fut.slice(0, 3).map((x) => x.collected_on || x.analyzed_at).join(', ')}`, 'no dates after today']);
    const seen = new Set(); let dups = 0;
    for (const x of rows) { const k = JSON.stringify(Object.keys(x).sort().map((f) => [f, x[f]])); if (seen.has(k)) dups++; seen.add(k); }
    if (dups) issues.push(['Duplicate lab rows', `${dups} exact duplicate row(s)`, 'no exact duplicates']);
    const allNull = rows.length ? fields.filter((f) => rows.every((x) => x[f] == null)) : [];
    if (allNull.length) issues.push(['Field null on every row', allNull.join(', '), 'each field populated on at least one row']);
    const pf = prev?.lab_fields?.[name];
    if (pf) {
      const added = fields.filter((f) => !pf.includes(f)), removed = pf.filter((f) => !fields.includes(f));
      if (added.length || removed.length) issues.push(['Schema drift vs last run', `${added.length ? 'added ' + added.join(', ') : ''}${added.length && removed.length ? '; ' : ''}${removed.length ? 'removed ' + removed.join(', ') : ''}`, `fields as last run (${pf.length})`]);
    }
    for (const [t, o, e] of issues) add('MEDIUM', 'database', `lab.${name}`, `${name}: ${t}`, o, e, 'Compare with the ETS Labs source CSV / InnoVint record and correct the ingest if wrong.');
    if (name === 'get_wine_lab_results' && rows.length >= 300) nc('lab.get_wine_lab_results.complete', 'returned the 300-row maximum, so later rows were not checked');
    if (name === 'get_smoke_markers' && currentVintage != null) {
      const hits = rows.filter((x) => x.vintage === currentVintage && typeof x.result_numeric === 'number' && x.result_numeric > 0 && x.result_operator !== '<');
      if (hits.length) add('LOW', 'database', 'lab.smoke_current_vintage', `Smoke markers detected in the ${currentVintage} vintage`,
        `${hits.length} value(s) above zero, e.g. ${hits.slice(0, 3).map((x) => `${x.analysis_code}=${x.result_numeric} ${x.units || ''}`.trim()).join('; ')}`, 'none detected', 'Review with the winemaker; compare against smoke-taint thresholds for the sample basis.');
    }
  }

  // 8. lot analyses + labour
  for (const [name, a] of [['get_lot_analyses', {}], ['get_labour_summary', {}]]) {
    const r = await tool(name, a);
    const rows = r.ok ? rowsOf(r.data) : null;
    const hasData = r.ok && (rows ? rows.length > 0 : r.data && (r.data.record_status === 'records_present' || (r.data.categories || []).length > 0));
    obs[name] = hasData ? 'ok' : 'fail';
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
  const known = KNOWN_ISSUES[id];
  add(sev, layer, id, `${known ? `[${known}] ` : ''}${producer}: ${st}${pr.detail ? ' - ' + clip(String(pr.detail), 200) : ''}`,
    clip(fmt(pr.observed ?? '(none recorded)'), 600), clip(fmt(pr.expected ?? '(none recorded)'), 600), nextStep(id));
}

function p4(c) {
  const id = c.check_id;
  if (id === 'gateway.p4.key_expiry') {
    const days = c.observed?.days_left;
    obs.key = { prefix: c.observed?.key_prefix ?? null, expires_at: c.observed?.expires_at ?? null, days_left: days ?? null };
    if (typeof days === 'number' && days < 14)
      add(days < 3 ? 'HIGH' : 'MEDIUM', 'gateway', id, `Gateway API key expires in ${days} days`, `key ${c.observed?.key_prefix} expires ${c.observed?.expires_at}`, '14 or more days left', nextStep(id));
    else if (typeof days !== 'number') nc('p4.key_expiry', 'P4 did not report days_left');
    return;
  }
  if (id === 'gateway.p4.write_capable_tools') {
    const w = c.observed?.write_capable_tools || [];
    if (w.length || c.status === 'fail') add('CRITICAL', 'gateway', id, 'Key allows a write-capable tool', w.join(', ') || c.status, 'no write-capable tools', nextStep(id));
    return;
  }
  if (c.status === 'fail') add('HIGH', 'gateway', id, `P4 ${id} failed`, clip(fmt(c.observed ?? c.detail ?? ''), 400), 'pass', nextStep(id));
  else if (c.status === 'warn' || c.status === 'error') add('MEDIUM', 'gateway', id, `P4 ${id}: ${c.status}`, clip(fmt(c.observed ?? c.detail ?? ''), 400), 'pass', nextStep(id));
}

// ---------- report ----------
function et(iso) {
  if (!iso) return 'n/a';
  const dt = new Date(iso);
  const e = new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short' }).format(dt);
  return `${dt.toISOString().slice(0, 16).replace('T', ' ')} UTC (${e})`;
}

function build() {
  findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.layer.localeCompare(b.layer));
  const worst = findings[0]?.severity;
  const prevNC = new Set(prev?.not_checked || []);
  const newlyUncheckable = prev ? notChecked.filter((n) => !prevNC.has(n.id)) : [];
  let status = 'GREEN';
  if (worst === 'CRITICAL' || worst === 'HIGH') status = 'RED';
  else if (findings.length || newlyUncheckable.length) status = 'YELLOW';
  const n = findings.length + (findings.length ? 0 : newlyUncheckable.length);
  const dateET = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/New_York' }).format(now);
  const subject = `Mars Telemetry ${status} - ${dateET}${status === 'GREEN' ? '' : `: ${n} issue(s)`}`;

  const L = [];
  // SUMMARY
  const counts = Object.entries(findings.reduce((m, f) => ((m[f.severity] = (m[f.severity] || 0) + 1), m), {}))
    .sort((a, b) => SEV_ORDER[a[0]] - SEV_ORDER[b[0]]).map(([k, c]) => `${c} ${k}`).join(', ');
  L.push('SUMMARY');
  if (authFailure || findings.some((f) => f.check_id === 'gateway.auth'))
    L.push(`Status ${status}. Gateway auth failed on the first call, so nothing else could be checked. Run at ${et(now.toISOString())}.`);
  else {
    L.push(`Status ${status}. Gateway health overall "${overall ?? 'unknown'}"; this run found ${findings.length ? counts : 'no issues'}${notChecked.length ? ` and ${notChecked.length} item(s) not checkable` : ''}.`
      + ` Producers: ${Object.entries(producerTimes).map(([p, t]) => `${p} run ${t.run_id} ${t.status}${t.stale ? ' STALE' : ''}`).join('; ') || 'none reported'}.`
      + ` Run at ${et(now.toISOString())}.`);
  }
  L.push('');
  // LAYER STATUS
  L.push('LAYER STATUS');
  const layerTime = {
    sources: producerTimes.p2_probes?.finished_at, ingestion: producerTimes.p1_database?.finished_at, database: producerTimes.p1_database?.finished_at,
    security: producerTimes.p1_database?.finished_at, dashboard: producerTimes.p3_frontend?.finished_at, gateway: health?.generated_at || null,
  };
  const layerSrc = { sources: 'P2', ingestion: 'P1', database: 'P1 + spot-checks', security: 'P1', dashboard: 'P3', gateway: 'P4 + this run' };
  for (const l of LAYERS) {
    const lf = findings.filter((f) => f.layer === l);
    const ncl = notChecked.find((x) => x.id === `layer.${l}`);
    const st = ncl ? 'NOT CHECKED' : lf.length ? lf[0].severity : 'OK';
    L.push(`- ${l.padEnd(10)} ${st.padEnd(11)} last check ${et(layerTime[l])} [${layerSrc[l]}]`);
  }
  L.push('');
  // OBSERVED
  if (obs.spot) {
    const s = obs.spot;
    L.push('SPOT-CHECK VALUES (this run)');
    if (s.soil_b2) L.push(`- soil_moisture B2 2024-07-01..08: ${s.soil_b2.non_null}/${s.soil_b2.total} non-null buckets${s.soil_estate ? `; estate-wide ${s.soil_estate.non_null}/${s.soil_estate.total}, ${s.soil_estate.min}-${s.soil_estate.max}%` : ` ${s.soil_b2.min}-${s.soil_b2.max}%`}`);
    if (s.gdd_2024) L.push(`- 2024 final calibrated GDD: ${s.gdd_2024.value} (${s.gdd_2024.day})`);
    for (const k of Object.keys(s).filter((k) => k.startsWith('anomalies_'))) L.push(`- ${k}: ${s[k].total} hits (${s[k].rules.join(', ')})`);
    if (s.vessels) L.push(`- vessels: total_count ${s.vessels.total}, active ${s.vessels.active}, placeholder capacity ${s.vessels.capacity_suspect}`);
    if (obs.key) L.push(`- gateway key ${obs.key.prefix} expires ${obs.key.expires_at?.slice(0, 10)} (${obs.key.days_left} days)`);
    L.push('');
  }
  // FINDINGS
  L.push('FINDINGS');
  if (!findings.length) L.push('- None.');
  findings.forEach((f, i) => {
    L.push(`${i + 1}. [${f.severity}] [${f.layer}] [${f.check_id}] ${f.title}`);
    L.push(`   Observed: ${f.observed}`);
    L.push(`   Expected: ${f.expected}`);
    L.push(`   Next step: ${f.next}`);
  });
  L.push('');
  // NOT CHECKED
  L.push('NOT CHECKED');
  if (!notChecked.length) L.push('- Nothing.');
  for (const x of notChecked) L.push(`- ${x.id}: ${x.reason}${prev && !prevNC.has(x.id) ? ' (checkable last run)' : ''}`);
  L.push('');
  // CHANGES
  L.push('CHANGES SINCE LAST RUN');
  const cur = baselinesObj(status);
  if (!prev) L.push(`- ${prevNote || 'First run, baselines recorded.'}`);
  else {
    const ch = [];
    if (prev.status && prev.status !== status) ch.push(`status ${prev.status} -> ${status}`);
    const pt = prev.tools || [], ct = cur.tools || [];
    const ta = ct.filter((t) => !pt.includes(t)), tr = pt.filter((t) => !ct.includes(t));
    if (ta.length) ch.push(`tools added: ${ta.join(', ')}`);
    if (tr.length) ch.push(`tools removed: ${tr.join(', ')}`);
    for (const [p, t] of Object.entries(cur.producers || {})) {
      const o = prev.producers?.[p];
      if (!o) ch.push(`${p}: new producer`);
      else if (o.run_id === t.run_id) ch.push(`${p}: no new run since last report (still run ${t.run_id})`);
      else if (o.status !== t.status) ch.push(`${p}: ${o.status} -> ${t.status}`);
    }
    for (const [k, v] of Object.entries(cur.spot || {})) if (prev.spot && JSON.stringify(prev.spot[k]) !== JSON.stringify(v)) ch.push(`spot ${k}: ${JSON.stringify(prev.spot[k] ?? null)} -> ${JSON.stringify(v)}`);
    for (const [k, v] of Object.entries(cur.lab_fields || {})) if (prev.lab_fields?.[k] && JSON.stringify(prev.lab_fields[k]) !== JSON.stringify(v)) ch.push(`lab fields changed: ${k}`);
    const pf = new Set(prev.finding_ids || []), cf = new Set(cur.finding_ids);
    const nf = [...cf].filter((x) => !pf.has(x)), rf = [...pf].filter((x) => !cf.has(x));
    if (nf.length) ch.push(`new findings: ${nf.join(', ')}`);
    if (rf.length) ch.push(`resolved since last run: ${rf.join(', ')}`);
    for (const x of newlyUncheckable) ch.push(`now not checkable: ${x.id}`);
    L.push(...(ch.length ? ch.map((c) => `- ${c}`) : ['- No changes.']));
  }
  L.push('');
  L.push('BASELINES-JSON: ' + JSON.stringify(cur));
  return { subject, text: L.join('\n') };
}

function baselinesObj(status) {
  return {
    v: 1, at: now.toISOString(), status, overall, tools: obs.tools || [],
    producers: producerTimes, spot: obs.spot || {}, lab_fields: obs.lab_fields || {},
    key: obs.key || null, not_checked: notChecked.map((x) => x.id), finding_ids: [...new Set(findings.map((f) => `${f.severity}:${f.check_id}`))],
  };
}

try { await main(); } catch (e) {
  add('HIGH', 'gateway', 'check.script', 'The check script hit an unexpected error', clip(String(e?.message || e), 200), 'a complete run', 'Re-run; if it repeats, the response format may have changed.');
}
const { subject, text } = build();
if (args['subject-out']) writeFileSync(args['subject-out'], subject + '\n');
if (args['html-out']) {
  const esc = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  writeFileSync(args['html-out'], `<pre style="font-family:Menlo,Consolas,monospace;font-size:12px;white-space:pre-wrap">${esc}</pre>`);
}
process.stdout.write(text + '\n');
