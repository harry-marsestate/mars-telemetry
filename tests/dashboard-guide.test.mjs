// The dashboard guide the chat serves (docs/SECURITY.md, "Dashboard guide for
// the chat"): generated from web/index.html, role-gated on the server, and
// worded exactly like the panels' own source labels.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { build, decl, evaluate, render } from '../scripts/build-dashboard-guide.mjs';
import { DASHBOARD_GUIDE as G } from '../supabase/functions/_shared/dashboard-guide.generated.ts';
import { DASHBOARD_RULES, dashboardMap, fillThresholds, findPanel, guideEntry, interpolate, panelsFor, provenance, runGuideTool } from '../supabase/functions/chat/dashboard-guide.ts';
import { contextText, validateContext } from '../supabase/functions/chat/dashboard-context.ts';
import { seriesSourceNote, TOOLS } from '../supabase/functions/chat/tools.ts';

const OPERATOR_ONLY = G.panels.filter((p) => p.minRole === 'operator');
// Titles only operator-only panels have ('Insights and Anomalies' is also the
// all-roles vineyard panel's title, so it says nothing on its own).
const OP_TITLES = OPERATOR_ONLY.map((p) => p.title).filter((t) => !G.panels.some((q) => q.minRole === 'all' && q.title === t));
// Reality as domain_reality() would answer it: climate real 2022-2026, wind/cellar never.
const reality = new Map([
  ['air_temp', new Set([2022, 2023, 2024, 2025, 2026])], ['humidity', new Set([2022, 2023, 2024, 2025, 2026])],
  ['soil_moisture', new Set([2022, 2023, 2024, 2025, 2026])], ['soil_temp', new Set([2022, 2023, 2024, 2025, 2026])],
  ['gdd_cumulative_calibrated', new Set([2022, 2023, 2024, 2025, 2026])], ['et0_in', new Set([2022, 2023, 2024, 2025, 2026])],
  ['wind_speed', new Set()], ['cellar_temp', new Set()], ['solar', new Set()],
]);
const rows = [
  { rule_key: 'wind_high', operator: 'gt', threshold: 22, rule_group: null },
  { rule_key: 'cellar_temp_low', operator: 'lt', threshold: 55, rule_group: 'cellar_temp' },
  { rule_key: 'cellar_temp_high', operator: 'gt', threshold: 58, rule_group: 'cellar_temp', display_label: 'Target {threshold_low}–{threshold_high} °F' },
];

test('the generated guide is up to date with web/index.html', () => {
  const now = readFileSync(new URL('../supabase/functions/_shared/dashboard-guide.generated.ts', import.meta.url), 'utf8');
  assert.equal(render(build(G.currentVintage)), now, 'run: node scripts/build-dashboard-guide.mjs');
});

test('every panel has a guide entry, and every entry a panel', () => {
  const { PANELS, PANEL_GUIDE } = evaluate(G.currentVintage);
  for (const p of PANELS) assert.ok(PANEL_GUIDE[p.id]?.what, `PANEL_GUIDE.${p.id}`);
  for (const id of Object.keys(PANEL_GUIDE)) assert.ok(PANELS.some((p) => p.id === id), `orphan ${id}`);
  for (const id of ['map', 'ov-vineyard', 'anom-v', 'ov-winery', 'anom-w']) assert.ok(G.panels.some((p) => p.id === id), id);
  for (const p of G.panels) {
    assert.ok(p.what.length > 30, p.id);
    assert.ok(p.tool || p.noTool, `${p.id}: a tool or what to say without one`);
  }
});

test("each panel's provenance is the label its subtitle shows, for every vintage, real and not", () => {
  const { PANELS, ctx } = evaluate(G.currentVintage);
  for (const p of PANELS) {
    for (const v of G.vintages) {
      const c = { primary: v, vintages: [v], compare: false, blocks: ['B1', 'B2', 'B3'] };
      for (const [flag, key] of [[true, 'real'], [false, 'notReal']]) {
        ctx.__real = flag;
        const shown = typeof p.sub === 'function' ? p.sub(c) : (p.sub ?? '');
        assert.equal(G.panels.find((x) => x.id === p.id).provenance[v][key], shown, `${p.id} ${v} ${key}`);
      }
    }
  }
});

test('honest provenance: simulated and modelled series say so', () => {
  const at = (id, v = 2026) => provenance(G.panels.find((p) => p.id === id), v, reality);
  assert.match(at('solar'), /^Simulated pyranometer/);
  assert.doesNotMatch(at('solar'), /measured/i);
  assert.match(at('wind'), /^Simulated/);
  assert.match(at('soilmoist'), /ERA5-Land model .* estate-wide, not per block/);
  assert.match(at('et0'), /Hargreaves .* air temperature only \(no wind, humidity or solar input\)/);
  assert.match(at('cellart'), /^Simulated building sensor/);
  assert.match(at('gdd', 2026), /uncalibrated/);
  assert.match(at('gdd', 2024), /calibrated to Napa Valley Grapegrowers/);
  const soil = G.sections.find((s) => s.id === 'soil').note[2026];
  assert.doesNotMatch(soil.real + soil.notReal, /Vineyard sensors/);
  assert.match(G.sections.find((s) => s.id === 'cellar').note[2026].real, /^Simulated building sensors/);
  // Unknown reality never claims "real".
  assert.match(provenance(G.panels.find((p) => p.id === 'soilmoist'), 2026, new Map()), /where real data exists .* otherwise Simulated/);
});

test('the solar question: the guide explains the panel, says it is simulated, and does not send the model elsewhere', () => {
  const solar = findPanel('solar', 'customer');
  const entry = guideEntry(solar, reality, rows);
  assert.match(entry, /Solar insolation \(W\/m²\) and UV index/);
  assert.match(entry, /Simulated: there is no pyranometer or UV sensor/);
  assert.match(entry, /Data tool: none\./);
  assert.match(dashboardMap('customer', reality), /- Solar insolation & UV \[solar, Climate\]: Simulated pyranometer .* · no data tool/);
  assert.match(DASHBOARD_RULES, /Never suggest a panel comes from an outside or unknown source/);
  assert.match(DASHBOARD_RULES, /say it is a different measure and that the link is your inference/);
  // From the before/after batch: the GDD answer computed its gap to the band,
  // and B2's answer offered per-block GDD.
  assert.match(DASHBOARD_RULES, /do not compute the gap or a time to reach it yourself/);
  assert.match(DASHBOARD_RULES, /estate-wide: do not offer or describe per-block versions/);
});

test('thresholds are filled from anomaly_thresholds, the same way the dashboard does', () => {
  // Parity with web/index.html interpolateThreshold() on the same rows.
  const ctx = {}; vm.createContext(ctx);
  vm.runInContext(decl('interpolateThreshold'), ctx);
  const byKey = new Map(rows.map((r) => [r.rule_key, r]));
  for (const r of rows) {
    const web = ctx.interpolateThreshold(r, byKey), ts = interpolate(r, rows);
    for (const f of ['low', 'high', 'display_label']) assert.equal(String(ts[f]), String(web[f]), `${r.rule_key}.${f}`);
  }
  assert.match(fillThresholds(G.panels.find((p) => p.id === 'wind').info, rows), /above about 22 mph/);
  assert.match(fillThresholds(G.panels.find((p) => p.id === 'cellart').info, rows), /55–58°F/);
  assert.match(fillThresholds(G.panels.find((p) => p.id === 'wind').info, []), /\(threshold not available\)/);
  assert.match(G.panels.find((p) => p.id === 'gdd').what, /3550-4050 GDD/, 'HARVEST_BAND from the dashboard constant');
});

test('a customer is never told about an operator-only panel, whatever the client asks', async () => {
  const map = dashboardMap('customer', reality);
  for (const t of OP_TITLES) assert.ok(!map.includes(t), `map names ${t}`);
  for (const p of OPERATOR_ONLY) assert.ok(!map.includes(`[${p.id},`), `map lists ${p.id}`);
  for (const p of OPERATOR_ONLY) {
    assert.equal(findPanel(p.id, 'customer'), null);
    const r = await runGuideTool({ panel_id: p.id }, 'customer', reality, async () => rows);
    assert.match(r.content, /^No panel/, p.id);
    assert.ok(!r.content.includes(p.what));
  }
  const winery = await runGuideTool({ tab: 'winery' }, 'customer', reality, async () => rows);
  for (const p of OPERATOR_ONLY) assert.ok(!winery.content.includes(`[${p.id}]`), `tab listing has ${p.id}`);
  // The same request as an operator gets them.
  assert.match((await runGuideTool({ panel_id: 'irrig' }, 'operator', reality, async () => rows)).content, /Irrigation volume applied/);
  assert.equal(panelsFor('pending').some((p) => p.minRole === 'operator'), false);
});

test('context is validated on the server: allowlists, role, accessible blocks', () => {
  assert.equal(validateContext(null, 'customer', ['B2']), null);
  assert.equal(validateContext({ tab: 'admin' }, 'customer', ['B2']), null);
  const c = validateContext({ tab: 'vineyard', blocks: ['B1', 'B2', 'B9', '<x>'], vintages: [2026, 1999, '2025'], panel: 'irrig', range: '30D', scrollDays: 9999, lastViewed: 'yes', surface: 'evil' }, 'customer', ['B2']);
  assert.deepEqual(c.blocks, ['B2'], 'narrowed to the caller\'s blocks, unknown ids dropped');
  assert.deepEqual(c.vintages, [2026]);
  assert.equal(c.panel, null, 'operator-only panel dropped for a customer');
  assert.equal(c.range, null);
  assert.equal(c.lastViewed, false);
  assert.equal(c.surface, 'tab');
  const text = contextText(c, 'customer', reality, rows);
  for (const t of OP_TITLES) assert.ok(!text.includes(t), `context names ${t}`);
  assert.match(text, /blocks: B2/);
  // A panel on another tab is dropped; a valid one carries its guide entry.
  assert.equal(validateContext({ tab: 'winery', panel: 'solar' }, 'operator', ['B1', 'B2', 'B3']).panel, null);
  const ok = validateContext({ tab: 'vineyard', panel: 'solar', range: '1D', blocks: [], vintages: [2026] }, 'customer', ['B2']);
  assert.match(contextText(ok, 'customer', reality, rows), /They asked about one panel: Solar insolation & UV \(1-day view\)[\s\S]*Simulated: there is no pyranometer/);
  // Failed accessible_blocks(): no block is named rather than trusting the client.
  assert.deepEqual(validateContext({ tab: 'vineyard', blocks: ['B1'] }, 'customer', null).blocks, []);
  // Chat tab: last viewed, said so.
  assert.match(contextText(validateContext({ tab: 'winery', lastViewed: true }, 'operator', ['B1', 'B2', 'B3']), 'operator', reality, rows), /data tab they last viewed was Winery Data, with these filters \(last viewed;/);
});

test('get_series says where its rows come from, in the dashboard\'s words', () => {
  assert.match(seriesSourceNote('wind_speed', [2026], reality, null), /2026: SIMULATED demonstration data, not a measurement \(dashboard label: "Simulated weather-station reading"\)/);
  assert.match(seriesSourceNote('air_temp', [2026], reality, null), /2026: Open-Meteo · ECMWF IFS model/);
  assert.match(seriesSourceNote('soil_moisture', [2026], reality, 'B2'), /estate-wide model output with no per-block values: a block filter returns no real readings, so omit block/);
  assert.match(seriesSourceNote('uv', [2026], new Map(), null), /source not confirmed/);
  assert.match(seriesSourceNote('solar', [2024], reality, null), /Solar panel does NOT plot these rows/);
});

test('shared tool descriptions no longer overclaim', () => {
  const d = (n) => TOOLS.find((t) => t.name === n).description;
  assert.doesNotMatch(d('get_series'), /real IoT sensor/);
  assert.match(d('get_series'), /NOT on-site IoT sensors/);
  assert.match(TOOLS.find((t) => t.name === 'get_series').input_schema.properties.metric.description, /'precipitation'/);
  assert.doesNotMatch(TOOLS.find((t) => t.name === 'get_series').input_schema.properties.metric.description, /'precip'/);
  assert.match(d('get_derived_series'), /\(2022, 2023, 2024, 2025\), uncalibrated for any other vintage/);
  assert.match(d('get_derived_series'), /Hargreaves estimate from air temperature alone/);
  assert.match(d('get_anomalies'), /wind rule runs on simulated wind/);
  assert.equal(TOOLS.some((t) => t.name === 'get_dashboard_guide'), false, 'the guide tool is chat-only, not an MCP tool');
});

test('the answer rules stay in force beside the dashboard rules', () => {
  const src = readFileSync(new URL('../supabase/functions/chat/index.ts', import.meta.url), 'utf8');
  assert.match(src, /\$\{ANSWER_RULES\}/);
  assert.match(src, /\$\{DASHBOARD_RULES\}/);
  assert.match(DASHBOARD_RULES, /The answer-support rules above still apply/);
  assert.match(src, /dashboardMap\(role, domainReality\)/, 'map built from the JWT-derived role');
  assert.match(src, /validateContext\(rawContext, role, accessible\)/);
});

// ── Phase 0 follow-ups (2026-10-12) ──────────────────────────────────────
import { runTool } from '../supabase/functions/chat/tools.ts';
const HTML = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');

test('get_anomalies marks results from simulated data as DEMONSTRATION, and only those', async () => {
  const rows = [{ metric_key: 'wind_speed', title: 'High wind' }, { metric_key: 'humidity', title: 'Humid' }, { metric_key: 'mystery', title: 'X' }];
  const db = { rpc: async () => ({ data: rows, error: null }) };
  const r = await runTool(db, 'get_anomalies', { vintage: 2026 }, 'all', reality);
  const out = JSON.parse(r.content.split('\n\n')[0]);
  assert.equal(out.length, 3, 'no rule removed');
  assert.match(out[0].data, /^DEMONSTRATION: evaluated on simulated data/);
  assert.equal(out[1].data, undefined, 'real humidity left alone');
  assert.equal(out[2].data, undefined, 'unknown domain never marked');
  assert.match(r.content, /1 result is from simulated data and marked DEMONSTRATION/);
  // Unknown reality (domain_reality failed): nothing is marked.
  const r2 = await runTool(db, 'get_anomalies', { vintage: 2026 }, 'all', new Map());
  assert.doesNotMatch(r2.content, /DEMONSTRATION/);
});

test('dashboard: demo-clock times and simulated alerts are labelled; soil help says surface layer; 2026 fruit is real', () => {
  assert.match(HTML, /'Demo clock · '\+NOW\.toLocaleTimeString/);
  assert.doesNotMatch(HTML, /'Live · '\+NOW/);
  assert.match(HTML, /\$\{L\.sim\?' \(demo clock\)':''\}/);
  assert.match(HTML, /h\.demo\?'<span class="anom-demo">Demonstration · simulated data<\/span> · ':''/);
  assert.match(HTML, /hits=\[\.\.\.rpcHits, \.\.\.clientHits\]\.map\(h=>\(\{\.\.\.h, demo:true\}\)\)/, 'every winery hit is simulated');
  assert.match(G.panels.find((p) => p.id === 'soilmoist').info, /0-7 cm surface layer/);
  assert.doesNotMatch(G.panels.find((p) => p.id === 'soilmoist').info, /active root zone/);
  assert.match(provenance(G.panels.find((p) => p.id === 'fruit'), 2026, reality), /^InnoVint grower receipts/);
  assert.match(provenance(G.panels.find((p) => p.id === 'fruit'), 2025, reality), /^Simulated weigh-tag/);
});

test('chat: text from a later model turn is separated from the earlier one', () => {
  const src = readFileSync(new URL('../supabase/functions/chat/index.ts', import.meta.url), 'utf8');
  assert.match(src, /if \(firstOfTurn && i > 0 && lastChar && !\/\\s\/\.test\(lastChar\) && !\/\^\\s\/\.test\(delta\)\) send\(\{ type: "text", text: "\\n\\n" \}\);/);
  assert.match(src, /if \(prev && !\/\\s\$\/\.test\(prev\) && !\/\^\\s\/\.test\(b\.text\)\) events\.push\(\{ type: "text", text: "\\n\\n" \}\);/);
});
