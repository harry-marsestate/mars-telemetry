#!/usr/bin/env node
// Generates supabase/functions/_shared/dashboard-guide.generated.ts from
// web/index.html (docs/SECURITY.md, "Dashboard guide for the chat"):
//
//   node scripts/build-dashboard-guide.mjs          # write the file
//   node scripts/build-dashboard-guide.mjs --check  # exit 1 if it is stale
//
// The dashboard stays the single source of truth. This script evaluates, in
// a sandbox, the declarations the panels are built from -- SECTIONS, PANELS,
// PANEL_GUIDE, DASHBOARD_EXTRAS, DATA_SOURCES, getDataSourceLabel() and the
// vintage sets it reads, HARVEST_BAND -- and records, per panel:
//   - id, tab, section, title, unit, minRole;
//   - the provenance label the panel's subtitle shows for every vintage, both
//     when that vintage's data is real and when it is not (the server picks
//     one with domain_reality(), exactly as the dashboard does);
//   - the panel's info text as a template whose threshold numbers are
//     {{rule_key.field}} tokens, filled server-side from anomaly_thresholds,
//     the table the dashboard reads;
//   - the hand-written `what` text and tool mapping from PANEL_GUIDE.
// Identifiers the declarations only reference inside render code are
// stubbed; nothing renders and nothing touches the network.
import { readFileSync, writeFileSync } from "node:fs";
import vm from "node:vm";

const ROOT = new URL("../", import.meta.url);
const HTML = readFileSync(new URL("web/index.html", ROOT), "utf8");
const OUT = new URL("supabase/functions/_shared/dashboard-guide.generated.ts", ROOT);

// Source of one top-level declaration (`const NAME = ...` or `function
// NAME(`): the shortest run of whole lines from its start that compiles.
// Compiling is the parser; no hand-written bracket or string scanning.
export function decl(name) {
  const re = new RegExp(`^(?:const|let) ${name}\\s*=|^function ${name}\\(`, "m");
  const m = re.exec(HTML);
  if (!m) throw new Error(`declaration not found: ${name}`);
  for (let end = HTML.indexOf("\n", m.index); end !== -1; end = HTML.indexOf("\n", end + 1)) {
    const src = HTML.slice(m.index, end);
    try { new vm.Script(src); return src; } catch { /* not complete yet */ }
  }
  throw new Error(`unterminated declaration: ${name}`);
}

const NAMES = ["FIRST_VINTAGE", "HARVEST_BAND", "REAL_LABOUR_VINTAGES", "labourEmptyReasonFor", "irrigBlkSubtitleFor",
  "IRRIGATION_REAL_VINTAGES", "REAL_FRUIT_VINTAGES", "CALIBRATED_GDD_VINTAGES", "OPEN_METEO_IFS_LABEL", "DATA_SOURCES",
  "getDataSourceLabel", "SECTIONS", "PANELS", "PANEL_GUIDE", "DASHBOARD_EXTRAS"];

export function evaluate(currentVintage) {
  const src = NAMES.map(decl).join("\n") + "\n;globalThis.__out = {FIRST_VINTAGE, HARVEST_BAND, SECTIONS, PANELS, PANEL_GUIDE, DASHBOARD_EXTRAS, getDataSourceLabel};";
  // A callable, indexable stand-in for anything only render code touches.
  const stub = () => new Proxy(function () {}, { get: (t, k) => (k === Symbol.toPrimitive ? () => "" : stub()), apply: () => stub() });
  const ctx = {
    CURRENT: currentVintage, console,
    __real: true,
    isRealClimateVintage: () => ctx.__real,
    // Threshold placeholders: {{rule_key.field}} for the server to fill.
    interpolateThreshold: (row) => row && ({ threshold: `{{${row.rule_key}.threshold}}`, low: `{{${row.rule_key}.low}}`, high: `{{${row.rule_key}.high}}`,
      display_label: `{{${row.rule_key}.display_label}}`, tooltip_phrase: `{{${row.rule_key}.tooltip_phrase}}` }),
  };
  vm.createContext(ctx);
  for (let tries = 0; ; tries++) {
    try { vm.runInContext(src, ctx, { filename: "web/index.html#guide" }); break; }
    catch (e) {
      const m = /^(\w+) is not defined$/.exec(e.message);
      if (!m || tries > 200) throw e;
      ctx[m[1]] = stub();
    }
  }
  return { ...ctx.__out, ctx };
}

const fakeTh = { byKey: { get: (k) => ({ rule_key: k, threshold: `{{${k}.threshold}}` }) } };
const call = (f, arg) => { try { const v = f(arg); return typeof v === "string" ? v : null; } catch { return null; } };

export function build(currentVintage) {
  const { FIRST_VINTAGE, HARVEST_BAND, SECTIONS, PANELS, PANEL_GUIDE, DASHBOARD_EXTRAS, ctx } = evaluate(currentVintage);
  const vintages = Array.from({ length: currentVintage - FIRST_VINTAGE + 1 }, (_, i) => FIRST_VINTAGE + i);
  const both = (fn) => Object.fromEntries(vintages.map((v) => {
    const c = { primary: v, vintages: [v], compare: false, blocks: ["B1", "B2", "B3"] };
    ctx.__real = true; const real = fn(c);
    ctx.__real = false; const notReal = fn(c);
    return [v, { real, notReal }];
  }));
  const sectionOf = (tab, id) => SECTIONS.find((s) => s.tab === tab && s.id === id);
  const sections = SECTIONS.map((s) => ({ tab: s.tab, id: s.id, label: s.label,
    note: both((c) => (typeof s.note === "function" ? call(s.note, c) : s.note) ?? "") }));
  const fill = (t) => t?.replace(/\{\{HARVEST_BAND\}\}/g, `${HARVEST_BAND[0]}-${HARVEST_BAND[1]}`) ?? null;
  const panels = PANELS.map((p) => {
    const g = PANEL_GUIDE[p.id];
    if (!g) throw new Error(`PANEL_GUIDE has no entry for panel '${p.id}'`);
    return {
      id: p.id, tab: p.tab, section: p.sect, sectionLabel: sectionOf(p.tab, p.sect)?.label ?? p.sect,
      minRole: p.minRole, title: p.title, unit: typeof p.unit === "string" ? p.unit : "",
      domain: g.domain ?? null, tool: g.tool ?? null, noTool: g.noTool ?? null, what: fill(g.what),
      info: typeof p.info === "function" ? call(p.info, fakeTh) : (p.info ?? null),
      provenance: both((c) => (typeof p.sub === "function" ? call(p.sub, c) : p.sub) ?? ""),
    };
  });
  for (const id of Object.keys(PANEL_GUIDE)) if (!PANELS.some((p) => p.id === id)) throw new Error(`PANEL_GUIDE entry '${id}' matches no panel`);
  const extras = DASHBOARD_EXTRAS.map((e) => ({
    id: e.id, tab: e.tab, section: e.sect, sectionLabel: "Overview", minRole: e.minRole, title: e.title, unit: e.unit,
    domain: e.domain ?? null, tool: e.tool ?? null, noTool: e.noTool ?? null, what: fill(e.what), info: null,
    provenance: Object.fromEntries(vintages.map((v) => [v, { real: e.provenance, notReal: e.provenance }])),
  }));
  return { firstVintage: FIRST_VINTAGE, currentVintage, vintages, harvestBand: HARVEST_BAND, sections, panels: [...extras, ...panels] };
}

export function render(guide) {
  return `// GENERATED by scripts/build-dashboard-guide.mjs from web/index.html -- do not edit.
// Regenerate after changing PANELS, PANEL_GUIDE, DASHBOARD_EXTRAS, SECTIONS,
// DATA_SOURCES/getDataSourceLabel() or a panel's info text:
//   node scripts/build-dashboard-guide.mjs
// tests/dashboard-guide.test.mjs fails while this file is stale.
export type GuidePanel = {
  id: string; tab: "vineyard" | "winery"; section: string; sectionLabel: string; minRole: "all" | "operator";
  title: string; unit: string; domain: string | null; tool: string | null; noTool: string | null;
  what: string; info: string | null; provenance: Record<string, { real: string; notReal: string }>;
};
export type GuideSection = { tab: string; id: string; label: string; note: Record<string, { real: string; notReal: string }> };
export const DASHBOARD_GUIDE: {
  firstVintage: number; currentVintage: number; vintages: number[]; harvestBand: number[];
  sections: GuideSection[]; panels: GuidePanel[];
} = ${JSON.stringify(guide, null, 2)};
`;
}

// The current vintage the guide is built for: the dashboard's own rule
// (_shared/vintage.ts mirrors it), evaluated now.
async function currentVintage() {
  const { currentVintage: cv } = await import(new URL("supabase/functions/_shared/vintage.ts", ROOT));
  return cv();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const text = render(build(await currentVintage()));
  if (process.argv.includes("--check")) {
    const now = readFileSync(OUT, "utf8");
    if (now !== text) { console.error("dashboard-guide.generated.ts is stale: run node scripts/build-dashboard-guide.mjs"); process.exit(1); }
    console.log("dashboard guide up to date");
  } else {
    writeFileSync(OUT, text);
    console.log(`wrote ${OUT.pathname}`);
  }
}
