import type Anthropic from "@anthropic-ai/sdk";
import { DASHBOARD_GUIDE, type GuidePanel } from "../_shared/dashboard-guide.generated.ts";
import type { DomainReality } from "./tools.ts";

// The dashboard guide served to the chat model (docs/SECURITY.md, "Dashboard
// guide for the chat"). Content comes from _shared/dashboard-guide.generated.ts,
// which scripts/build-dashboard-guide.mjs generates from web/index.html, so
// the chat and the screen describe a panel with the same words.
//
// Role is the ONLY gate on what a user may be told, and it is the role the
// function resolved from the caller's JWT (current_role_name()), never
// anything the client sent. An operator-only panel is invisible to everyone
// else here: not in the map, not returned by the tool, not named in context
// -- asking for it by id gets the same answer as an id that does not exist.

export type ThresholdRow = { rule_key: string; operator?: string | null; threshold: number | null; rule_group?: string | null; display_label?: string | null; tooltip_phrase?: string | null };

export const visibleTo = (p: GuidePanel, role: string | null) => p.minRole === "all" || role === "operator";

export function panelsFor(role: string | null, tab?: string): GuidePanel[] {
  return DASHBOARD_GUIDE.panels.filter((p) => visibleTo(p, role) && (!tab || p.tab === tab));
}

export function findPanel(id: unknown, role: string | null): GuidePanel | null {
  if (typeof id !== "string") return null;
  const p = DASHBOARD_GUIDE.panels.find((x) => x.id === id);
  return p && visibleTo(p, role) ? p : null;
}

// Which provenance label applies to a vintage. Unlike tools.ts isDomainReal()
// (which fails open to "real" for data gating), an unknown reality never
// claims "real": both labels are given.
export function provenance(p: GuidePanel, vintage: number, reality: DomainReality): string {
  const e = p.provenance[String(vintage)];
  if (!e) return "not shown for this vintage";
  if (e.real === e.notReal || !p.domain) return e.real;
  const set = reality.get(p.domain);
  if (!set) return `${e.real} where real data exists for ${vintage}; otherwise ${e.notReal}`;
  return set.has(vintage) ? e.real : e.notReal;
}

// "2022-2025: X; 2026: Y" -- consecutive vintages with the same label merged.
export function provenanceByVintage(p: GuidePanel, reality: DomainReality): string {
  const runs: { from: number; to: number; label: string }[] = [];
  for (const v of DASHBOARD_GUIDE.vintages) {
    const label = provenance(p, v, reality);
    const last = runs[runs.length - 1];
    if (last && last.label === label && last.to === v - 1) last.to = v;
    else runs.push({ from: v, to: v, label });
  }
  return runs.map((r) => `${r.from === r.to ? r.from : `${r.from}-${r.to}`}: ${r.label || "(no source label)"}`).join("; ");
}

// Same token rules as web/index.html interpolateThreshold(): a 'lt' row
// supplies the low bound, a 'gt' row the high bound, the sibling in the same
// rule_group the other one. tests/dashboard-guide.test.mjs checks the two
// agree on the same rows.
export function interpolate(row: ThresholdRow, rows: ThresholdRow[]) {
  const sibling = row.rule_group ? rows.find((r) => r.rule_group === row.rule_group && r.rule_key !== row.rule_key) : undefined;
  const low = row.operator === "lt" ? row.threshold : sibling?.threshold;
  const high = row.operator === "gt" ? row.threshold : sibling?.threshold;
  const sub = (s: string | null | undefined) => s == null ? s : s
    .replace(/\{threshold_low\}/g, String(low)).replace(/\{threshold_high\}/g, String(high)).replace(/\{threshold\}/g, String(row.threshold));
  return { threshold: row.threshold, low, high, display_label: sub(row.display_label), tooltip_phrase: sub(row.tooltip_phrase) };
}

// Fills {{rule_key.field}} tokens from anomaly_thresholds rows (the table the
// dashboard reads). A missing value says so rather than inventing a number.
export function fillThresholds(text: string | null, rows: ThresholdRow[] | null): string | null {
  if (!text) return text;
  return text.replace(/\{\{([a-z0-9_]+)\.(threshold|low|high|display_label|tooltip_phrase)\}\}/g, (_, key: string, field: string) => {
    const row = rows?.find((r) => r.rule_key === key);
    const v = row ? (interpolate(row, rows!) as Record<string, unknown>)[field] : null;
    return v == null || v === "undefined" ? "(threshold not available)" : String(v);
  });
}

// Compact map for the system prompt: every panel this role can see, with the
// current vintage's provenance and whether a tool returns its data.
export function dashboardMap(role: string | null, reality: DomainReality): string {
  const cur = DASHBOARD_GUIDE.currentVintage;
  const lines: string[] = [];
  for (const tab of ["vineyard", "winery"] as const) {
    const ps = panelsFor(role, tab);
    if (!ps.length) continue;
    lines.push(`${tab === "vineyard" ? "Vineyard Data" : "Winery Data"} tab:`);
    for (const p of ps) {
      lines.push(`- ${p.title} [${p.id}, ${p.sectionLabel}, ${p.scope}]: ${provenance(p, cur, reality)}${p.tool ? "" : " · no data tool"}`);
    }
  }
  return lines.join("\n");
}

const SCOPE_LINE: Record<string, string> = {
  "estate-wide": "Scope: estate-wide -- one series for the whole estate, no per-block values. Do not offer, describe or address per-block versions of it.",
  "per-block": "Scope: per block.",
  "cellar": "Scope: the cellar (barrel room), not the vineyard blocks.",
  "per-lot": "Scope: per lot.",
  "per-vessel": "Scope: per vessel.",
};
// bandLine: the server-computed harvest-band position (tools.ts
// harvestBandPosition), given only for the GDD panel.
export function guideEntry(p: GuidePanel, reality: DomainReality, rows: ThresholdRow[] | null, bandLine: string | null = null): string {
  const info = fillThresholds(p.info, rows);
  return [
    `${p.title} [${p.id}] -- ${p.tab === "vineyard" ? "Vineyard Data" : "Winery Data"} tab, ${p.sectionLabel}${p.unit ? `, unit: ${p.unit}` : ""}`,
    `What it shows: ${p.what}`,
    p.scope ? SCOPE_LINE[p.scope] ?? `Scope: ${p.scope}.` : null,
    p.id === "gdd" && bandLine ? `Harvest band position, computed by the server -- quote it, do not compute your own: ${bandLine}` : null,
    info ? `How to read it (the panel's own help text): ${info}` : null,
    `Where the data comes from, by vintage (the panel's own source label): ${provenanceByVintage(p, reality)}`,
    p.tool ? `Data tool: ${p.tool}` : `Data tool: none. ${p.noTool ?? ""}`.trim(),
  ].filter(Boolean).join("\n");
}

export const DASHBOARD_RULES = `About the dashboard. The user is looking at the Mars Telemetry dashboard: a Vineyard Data tab, a Winery Data tab, and this chat (also available as a floating window over the data tabs). The dashboard map below lists the panels THIS user can see and where each panel's data really comes from for the current vintage. When the user asks about a chart, panel or tile ("this chart", "what am I looking at", a panel's name):
- Explain it from the dashboard guide first: call get_dashboard_guide for the panel's full entry unless it is already in the dashboard context. Bring in data from a data tool after that, if it helps.
- Say plainly where the data comes from, in the guide's words: measured records, modelled (Open-Meteo ECMWF IFS or ERA5-Land model output, not on-site sensors), estimated, or simulated. A simulated panel shows demonstration data, not measurements: say so, and never present its values as real conditions.
- If no data tool returns that panel's data, say so and say the panel is part of this dashboard. Never suggest a panel comes from an outside or unknown source.
- If you offer a related measure instead (for example diurnal range or ET0 for a question about sunlight), say it is a different measure and that the link is your inference, not the same thing.
- A panel that is not in the map is not on this user's dashboard: do not describe it or guess what it would show.
- GDD against the harvest band: quote the server-computed harvest_band_position ("statement", or position and gap_gdd) exactly as given, from the GDD guide entry or a get_derived_series result. Never subtract GDD figures, compute a gap, a pace or a date to reach the band yourself. If the position is "unavailable", say the current figure is not available. For any other band or threshold, say below, within or above and quote both figures as given.
- Offer per-block data only for series whose scope in the map or guide is "per-block". A series marked "estate-wide" (all climate, solar, wind, UV, ECMWF and ERA5-Land soil data) has no per-block values: never offer, suggest or describe a per-block version, and do not tie it to the user's block (no "for B2"), even when the user has one block.
The answer-support rules above still apply to everything you say about a panel.`;

export const GUIDE_TOOL: Anthropic.Tool = {
  name: "get_dashboard_guide",
  description: "The dashboard guide: what a panel on the user's Mars Telemetry dashboard shows, how to read it (thresholds and bands filled from the live settings), where its data comes from for each vintage (measured, modelled, estimated or simulated, in the panel's own words) and which data tool, if any, returns it. Pass panel_id (from the dashboard map) for one panel, or tab for every panel on a tab. Only panels this user can see are returned.",
  input_schema: {
    type: "object",
    properties: {
      panel_id: { type: "string", description: "Panel id from the dashboard map, e.g. 'solar' or 'gdd'." },
      tab: { type: "string", enum: ["vineyard", "winery"], description: "Every panel on this tab, when no panel_id is given." },
    },
    required: [],
  },
};

export async function runGuideTool(
  input: Record<string, unknown>, role: string | null, reality: DomainReality,
  loadThresholds: () => Promise<ThresholdRow[] | null>,
  loadBandLine: () => Promise<string | null> = () => Promise.resolve(null),
): Promise<{ content: string; isError: boolean }> {
  const rows = await loadThresholds();
  if (input.panel_id != null) {
    const p = findPanel(input.panel_id, role);
    if (!p) return { content: `No panel '${String(input.panel_id)}' on this user's dashboard. Use an id from the dashboard map.`, isError: false };
    return { content: guideEntry(p, reality, rows, p.id === "gdd" ? await loadBandLine() : null), isError: false };
  }
  const tab = input.tab === "vineyard" || input.tab === "winery" ? input.tab : null;
  if (!tab) return { content: "Pass panel_id, or tab ('vineyard' or 'winery').", isError: true };
  const ps = panelsFor(role, tab);
  const band = ps.some((p) => p.id === "gdd") ? await loadBandLine() : null;
  return { content: ps.map((p) => guideEntry(p, reality, rows, p.id === "gdd" ? band : null)).join("\n\n"), isError: false };
}
