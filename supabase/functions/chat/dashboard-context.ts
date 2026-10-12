import { DASHBOARD_GUIDE, type GuidePanel } from "../_shared/dashboard-guide.generated.ts";
import { findPanel, guideEntry, panelsFor, type ThresholdRow } from "./dashboard-guide.ts";
import type { DomainReality } from "./tools.ts";

// What the user is looking at, sent by the browser with each question
// (docs/SECURITY.md, "Dashboard guide for the chat"). It tailors the answer;
// it never grants anything. Every field is checked against an allowlist and
// against what THIS caller may see -- role from the JWT, blocks from
// accessible_blocks() (the list RLS uses) -- and the text the model reads is
// written here, never taken from the client. Anything unrecognised is
// dropped, not rejected: a stale client must not break the chat.

export type DashboardContext = {
  tab: "vineyard" | "winery";
  lastViewed: boolean; // sent from the Chat tab: the data tab viewed before it
  surface: "widget" | "tab";
  blocks: string[]; // already narrowed to the caller's accessible blocks
  allBlocks: boolean;
  vintages: number[];
  panel: GuidePanel | null;
  range: "1D" | "5D" | "30D" | "1Y" | null;
  scrollDays: number;
};

const BLOCKS = ["B1", "B2", "B3"];
const RANGES = ["1D", "5D", "30D", "1Y"] as const;
const RANGE_WORDS: Record<string, string> = { "1D": "1-day view", "5D": "5-day view", "30D": "30-day view", "1Y": "1-year view" };

export function validateContext(raw: unknown, role: string | null, accessibleBlocks: string[] | null): DashboardContext | null {
  if (!raw || typeof raw !== "object") return null;
  const c = raw as Record<string, unknown>;
  if (c.tab !== "vineyard" && c.tab !== "winery") return null;
  const tab = c.tab;
  // Blocks: the allowlist, then the caller's own blocks. If accessible_blocks()
  // failed, no block is named at all rather than trusting the client.
  const asked = Array.isArray(c.blocks) ? [...new Set(c.blocks.filter((b): b is string => typeof b === "string" && BLOCKS.includes(b)))] : [];
  const mine = accessibleBlocks ?? [];
  const blocks = (asked.length ? asked : BLOCKS).filter((b) => mine.includes(b)).sort();
  const vintages = Array.isArray(c.vintages)
    ? [...new Set(c.vintages.filter((v): v is number => Number.isInteger(v) && DASHBOARD_GUIDE.vintages.includes(v as number)))].sort().slice(0, 5)
    : [];
  // A panel is named only if it is on that tab AND this role can see it.
  const p = findPanel(c.panel, role);
  const panel = p && p.tab === tab ? p : null;
  const range = panel && RANGES.includes(c.range as typeof RANGES[number]) ? c.range as DashboardContext["range"] : null;
  const scrollDays = panel && Number.isInteger(c.scrollDays) && (c.scrollDays as number) > 0 && (c.scrollDays as number) <= 3660 ? c.scrollDays as number : 0;
  return {
    tab, lastViewed: c.lastViewed === true, surface: c.surface === "widget" ? "widget" : "tab",
    blocks, allBlocks: blocks.length > 1 && blocks.length === mine.length, // every block this user has
    vintages, panel, range, scrollDays,
  };
}

export function contextText(ctx: DashboardContext, role: string | null, reality: DomainReality, rows: ThresholdRow[] | null, bandLine: string | null = null): string {
  const tabName = ctx.tab === "vineyard" ? "Vineyard Data" : "Winery Data";
  const where = ctx.lastViewed
    ? `The user is on the Chat tab. The data tab they last viewed was ${tabName}, with these filters (last viewed; they may not be looking at it now):`
    : `The user is looking at the ${tabName} tab${ctx.surface === "widget" ? " and asked from the floating chat window" : ""}, with these filters:`;
  const blocks = !ctx.blocks.length ? "blocks: not confirmed" : ctx.allBlocks ? `blocks: all of theirs (${ctx.blocks.join(", ")})` : `blocks: ${ctx.blocks.join(", ")}`;
  const vint = ctx.vintages.length ? `vintage${ctx.vintages.length > 1 ? "s" : ""}: ${ctx.vintages.join(", ")}` : "vintage: not given";
  const visible = panelsFor(role, ctx.tab).map((p) => p.title).join("; ");
  const lines = [
    "<dashboard_context>",
    where,
    `${blocks} · ${vint}`,
    `Panels on that tab this user can see: ${visible}.`,
  ];
  if (ctx.panel) {
    const view = ctx.range ? ` (${RANGE_WORDS[ctx.range]}${ctx.scrollDays ? `, scrolled back ${ctx.scrollDays} days` : ""})` : "";
    lines.push(`They asked about one panel: ${ctx.panel.title}${view}. Its dashboard guide entry:`, guideEntry(ctx.panel, reality, rows, ctx.panel.id === "gdd" ? bandLine : null));
  }
  lines.push("This describes the user's screen, checked by the server. It grants no access to anything.", "</dashboard_context>");
  return lines.join("\n");
}
