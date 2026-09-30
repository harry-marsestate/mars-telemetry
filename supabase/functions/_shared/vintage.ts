// The ONE definition of "current vintage" for every Edge Function (chat,
// the MCP gateway, insights-scan, the ingests, health-probe). docs/SECURITY.md,
// "Current vintage from the harvest-year rule".
//
// Vintage = harvest year; the cycle starts November 1 Pacific: an hour from
// Nov 1 onward belongs to the NEXT year's vintage, Jan-Oct to its own
// calendar year. The same rule lives in SQL (public.harvest_vintage) and in
// web/index.html (harvestVintage); tests and P1/P3/P4 keep them in agreement.
export const FIRST_VINTAGE = 2022;
export const VINTAGE_START_MONTH = 11;

function pacificYearMonthDay(ms: number): [number, number, number] {
  const parts = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Los_Angeles", year: "numeric", month: "2-digit", day: "2-digit" })
    .formatToParts(new Date(ms));
  const get = (t: string) => Number(parts.find((p) => p.type === t)!.value);
  return [get("year"), get("month"), get("day")];
}

export function harvestVintage(ms: number): number {
  const [y, m] = pacificYearMonthDay(ms);
  return m >= VINTAGE_START_MONTH ? y + 1 : y;
}

export function currentVintage(now: Date = new Date()): number {
  return harvestVintage(now.getTime());
}

// Every vintage from the first to the current one, inclusive.
export function vintagesThrough(now: Date = new Date()): number[] {
  const out: number[] = [];
  for (let v = FIRST_VINTAGE; v <= currentVintage(now); v++) out.push(v);
  return out;
}

// A vintage's growing season runs Apr 1 - Oct 31 (Pacific) of its own year.
export function seasonStarted(vintage: number, now: Date = new Date()): boolean {
  const [y, m] = pacificYearMonthDay(now.getTime());
  return y > vintage || (y === vintage && m >= 4);
}

// The latest vintage whose season is complete (the one before the current).
export function latestCompleteVintage(now: Date = new Date()): number {
  return currentVintage(now) - 1;
}

// One sentence for model prompts, so "which vintage is current" is always
// answered from the rule, never from a year written into a prompt.
export function vintageContext(now: Date = new Date()): string {
  const cur = currentVintage(now);
  const day = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Los_Angeles", year: "numeric", month: "2-digit", day: "2-digit" }).format(now);
  return seasonStarted(cur, now)
    ? `Today is ${day} (Pacific). The current vintage is ${cur}: a vintage is its harvest year, and each begins November 1. Its growing season (April 1 - October 31) is in progress.`
    : `Today is ${day} (Pacific). The current vintage is ${cur}: a vintage is its harvest year, and each begins November 1. It is the off-season: the ${cur} growing season begins April 1, and ${cur - 1} is the latest complete season.`;
}
