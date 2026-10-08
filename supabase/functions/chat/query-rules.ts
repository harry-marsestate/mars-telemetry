// Shared query rules for chat/tools.ts and the MCP gateway's duplicated
// total_count filters (mcp/data-tools.ts): one implementation of each, so the
// two can never disagree. docs/SECURITY.md, "Chat tool findings" (2026-10-07).

const MONTH_NAMES = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
const ESTATE_TZ = "America/Los_Angeles";
const BARE_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

// ── Date bounds ─────────────────────────────────────────────────────────
// A bare date ('YYYY-MM-DD') means the estate's whole calendar day; an
// explicit timestamp is honored exactly as given (inclusive). How "the day"
// maps to stored values depends on how the column stores time:
//   "instant"   -- real UTC instants (InnoVint lot_analyses.recorded_at,
//                  sensor_readings.recorded_at): the Pacific day,
//                  [D 00:00 America/Los_Angeles, D+1 00:00 America/Los_Angeles).
//   "wallclock" -- local wall-clock time marked +00 (ETS analyzed_at, per the
//                  CSV/PDF ingest convention; daily_derived.day, a Pacific day
//                  label at UTC midnight): [D 00:00Z, D+1 00:00Z), which IS
//                  the local calendar day for these columns.
//   "date"      -- a plain date column (lab_samples.collected_on): the bounds
//                  are dates, both inclusive.
// The old code passed a bare end_date to `lte`, which compares as D 00:00 and
// dropped the rest of that day (Colin: 0 rows same-day vs 11 ETS / 9 InnoVint).
export type TimeStorage = "instant" | "wallclock" | "date";

export interface DateBounds {
  gte?: string;       // inclusive lower bound (ISO instant)
  lt?: string;        // exclusive upper bound (bare end date)
  lte?: string;       // inclusive upper bound (explicit end timestamp)
  label: string;      // the effective interval, in words, for the response
  error?: string;
}

function parts(d: string): [number, number, number] {
  const m = d.match(BARE_DATE)!;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

export function isBareDate(v: unknown): v is string {
  if (typeof v !== "string" || !BARE_DATE.test(v)) return false;
  const [y, m, d] = parts(v);
  const t = new Date(Date.UTC(y, m - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === m - 1 && t.getUTCDate() === d;
}

export function addDays(date: string, n: number): string {
  const [y, m, d] = parts(date);
  return new Date(Date.UTC(y, m - 1, d + n)).toISOString().slice(0, 10);
}

// The calendar date an instant falls on in the estate's time zone.
export function pacificDate(instant: string | number | Date): string {
  const f = new Intl.DateTimeFormat("en-CA", { timeZone: ESTATE_TZ, year: "numeric", month: "2-digit", day: "2-digit" });
  return f.format(new Date(instant));
}

// Midnight at the start of `date` in America/Los_Angeles, as a UTC instant.
// DST changes happen at 02:00 local, so local midnight always exists exactly
// once: it is UTC 07:00 (PDT) or 08:00 (PST).
export function pacificMidnightUtc(date: string): string {
  const [y, m, d] = parts(date);
  for (const offsetHours of [7, 8]) {
    const t = new Date(Date.UTC(y, m - 1, d, offsetHours));
    const local = new Intl.DateTimeFormat("en-GB", { timeZone: ESTATE_TZ, hour: "2-digit", hourCycle: "h23" }).format(t);
    if (pacificDate(t) === date && Number(local) === 0) return t.toISOString();
  }
  throw new Error(`no Pacific midnight for ${date}`);
}

export function dayLabel(isoDate: string): string {
  const [y, m, d] = isoDate.slice(0, 10).split("-");
  return `${MONTH_NAMES[Number(m) - 1]} ${Number(d)}, ${y}`;
}

function dayStart(date: string, storage: TimeStorage): string {
  return storage === "instant" ? pacificMidnightUtc(date) : `${date}T00:00:00.000Z`;
}

export function resolveDateBounds(column: string, start: unknown, end: unknown, storage: TimeStorage, names = ["start_date", "end_date"]): DateBounds {
  const has = (v: unknown) => v !== undefined && v !== null && v !== "";
  for (const [v, name] of [[start, names[0]], [end, names[1]]] as const) {
    if (has(v) && (typeof v !== "string" || (!isBareDate(v) && (!/\d{4}-\d{2}-\d{2}T/.test(v) || Number.isNaN(Date.parse(v)))))) {
      return { label: "", error: `${name} must be a calendar date 'YYYY-MM-DD' (the whole day) or an ISO 8601 timestamp; got ${JSON.stringify(v)}.` };
    }
  }
  const b: DateBounds = { label: "" };
  if (storage === "date") {
    const day = (v: unknown) => (isBareDate(v) ? v : new Date(v as string).toISOString().slice(0, 10));
    if (has(start)) b.gte = day(start);
    if (has(end)) b.lte = day(end);
    if (b.gte && b.lte && b.lte < b.gte) return { label: "", error: `${names[1]} (${end}) is before ${names[0]} (${start}): the interval is empty.` };
    const where = [b.gte && `${column} >= ${b.gte}`, b.lte && `${column} <= ${b.lte}`].filter(Boolean).join(" and ");
    b.label = where ? `Effective interval: ${where} (calendar dates, both inclusive).` : `Effective interval: all dates (no ${names[0]}/${names[1]}).`;
    return b;
  }
  if (has(start)) b.gte = isBareDate(start) ? dayStart(start, storage) : new Date(start as string).toISOString();
  if (has(end)) {
    if (isBareDate(end)) b.lt = dayStart(addDays(end, 1), storage);
    else b.lte = new Date(end as string).toISOString();
  }
  const upper = b.lt ?? b.lte;
  if (b.gte && upper && (b.lt ? upper <= b.gte : upper < b.gte)) {
    return { label: "", error: `${names[1]} (${end}) is before ${names[0]} (${start}): the interval is empty.` };
  }
  const where = [b.gte && `${column} >= ${b.gte}`, b.lt && `${column} < ${b.lt}`, b.lte && `${column} <= ${b.lte}`].filter(Boolean).join(" and ");
  const days = [isBareDate(start) ? `from the start of ${dayLabel(start)}` : "", isBareDate(end) ? `through the end of ${dayLabel(end)} (a bare end date includes that whole day)` : ""].filter(Boolean).join(" ");
  const basis = storage === "instant"
    ? "Pacific calendar days (America/Los_Angeles)"
    : "the local calendar day (this column stores local wall-clock time marked +00, so these UTC bounds are local days)";
  b.label = where
    ? `Effective interval: ${where}${days ? ` -- ${days}, in ${basis}` : ""}.`
    : `Effective interval: all dates (no ${names[0]}/${names[1]}).`;
  return b;
}

// deno-lint-ignore no-explicit-any
export function applyBounds(q: any, column: string, b: DateBounds): any {
  if (b.gte) q = q.gte(column, b.gte);
  if (b.lt) q = q.lt(column, b.lt);
  if (b.lte) q = q.lte(column, b.lte);
  return q;
}

// ── Identifiers ─────────────────────────────────────────────────────────
// Stored conventions, verified exhaustively against production 2026-10-07:
// block ids, lot codes and ETS sample numbers are upper case; InnoVint
// analysis_type, ETS analysis_code and vessel_type are lower case; none has
// surrounding whitespace. Normalising input to the stored case keeps exact
// (index-friendly, unambiguous) matching while 'b2' and ' MA24CSV3 ' work.
export function normUpper(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const t = v.trim();
  return t ? t.toUpperCase() : undefined;
}
export function normLower(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const t = v.trim();
  return t ? t.toLowerCase() : undefined;
}
export function normText(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const t = v.trim();
  return t || undefined;
}

// ── Analyte variants ────────────────────────────────────────────────────
// The same analyte reported at different reference temperatures (ETS
// ethanol_at_20c / ethanol_at_60f; InnoVint ethanol-20c / ethanol-60f /
// ethanol / alcohol) are different measurements and never interchangeable,
// but a request for one must surface the others. Family = the code without
// its temperature suffix, with InnoVint's 'alcohol' treated as ethanol.
export function analyteFamily(code: string): string {
  const base = code.toLowerCase().replace(/[_-]?(at[_-]?)?\d+(\.\d+)?[_-]?(c|f|deg[_-]?[cf])$/, "");
  return base === "alcohol" ? "ethanol" : base;
}

export function temperatureLabel(code: string): string {
  const m = code.toLowerCase().match(/(\d+(?:\.\d+)?)[_-]?(c|f)$/);
  return m ? `${m[1]}°${m[2].toUpperCase()}` : "no stated reference temperature";
}

// ── Server-side change arithmetic ───────────────────────────────────────
// The model must never do this arithmetic itself (Colin: 2.4 Brix over 28
// days reported as ~0.3/day; correct 0.086/day). Values are rounded to the
// precision of the inputs; rates to 3 decimals.
export function decimals(v: number): number {
  const s = String(v);
  if (/e-/i.test(s)) return Number(s.split(/e-/i)[1]);
  const i = s.indexOf(".");
  return i === -1 ? 0 : s.length - i - 1;
}
export function round(v: number, dp: number): number {
  const f = 10 ** dp;
  return Math.round((v + Math.sign(v) * Number.EPSILON) * f) / f;
}
const signed = (v: number) => (v > 0 ? `+${v}` : `${v}`);

export interface Point { date: string; value: number }

export function daysBetween(a: string, b: string): number {
  return Math.round((Date.parse(`${b.slice(0, 10)}T00:00:00Z`) - Date.parse(`${a.slice(0, 10)}T00:00:00Z`)) / 86400000);
}

// "23 (August 25, 2026) -> 26.7 (September 30, 2026): +3.7 over 36 days = +0.103/day; steps: ..."
// Points must be one per date, ascending. Returns null for fewer than two.
export function describeChange(points: Point[], unit = "", withSteps = true): string | null {
  if (points.length < 2) return null;
  const first = points[0], last = points[points.length - 1];
  const dp = Math.max(...points.map((p) => decimals(p.value)));
  const u = unit ? ` ${unit}` : "";
  const step = (a: Point, b: Point) => {
    const d = daysBetween(a.date, b.date);
    const ch = round(b.value - a.value, dp);
    return d > 0 ? `${signed(ch)}${u} over ${d} day${d === 1 ? "" : "s"} = ${signed(round(ch / d, 3))}${u}/day` : `${signed(ch)}${u} (same day)`;
  };
  let s = `${first.value} (${dayLabel(first.date)}) -> ${last.value} (${dayLabel(last.date)}): ${step(first, last)}`;
  if (withSteps && points.length > 2) {
    s += `; between consecutive readings: ${points.slice(1).map((p, i) => `${dayLabel(points[i].date)} -> ${dayLabel(p.date)} ${step(points[i], p)}`).join(", ")}`;
  }
  return s;
}

// ── Answer rules ────────────────────────────────────────────────────────
// Shared by the in-app system prompt (chat/index.ts) and the MCP server's
// initialize instructions (mcp/handler.ts), so an external agent gets the same
// rules as the in-app model.
export const ANSWER_RULES = `Answer-support rules (they override any instruction to explain or interpret):
- Quote changes and rates exactly as a tool's "Changes" note states them. Never compute a rate, difference, average or total yourself; if no tool states the figure you need, say it was not computed rather than estimating it.
- No causal explanations (weather, irrigation, cellar or vineyard actions, or anything else) unless a tool result in this conversation contains the supporting event -- e.g. an irrigation record, a cellar action, or the climate readings for that same period. Without one, say what changed and stop. With one, say the two coincided and cite both values; do not claim one caused the other.
- Name the source for every figure: InnoVint (get_lot_analyses) for lot analyses; ETS Labs (get_wine_lab_results, get_berry_maturity, get_smoke_markers) for lab samples. Quote the ETS lab_sample_no when naming a sample, and say when a collection date was inferred rather than recorded.
- When one source has no match, follow the tool's pointer to the other source before asking the user.
- If a result says it was truncated or a scan was incomplete, say so; never present a partial range or count as complete.`;
