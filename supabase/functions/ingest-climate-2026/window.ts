// Upsert/refresh window limits for ingest-climate-2026. Pure functions so
// they can be tested without a deployed function.
//
// Open-Meteo's archive endpoint returns values for every hour of end_date,
// including hours that haven't happened yet (confirmed 2026-09-29: the 06:17
// PDT run stored 07:00-23:00 PDT forecast values under open_meteo_era5).
// Forecasts are not observations, so nothing later than the last fully
// elapsed hour is stored, and daily_weather is refreshed only through the
// last complete America/Los_Angeles day (a partial day would aggregate a
// partial set of hours).

const HOUR_MS = 3_600_000;

// Latest recorded_at (ms) that may be stored: the top of the current hour.
// An HH:00 value is an instantaneous reading at HH:00 (temperature,
// humidity) or the total for the hour ending at HH:00 (precipitation), so
// either way it exists once HH:00 has passed.
export function lastElapsedHourMs(nowMs: number): number {
  return Math.floor(nowMs / HOUR_MS) * HOUR_MS;
}

// Open-Meteo is asked for timezone=UTC, so an hourly time is a UTC wall
// clock ("2026-09-29T14:00"). Stamping it Z makes recorded_at independent of
// DST. The previous request used America/Los_Angeles and stamped a fixed
// -07:00, which was only correct while Open-Meteo labelled its response with
// a -07:00 offset: it reports ONE utc_offset_seconds per response, observed
// as -25200 even for PST dates while the request was made during PDT.
export function stampUtc(time: string): string {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(time)) throw new Error(`unexpected Open-Meteo time '${time}'`);
  return `${time}:00Z`;
}

// YYYY-MM-DD plus n calendar days.
export function addDays(date: string, n: number): string {
  const d = new Date(`${date}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}

// Yesterday, in America/Los_Angeles, as YYYY-MM-DD.
export function lastCompletePacificDay(now: Date): string {
  const today = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Los_Angeles" }).format(now);
  const d = new Date(`${today}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() - 1);
  return d.toISOString().slice(0, 10);
}

// Last UTC date to request. One day past endStr covers the Pacific evening of
// endStr (Open-Meteo is asked for UTC dates), but never past today (UTC):
// Open-Meteo rejects a later end_date with a 400 "out of allowed range"
// (seen live 2026-09-29, when the day-past fetch made every metric fail).
export function fetchWindowEnd(endStr: string, now: Date): string {
  return [addDays(endStr, 1), now.toISOString().slice(0, 10)].sort()[0];
}

export const LATITUDE = 38.603091360858635;
export const LONGITUDE = -122.45867651725105;
export const ELEVATION_M = 670;
const ARCHIVE_URL = "https://archive-api.open-meteo.com/v1/archive";

// The exact request URL the function sends -- shared with the pre-merge live
// check so a parameter change is tested against Open-Meteo as built.
export function archiveUrl(startDate: string, endDate: string, hourlyVars: string[], models?: string): string {
  const params = new URLSearchParams({
    latitude: String(LATITUDE), longitude: String(LONGITUDE), elevation: String(ELEVATION_M),
    start_date: startDate, end_date: endDate, hourly: hourlyVars.join(","),
    temperature_unit: "fahrenheit", timezone: "UTC",
    precipitation_unit: "inch",
  });
  if (models) params.set("models", models);
  return `${ARCHIVE_URL}?${params.toString()}`;
}

export interface FetchOutcome<T> { data?: T; error?: string; outOfRange?: boolean }

// Open-Meteo's notion of "today" may still be behind fetchWindowEnd(): if
// end_date is rejected as out of range, retry ONCE with end_date one day
// earlier -- but never earlier than endStr, the last day the caller asked
// for. (For the scheduled run fetchEnd is already endStr, so no retry.)
export async function fetchWithEndFallback<T>(
  fetchFor: (endDate: string) => Promise<FetchOutcome<T>>, fetchEnd: string, endStr: string,
): Promise<FetchOutcome<T> & { endUsed: string; fallback: boolean }> {
  const first = await fetchFor(fetchEnd);
  const earlier = addDays(fetchEnd, -1);
  if (!first.outOfRange || earlier < endStr) return { ...first, endUsed: fetchEnd, fallback: false };
  return { ...(await fetchFor(earlier)), endUsed: earlier, fallback: true };
}

// A 400 whose body says end_date is outside the allowed range.
export function isEndDateOutOfRange(status: number, body: string): boolean {
  return status === 400 && /end_date/.test(body) && /out of allowed range/.test(body);
}

// Calendar year of an instant in America/Los_Angeles -- the vintage an hour
// belongs to. The VINTAGE guard in index.ts refuses to write an hour whose
// Pacific year isn't the job's hard-coded VINTAGE (docs/SECURITY.md tracked
// item: VINTAGE = 2026 must change before 2027).
export function pacificYear(ms: number): number {
  return Number(new Intl.DateTimeFormat("en-CA", { timeZone: "America/Los_Angeles", year: "numeric" }).format(new Date(ms)));
}
