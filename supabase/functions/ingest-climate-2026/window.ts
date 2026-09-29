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
