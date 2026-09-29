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

// Yesterday, in America/Los_Angeles, as YYYY-MM-DD.
export function lastCompletePacificDay(now: Date): string {
  const today = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Los_Angeles" }).format(now);
  const d = new Date(`${today}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() - 1);
  return d.toISOString().slice(0, 10);
}
