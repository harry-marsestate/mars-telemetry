import "@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "@supabase/server";

// Daily real-2026-climate ingestion. Ports ingestion/open_meteo/client.py +
// backfill_phase1.py/backfill_climate_round2.py's fetch/scale/upsert logic
// into a scheduled Edge Function (those scripts are one-time, hand-run
// Python -- 2022-2025 only, by design; this is the always-2026, always-on
// daily counterpart). Scope is deliberately narrower than the historical
// backfill: air_temp, humidity, precipitation, soil_moisture, soil_temp
// only. Solar/wind/irrigation/labour stay mock indefinitely (solar has no
// real UI consumer yet, wind has no usable real source, irrigation/labour
// are explicitly out of scope for this project -- see docs/SECURITY.md).
//
// pg_cron-only, same auth mode as insights-scan/notify-admin-approval
// (server-to-server, secret key only).
export default {
  fetch: withSupabase({ auth: ["secret"] }, async (req, ctx) => {
    try {
      const body = await req.json().catch(() => ({}));
      const { start_date, end_date, days_back } = body ?? {};

      // Rolling window, anchored to the REAL wall-clock date the job
      // actually runs on -- deliberately NOT MOCK_NOW (the frontend's
      // fixed "2026-07-28" demo anchor). ERA5's real publication lag is
      // relative to true present, not this app's frozen season-in-progress
      // narrative; and the whole point of this design (see the "as of"
      // function below) is that the displayed real-data date is allowed to
      // land wherever ERA5 actually has coverage, not wherever the rest of
      // the app pretends "now" is. Default 14 days back -- a safe window
      // that self-heals: any day ERA5 hasn't published yet on one run
      // simply comes back null (skipped, not written) and gets picked up
      // on a later run while it's still inside the trailing window.
      const end = end_date ? new Date(`${end_date}T00:00:00Z`) : new Date();
      const start = start_date
        ? new Date(`${start_date}T00:00:00Z`)
        : new Date(end.getTime() - (Number(days_back) > 0 ? Number(days_back) : 14) * 86400000);
      const startStr = start.toISOString().slice(0, 10);
      const endStr = end.toISOString().slice(0, 10);

      const VINTAGE = 2026;
      const results: Record<string, { written: number; nulls: number; error?: string }> = {};

      const weatherData = await fetchHourly(startStr, endStr, ["temperature_2m", "relative_humidity_2m", "precipitation"]);
      if (weatherData.error) {
        results.air_temp = { written: 0, nulls: 0, error: weatherData.error };
        results.humidity = { written: 0, nulls: 0, error: weatherData.error };
        results.precipitation = { written: 0, nulls: 0, error: weatherData.error };
      } else {
        await upsertMetric(ctx, results, "air_temp", weatherData.data!, "temperature_2m", VINTAGE, 1);
        await upsertMetric(ctx, results, "humidity", weatherData.data!, "relative_humidity_2m", VINTAGE, 1);
        await upsertMetric(ctx, results, "precipitation", weatherData.data!, "precipitation", VINTAGE, 1, "inch");
      }

      const soilData = await fetchHourly(startStr, endStr, ["soil_moisture_0_to_7cm", "soil_temperature_0_to_7cm"], "era5_land");
      if (soilData.error) {
        results.soil_moisture = { written: 0, nulls: 0, error: soilData.error };
        results.soil_temp = { written: 0, nulls: 0, error: soilData.error };
      } else {
        // scale=100: ERA5-Land reports volumetric water content as a 0-1
        // fraction; every consumer here (the mock data, soil_below_refill's
        // threshold, the "% VWC" unit) expects 0-100 -- see client.py's
        // matching comment.
        await upsertMetric(ctx, results, "soil_moisture", soilData.data!, "soil_moisture_0_to_7cm", VINTAGE, 100);
        await upsertMetric(ctx, results, "soil_temp", soilData.data!, "soil_temperature_0_to_7cm", VINTAGE, 1);
      }

      const anyWritten = Object.values(results).some((r) => r.written > 0);
      let refreshError: string | undefined;
      if (anyWritten) {
        const { error } = await ctx.supabaseAdmin.rpc("refresh_daily_weather_range", {
          p_vintage: VINTAGE, p_start: startStr, p_end: endStr,
        });
        if (error) {
          console.error("ingest-climate-2026: refresh_daily_weather_range failed", error);
          refreshError = error.message;
        }
      }

      const { data: asOf, error: asOfErr } = await ctx.supabaseAdmin.rpc("real_climate_as_of_2026");
      if (asOfErr) console.error("ingest-climate-2026: could not read real_climate_as_of_2026", asOfErr);

      const anyError = Object.values(results).some((r) => r.error) || !!refreshError;
      return Response.json({
        ok: !anyError,
        window: { start: startStr, end: endStr },
        results,
        daily_weather_refreshed: anyWritten && !refreshError,
        refresh_error: refreshError ?? null,
        real_as_of: asOf ?? null,
      }, { status: anyError ? 207 : 200 });
    } catch (err) {
      // Whatever failed, however early -- log it and leave the DB (and
      // therefore real_climate_as_of_2026()) exactly as the last
      // successful run left it. Nothing here ever deletes or blanks a
      // prior day's row, so a thrown error before any upsert runs is
      // always safe to just log and return from.
      console.error("ingest-climate-2026: unexpected error", err);
      return Response.json({ ok: false, reason: "unexpected error", detail: String(err) }, { status: 500 });
    }
  }),
};

const LATITUDE = 38.603091360858635;
const LONGITUDE = -122.45867651725105;
const ELEVATION_M = 670;
const ARCHIVE_URL = "https://archive-api.open-meteo.com/v1/archive";
const SOURCE_SYSTEM = "open_meteo_era5";
const SENSOR_ID = "OM-ERA5";

interface OpenMeteoResponse {
  elevation?: number;
  hourly?: { time: string[]; [key: string]: unknown };
}

async function fetchHourly(
  startDate: string, endDate: string, hourlyVars: string[], models?: string,
): Promise<{ data?: OpenMeteoResponse; error?: string }> {
  const params = new URLSearchParams({
    latitude: String(LATITUDE), longitude: String(LONGITUDE), elevation: String(ELEVATION_M),
    start_date: startDate, end_date: endDate, hourly: hourlyVars.join(","),
    temperature_unit: "fahrenheit", timezone: "America/Los_Angeles",
    precipitation_unit: "inch",
  });
  if (models) params.set("models", models);

  try {
    const resp = await fetch(`${ARCHIVE_URL}?${params.toString()}`);
    if (!resp.ok) return { error: `Open-Meteo ${resp.status}: ${await resp.text()}` };
    const data: OpenMeteoResponse = await resp.json();
    if (data.elevation == null || Math.abs(data.elevation - ELEVATION_M) > 1) {
      return { error: `elevation mismatch: got ${data.elevation}, expected ${ELEVATION_M} -- refusing to ingest` };
    }
    return { data };
  } catch (err) {
    return { error: String(err) };
  }
}

// Same fixed PDT (-07:00) convention as backfill_phase1.py -- valid for
// this job's Apr-Oct operating window (matches the app's own season
// scope), same DST caveat that script documents: would need real
// timezone logic if this ever needed to run in Nov-Mar.
const PDT_OFFSET = "-07:00";

async function upsertMetric(
  ctx: { supabaseAdmin: { from: (t: string) => any } },
  results: Record<string, { written: number; nulls: number; error?: string }>,
  metricKey: string, data: OpenMeteoResponse, variable: string, vintage: number, scale: number,
) {
  try {
    const times = data.hourly?.time ?? [];
    const values = (data.hourly?.[variable] as (number | null)[] | undefined) ?? [];
    const rows: { metric_key: string; sensor_id: string; block_id: null; tank_id: null; recorded_at: string; value: number; source_system: string; vintage: number }[] = [];
    let nulls = 0;
    for (let i = 0; i < times.length; i++) {
      const v = values[i];
      if (v == null) { nulls++; continue; }
      rows.push({
        metric_key: metricKey, sensor_id: SENSOR_ID, block_id: null, tank_id: null,
        recorded_at: `${times[i]}${PDT_OFFSET}`, value: v * scale, source_system: SOURCE_SYSTEM, vintage,
      });
    }
    if (rows.length === 0) { results[metricKey] = { written: 0, nulls }; return; }
    const { error } = await ctx.supabaseAdmin.from("sensor_readings")
      .upsert(rows, { onConflict: "metric_key,sensor_id,recorded_at" });
    if (error) {
      console.error(`ingest-climate-2026: upsert failed for ${metricKey}`, error);
      results[metricKey] = { written: 0, nulls, error: error.message };
      return;
    }
    results[metricKey] = { written: rows.length, nulls };
  } catch (err) {
    console.error(`ingest-climate-2026: unexpected error upserting ${metricKey}`, err);
    results[metricKey] = { written: 0, nulls: 0, error: String(err) };
  }
}
