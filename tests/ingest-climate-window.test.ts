// ingest-climate-2026's upsert/refresh window (window.ts).
//   npx deno test --no-lock tests/ingest-climate-window.test.ts
import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  addDays, archiveUrl, CLIMATE_SOURCES, requestedModel, fetchWindowEnd, fetchWithEndFallback, isEndDateOutOfRange, lastCompletePacificDay,
  lastElapsedHourMs, pacificYear, stampUtc,
} from "../supabase/functions/ingest-climate-2026/window.ts";

Deno.test("cutoff is the top of the current hour", () => {
  assertEquals(lastElapsedHourMs(Date.parse("2026-09-29T13:17:03Z")), Date.parse("2026-09-29T13:00:00Z"));
  assertEquals(lastElapsedHourMs(Date.parse("2026-09-29T13:00:00Z")), Date.parse("2026-09-29T13:00:00Z"));
});

Deno.test("the 2026-09-29 13:17 UTC run would have stored nothing after 06:00 PDT", () => {
  const cutoff = lastElapsedHourMs(Date.parse("2026-09-29T13:17:03Z"));
  assertEquals(Date.parse("2026-09-29T06:00:00-07:00") <= cutoff, true);
  assertEquals(Date.parse("2026-09-29T07:00:00-07:00") <= cutoff, false);
  assertEquals(Date.parse("2026-09-29T23:00:00-07:00") <= cutoff, false);
});

Deno.test("daily refresh stops at the last complete Pacific day", () => {
  assertEquals(lastCompletePacificDay(new Date("2026-09-29T13:17:00Z")), "2026-09-28"); // 06:17 PDT Sep 29
  assertEquals(lastCompletePacificDay(new Date("2026-09-30T03:00:00Z")), "2026-09-28"); // 20:00 PDT Sep 29
  assertEquals(lastCompletePacificDay(new Date("2026-10-01T08:00:00Z")), "2026-09-30"); // 01:00 PDT Oct 1
});

// DST ends 2026-11-01 at 09:00 UTC (02:00 PDT -> 01:00 PST).
Deno.test("cutoff and UTC stamps across the 2026-11-01 DST switch", () => {
  const cutoff = lastElapsedHourMs(Date.parse("2026-11-01T13:17:00Z")); // 05:17 PST
  assertEquals(cutoff, Date.parse("2026-11-01T13:00:00Z"));
  assertEquals(Date.parse(stampUtc("2026-11-01T13:00")) <= cutoff, true);  // 05:00 PST, elapsed
  assertEquals(Date.parse(stampUtc("2026-11-01T14:00")) <= cutoff, false); // 06:00 PST, future
  // What the old scheme would have done with a PST local label: 06:00 PST
  // stamped -07:00 lands an hour early, on 13:00Z, and passes the cutoff.
  assertEquals(Date.parse("2026-11-01T06:00:00-07:00") <= cutoff, true);
  assertEquals(Date.parse("2026-11-01T06:00:00-08:00") <= cutoff, false);
  // Hours either side of the switch stay one hour apart when stamped UTC.
  assertEquals(Date.parse(stampUtc("2026-11-01T09:00")) - Date.parse(stampUtc("2026-11-01T08:00")), 3_600_000);
});

Deno.test("lastCompletePacificDay across the 2026-11-01 DST switch", () => {
  assertEquals(lastCompletePacificDay(new Date("2026-11-01T07:30:00Z")), "2026-10-31"); // 00:30 PDT Nov 1
  assertEquals(lastCompletePacificDay(new Date("2026-11-01T08:30:00Z")), "2026-10-31"); // 01:30 PDT (first)
  assertEquals(lastCompletePacificDay(new Date("2026-11-01T09:30:00Z")), "2026-10-31"); // 01:30 PST (repeated)
  assertEquals(lastCompletePacificDay(new Date("2026-11-02T07:30:00Z")), "2026-10-31"); // 23:30 PST Nov 1
  assertEquals(lastCompletePacificDay(new Date("2026-11-02T08:30:00Z")), "2026-11-01"); // 00:30 PST Nov 2
  assertEquals(lastCompletePacificDay(new Date("2026-11-02T13:17:00Z")), "2026-11-01"); // the 13:17 UTC run
});

Deno.test("UTC stamps equal the old -07:00 stamps for PDT dates (stored rows keep their keys)", () => {
  // UTC 14:00 on 2026-09-29 == 07:00 PDT, which the old scheme stamped "2026-09-29T07:00-07:00".
  assertEquals(Date.parse(stampUtc("2026-09-29T14:00")), Date.parse("2026-09-29T07:00:00-07:00"));
});

Deno.test("stampUtc rejects anything but a bare hourly wall-clock time", () => {
  for (const bad of ["2026-09-29T14:00Z", "2026-09-29T14:00:00", "2026-09-29 14:00", ""]) {
    let threw = false;
    try { stampUtc(bad); } catch { threw = true; }
    assertEquals(threw, true, bad);
  }
});

Deno.test("addDays crosses month ends", () => {
  assertEquals(addDays("2026-09-30", 1), "2026-10-01");
  assertEquals(addDays("2026-10-31", 1), "2026-11-01");
});

Deno.test("fetchWindowEnd: one day past endStr, never past today (UTC)", () => {
  // The 13:17 UTC scheduled run: endStr is today, so no extra day.
  assertEquals(fetchWindowEnd("2026-09-30", new Date("2026-09-30T13:17:00Z")), "2026-09-30");
  // A backfill ending in the past keeps its extra day.
  assertEquals(fetchWindowEnd("2026-09-20", new Date("2026-09-30T13:17:00Z")), "2026-09-21");
  // Late Pacific evening, UTC already a day ahead: endStr+1 == UTC today.
  assertEquals(fetchWindowEnd("2026-09-29", new Date("2026-09-30T03:00:00Z")), "2026-09-30");
});

const OUT_OF_RANGE = `{"error":true,"reason":"Parameter 'end_date' is out of allowed range from 1940-01-01 to 2026-09-29"}`;

Deno.test("isEndDateOutOfRange recognises only that 400", () => {
  assertEquals(isEndDateOutOfRange(400, OUT_OF_RANGE), true);
  assertEquals(isEndDateOutOfRange(400, `{"error":true,"reason":"Cannot initialize WeatherVariable"}`), false);
  assertEquals(isEndDateOutOfRange(500, OUT_OF_RANGE), false);
});

Deno.test("fetchWithEndFallback: success first time, no retry", async () => {
  const calls: string[] = [];
  const r = await fetchWithEndFallback(async (e) => { calls.push(e); return { data: 1 }; }, "2026-09-21", "2026-09-20");
  assertEquals(calls, ["2026-09-21"]);
  assertEquals([r.data, r.endUsed, r.fallback], [1, "2026-09-21", false]);
});

Deno.test("fetchWithEndFallback: out-of-range 400 retries exactly once, a day earlier", async () => {
  const calls: string[] = [];
  const r = await fetchWithEndFallback(async (e) => {
    calls.push(e);
    return e === "2026-09-30" ? { error: `Open-Meteo 400: ${OUT_OF_RANGE}`, outOfRange: true } : { data: 2 };
  }, "2026-09-30", "2026-09-29");
  assertEquals(calls, ["2026-09-30", "2026-09-29"]);
  assertEquals([r.data, r.endUsed, r.fallback, r.error], [2, "2026-09-29", true, undefined]);
});

Deno.test("fetchWithEndFallback: a second out-of-range is returned, not retried again", async () => {
  const calls: string[] = [];
  const r = await fetchWithEndFallback(async (e) => { calls.push(e); return { error: "Open-Meteo 400", outOfRange: true }; },
    "2026-09-30", "2026-09-29");
  assertEquals(calls, ["2026-09-30", "2026-09-29"]);
  assertEquals([r.fallback, r.error], [true, "Open-Meteo 400"]);
});

Deno.test("fetchWithEndFallback: never goes earlier than endStr", async () => {
  const calls: string[] = [];
  const r = await fetchWithEndFallback(async (e) => { calls.push(e); return { error: "Open-Meteo 400", outOfRange: true }; },
    "2026-09-30", "2026-09-30");
  assertEquals(calls, ["2026-09-30"]);
  assertEquals([r.fallback, r.endUsed, r.error], [false, "2026-09-30", "Open-Meteo 400"]);
});

Deno.test("fetchWithEndFallback: other errors are not retried", async () => {
  const calls: string[] = [];
  await fetchWithEndFallback(async (e) => { calls.push(e); return { error: "Open-Meteo 500" }; }, "2026-09-21", "2026-09-20");
  assertEquals(calls, ["2026-09-21"]);
});

Deno.test("archiveUrl builds the request the function sends", () => {
  const u = new URL(archiveUrl("2026-09-16", "2026-09-30", ["temperature_2m", "precipitation"], "era5_land"));
  assertEquals(u.origin + u.pathname, "https://archive-api.open-meteo.com/v1/archive");
  assertEquals(u.searchParams.get("timezone"), "UTC");
  assertEquals(u.searchParams.get("end_date"), "2026-09-30");
  assertEquals(u.searchParams.get("hourly"), "temperature_2m,precipitation");
  assertEquals(u.searchParams.get("models"), "era5_land");
});

Deno.test("pacificYear decides the vintage at the Pacific New Year, not UTC's", () => {
  assertEquals(pacificYear(Date.parse("2026-12-31T23:30:00-08:00")), 2026);
  assertEquals(pacificYear(Date.parse("2027-01-01T07:30:00Z")), 2026); // 23:30 PST Dec 31
  assertEquals(pacificYear(Date.parse("2027-01-01T08:30:00Z")), 2027); // 00:30 PST Jan 1
  assertEquals(pacificYear(Date.parse(stampUtc("2026-09-30T13:00"))), 2026);
});

Deno.test("climate sources are pinned: ecmwf_ifs for weather, era5_land for soil, with matching labels", () => {
  assertEquals([CLIMATE_SOURCES.weather.model, CLIMATE_SOURCES.weather.source_system, CLIMATE_SOURCES.weather.sensor_id], ["ecmwf_ifs", "open_meteo_ecmwf_ifs", "OM-IFS"]);
  assertEquals([CLIMATE_SOURCES.soil.model, CLIMATE_SOURCES.soil.source_system, CLIMATE_SOURCES.soil.sensor_id], ["era5_land", "open_meteo_era5_land", "OM-ERA5-LAND"]);
  for (const g of Object.values(CLIMATE_SOURCES)) {
    assertEquals(requestedModel(archiveUrl("2026-09-16", "2026-09-30", [...g.vars], g.model)), g.model);
    assert(!/era5/i.test(g.source_system) || g.model.startsWith("era5"), "an ERA5 label only for an ERA5 model");
  }
  assertEquals(requestedModel(archiveUrl("2026-09-16", "2026-09-30", ["temperature_2m"])), null, "no models param = best_match");
});

Deno.test("ingest source: every archive fetch passes a pinned model, and rows carry the source's labels", async () => {
  const src = await Deno.readTextFile(new URL("../supabase/functions/ingest-climate-2026/index.ts", import.meta.url));
  const calls = [...src.matchAll(/fetchHourly\(startStr, e, ([^)]*)\)/g)].map((m) => m[1]);
  assertEquals(calls, ["[...CLIMATE_SOURCES.weather.vars], CLIMATE_SOURCES.weather.model", "[...CLIMATE_SOURCES.soil.vars], CLIMATE_SOURCES.soil.model"]);
  assert(!/open_meteo_era5"|"OM-ERA5"/.test(src), "no hard-coded legacy label");
  assert(src.includes("sensor_id: source.sensor_id") && src.includes("source_system: source.source_system"));
  assertEquals((src.match(/upsertMetric\(ctx, results, cutoffMs, "[a-z_]+", weatherData\.data!, "[a-z_0-9]+", VINTAGE, \d+, CLIMATE_SOURCES\.weather\)/g) ?? []).length, 3);
  assertEquals((src.match(/upsertMetric\(ctx, results, cutoffMs, "[a-z_]+", soilData\.data!, "[a-z_0-9]+", VINTAGE, \d+, CLIMATE_SOURCES\.soil\)/g) ?? []).length, 2);
});
