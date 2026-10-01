// Offline test for supabase/migrations/20261001120000_latest_reading.sql on
// PGlite: latest_reading() returns the newest raw reading at or before the
// as-of instant, with series_bucketed()'s exact row eligibility.
//
//   (cd scripts && npm install) && node --test tests/latest-reading.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const requireFromScripts = createRequire(new URL("../scripts/package.json", import.meta.url));
const { PGlite } = await import(pathToFileURL(requireFromScripts.resolve("@electric-sql/pglite")).href);
const sql = (f) => readFileSync(new URL(`../supabase/migrations/${f}`, import.meta.url), "utf8");

let db;
const latest = async (metric, block, vintage, asOf, agg = "avg") =>
  (await db.query("select t, v::float8 as v from public.latest_reading($1, $2, $3, $4, $5)", [metric, block, vintage, asOf, agg]))
    .rows.map((r) => ({ t: r.t.toISOString(), v: r.v }))[0] ?? null;
const bucket = async (metric, block, vintage, start, end, b, agg = "avg") =>
  (await db.query("select t, v::float8 as v from public.series_bucketed($1, $2, $3, $4, $5, $6::interval, $7)", [metric, block, vintage, start, end, b, agg]))
    .rows.map((r) => r.v);

before(async () => {
  db = new PGlite();
  await db.exec(`
    set timezone = 'UTC';
    create role anon; create role authenticated; create role service_role;
    create table public.real_data_sources (source_system text primary key);
    insert into public.real_data_sources values ('open_meteo_ecmwf_ifs'), ('open_meteo_era5_land');
    create table public.sensor_readings (metric_key text, block_id text, vintage int, recorded_at timestamptz, value numeric, source_system text);
    insert into public.sensor_readings values
      -- 2026 air_temp: real hourly (incl. one AFTER the as-of) and a newer mock row that real supersedes
      ('air_temp', null, 2026, '2026-09-25T20:00Z', 75, 'open_meteo_ecmwf_ifs'),
      ('air_temp', null, 2026, '2026-09-25T21:00Z', 77, 'open_meteo_ecmwf_ifs'),
      ('air_temp', null, 2026, '2026-09-25T22:00Z', 79, 'open_meteo_ecmwf_ifs'),
      ('air_temp', null, 2026, '2026-09-25T21:10Z', 99, 'weather_station'),
      -- soil: real estate-wide row, mock per-block rows (mock must not leak into either scope)
      ('soil_moisture', null, 2026, '2026-09-25T21:00Z', 14, 'open_meteo_era5_land'),
      ('soil_moisture', 'B1', 2026, '2026-07-28T21:00Z', 30, 'soil_probe'),
      -- 2025 mock-only per-block metric: estate scope averages the blocks at the newest instant
      ('soil_temp', 'B1', 2025, '2025-07-01T12:00Z', 60, 'soil_probe'),
      ('soil_temp', 'B2', 2025, '2025-07-01T12:00Z', 70, 'soil_probe'),
      ('soil_temp', 'B2', 2025, '2025-07-01T11:00Z', 10, 'soil_probe'),
      -- flux: hourly precipitation totals; a NULL value is skipped
      ('precipitation', null, 2026, '2026-09-25T19:00Z', 0.02, 'open_meteo_ecmwf_ifs'),
      ('precipitation', null, 2026, '2026-09-25T20:00Z', 0.05, 'open_meteo_ecmwf_ifs'),
      ('precipitation', null, 2026, '2026-09-25T21:00Z', null, 'open_meteo_ecmwf_ifs'),
      ('irrigation_volume', 'B1', 2026, '2026-07-28T05:00Z', 100, 'flow_meter'),
      ('irrigation_volume', 'B2', 2026, '2026-07-28T05:00Z', 250, 'flow_meter');
  `);
  await db.exec(sql("20260930045000_series_bucketed_per_row_vintage_precedence.sql"));
  await db.exec(sql("20261001120000_latest_reading.sql"));
});

const ASOF = "2026-09-25T21:20:00Z"; // the dashboard's 2026 anchor: as-of day 14:20 Pacific

test("newest raw reading at or before the as-of, never after it", async () => {
  assert.deepEqual(await latest("air_temp", null, 2026, ASOF), { t: "2026-09-25T21:00:00.000Z", v: 77 });
  assert.deepEqual(await latest("air_temp", null, 2026, "2026-09-25T20:59:59Z"), { t: "2026-09-25T20:00:00.000Z", v: 75 });
});

test("real supersedes mock within the vintage (same rule as series_bucketed)", async () => {
  // the 21:10 weather_station row is newer than 21:00 but is mock
  assert.equal((await latest("air_temp", null, 2026, ASOF)).v, 77);
  assert.deepEqual(await latest("soil_moisture", null, 2026, ASOF), { t: "2026-09-25T21:00:00.000Z", v: 14 });
  // per-block scope: real estate rows exist, so B1's mock rows are excluded -> nothing, as series_bucketed
  assert.equal(await latest("soil_moisture", "B1", 2026, ASOF), null);
  assert.deepEqual(await bucket("soil_moisture", "B1", 2026, "2026-07-28T00:00Z", "2026-07-28T23:00Z", "1 day"), [null]);
});

test("estate scope aggregates the blocks at the newest instant, like a bucket holding only that instant", async () => {
  assert.deepEqual(await latest("soil_temp", null, 2025, "2025-07-02T00:00Z"), { t: "2025-07-01T12:00:00.000Z", v: 65 });
  assert.deepEqual(await bucket("soil_temp", null, 2025, "2025-07-01T12:00Z", "2025-07-01T12:00Z", "1 hour"), [65]);
  assert.deepEqual(await latest("irrigation_volume", null, 2026, ASOF, "sum"), { t: "2026-07-28T05:00:00.000Z", v: 350 });
});

test("flux metric: the newest non-null interval value", async () => {
  assert.deepEqual(await latest("precipitation", null, 2026, ASOF, "sum"), { t: "2026-09-25T20:00:00.000Z", v: 0.05 });
});

test("equals the 1-hour bucket that holds the same reading", async () => {
  const l = await latest("air_temp", null, 2026, ASOF);
  assert.deepEqual(await bucket("air_temp", null, 2026, l.t, l.t, "1 hour"), [l.v]);
});

test("no rows -> no row; grants: authenticated and service_role only", async () => {
  assert.equal(await latest("air_temp", null, 2024, ASOF), null);
  const { rows } = await db.query(`select r.rolname, has_function_privilege(r.rolname, 'public.latest_reading(text,text,integer,timestamptz,text)', 'execute') as x
    from pg_roles r where r.rolname in ('anon','authenticated','service_role') order by 1`);
  assert.deepEqual(rows.map((r) => [r.rolname, r.x]), [["anon", false], ["authenticated", true], ["service_role", true]]);
});
