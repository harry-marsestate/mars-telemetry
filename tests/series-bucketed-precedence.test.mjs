// Offline test for supabase/migrations/20260930045000_series_bucketed_per_row_vintage_precedence.sql
// on PGlite: real-over-mock precedence with and without a vintage.
//
//   (cd scripts && npm install) && node --test tests/series-bucketed-precedence.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const requireFromScripts = createRequire(new URL("../scripts/package.json", import.meta.url));
const { PGlite } = await import(pathToFileURL(requireFromScripts.resolve("@electric-sql/pglite")).href);
const migration = readFileSync(new URL("../supabase/migrations/20260930045000_series_bucketed_per_row_vintage_precedence.sql", import.meta.url), "utf8");

let db;
const series = async (metric, block, vintage, start, end, bucket = "24 hours") =>
  (await db.query("select t, v::float8 as v from public.series_bucketed($1, $2, $3, $4, $5, $6::interval)", [metric, block, vintage, start, end, bucket]))
    .rows.map((r) => r.v);

before(async () => {
  db = new PGlite();
  await db.exec(`
    set timezone = 'UTC';
    create table public.real_data_sources (source_system text primary key);
    insert into public.real_data_sources values ('open_meteo_era5');
    create table public.sensor_readings (metric_key text, block_id text, vintage int, recorded_at timestamptz, value numeric, source_system text);
    -- 2025: mock only. 2026: real (estate-wide) AND mock (estate-wide + per block) on the same days.
    insert into public.sensor_readings values
      ('air_temp', null, 2025, '2025-07-01T12:00Z', 10, 'weather_station'),
      ('air_temp', null, 2026, '2026-07-01T12:00Z', 70, 'open_meteo_era5'),
      ('air_temp', null, 2026, '2026-07-01T13:00Z', 90, 'weather_station'),
      ('soil_moisture', null, 2026, '2026-07-01T12:00Z', 30, 'open_meteo_era5'),
      ('soil_moisture', 'B2', 2026, '2026-07-01T12:00Z', 12, 'soil_probe'),
      ('soil_moisture', 'B2', 2025, '2025-07-01T12:00Z', 14, 'soil_probe'),
      ('cellar_temp', null, 2026, '2026-07-01T12:00Z', 55, 'hvac');
  `);
  await db.exec(migration);
});

test("vintage passed: real supersedes mock within that vintage (unchanged behaviour)", async () => {
  assert.deepEqual(await series("air_temp", null, 2026, "2026-07-01T00:00Z", "2026-07-01T00:00Z"), [70]);
  assert.deepEqual(await series("air_temp", null, 2025, "2025-07-01T00:00Z", "2025-07-01T00:00Z"), [10]);
  assert.deepEqual(await series("soil_moisture", "B2", 2026, "2026-07-01T00:00Z", "2026-07-01T00:00Z"), [null]);
  assert.deepEqual(await series("cellar_temp", null, 2026, "2026-07-01T00:00Z", "2026-07-01T00:00Z"), [55]);
});

test("no vintage: each row's own vintage decides -- no mock blended into a real vintage", async () => {
  // The old definition returned 80 here (real 70 averaged with mock 90).
  assert.deepEqual(await series("air_temp", null, null, "2026-07-01T00:00Z", "2026-07-01T00:00Z"), [70]);
  // The old definition returned 12 (mock probe) where the vintage-scoped call returns nothing.
  assert.deepEqual(await series("soil_moisture", "B2", null, "2026-07-01T00:00Z", "2026-07-01T00:00Z"), [null]);
  // A mock-only vintage still shows its mock data; a cross-vintage window mixes nothing.
  assert.deepEqual(await series("air_temp", null, null, "2025-07-01T00:00Z", "2026-07-01T00:00Z", "365 days"), [10, 70]);
  assert.deepEqual(await series("soil_moisture", "B2", null, "2025-07-01T00:00Z", "2026-07-01T00:00Z", "365 days"), [14, null]);
  assert.deepEqual(await series("cellar_temp", null, null, "2026-07-01T00:00Z", "2026-07-01T00:00Z"), [55]);
});

test("no-vintage result equals the vintage-scoped result inside one vintage", async () => {
  for (const [m, b] of [["air_temp", null], ["soil_moisture", "B2"], ["soil_moisture", null], ["cellar_temp", null]]) {
    assert.deepEqual(await series(m, b, null, "2026-06-30T00:00Z", "2026-07-02T00:00Z", "6 hours"), await series(m, b, 2026, "2026-06-30T00:00Z", "2026-07-02T00:00Z", "6 hours"), `${m}/${b}`);
  }
});
