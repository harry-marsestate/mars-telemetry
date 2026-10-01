// Offline test for the P1 tripwire database.insights_estate_inputs_estate_wide
// (supabase/migrations/20261001140000_p1_insights_estate_inputs.sql) on PGlite.
// Runs the check's exact SQL block from the migration against a stub
// record_result, and checks the migration redefines run_p1_checks() as the
// previous migration left it plus only that block.
//
//   (cd scripts && npm install) && node --test tests/p1-insights-estate-inputs.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const requireFromScripts = createRequire(new URL("../scripts/package.json", import.meta.url));
const { PGlite } = await import(pathToFileURL(requireFromScripts.resolve("@electric-sql/pglite")).href);
const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
const mig = read("supabase/migrations/20261001140000_p1_insights_estate_inputs.sql");
const prev = read("supabase/migrations/20260930140000_vintage_2027_current_vintage_rule.sql");

const fnOf = (sql) => { const i = sql.indexOf("CREATE OR REPLACE FUNCTION system_health.run_p1_checks()"); return sql.slice(i, sql.indexOf("end $function$;", i) + 15); };
const start = mig.indexOf("  -- Tripwire for insights_customer_read");
const block = mig.slice(start, mig.indexOf("  return v_run;", start));

let db;
async function runCheck() {
  await db.exec("delete from system_health.results");
  await db.exec(`do $do$ declare v_run bigint := 1; v_status text; begin\n${block}\nend $do$;`);
  return (await db.query("select status, observed, detail from system_health.results")).rows;
}

before(async () => {
  db = new PGlite();
  await db.exec(`
    create schema system_health;
    create table system_health.results (run bigint, layer text, check_id text, status text, observed jsonb, expected jsonb, detail text);
    create function system_health.record_result(p_run bigint, p_layer text, p_check text, p_status text, p_obs jsonb, p_exp jsonb, p_detail text)
      returns void language sql as $$ insert into system_health.results values (p_run, p_layer, p_check, p_status, p_obs, p_exp, p_detail) $$;
    create table public.real_data_sources (source_system text primary key);
    insert into public.real_data_sources values ('open_meteo_ecmwf_ifs'), ('open_meteo_era5_land');
    create table public.sensor_readings (metric_key text, block_id text, vintage int, source_system text);
    insert into public.sensor_readings values
      ('air_temp', null, 2025, 'open_meteo_ecmwf_ifs'), ('soil_moisture', null, 2026, 'open_meteo_era5_land'),
      ('soil_moisture', 'B1', 2026, 'soil_probe'), ('soil_temp', 'B2', 2026, 'soil_probe'),   -- mock per-block
      ('irrigation_volume', 'B2', 2025, 'open_meteo_ecmwf_ifs');                              -- operator metric, not an insight input here
  `);
});

test("migration = previous run_p1_checks() + only the tripwire block", () => {
  const before = fnOf(prev), after = fnOf(mig);
  assert.equal(after.replace(block, ""), before);
  assert.ok(mig.includes("revoke all on function system_health.run_p1_checks() from public, anon, authenticated, service_role;"));
});

test("metric list equals insights-scan's RAW_METRIC_KEYS", () => {
  const ts = read("supabase/functions/insights-scan/metrics.ts").match(/const RAW_METRIC_KEYS = \[([^\]]*)\]/)[1];
  const sql = block.match(/v_metrics text\[\] := array\[([^\]]*)\]/)[1];
  const list = (s) => s.split(",").map((x) => x.trim().replace(/^["']|["']$/g, ""));
  assert.deepEqual(list(sql), list(ts));
});

test("estate-wide real rows + mock per-block rows: pass, mock reported", async () => {
  const [r] = await runCheck();
  assert.equal(r.status, "pass");
  assert.deepEqual(r.observed.real_per_block_rows, []);
  assert.equal(r.observed.mock_per_block_rows_not_used_by_insights.length, 2);
  assert.equal(r.detail, null);
});

test("a real per-block row of an insight input: fail, saying what to do", async () => {
  await db.exec("insert into public.sensor_readings values ('soil_moisture', 'B3', 2026, 'open_meteo_era5_land')");
  const [r] = await runCheck();
  assert.equal(r.status, "fail");
  assert.deepEqual(r.observed.real_per_block_rows, [{ metric: "soil_moisture", vintage: 2026, block: "B3", source: "open_meteo_era5_land", rows: 1 }]);
  assert.match(r.detail, /block_id-null rows only/);
  assert.match(r.detail, /require access to every block for estate rows in the insights_customer_read policy/);
  await db.exec("delete from public.sensor_readings where block_id = 'B3'");
});

test("any vintage and every raw input metric trips it (precipitation, 2022)", async () => {
  await db.exec("insert into public.sensor_readings values ('precipitation', 'B1', 2022, 'open_meteo_ecmwf_ifs')");
  assert.equal((await runCheck())[0].status, "fail");
  await db.exec("delete from public.sensor_readings where metric_key = 'precipitation'");
  assert.equal((await runCheck())[0].status, "pass");
});
