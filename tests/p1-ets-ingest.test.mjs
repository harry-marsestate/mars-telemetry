// Offline test for P1's ETS ingestion checks
// (supabase/migrations/20261006120100_p1_ets_ingest.sql) on PGlite: runs the
// block's exact SQL against a stub record_result, and checks the migration
// redefines run_p1_checks() as the previous migration left it plus only that block.
//
//   (cd scripts && npm install) && node --test tests/p1-ets-ingest.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const requireFromScripts = createRequire(new URL("../scripts/package.json", import.meta.url));
const { PGlite } = await import(pathToFileURL(requireFromScripts.resolve("@electric-sql/pglite")).href);
const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
const mig = read("supabase/migrations/20261006120100_p1_ets_ingest.sql");
const prev = read("supabase/migrations/20261001140000_p1_insights_estate_inputs.sql");

const fnOf = (sql) => { const i = sql.indexOf("CREATE OR REPLACE FUNCTION system_health.run_p1_checks()"); return sql.slice(i, sql.indexOf("end $function$;", i) + 15); };
const start = mig.indexOf("  -- ETS PDF report ingestion");
const block = mig.slice(start, mig.indexOf("  return v_run;", start));

let db;
async function runCheck() {
  await db.exec("delete from system_health.results");
  await db.exec(`do $do$ declare v_run bigint := 1; v_status text; v_obs jsonb; v_n bigint; begin\n${block}\nend $do$;`);
  return Object.fromEntries((await db.query("select check_id, status, observed, detail from system_health.results")).rows.map((r) => [r.check_id, r]));
}

before(async () => {
  db = new PGlite();
  await db.exec(`
    create schema system_health;
    create table system_health.results (run bigint, layer text, check_id text, status text, observed jsonb, expected jsonb, detail text);
    create function system_health.record_result(p_run bigint, p_layer text, p_check text, p_status text, p_obs jsonb, p_exp jsonb, p_detail text)
      returns void language sql as $$ insert into system_health.results values (p_run, p_layer, p_check, p_status, p_obs, p_exp, p_detail) $$;
    create table system_health.ingestion_runs (asset text, started_at timestamptz, status text, http_status int, rows_written int, error text);
    create table public.ets_ingest_quarantine (report_no text, sample_id text, analyte_name text, reason text, first_seen_at timestamptz default now());
  `);
});

test("migration = previous run_p1_checks() + only the ETS block", () => {
  assert.equal(fnOf(mig).replace(block, ""), fnOf(prev));
  assert.ok(mig.includes("revoke all on function system_health.run_p1_checks() from public, anon, authenticated, service_role;"));
});

test("never run: warn; other assets don't count", async () => {
  await db.exec("insert into system_health.ingestion_runs values ('ingest-innovint', now(), 'success', 200, 5, null)");
  const r = await runCheck();
  assert.equal(r["ingestion.ets_report.last_run"].status, "warn");
  assert.match(r["ingestion.ets_report.last_run"].detail, /no successful/);
  assert.equal(r["ingestion.ets_report.quarantine"].status, "pass");
});

test("a heartbeat or partial run within 10 days passes; older than 10 days warns", async () => {
  await db.exec("insert into system_health.ingestion_runs values ('ingest-ets-report', now() - interval '11 days', 'success', 200, 0, null)");
  assert.equal((await runCheck())["ingestion.ets_report.last_run"].status, "warn");
  await db.exec("insert into system_health.ingestion_runs values ('ingest-ets-report', now() - interval '6 days', 'partial', 207, 3, null)");
  const r = await runCheck();
  assert.equal(r["ingestion.ets_report.last_run"].status, "pass");
  assert.equal(r["ingestion.ets_report.last_run"].observed.status, "partial");
});

test("a refused run in the last 10 days warns even after a later success", async () => {
  await db.exec("insert into system_health.ingestion_runs values ('ingest-ets-report', now() - interval '2 days', 'error', 400, null, 'sample_date must be YYYY-MM-DD')");
  await db.exec("insert into system_health.ingestion_runs values ('ingest-ets-report', now() - interval '1 day', 'success', 200, 0, null)");
  const r = (await runCheck())["ingestion.ets_report.last_run"];
  assert.equal(r.status, "warn");
  assert.equal(r.observed.error_runs_10d, 1);
});

test("quarantine rows warn, with a sample of them; never fail", async () => {
  await db.exec("insert into public.ets_ingest_quarantine (report_no, sample_id, analyte_name, reason) select 'R1', '609290802', 'a' || g, 'unknown analyte' from generate_series(1, 25) g");
  const r = (await runCheck())["ingestion.ets_report.quarantine"];
  assert.equal(r.status, "warn");
  assert.equal(r.observed.rows, 25);
  assert.equal(r.observed.sample.length, 20);
  assert.match(r.detail, /^25 ETS analyte/);
  assert.ok(!/'fail'/.test(block));
});
