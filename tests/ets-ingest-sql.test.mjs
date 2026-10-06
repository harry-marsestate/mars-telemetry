// Offline tests for supabase/migrations/20261006120000_ets_report_ingest.sql on
// PGlite: the key check, validation/quarantine, idempotent upserts into the
// CSV path's own tables, the harvest-year vintage, and that no API role gains
// any access it did not have.
//
//   (cd scripts && npm install) && node --test tests/ets-ingest-sql.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const requireFromScripts = createRequire(new URL("../scripts/package.json", import.meta.url));
const { PGlite } = await import(pathToFileURL(requireFromScripts.resolve("@electric-sql/pglite")).href);
const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
const migration = (name) => read(`supabase/migrations/${name}`);
const between = (s, from, to) => { const i = s.indexOf(from); assert.ok(i >= 0, from); const j = s.indexOf(to, i); assert.ok(j > i, to); return s.slice(i, j); };
const fixture = JSON.parse(read("tests/fixtures/ets-analysis-codes.json"));

const KEY = "ets_ingest_test_key_0123456789abcdefghijklmnopqrstuv";
const KEY_SHA = createHash("sha256").update(KEY).digest("hex");

let db;
const q = (sql, params) => db.query(sql, params);
const apply = async (payload, keySha = KEY_SHA) =>
  (await q("select public.ets_ingest_apply($1, $2::jsonb) as r", [keySha, JSON.stringify(payload)])).rows[0].r;
async function as(role, sql, params) {
  await q("begin");
  try { await q(`set local role ${role}`); return { rows: (await q(sql, params)).rows }; }
  catch (e) { return { error: e.message }; }
  finally { await q("rollback"); }
}

const maturity = (over = {}) => ({
  report_no: "2338065R", sample_id: "609290801", sample_name: "Mars 2 (berries)", block: null,
  sample_date: "2026-09-29", received_at: "2026-09-29T16:10:00-07:00", reported_at: "2026-09-30T09:00:00-07:00",
  source: "ets_pdf_email",
  analytes: [
    { name: "brix", value: 24.6, unit: "degrees", analysis_date: "2026-09-29 16:34" },
    { name: "pH", value: "3.52", unit: "", analysis_date: "2026-09-29 16:34" },
    { name: "titratable acidity", value: 6.1, unit: "g/L", analysis_date: "2026-09-29 16:34" },
    { name: "Dyostem Histogram: 0.5", value: 12, unit: null, analysis_date: "2026-09-29 16:58" },
  ],
  ...over,
});

before(async () => {
  db = new PGlite();
  const ets = migration("20260920120000_ets_berry_ingestion.sql");
  const winery = migration("20260920180000_ets_winery_ingestion.sql");
  await db.exec(`
    create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;
    grant usage on schema public to anon, authenticated, service_role;
    create schema auth; create function auth.uid() returns uuid language sql as $$ select null::uuid $$;
    create table user_profiles (id uuid primary key, role text, status text);
    create function current_role_name() returns text language sql stable security definer set search_path = public as $$
      select case when status = 'approved' then role else 'pending' end from user_profiles where id = auth.uid() $$;
    create table blocks (block_id text primary key);
    insert into blocks values ('B1'), ('B2'), ('B3');
    create table vintages (vintage int primary key);
    insert into vintages values (2022), (2023), (2024), (2025), (2026), (2027);
    create schema vault;
    create table vault.decrypted_secrets (name text, decrypted_secret text);
    insert into vault.decrypted_secrets values ('ets_ingest_key', '${KEY}'), ('edge_functions_secret_key', 'sb_secret_other');
  `);
  // The CSV path's tables and RLS exactly as the migrations made them.
  await db.exec(between(ets, "create table lab_samples (", "-- ── berry_maturity_by_block"));
  await db.exec(between(winery, "alter table lab_samples drop constraint", "-- ── Reconciliation"));
  await db.exec(between(migration("20260930100000_harvest_year_vintage.sql"), "create function public.harvest_vintage", "create or replace view"));
  await db.exec(migration("20260930020000_system_health.sql"));
  await db.exec(migration("20261006120000_ets_report_ingest.sql"));
  // Two CSV-ingested rows the PDF path must never overwrite.
  await db.exec(`
    insert into lab_samples (lab_sample_no, lab_group_no, sample_description_raw, sample_type, block_id, vintage, collected_on,
                             collected_on_source, received_on, source_file)
    values ('609220727', '2338065R', 'Mars 2 (berries)', 'berry_maturity', 'B2', 2026, '2026-09-22', 'inferred_from_receipt', '2026-09-22',
            'ETSLabsReport_17798_09_24_2026.csv');
    insert into lab_results (sample_id, analysis_name_raw, analysis_code, result_raw, result_numeric, result_operator, units, analyzed_at)
    select id, 'brix', 'brix', '25.1', 25.1, '=', 'degrees', '2026-09-22 16:34' from lab_samples where lab_sample_no = '609220727';
  `);
});

test("ets_analysis_code() equals parse.py's analysis_code_for() on every seed analysis name", async () => {
  for (const [name, code] of Object.entries(fixture.codes)) {
    const { rows: [r] } = await q("select public.ets_analysis_code($1) as c", [name]);
    assert.equal(r.c, code, name);
  }
});

test("ets_description_block equals parse.py's DESCRIPTION_BLOCK (berry entries)", async () => {
  const want = Object.entries(fixture.description_block).filter(([, b]) => b !== null).sort();
  const { rows } = await q("select description, block_id from ets_description_block order by 1");
  assert.deepEqual(rows.map((r) => [r.description, r.block_id]), want);
});

test("every seed analysis code of a vineyard sample type is in the spec; no winery code is", async () => {
  const { rows } = await q("select analysis_code, sample_type from ets_analyte_spec");
  const spec = new Set(rows.map((r) => r.analysis_code));
  for (const c of ["brix", "ph", "titratable_acidity", "l_malic_acid", "glucose_fructose", "berry_weight", "berry_volume",
    "berry_volume_variability", "sugar_per_berry_by_volume", "guaiacol", "cresols_sum"]) assert.ok(spec.has(c), c);
  for (const c of ["ethanol_at_20c", "volatile_acidity_acetic_acid", "free_sulfur_dioxide", "potassium"]) assert.ok(!spec.has(c), c);
  // The nine berry_maturity_by_block pivots on (parse_report_0924.MATURITY_CODES).
  const maturity = rows.filter((r) => r.sample_type === "berry_maturity" && r.analysis_code !== "dyostem_histogram").map((r) => r.analysis_code).sort();
  const py = read("ingestion/ets_labs/parse_report_0924.py").match(/MATURITY_CODES = \{([^}]*)\}/)[1].match(/"([a-z_]+)"/g).map((s) => s.slice(1, -1)).sort();
  assert.deepEqual(maturity, py);
});

test("wrong, missing or malformed key: 401, nothing written", async () => {
  for (const k of [createHash("sha256").update("nope").digest("hex"), "", null, KEY, "sb_secret_other"]) {
    const r = await apply(maturity(), k);
    assert.equal(r.http_status, 401, String(k));
  }
  assert.equal((await q("select count(*)::int n from ets_report_samples")).rows[0].n, 0);
  assert.equal((await q("select public.ets_ingest_key_ok($1) ok", [KEY_SHA])).rows[0].ok, true);
});

test("malformed payloads: 400 and nothing written", async () => {
  const cases = [
    [{ ...maturity(), source: "csv" }, /source/],
    [maturity({ report_no: "" }), /report_no/],
    [maturity({ sample_date: "9/29/2026" }), /sample_date/],
    [maturity({ received_at: "2026-09-29T16:10:00" }), /received_at/],
    [maturity({ analytes: [] }), /analytes/],
    [maturity({ analytes: [{ value: 1 }] }), /name/],
    [maturity({ analytes: [{ name: "brix", value: 1, unit: "degrees", analysis_date: "2026-09-29" }, { name: "brix", value: 2, unit: "degrees", analysis_date: "2026-09-29" }] }), /duplicate/],
    [maturity({ sample_date: "2026-02-30" }), /real date/],
  ];
  for (const [p, re] of cases) {
    const r = await apply(p);
    assert.equal(r.http_status, 400, JSON.stringify(r));
    assert.match(r.reason, re);
  }
  assert.equal((await q("select count(*)::int n from ets_ingest_quarantine")).rows[0].n, 0);
  assert.equal((await q("select count(*)::int n from ets_report_samples")).rows[0].n, 0);
});

test("a valid report writes the CSV path's rows: block from the description, harvest-year vintage, censored values", async () => {
  const p = maturity();
  p.analytes.push({ name: "L-malic acid", value: "< 0.5", unit: "g/L", analysis_date: "2026-09-29" });
  const r = await apply(p);
  assert.equal(r.http_status, 200, JSON.stringify(r));
  assert.deepEqual([r.written, r.quarantined], [5, 0]);
  assert.deepEqual(r.sample, { status: "written", lab_sample_no: "609290801", block_id: "B2", vintage: 2026, sample_type: "berry_maturity" });
  assert.ok(r.rows.every((x) => x.status === "written" && x.action === "inserted"));
  const { rows: [s] } = await q("select * from lab_samples where lab_sample_no = '609290801'");
  assert.equal(s.lab_group_no, "2338065R");
  assert.equal(s.collected_on_source, "report");
  assert.equal(s.source_system, "ets_labs");
  assert.equal(s.source_file, "ets_pdf_email");
  assert.equal(s.received_on.toISOString().slice(0, 10), "2026-09-29");
  const { rows } = await q(`select analysis_name_raw, analysis_code, result_raw, result_numeric::text, result_operator, units, analyzed_at
                              from lab_results r join lab_samples s on s.id = r.sample_id where s.lab_sample_no = '609290801' order by analysis_code`);
  assert.deepEqual(rows.map((x) => [x.analysis_name_raw, x.analysis_code, x.result_raw, x.result_numeric, x.result_operator, x.units]), [
    ["brix", "brix", "24.6", "24.6", "=", "degrees"],
    ["L-malic acid", "l_malic_acid", "< 0.5", "0.5", "<", "g/L"],
    ["pH", "ph", "3.52", "3.52", "=", null],
    ["titratable acidity", "titratable_acidity", "6.1", "6.1", "=", "g/L"],
  ]);
  // Wall-clock as UTC, the CSV path's convention.
  assert.equal(rows[0].analyzed_at.toISOString(), "2026-09-29T16:34:00.000Z");
  const { rows: [h] } = await q("select bin_ml::text, berry_count from berry_volume_histogram h join lab_samples s on s.id = h.sample_id where s.lab_sample_no = '609290801'");
  assert.deepEqual([h.bin_ml, h.berry_count], ["0.5", 12]);
  const { rows: [prov] } = await q("select report_no, source, reported_at from ets_report_samples where lab_sample_no = '609290801'");
  assert.equal(prov.report_no, "2338065R");
  assert.equal(prov.reported_at.toISOString(), "2026-09-30T16:00:00.000Z");
});

test("idempotent: the same report again updates in place; a corrected analysis_date moves the row, not duplicates it", async () => {
  const before = (await q("select count(*)::int n from lab_results")).rows[0].n;
  const p = maturity();
  p.analytes[0] = { ...p.analytes[0], value: 24.8, analysis_date: "2026-09-29 17:00" };
  const r = await apply(p);
  assert.equal(r.http_status, 200);
  assert.ok(r.rows.every((x) => x.action === "updated"), JSON.stringify(r.rows));
  assert.equal((await q("select count(*)::int n from lab_results")).rows[0].n, before);
  const { rows: [b] } = await q("select result_numeric::text v, analyzed_at from lab_results r join lab_samples s on s.id = r.sample_id where s.lab_sample_no = '609290801' and analysis_name_raw = 'brix'");
  assert.deepEqual([b.v, b.analyzed_at.toISOString()], ["24.8", "2026-09-29T17:00:00.000Z"]);
  assert.equal((await q("select count(*)::int n from lab_samples where lab_sample_no = '609290801'")).rows[0].n, 1);
});

test("unknown analyte, wrong unit, out of range: quarantined with a reason; the rest is written (207)", async () => {
  const p = maturity({ sample_id: "609290802", sample_name: "Mars 3 (berries)" });
  p.analytes = [
    { name: "brix", value: 23.9, unit: "degrees", analysis_date: "2026-09-29" },
    { name: "ethanol at 20C", value: 14.1, unit: "% vol", analysis_date: "2026-09-29" },
    { name: "titratable acidity", value: 6.4, unit: "mg/L", analysis_date: "2026-09-29" },
    { name: "pH", value: 35.2, unit: "", analysis_date: "2026-09-29" },
    { name: "berry weight", value: "n/a", unit: "g/berry", analysis_date: "2026-09-29" },
    { name: "Dyostem Histogram: 2.5", value: 3, unit: "", analysis_date: "2026-09-29" },
  ];
  const r = await apply(p);
  assert.equal(r.http_status, 207);
  assert.deepEqual([r.written, r.quarantined], [1, 5]);
  const by = Object.fromEntries(r.rows.map((x) => [x.analyte, x]));
  assert.match(by["ethanol at 20C"].reason, /unknown analyte/);
  assert.match(by["titratable acidity"].reason, /unit mg\/L is not accepted/);
  assert.match(by["pH"].reason, /outside 2.5..4.5/);
  assert.match(by["berry weight"].reason, /not a number/);
  assert.match(by["Dyostem Histogram: 2.5"].reason, /bin/);
  assert.equal((await q("select count(*)::int n from ets_ingest_quarantine where sample_id = '609290802'")).rows[0].n, 5);
  // Re-sent unchanged: same 5 quarantine rows, seen twice.
  await apply(p);
  assert.deepEqual((await q("select count(*)::int n, min(seen_count) s from ets_ingest_quarantine where sample_id = '609290802'")).rows[0], { n: 5, s: 2 });
  // Fixed and re-sent: the fixed row is written and leaves quarantine.
  p.analytes[2].unit = "g/L";
  const r2 = await apply(p);
  assert.equal(r2.quarantined, 4);
  assert.equal((await q("select count(*)::int n from ets_ingest_quarantine where sample_id = '609290802'")).rows[0].n, 4);
});

test("µg spellings are one unit; smoke markers are berry_smoke", async () => {
  const r = await apply(maturity({
    sample_id: "609290803", analytes: [
      { name: "guaiacol (GC/MS)", value: 1.2, unit: "ug/kg", analysis_date: "2026-09-29" },
      { name: "4-methylguaiacol GC MS/MS", value: "< 0.5", unit: "μg/kg", analysis_date: "2026-09-29" },
    ],
  }));
  assert.equal(r.http_status, 200, JSON.stringify(r));
  assert.equal(r.sample.sample_type, "berry_smoke");
  const { rows } = await q("select analysis_code, units from lab_results r join lab_samples s on s.id = r.sample_id where s.lab_sample_no = '609290803' order by 1");
  assert.deepEqual(rows.map((x) => [x.analysis_code, x.units]), [["4_methylguaiacol", "µg/kg"], ["guaiacol", "µg/kg"]]);
});

test("sample-level refusals quarantine every analyte and write nothing", async () => {
  const cases = [
    [maturity({ sample_id: "609220727" }), /already exists from ETSLabsReport_17798_09_24_2026.csv/],
    [maturity({ report_no: "OTHER1" }), /already belongs to report 2338065R/],
    [maturity({ sample_id: "609290801A", report_no: "R2" }), /lettered sample number/],
    [maturity({ sample_id: "ABC", report_no: "R3" }), /9-digit/],
    [maturity({ sample_id: "609290804", sample_name: "Unknown lot" }), /block unknown/],
    [maturity({ sample_id: "609290805", block: "B9" }), /not a known block/],
    [maturity({ sample_id: "609290806", block: "3" }), /disagrees with sample_name/],
    [maturity({ sample_id: "609290807", sample_date: "2029-06-01" }), /vintage 2029/],
    [maturity({ sample_id: "609290808", analytes: [
      { name: "brix", value: 24, unit: "degrees", analysis_date: "2026-09-29" },
      { name: "guaiacol (GC/MS)", value: 1, unit: "µg/kg", analysis_date: "2026-09-29" }] }), /mix/],
  ];
  const samplesBefore = (await q("select count(*)::int n from lab_samples")).rows[0].n;
  for (const [p, re] of cases) {
    const r = await apply(p);
    assert.equal(r.http_status, 207, JSON.stringify(r));
    assert.equal(r.written, 0);
    assert.equal(r.sample.status, "quarantined");
    assert.match(r.sample.reason, re);
    assert.ok(r.rows.every((x) => x.status === "quarantined"));
  }
  assert.equal((await q("select count(*)::int n from lab_samples")).rows[0].n, samplesBefore);
  // The CSV row is untouched.
  const { rows: [csv] } = await q("select r.result_numeric::text v, s.source_file from lab_results r join lab_samples s on s.id = r.sample_id where s.lab_sample_no = '609220727'");
  assert.deepEqual([csv.v, csv.source_file], ["25.1", "ETSLabsReport_17798_09_24_2026.csv"]);
});

test("block given explicitly as 'B3' / 'Block 3' / '3' for an unmapped name; harvest-year vintage rolls over on Nov 1", async () => {
  const r = await apply(maturity({ sample_id: "611020001", report_no: "R10", sample_name: "Late pick B3", block: "Block 3", sample_date: "2026-11-02" }));
  assert.equal(r.http_status, 200, JSON.stringify(r));
  assert.deepEqual([r.sample.block_id, r.sample.vintage], ["B3", 2027]);
  const r2 = await apply(maturity({ sample_id: "610310001", report_no: "R11", sample_name: "Late pick B3", block: "3", sample_date: "2026-10-31" }));
  assert.deepEqual([r2.sample.block_id, r2.sample.vintage], ["B3", 2026]);
});

test("RLS/grants: API roles cannot write any ETS table or call the functions; only service_role can call", async () => {
  for (const role of ["anon", "authenticated"]) {
    for (const t of ["ets_analyte_spec", "ets_description_block", "ets_report_samples", "ets_ingest_quarantine", "lab_samples", "lab_results", "berry_volume_histogram"]) {
      const { rows: [p] } = await q("select has_table_privilege($1, $2, 'INSERT,UPDATE,DELETE') as w", [role, `public.${t}`]);
      assert.equal(p.w, false, `${role} write ${t}`);
    }
    for (const f of ["public.ets_ingest_apply(text, jsonb)", "public.ets_ingest_key_ok(text)", "public.ets_analysis_code(text)"]) {
      const { rows: [p] } = await q("select has_function_privilege($1, $2, 'EXECUTE') as x", [role, f]);
      assert.equal(p.x, false, `${role} execute ${f}`);
    }
  }
  for (const t of ["ets_analyte_spec", "ets_description_block", "ets_report_samples", "ets_ingest_quarantine"]) {
    const { rows: [p] } = await q("select has_table_privilege('service_role', $1, 'SELECT,INSERT,UPDATE,DELETE') as any", [`public.${t}`]);
    assert.equal(p.any, false, `service_role ${t}`);
  }
  for (const t of ["ets_analyte_spec", "ets_description_block"]) {
    const { rows: [p] } = await q("select has_table_privilege('authenticated', $1, 'SELECT') as r", [`public.${t}`]);
    assert.equal(p.r, false, `authenticated select ${t}`);
  }
  const svc = await as("service_role", "select (public.ets_ingest_apply($1, '{}'::jsonb))->>'http_status' s", [KEY_SHA]);
  assert.equal(svc.rows?.[0]?.s, "400", svc.error);
});

test("RLS: quarantine and provenance readable by approved operators only; lab_samples read access unchanged", async () => {
  await q(`insert into user_profiles values ('00000000-0000-0000-0000-000000000001', 'operator', 'approved'),
                                            ('00000000-0000-0000-0000-000000000002', 'customer', 'approved'),
                                            ('00000000-0000-0000-0000-000000000003', 'operator', 'pending')`);
  const readAs = async (uid, t) => {
    await q("begin");
    try {
      await q(`create or replace function auth.uid() returns uuid language sql as $$ select '${uid}'::uuid $$`);
      await q("set local role authenticated");
      return (await q(`select count(*)::int n from public.${t}`)).rows[0].n;
    } finally { await q("rollback"); }
  };
  for (const t of ["ets_ingest_quarantine", "ets_report_samples", "lab_samples"]) {
    assert.ok(await readAs("00000000-0000-0000-0000-000000000001", t) > 0, `operator ${t}`);
    assert.equal(await readAs("00000000-0000-0000-0000-000000000002", t), 0, `customer ${t}`);
    assert.equal(await readAs("00000000-0000-0000-0000-000000000003", t), 0, `pending operator ${t}`);
  }
  const { rows } = await q("select tablename, policyname, cmd from pg_policies where tablename like 'ets_%' order by 1");
  assert.deepEqual(rows.map((r) => [r.tablename, r.cmd]), [["ets_ingest_quarantine", "SELECT"], ["ets_report_samples", "SELECT"]]);
});

test("ingestion_runs accepts the new asset", async () => {
  await q("select public.log_ingestion_run('ingest-ets-report', now(), 'partial', 207, 1, null, null)");
  assert.equal((await q("select count(*)::int n from system_health.ingestion_runs where asset = 'ingest-ets-report'")).rows[0].n, 1);
});
