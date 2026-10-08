// Offline tests for supabase/migrations/20261007120000_chat_tool_scope.sql on
// PGlite, over the real lab/lot DDL and RLS from their own migrations: the two
// scope functions (full match sets with no row cap, cross-source pointers,
// temperature variants, Pacific/wall-clock bounds) and the provenance columns
// on berry_maturity_by_block. docs/SECURITY.md, "Chat tool findings".
//
//   (cd scripts && npm install) && node --test tests/chat-tool-scope-sql.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const requireFromScripts = createRequire(new URL("../scripts/package.json", import.meta.url));
const { PGlite } = await import(pathToFileURL(requireFromScripts.resolve("@electric-sql/pglite")).href);
const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
const migration = (name) => read(`supabase/migrations/${name}`);
const between = (s, from, to) => { const i = s.indexOf(from); assert.ok(i >= 0, from); const j = to ? s.indexOf(to, i) : s.length; assert.ok(j > i, to); return s.slice(i, j); };

const OPERATOR = "00000000-0000-0000-0000-00000000000a";
const CUSTOMER = "00000000-0000-0000-0000-00000000000c";
const NEW_MIGRATION = migration("20261007120000_chat_tool_scope.sql");

let db;
const q = (sql, params) => db.query(sql, params);
// Run one statement as `role` with auth.uid() = uid, in a rolled-back transaction.
async function as(role, uid, sql, params) {
  await q("begin");
  try {
    await q(`select set_config('test.uid', $1, true)`, [uid ?? ""]);
    await q(`set local role ${role}`);
    return { rows: (await q(sql, params)).rows };
  } catch (e) { return { error: e.message }; }
  finally { await q("rollback"); }
}
const lotScope = async (args, uid = OPERATOR, role = "authenticated") => {
  const r = await as(role, uid, `select public.chat_lot_analyses_scope(
      p_lot_code => $1, p_lot_name => $2, p_analysis_type => $3,
      p_start => $4::timestamptz, p_end_exclusive => $5::timestamptz, p_end_inclusive => $6::timestamptz) as s`,
    [args.lot_code ?? null, args.lot_name ?? null, args.analysis_type ?? null, args.start ?? null, args.end_exclusive ?? null, args.end_inclusive ?? null]);
  if (r.error) throw new Error(r.error);
  return r.rows[0].s;
};
const etsScope = async (args, uid = OPERATOR, role = "authenticated") => {
  const r = await as(role, uid, `select public.chat_ets_winery_scope(
      p_sample_type => $1, p_description => $2, p_lab_sample_no => $3, p_lot_code => $4, p_vintage => $5::int,
      p_analysis_code => $6, p_start => $7::timestamptz, p_end_exclusive => $8::timestamptz, p_end_inclusive => $9::timestamptz) as s`,
    [args.sample_type ?? null, args.description ?? null, args.lab_sample_no ?? null, args.lot_code ?? null, args.vintage ?? null,
     args.analysis_code ?? null, args.start ?? null, args.end_exclusive ?? null, args.end_inclusive ?? null]);
  if (r.error) throw new Error(r.error);
  return r.rows[0].s;
};

before(async () => {
  db = new PGlite();
  // PostgREST and the gateway's connection both run in UTC.
  await db.exec(`set timezone to 'UTC';`);
  await db.exec(`
    create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;
    create role mcp_reader nologin noinherit nobypassrls;
    grant usage on schema public to anon, authenticated, service_role, mcp_reader;
    create schema auth; grant usage on schema auth to authenticated, mcp_reader, anon;
    create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('test.uid', true), '')::uuid $$;
    grant execute on function auth.uid() to authenticated, mcp_reader, anon;
    create table user_profiles (id uuid primary key, role text, status text);
    insert into user_profiles values ('${OPERATOR}', 'operator', 'approved'), ('${CUSTOMER}', 'customer', 'approved');
    create function current_role_name() returns text language sql stable security definer set search_path = public as $$
      select case when status = 'approved' then role else 'pending' end from user_profiles where id = auth.uid() $$;
    grant execute on function current_role_name() to authenticated, mcp_reader;
    create table blocks (block_id text primary key);
    insert into blocks values ('B1'), ('B2'), ('B3');
    create table vintages (vintage int primary key);
    insert into vintages values (2022), (2023), (2024), (2025), (2026), (2027);
  `);
  const ets = migration("20260920120000_ets_berry_ingestion.sql");
  const winery = migration("20260920180000_ets_winery_ingestion.sql");
  const lv = migration("20260811215238_lot_analyses_vessels.sql");
  // Lab tables and RLS exactly as their migrations made them.
  await db.exec(between(ets, "create table lab_samples (", "-- ── berry_maturity_by_block"));
  await db.exec(between(winery, "alter table lab_samples drop constraint", "-- ── Reconciliation"));
  await db.exec(between(winery, "create table ets_lot_bridge (", "create view ets_lot_analyses_reconciliation"));
  await db.exec(between(migration("20261006120000_ets_report_ingest.sql"), "alter table lab_samples drop constraint lab_samples_collected_on_source_check", "\n\n"));
  await db.exec(between(migration("20260920130000_lab_results_current.sql"), "create view lab_results_current as", "create or replace view berry_maturity_by_block"));
  await db.exec(between(migration("20260920140000_lab_samples_current.sql"), "create view lab_samples_current as", null));
  // InnoVint lot tables and RLS.
  await db.exec(between(lv, "create table lot_analyses (", "-- One row per InnoVint vessel"));
  await db.exec(between(migration("20260811231659_lot_names.sql"), "alter table lot_analyses add column", ";") + ";");
  // RLS on lot_analyses: on in production, stated in a migration only since
  // 20261007130000 (Supabase had enabled it on create). vessels isn't built here.
  await db.exec(migration("20261007130000_lot_analyses_vessels_rls.sql").replace("alter table public.vessels enable row level security;", ""));
  await db.exec(between(migration("20260920150000_lot_canonical_map.sql"), "create table lot_canonical_map (", "-- ── Resolved clusters"));
  // mcp_reader's SELECT set for these relations (20260926150000).
  await db.exec(`grant select on lab_samples_current, lab_results_current, berry_maturity_by_block, lot_analyses, lot_canonical_map,
                  lab_samples, lab_results, ets_lot_bridge to mcp_reader;`);

  // Seed: the production cases Colin hit, at their production shapes.
  await db.exec(`
    insert into lab_samples (lab_sample_no, lab_group_no, sample_description_raw, sample_type, block_id, vintage, collected_on, collected_on_source, received_on, source_file) values
      ('310310429', 'G1', 'T-7 V-2 (fermenting)', 'ferment', 'B2', 2023, '2023-10-31', 'inferred_from_receipt', '2023-10-31', 'f.csv'),
      ('602250939', 'G2', 'MA24CS', 'wine', null, 2024, '2026-02-25', 'inferred_from_receipt', '2026-02-25', 'f.csv'),
      ('411131659', 'G3', 'MA24CSV2', 'wine', null, 2024, '2024-11-13', 'inferred_from_receipt', '2024-11-13', 'f.csv'),
      ('411131660', 'G3', 'MA23CSV3', 'wine', null, 2023, '2024-11-13', 'inferred_from_receipt', '2024-11-13', 'f.csv'),
      ('608140601', 'G4', '26MARCH', 'must', null, 2026, '2026-08-14', 'inferred_from_receipt', '2026-08-14', 'f.csv'),
      ('608250190', 'G5', 'Mars 2 (berries)', 'berry_maturity', 'B2', 2026, '2026-08-25', 'description', '2026-08-25', 'f.csv'),
      ('609220727', 'G6', 'Mars 2 (berries)', 'berry_maturity', 'B2', 2026, '2026-09-22', 'inferred_from_receipt', '2026-09-22', 'f.csv'),
      ('609300127', 'G7', 'Mars 2 (berries)', 'berry_maturity', 'B2', 2026, '2026-09-30', 'report', '2026-09-30', 'r.pdf'),
      ('508260303', 'G8', 'Mars 2 smoke', 'berry_smoke', 'B2', 2025, '2025-08-26', 'inferred_from_receipt', '2025-08-26', 'f.csv');
    insert into lab_results (sample_id, analysis_name_raw, analysis_code, result_raw, result_numeric, result_operator, units, analyzed_at)
    select s.id, v.name, v.code, v.raw, v.raw::numeric, '=', v.units, v.at::timestamptz
      from (values
        ('310310429', 'ethanol at 20C', 'ethanol_at_20c', '8.1', '% vol', '2023-11-01 15:03+00'),
        ('310310429', 'glucose + fructose', 'glucose_fructose', '115', 'g/L', '2023-11-01 15:03+00'),
        ('602250939', 'ethanol at 20C', 'ethanol_at_20c', '15.22', '% vol', '2026-02-25 15:39+00'),
        ('602250939', 'ethanol at 60F', 'ethanol_at_60f', '15.14', '% vol', '2026-02-25 15:56+00'),
        ('411131659', 'ethanol at 20C', 'ethanol_at_20c', '14.85', '% vol', '2024-11-13 10:00+00'),
        ('411131660', 'ethanol at 20C', 'ethanol_at_20c', '14.82', '% vol', '2024-11-13 10:00+00'),
        ('608250190', 'brix', 'brix', '23.0', 'degrees', '2026-08-25 16:34+00'),
        ('609220727', 'brix', 'brix', '25.4', 'degrees', '2026-09-22 16:34+00'),
        ('609300127', 'brix', 'brix', '26.7', 'degrees', '2026-09-30 16:34+00'),
        ('508260303', 'guaiacol', 'guaiacol', '1', 'µg/kg', '2025-08-27 12:00+00')
      ) v(no, name, code, raw, units, at) join lab_samples s on s.lab_sample_no = v.no;
    -- 26MARCH: 11 results on 2026-08-14 lab wall-clock time (00:00Z..23:00Z).
    insert into lab_results (sample_id, analysis_name_raw, analysis_code, result_raw, result_numeric, result_operator, units, analyzed_at)
    select s.id, 'a' || g, 'code_' || g, '1', 1, '=', 'x', '2026-08-14 00:00+00'::timestamptz + (g * 2 || ' hours')::interval
      from lab_samples s, generate_series(0, 10) g where s.lab_sample_no = '608140601';

    insert into lot_canonical_map (duplicate_lot_code, canonical_lot_code, confidence) values ('MA23CSV322', 'MA23CSV3', 'confirmed');
    -- MA24CSV3: 1,300 rows (more than PostgREST's 1,000 db-max-rows), first
    -- 2024-10-01, last 2026-02-03 -- the range the capped scan got wrong.
    insert into lot_analyses (source_id, lot_id, analysis_type, value, unit, recorded_at, lot_name, lot_code)
    select 'v3-' || g, 'lot_v3', case when g % 2 = 0 then 'brix' else 'temperature' end, 20, 'x',
           '2024-10-01 07:00+00'::timestamptz + (g * (date '2026-02-03' - date '2024-10-01') / 1299.0 || ' days')::interval,
           '2024 Cabernet Sauvignon, V3', 'MA24CSV3'
      from generate_series(0, 1299) g;
    insert into lot_analyses (source_id, lot_id, analysis_type, value, unit, recorded_at, lot_name, lot_code) values
      ('v3-e20', 'lot_v3', 'ethanol-20c', 14.8, '%', '2025-03-01 18:00+00', '2024 Cabernet Sauvignon, V3', 'MA24CSV3'),
      ('v3-e60', 'lot_v3', 'ethanol-60f', 14.7, '%', '2025-03-01 18:00+00', '2024 Cabernet Sauvignon, V3', 'MA24CSV3'),
      ('dup-1', 'lot_dup', 'brix', 22, 'Brix', '2023-10-27 07:00+00', 'Cabernet Sauvignon, V3', 'MA23CSV322'),
      ('can-1', 'lot_can', 'brix', 22, 'Brix', '2023-10-27 07:00+00', 'Cabernet Sauvignon, V3', 'MA23CSV3');
    -- MA22CS: 9 readings at 07:00Z = local midnight Pacific, 2024-05-01.
    insert into lot_analyses (source_id, lot_id, analysis_type, value, unit, recorded_at, lot_name, lot_code)
    select 'cs-' || g, 'lot_cs', 'ph', 3.5, '', '2024-05-01 07:00+00', 'Estate Blend', 'MA22CS' from generate_series(1, 9) g;
    -- An evening Pacific reading (2024-05-01 17:00 PDT = 2024-05-02 00:00Z).
    insert into lot_analyses (source_id, lot_id, analysis_type, value, unit, recorded_at, lot_name, lot_code)
    values ('cs-eve', 'lot_cs', 'ph', 3.6, '', '2024-05-02 00:00+00', 'Estate Blend', 'MA22CS');
  `);
  // The view as it was, then the new migration on top: proves the
  // column-append is a valid CREATE OR REPLACE over the existing view.
  await db.exec(NEW_MIGRATION);
});

test("chat_lot_analyses_scope counts and ranges every matching row -- no 1000-row cap (Colin 3a)", async () => {
  const s = await lotScope({ lot_code: "MA24CSV3" });
  const lot = s.lots.find((l) => l.lot_code === "MA24CSV3");
  assert.equal(lot.n, 1302);
  assert.equal(s.total, 1302);
  assert.equal(new Date(lot.first_at).toISOString(), "2024-10-01T07:00:00.000Z");
  assert.equal(new Date(lot.last_at).toISOString(), "2026-02-03T07:00:00.000Z");
  // Broad, unfiltered: every lot present, ranges identical to the targeted ones.
  const broad = await lotScope({});
  assert.equal(broad.total, 1302 + 10 + 1);
  assert.deepEqual(broad.lots.map((l) => l.lot_code), ["MA22CS", "MA23CSV3", "MA24CSV3"]);
  assert.equal(broad.lots.find((l) => l.lot_code === "MA24CSV3").last_at, lot.last_at);
});

test("superseded duplicates: excluded from a lot_name search, honored for an explicit lot_code", async () => {
  const byName = await lotScope({ lot_name: "Cabernet Sauvignon, V3" });
  assert.deepEqual(byName.lots.map((l) => l.lot_code), ["MA23CSV3", "MA24CSV3"]);
  const explicit = await lotScope({ lot_code: "MA23CSV322" });
  assert.equal(explicit.total, 1);
});

test("Pacific-day bounds: [D 07:00Z, D+1 07:00Z) for May 1, 2024 keeps all 10 readings, the evening one too (Colin 2a)", async () => {
  const day = await lotScope({ lot_code: "MA22CS", start: "2024-05-01T07:00:00Z", end_exclusive: "2024-05-02T07:00:00Z" });
  assert.equal(day.total, 10);
  // The old lte-midnight bound: zero.
  const old = await lotScope({ lot_code: "MA22CS", start: "2024-05-01", end_inclusive: "2024-05-01" });
  assert.equal(old.total, 0);
});

test("analysis_types lists every type for the matched lots, so ethanol-60f surfaces next to ethanol-20c (Colin 1b)", async () => {
  const s = await lotScope({ lot_code: "MA24CSV3", analysis_type: "ethanol-20c" });
  assert.equal(s.total, 1);
  assert.deepEqual(s.analysis_types.map((t) => t.analysis_type).filter((t) => t.startsWith("ethanol")), ["ethanol-20c", "ethanol-60f"]);
});

test("no InnoVint lot: ets_samples points at the ETS sample by description, number or bridge (Colin 1a)", async () => {
  const byName = await lotScope({ lot_name: "T-7 V-2" });
  assert.equal(byName.total, 0);
  assert.deepEqual(byName.ets_samples.map((e) => [e.lab_sample_no, e.sample_type, e.n_results, e.analysis_codes]),
    [["310310429", "ferment", 2, "ethanol_at_20c, glucose_fructose"]]);
  assert.equal((await lotScope({ lot_code: "310310429" })).ets_samples[0].lab_sample_no, "310310429");
  assert.deepEqual((await lotScope({ lot_code: "MA23CSV3-AP" })).ets_samples.map((e) => e.lab_sample_no), ["411131660"]);
  // A lot that exists in InnoVint gets no pointer.
  assert.deepEqual((await lotScope({ lot_code: "MA22CS" })).ets_samples, []);
});

test("chat_ets_winery_scope: lab_sample_no exact, a number passed as description, lot_code exact or bridged (Colin 2b)", async () => {
  assert.deepEqual((await etsScope({ lab_sample_no: "608140601" })).samples.map((s) => s.sample_description_raw), ["26MARCH"]);
  assert.deepEqual((await etsScope({ description: "310310429" })).samples.map((s) => s.lab_sample_no), ["310310429"]);
  assert.deepEqual((await etsScope({ description: "T-7 V-2" })).samples.map((s) => s.lab_sample_no), ["310310429"]);
  // 'MA24CS' as a description is a substring of MA24CSV2; as a lot_code it is exact.
  assert.deepEqual((await etsScope({ description: "MA24CS" })).samples.map((s) => s.sample_description_raw).sort(), ["MA24CS", "MA24CSV2"]);
  assert.deepEqual((await etsScope({ lot_code: "MA24CS" })).samples.map((s) => s.sample_description_raw), ["MA24CS"]);
  assert.deepEqual((await etsScope({ lot_code: "MA23CSV3-AP" })).samples.map((s) => s.lab_sample_no), ["411131660"]);
  const s = (await etsScope({ lab_sample_no: "310310429" })).samples[0];
  assert.equal(s.collected_on_source, "inferred_from_receipt");
});

test("chat_ets_winery_scope: analysis_codes carries both ethanol variants; total honors code and bounds (Colin 1b, 2a)", async () => {
  const v = await etsScope({ lot_code: "MA24CS", analysis_code: "ethanol_at_20c" });
  assert.equal(v.total, 1);
  assert.deepEqual(v.analysis_codes.map((c) => c.analysis_code), ["ethanol_at_20c", "ethanol_at_60f"]);
  // Same-day, wall-clock: [2026-08-14 00:00Z, 2026-08-15 00:00Z) -> 11.
  assert.equal((await etsScope({ description: "26MARCH", start: "2026-08-14T00:00:00Z", end_exclusive: "2026-08-15T00:00:00Z" })).total, 11);
  assert.equal((await etsScope({ description: "26MARCH", start: "2026-08-14", end_inclusive: "2026-08-14" })).total, 1, "the old lte-midnight bound kept only the 00:00 result");
});

test("chat_ets_winery_scope: no winery sample -> vineyard and InnoVint pointers; none when it matches", async () => {
  const vineyard = await etsScope({ lab_sample_no: "609220727" });
  assert.deepEqual(vineyard.samples, []);
  assert.deepEqual(vineyard.vineyard_samples.map((x) => [x.lab_sample_no, x.sample_type, x.block_id]), [["609220727", "berry_maturity", "B2"]]);
  const lots = await etsScope({ description: "MA22CS" });
  assert.deepEqual(lots.innovint_lots.map((l) => [l.lot_code, l.n]), [["MA22CS", 10]]);
  const hit = await etsScope({ description: "26MARCH" });
  assert.deepEqual([hit.vineyard_samples, hit.innovint_lots], [[], []]);
});

test("berry_maturity_by_block: provenance appended, existing columns unchanged (Colin 4)", async () => {
  const cols = (await q(`select attname from pg_attribute where attrelid = 'berry_maturity_by_block'::regclass and attnum > 0 order by attnum`)).rows.map((r) => r.attname);
  assert.deepEqual(cols, ["block_id", "collected_on", "vintage", "brix", "ph", "titratable_acidity", "l_malic_acid", "glucose_fructose",
    "berry_weight_g", "berry_volume_ml", "berry_volume_variability_pct", "sugar_per_berry_mg", "lab_sample_no", "collected_on_source", "collected_on_inferred"]);
  const r = await as("authenticated", OPERATOR, `select to_char(collected_on, 'YYYY-MM-DD') d, brix::text, lab_sample_no, collected_on_source, collected_on_inferred from berry_maturity_by_block order by collected_on`);
  assert.deepEqual(r.rows.map((x) => [x.d, x.brix, x.lab_sample_no, x.collected_on_source, x.collected_on_inferred]), [
    ["2026-08-25", "23.0", "608250190", "description", false],
    ["2026-09-22", "25.4", "609220727", "inferred_from_receipt", true],
    ["2026-09-30", "26.7", "609300127", "report", false],
  ]);
  const opts = (await q(`select reloptions from pg_class where oid = 'berry_maturity_by_block'::regclass`)).rows[0].reloptions;
  assert.deepEqual(opts, ["security_invoker=true"]);
});

test("RLS still decides: a customer sees nothing through either function or the view", async () => {
  const lot = await lotScope({ lot_code: "MA24CSV3" }, CUSTOMER);
  assert.deepEqual([lot.total, lot.lots, lot.ets_samples], [0, [], []]);
  assert.deepEqual((await lotScope({ lot_name: "T-7" }, CUSTOMER)).ets_samples, []);
  const ets = await etsScope({ description: "MA24CS" }, CUSTOMER);
  assert.deepEqual([ets.samples, ets.total, ets.innovint_lots], [[], 0, []]);
  assert.deepEqual((await as("authenticated", CUSTOMER, "select * from berry_maturity_by_block")).rows, []);
});

test("privileges: SECURITY INVOKER, search_path pinned, EXECUTE for authenticated and mcp_reader, never anon", async () => {
  const fns = (await q(`select proname, prosecdef, provolatile, proconfig from pg_proc where proname in ('chat_lot_analyses_scope', 'chat_ets_winery_scope') order by 1`)).rows;
  assert.deepEqual(fns.map((f) => [f.proname, f.prosecdef, f.provolatile, f.proconfig]), [
    ["chat_ets_winery_scope", false, "s", ["search_path=public"]],
    ["chat_lot_analyses_scope", false, "s", ["search_path=public"]],
  ]);
  for (const fn of ["chat_lot_analyses_scope(text,text,text,timestamptz,timestamptz,timestamptz)", "chat_ets_winery_scope(text,text,text,text,integer,text,timestamptz,timestamptz,timestamptz)"]) {
    const p = (await q(`select has_function_privilege('anon', $1, 'execute') a, has_function_privilege('authenticated', $1, 'execute') u,
                               has_function_privilege('mcp_reader', $1, 'execute') m, has_function_privilege('public', $1, 'execute') p`, [`public.${fn}`])).rows[0];
    assert.deepEqual(p, { a: false, u: true, m: true, p: false }, fn);
  }
  assert.match((await as("anon", null, "select public.chat_lot_analyses_scope()")).error ?? "", /permission denied/);
  // mcp_reader with the operator's claims: the gateway's path works.
  assert.equal((await lotScope({ lot_code: "MA24CSV3" }, OPERATOR, "mcp_reader")).total, 1302);
  assert.equal((await etsScope({ lot_code: "MA24CS" }, OPERATOR, "mcp_reader")).samples.length, 1);
});
