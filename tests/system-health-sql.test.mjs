// Offline tests for supabase/migrations/20260930020000_system_health.sql on
// PGlite (real Postgres in WASM: roles, GRANTs, RLS and SECURITY DEFINER behave
// as on the server).
//
//   (cd scripts && npm install) && node --test tests/system-health-sql.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const requireFromScripts = createRequire(new URL("../scripts/package.json", import.meta.url));
const load = (spec) => import(pathToFileURL(requireFromScripts.resolve(spec)).href);
const { PGlite } = await load("@electric-sql/pglite");
const migration = (name) => readFileSync(new URL(`../supabase/migrations/${name}`, import.meta.url), "utf8");

let db;
const q = (sql, params) => db.query(sql, params);
// Runs sql as role inside a rolled-back transaction; returns rows or the error message.
async function as(role, sql, params) {
  await q("begin");
  try {
    await q(`set local role ${role}`);
    const r = await q(sql, params);
    return { rows: r.rows };
  } catch (e) {
    return { error: e.message };
  } finally {
    await q("rollback");
  }
}

before(async () => {
  db = new PGlite();
  await db.exec(`
    create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;
    grant usage on schema public to anon, authenticated, service_role;
  `);
  await db.exec(migration("20260930020000_system_health.sql"));
});

test("tables: RLS on, zero policies, no privilege for any API role or health_writer", async () => {
  const { rows } = await q(`select c.relname, c.relrowsecurity,
      (select count(*) from pg_policies p where p.schemaname='system_health' and p.tablename=c.relname)::int as policies
    from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='system_health' and c.relkind='r' order by 1`);
  assert.deepEqual(rows.map((r) => r.relname), ["health_baselines", "health_results", "health_runs", "ingestion_runs"]);
  for (const r of rows) { assert.equal(r.relrowsecurity, true, r.relname); assert.equal(r.policies, 0, r.relname); }
  for (const role of ["anon", "authenticated", "service_role", "health_writer"]) {
    for (const t of rows.map((r) => r.relname)) {
      const { rows: [p] } = await q(`select has_table_privilege($1, 'system_health.' || $2, 'SELECT,INSERT,UPDATE,DELETE') as any`, [role, t]);
      assert.equal(p.any, false, `${role} on ${t}`);
    }
  }
});

test("health_writer: can open a run and record results, nothing else", async () => {
  const run = await as("health_writer", "select system_health.record_run('p2_probes') as id");
  assert.ok(run.rows?.[0]?.id, run.error);
  for (const sql of [
    "select * from system_health.health_runs",
    "insert into system_health.health_runs(producer) values ('p1_database')",
    "select public.log_ingestion_run('ingest-innovint', now(), 'success')",
    "select system_health.prune()",
  ]) {
    const r = await as("health_writer", sql);
    assert.match(r.error ?? "", /permission denied/, sql);
  }
  const role = (await q("select rolcanlogin, rolbypassrls, rolinherit, rolconnlimit from pg_roles where rolname='health_writer'")).rows[0];
  assert.deepEqual(role, { rolcanlogin: false, rolbypassrls: false, rolinherit: false, rolconnlimit: 5 });
  const members = (await q("select count(*)::int n from pg_auth_members m join pg_roles r on r.oid=m.member where r.rolname='health_writer'")).rows[0].n;
  assert.equal(members, 0, "health_writer is a member of no role");
});

test("record_result keeps the run status the worst of its results", async () => {
  await q("begin");
  await q("set local role health_writer");
  const { rows: [{ id }] } = await q("select system_health.record_run('p3_frontend') as id");
  const status = async () => { await q("reset role"); const s = (await q("select status, finished_at is not null as fin from system_health.health_runs where id=$1", [id])).rows[0]; await q("set local role health_writer"); return s; };
  await q("select system_health.record_result($1, 'frontend', 'frontend.a', 'pass')", [id]);
  assert.deepEqual(await status(), { status: "pass", fin: true });
  await q("select system_health.record_result($1, 'frontend', 'frontend.b', 'warn', '{\"x\":1}', '{\"x\":0}', 'detail')", [id]);
  assert.equal((await status()).status, "warn");
  await q("select system_health.record_result($1, 'frontend', 'frontend.c', 'fail')", [id]);
  await q("select system_health.record_result($1, 'frontend', 'frontend.d', 'pass')", [id]);
  assert.equal((await status()).status, "fail");
  await assert.rejects(q("select system_health.record_result($1, 'frontend', 'frontend.a', 'pass')", [id]), /duplicate key/);
  await q("rollback");
});

test("writers can't rewrite history or send oversized payloads", async () => {
  assert.match((await as("health_writer", "select system_health.record_run('p2_probes', now() - interval '4 hours')")).error, /within the last 3 hours/);
  const { rows: [{ id }] } = await q("insert into system_health.health_runs(producer, started_at) values ('p2_probes', now() - interval '4 hours') returning id");
  assert.match((await as("health_writer", "select system_health.record_result($1, 'source', 'source.x', 'pass')", [id])).error, /closed/);
  const { rows: [{ id: open }] } = await q("select system_health.record_run('p2_probes') as id");
  assert.match((await as("health_writer", "select system_health.record_result($1, 'source', 'source.big', 'pass', jsonb_build_object('x', repeat('a', 70000)))", [open])).error, /64 KB/);
  assert.match((await as("health_writer", "select system_health.record_result($1, 'nope', 'source.y', 'pass')", [open])).error, /check constraint/);
  assert.match((await as("health_writer", "select system_health.record_result($1, 'source', 'Bad Id!', 'pass')", [open])).error, /check constraint/);
});

test("log_ingestion_run: service_role only; anon/authenticated denied", async () => {
  const ok = await as("service_role", "select public.log_ingestion_run('ingest-climate-2026', now(), 'partial', 207, 12, 'soil failed', '{\"a\":1}') as id");
  assert.ok(ok.rows?.[0]?.id, ok.error);
  for (const role of ["anon", "authenticated"]) {
    assert.match((await as(role, "select public.log_ingestion_run('ingest-innovint', now(), 'success')")).error ?? "", /permission denied/, role);
  }
  assert.match((await as("service_role", "select * from system_health.ingestion_runs")).error ?? "", /permission denied/);
  assert.match((await as("service_role", "select public.log_ingestion_run('other-asset', now(), 'success')")).error ?? "", /check constraint/);
});

test("prune deletes only rows older than the retention window, never baselines", async () => {
  await db.exec("delete from system_health.health_runs; delete from system_health.ingestion_runs; delete from system_health.health_baselines");
  await q("insert into system_health.health_runs(producer, started_at) values ('p1_database', now() - interval '91 days'), ('p1_database', now() - interval '89 days')");
  await q("insert into system_health.ingestion_runs(asset, started_at, status) values ('ingest-innovint', now() - interval '100 days', 'success'), ('ingest-innovint', now(), 'success')");
  await q("insert into system_health.health_baselines(check_id, value, set_by) values ('db.x', '1', 'test')");
  const { rows: [{ prune }] } = await q("select system_health.prune() as prune");
  assert.deepEqual(prune, { health_runs_deleted: 1, ingestion_runs_deleted: 1 });
  assert.equal((await q("select count(*)::int n from system_health.health_baselines")).rows[0].n, 1);
});
