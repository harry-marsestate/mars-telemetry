// Offline test for supabase/migrations/20261007130000_lot_analyses_vessels_rls.sql
// on PGlite: lot_analyses and vessels exactly as 20260811215238 created them
// (policies and grants, but RLS never enabled), then this migration.
//
//   (cd scripts && npm install) && node --test tests/lot-vessels-rls-sql.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const requireFromScripts = createRequire(new URL("../scripts/package.json", import.meta.url));
const { PGlite } = await import(pathToFileURL(requireFromScripts.resolve("@electric-sql/pglite")).href);
const migration = (n) => readFileSync(new URL(`../supabase/migrations/${n}`, import.meta.url), "utf8");

const OPERATOR = "00000000-0000-0000-0000-00000000000a";
const CUSTOMER = "00000000-0000-0000-0000-00000000000c";
let db;
async function count(uid, table) {
  await db.query("begin");
  try {
    await db.query("select set_config('test.uid', $1, true)", [uid]);
    await db.query("set local role authenticated");
    return Number((await db.query(`select count(*)::int n from public.${table}`)).rows[0].n);
  } finally { await db.query("rollback"); }
}

before(async () => {
  db = new PGlite();
  await db.exec(`
    create role anon nologin; create role authenticated nologin;
    grant usage on schema public to anon, authenticated;
    create schema auth; grant usage on schema auth to authenticated;
    create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('test.uid', true), '')::uuid $$;
    create table user_profiles (id uuid primary key, role text, status text);
    insert into user_profiles values ('${OPERATOR}', 'operator', 'approved'), ('${CUSTOMER}', 'customer', 'approved');
    create function current_role_name() returns text language sql stable security definer set search_path = public as $$
      select case when status = 'approved' then role else 'pending' end from user_profiles where id = auth.uid() $$;
    grant execute on function current_role_name() to authenticated;
    create table blocks (block_id text primary key); insert into blocks values ('B1'), ('B2'), ('B3');
  `);
  await db.exec(migration("20260811215238_lot_analyses_vessels.sql"));
  await db.exec(`
    insert into lot_analyses (source_id, lot_id, analysis_type, value, unit, recorded_at) values ('a1', 'l1', 'brix', 24, 'Brix', now());
    insert into vessels (vessel_id, code, vessel_type, archived) values ('v1', 'T1', 'tank', false);
  `);
});

test("before: the policies exist but RLS is off, so a customer reads every row (the gap)", async () => {
  assert.equal(await count(CUSTOMER, "lot_analyses"), 1);
  assert.equal(await count(CUSTOMER, "vessels"), 1);
});

test("after: RLS enabled (not forced), customer sees nothing, operator sees everything; re-running is a no-op", async () => {
  await db.exec(migration("20261007130000_lot_analyses_vessels_rls.sql"));
  const flags = (await db.query(`select relname, relrowsecurity, relforcerowsecurity from pg_class
                                  where relname in ('lot_analyses', 'vessels') order by relname`)).rows;
  assert.deepEqual(flags, [
    { relname: "lot_analyses", relrowsecurity: true, relforcerowsecurity: false },
    { relname: "vessels", relrowsecurity: true, relforcerowsecurity: false },
  ]);
  for (const t of ["lot_analyses", "vessels"]) {
    assert.equal(await count(CUSTOMER, t), 0, t);
    assert.equal(await count(OPERATOR, t), 1, t);
  }
  await db.exec(migration("20261007130000_lot_analyses_vessels_rls.sql"));
  assert.equal(await count(CUSTOMER, "lot_analyses"), 0);
});
