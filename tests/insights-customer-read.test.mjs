// Offline test for supabase/migrations/20261001130000_insights_customer_read.sql
// on PGlite: which `insights` rows each role can read through RLS.
//
//   (cd scripts && npm install) && node --test tests/insights-customer-read.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const requireFromScripts = createRequire(new URL("../scripts/package.json", import.meta.url));
const { PGlite } = await import(pathToFileURL(requireFromScripts.resolve("@electric-sql/pglite")).href);
const sql = (f) => readFileSync(new URL(`../supabase/migrations/${f}`, import.meta.url), "utf8");

let db;
// Rows the given caller can read, as "metric_a|metric_b|scope".
async function visible(role, blocks) {
  await db.exec(`reset role; select set_config('test.role', '${role ?? ""}', false), set_config('test.blocks', '${blocks.join(",")}', false);`);
  await db.exec("set role authenticated");
  const r = await db.query("select metric_a, metric_b, coalesce(scope_block_id, 'estate') s from public.insights order by 1, 2, 3");
  await db.exec("reset role");
  return r.rows.map((x) => `${x.metric_a}|${x.metric_b}|${x.s}`);
}

before(async () => {
  db = new PGlite();
  await db.exec(`
    create role anon; create role authenticated; create role service_role;
    -- stand-ins for the auth helpers (20260806034231_auth_helpers.sql), driven by session settings
    create function public.current_role_name() returns text language sql stable as $$ select nullif(current_setting('test.role', true), '') $$;
    create function public.accessible_blocks() returns setof text language sql stable as $$
      select unnest(string_to_array(nullif(current_setting('test.blocks', true), ''), ',')) $$;
    create table public.metric_registry (metric_key text primary key, min_role text not null);
    insert into public.metric_registry values
      ('air_temp','all'), ('humidity','all'), ('soil_moisture','all'), ('soil_temp','all'), ('dtr','all'),
      ('irrigation_volume','operator'), ('cellar_temp','operator');
    create table public.metric_derivation (metric_key text, derived_from text);
    insert into public.metric_derivation values ('gdd_day','air_temp'), ('vpd_kpa','air_temp'), ('vpd_kpa','humidity'),
      ('secret_ratio','air_temp'), ('secret_ratio','irrigation_volume');
    create table public.insights (id serial primary key, tab text, metric_a text, metric_b text, scope_kind text,
      scope_block_id text, status text);
    grant select on public.insights to authenticated;
    alter table public.insights enable row level security;
    create policy insights_read on public.insights for select using (current_role_name() = 'operator');
    insert into public.insights (tab, metric_a, metric_b, scope_kind, scope_block_id, status) values
      ('vineyard', 'air_temp', 'humidity', 'estate', null, 'surfaced'),          -- customer: yes
      ('vineyard', 'gdd_day', 'soil_moisture', 'estate', null, 'surfaced'),      -- derived from visible input: yes
      ('vineyard', 'humidity', 'vpd_kpa', 'estate', null, 'surfaced'),           -- derived from two visible inputs: yes
      ('vineyard', 'air_temp', 'humidity', 'estate', null, 'below_threshold'),   -- not surfaced: operator only
      ('vineyard', 'harvest_yield_tons', 'irrigation_volume', 'block', 'B2', 'surfaced'), -- operator metrics
      ('vineyard', 'air_temp', 'irrigation_volume', 'estate', null, 'surfaced'), -- one operator metric
      ('vineyard', 'air_temp', 'labour_cost', 'estate', null, 'surfaced'),       -- unregistered metric: default deny
      ('vineyard', 'air_temp', 'secret_ratio', 'estate', null, 'surfaced'),      -- derived from an operator input
      ('vineyard', 'air_temp', 'soil_moisture', 'block', 'B1', 'surfaced'),      -- B1 only
      ('vineyard', 'air_temp', 'soil_moisture', 'block', 'B2', 'surfaced'),      -- B2 only
      ('winery', 'air_temp', 'humidity', 'estate', null, 'surfaced');            -- winery: operator only
  `);
  await db.exec(sql("20261001130000_insights_customer_read.sql"));
});

test("operator reads every row (policy unchanged)", async () => {
  assert.equal((await visible("operator", ["B1", "B2", "B3"])).length, 11);
});

test("customer with all blocks: only surfaced vineyard rows over customer-visible metrics", async () => {
  assert.deepEqual(await visible("customer", ["B1", "B2", "B3"]), [
    "air_temp|humidity|estate",
    "air_temp|soil_moisture|B1",
    "air_temp|soil_moisture|B2",
    "gdd_day|soil_moisture|estate",
    "humidity|vpd_kpa|estate",
  ]);
});

test("customer scoped to B2: no B1 block insight, estate ones kept", async () => {
  assert.deepEqual(await visible("customer", ["B2"]), [
    "air_temp|humidity|estate",
    "air_temp|soil_moisture|B2",
    "gdd_day|soil_moisture|estate",
    "humidity|vpd_kpa|estate",
  ]);
});

test("labour, irrigation, yield and operator-derived metrics never reach a customer", async () => {
  const rows = (await visible("customer", ["B1", "B2", "B3"])).join(" ");
  for (const m of ["labour_cost", "irrigation_volume", "harvest_yield_tons", "secret_ratio"]) assert.ok(!rows.includes(m), m);
});

test("pending and signed-out callers read nothing", async () => {
  assert.deepEqual(await visible("pending", ["B1", "B2", "B3"]), []);
  assert.deepEqual(await visible(null, []), []);
});

test("customer_visible_metric is not executable by anon", async () => {
  const r = await db.query("select has_function_privilege('anon', 'public.customer_visible_metric(text)', 'execute') ok");
  assert.equal(r.rows[0].ok, false);
});
