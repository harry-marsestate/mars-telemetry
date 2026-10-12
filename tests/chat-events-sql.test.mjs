// Offline test for supabase/migrations/20261012120000_chat_events.sql on
// PGlite: who can insert and read chat_events, and that text is stored only
// on a "this was wrong" flag.
//
//   (cd scripts && npm install) && node --test tests/chat-events-sql.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const requireFromScripts = createRequire(new URL("../scripts/package.json", import.meta.url));
const { PGlite } = await import(pathToFileURL(requireFromScripts.resolve("@electric-sql/pglite")).href);
const migration = readFileSync(new URL("../supabase/migrations/20261012120000_chat_events.sql", import.meta.url), "utf8");

const OPERATOR = "00000000-0000-0000-0000-00000000000a";
const CUSTOMER = "00000000-0000-0000-0000-00000000000c";
const PENDING = "00000000-0000-0000-0000-00000000000e";
let db;

// Runs `sql` as `uid` in the authenticated role, inside a transaction that is
// committed (keep=true) or rolled back. Returns rows, or throws the DB error.
async function as(uid, sql, params = [], keep = false) {
  await db.query("begin");
  try {
    await db.query("select set_config('test.uid', $1, true)", [uid]);
    await db.query("set local role authenticated");
    const r = await db.query(sql, params);
    await db.query(keep ? "commit" : "rollback");
    return r.rows;
  } catch (e) { await db.query("rollback"); throw e; }
}
const ins = (uid, cols, keep) => {
  const k = Object.keys(cols);
  return as(uid, `insert into public.chat_events (${k.join(",")}) values (${k.map((_, i) => `$${i + 1}`).join(",")})`, Object.values(cols), keep);
};

before(async () => {
  db = new PGlite();
  await db.exec(`
    create role anon nologin; create role authenticated nologin;
    grant usage on schema public to anon, authenticated;
    create schema auth; grant usage on schema auth to authenticated;
    create table auth.users (id uuid primary key);
    insert into auth.users values ('${OPERATOR}'), ('${CUSTOMER}'), ('${PENDING}');
    create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('test.uid', true), '')::uuid $$;
    grant execute on function auth.uid() to authenticated;
    create table user_profiles (id uuid primary key, role text, status text);
    insert into user_profiles values ('${OPERATOR}', 'operator', 'approved'), ('${CUSTOMER}', 'customer', 'approved'), ('${PENDING}', 'customer', 'pending');
    create function current_role_name() returns text language sql stable security definer set search_path = public as $$
      select case when status = 'approved' then role else 'pending' end from user_profiles where id = auth.uid() $$;
    grant execute on function current_role_name() to authenticated;
  `);
  await db.exec(migration);
});

test("approved users insert their own events; user_id comes from auth.uid()", async () => {
  await ins(CUSTOMER, { surface: "widget", event: "open" }, true);
  await ins(OPERATOR, { surface: "tab", event: "ask", turn_index: 0 }, true);
  const rows = (await db.query("select user_id, event from public.chat_events order by id")).rows;
  assert.deepEqual(rows.map((r) => [r.user_id, r.event]), [[CUSTOMER, "open"], [OPERATOR, "ask"]]);
});

test("nobody can write another user's id: the column is not granted", async () => {
  await assert.rejects(ins(CUSTOMER, { user_id: OPERATOR, surface: "widget", event: "open" }), /permission denied/);
});

test("pending accounts and anonymous callers cannot insert", async () => {
  await assert.rejects(ins(PENDING, { surface: "widget", event: "open" }), /row-level security/);
  await assert.rejects(ins("", { surface: "widget", event: "open" }), /row-level security|null value/);
});

test("text is refused on every event except flag_wrong", async () => {
  for (const event of ["open", "ask", "thumb_up", "thumb_down"]) {
    await assert.rejects(ins(CUSTOMER, { surface: "widget", event, question: "q" }), /chat_events_text_only_on_flag/, event);
    await assert.rejects(ins(CUSTOMER, { surface: "widget", event, answer: "a" }), /chat_events_text_only_on_flag/, event);
  }
  await ins(CUSTOMER, { surface: "widget", event: "flag_wrong", turn_index: 2, question: "q", answer: "a" });
});

test("values are constrained: surface, event, panel id shape, text length", async () => {
  await assert.rejects(ins(CUSTOMER, { surface: "email", event: "open" }), /check/);
  await assert.rejects(ins(CUSTOMER, { surface: "widget", event: "export" }), /check/);
  await assert.rejects(ins(CUSTOMER, { surface: "widget", event: "ask", panel_id: "x'; drop" }), /check/);
  await assert.rejects(ins(CUSTOMER, { surface: "widget", event: "flag_wrong", question: "q".repeat(4101) }), /check/);
  await ins(CUSTOMER, { surface: "widget", event: "ask", panel_id: "soilmoist" });
});

test("only operators read events; customers cannot read even their own", async () => {
  assert.equal((await as(CUSTOMER, "select * from public.chat_events")).length, 0);
  assert.equal((await as(PENDING, "select * from public.chat_events")).length, 0);
  assert.equal((await as(OPERATOR, "select * from public.chat_events")).length, 2);
});

test("no update or delete through the API, for anyone", async () => {
  for (const uid of [OPERATOR, CUSTOMER]) {
    await assert.rejects(as(uid, "update public.chat_events set event = 'ask'"), /permission denied/);
    await assert.rejects(as(uid, "delete from public.chat_events"), /permission denied/);
  }
});

test("anon has no access at all", async () => {
  await db.query("begin");
  try {
    await db.query("set local role anon");
    await assert.rejects(db.query("select * from public.chat_events"), /permission denied/);
  } finally { await db.query("rollback"); }
});
