// Offline tests for supabase/migrations/20260930030000_agent_key_scopes_and_rate_limits.sql:
// per-key tool scopes, the operator-only guard for health tools, the gateway's
// mcp_key_scope()/mcp_authorize_call(), rate limits and their audit trail.
// Same PGlite harness and real migrations as tests/agent-keys-sql.test.mjs,
// plus the migration under test.
//
//   (cd scripts && npm install) && node --test tests/agent-key-scopes-sql.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { sha256Hex } from "../supabase/functions/mcp/auth.ts";

const requireFromScripts = createRequire(new URL("../scripts/package.json", import.meta.url));
const load = (spec) => import(pathToFileURL(requireFromScripts.resolve(spec)).href);
const { PGlite } = await load("@electric-sql/pglite");
const { pgcrypto } = await load("@electric-sql/pglite/contrib/pgcrypto");

const migration = (name) => readFileSync(new URL(`../supabase/migrations/${name}`, import.meta.url), "utf8");

const ADMIN = "aaaaaaaa-0000-4000-8000-000000000001";
const OPERATOR = "bbbbbbbb-0000-4000-8000-000000000002";
const CUSTOMER = "cccccccc-0000-4000-8000-000000000003";
const PENDING = "dddddddd-0000-4000-8000-000000000004";
const REJECTED = "eeeeeeee-0000-4000-8000-000000000005";
const ADMIN_EMAIL = "admin@example.test";

let db;

before(async () => {
  db = new PGlite({ extensions: { pgcrypto } });
  await db.exec(`
    create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;
    create schema extensions;
    create schema auth;
    create table auth.users (id uuid primary key, email text, banned_until timestamptz, deleted_at timestamptz,
      email_confirmed_at timestamptz, raw_app_meta_data jsonb default '{}'::jsonb, raw_user_meta_data jsonb default '{}'::jsonb);
    create function auth.uid() returns uuid language sql stable as $$
      select coalesce(nullif(current_setting('request.jwt.claim.sub', true), ''),
                      (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub'))::uuid $$;
    create function auth.jwt() returns jsonb language sql stable as $$
      select coalesce(nullif(current_setting('request.jwt.claim', true), ''),
                      nullif(current_setting('request.jwt.claims', true), ''))::jsonb $$;
    grant usage on schema auth to anon, authenticated, service_role;
    grant usage on schema public to anon, authenticated, service_role;
    create table public.user_profiles (
      id uuid primary key references auth.users(id) on delete cascade,
      full_name text,
      role text not null default 'customer' check (role in ('operator','customer')),
      status text not null default 'pending' check (status in ('pending','approved','rejected')),
      first_name text, last_name text,
      data_mode text not null default 'all',
      customer_account_id text
    );
    alter table public.user_profiles enable row level security;
    -- Production's table-wide grant (docs/SECURITY.md: admin_manages_profiles
    -- relies on it), so admin-via-REST updates are tested for real.
    grant select, update on public.user_profiles to authenticated;
    -- The on_auth_user_created binding (20260806033809); handle_new_user()'s
    -- real body arrives with 20260926180000.
    create function public.handle_new_user() returns trigger language plpgsql as $$ begin return new; end $$;
    create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();
    -- 20260926150000 minus its view grants (the views don't exist here).
    create role mcp_reader nologin noinherit nobypassrls;
    create role mcp_gateway nologin noinherit nobypassrls;
    grant mcp_reader to mcp_gateway;
  `);
  await db.exec(migration("20260810164048_admin_manages_profiles.sql"));
  await db.exec(migration("20260810165833_user_confirmed_notify_profile.sql"));
  await db.exec(migration("20260926150001_agent_api_keys.sql"));
  await db.exec(migration("20260926160000_agent_keys_admin.sql"));
  await db.exec(migration("20260926165000_mcp_auth_banned_users.sql"));
  await db.exec(migration("20260926170000_agent_keys_admin_detail.sql"));
  await db.exec(migration("20260926180000_service_accounts.sql"));
  await db.exec(migration("20260926190000_service_account_type_sync.sql"));
  await db.exec(migration("20260930030000_agent_key_scopes_and_rate_limits.sql"));
  await db.exec(migration("20260930120000_admin_key_tool_selection.sql"));
  await db.exec(`
    insert into auth.users values
      ('${ADMIN}', '${ADMIN_EMAIL}'), ('${OPERATOR}', 'op@example.test'), ('${CUSTOMER}', 'cust@example.test'),
      ('${PENDING}', 'pending@example.test'), ('${REJECTED}', 'rejected@example.test');
    insert into public.user_profiles as up (id, role, status, is_admin, first_name, last_name, data_mode) values
      ('${ADMIN}', 'operator', 'approved', true, 'Ada', 'Admin', 'all'),
      ('${OPERATOR}', 'operator', 'approved', false, 'Otto', 'Operator', 'real_only'),
      ('${CUSTOMER}', 'customer', 'approved', false, 'Cora', 'Customer', 'all'),
      ('${PENDING}', 'customer', 'pending', false, 'Pat', 'Pending', 'all'),
      ('${REJECTED}', 'operator', 'rejected', false, 'Rex', 'Rejected', 'all')
      on conflict (id) do update set role = excluded.role, status = excluded.status, is_admin = excluded.is_admin,
        first_name = excluded.first_name, last_name = excluded.last_name, data_mode = excluded.data_mode;
  `);
});

// ---- helpers ----------------------------------------------------------------
const now = () => Math.floor(Date.now() / 1000);
const pwAmr = (secondsAgo) => [{ method: "password", timestamp: now() - secondsAgo }];
const adminClaims = (amr = pwAmr(30)) => ({ sub: ADMIN, role: "authenticated", email: ADMIN_EMAIL, amr });

// Runs fn(query) inside a transaction as `role` with `claims`, always rolled back.
async function as(role, claims, fn) {
  await db.exec("begin");
  try {
    if (claims) await db.query("select set_config('request.jwt.claims', $1, true)", [JSON.stringify(claims)]);
    await db.exec(`set local role ${role}`);
    return await fn((sql, params = []) => db.query(sql, params).then((r) => r.rows));
  } finally {
    await db.exec("rollback");
  }
}
// Like `as`, but returns the error message (or null) of a single statement.
async function errorAs(role, claims, sql, params = []) {
  return as(role, claims, async (q) => {
    try { await q(sql, params); return null; } catch (e) { return e.message; }
  });
}
// Owner-context transaction (the CLI's path), always rolled back.
async function asOwner(fn) {
  await db.exec("begin");
  try { return await fn((sql, params = []) => db.query(sql, params).then((r) => r.rows)); } finally { await db.exec("rollback"); }
}
const issueOwner = (q, user = OPERATOR, label = "t", days = 90, allow = false) =>
  q("select * from public.agent_key_issue($1, $2, $3, 'test', $4)", [user, label, days, allow]).then((r) => r[0]);


const ROUND_ONE = ["get_berry_maturity", "get_smoke_markers", "get_wine_lab_results", "get_lot_analyses", "get_labour_summary"];
const DATA_NINE = [...ROUND_ONE, "get_series", "get_derived_series", "get_anomalies", "get_vessels"];
const HEALTH = ["get_system_health", "get_health_history", "get_health_baselines"];
const issueTools = (q, user, tools) =>
  q("select * from public.agent_key_issue($1, 'scoped', 30, 'test', false, $2)", [user, tools]).then((r) => r[0]);
// An expected failure inside an open transaction: isolated by a savepoint so the
// transaction stays usable for the next statement.
async function rejectsIn(q, run, re) {
  await q("savepoint expect_error");
  try {
    await assert.rejects(run(), re);
  } finally {
    await q("rollback to savepoint expect_error");
  }
}

test("existing keys (and keys issued without tools) get exactly the five round-one tools", async () => {
  await asOwner(async (q) => {
    const row = await issueOwner(q, OPERATOR, "legacy-style", 30);
    assert.deepEqual(row.allowed_tools, ROUND_ONE);
    const [k] = await q("select allowed_tools, rate_per_minute, rate_per_day from public.agent_api_keys where id=$1", [row.id]);
    assert.deepEqual(k, { allowed_tools: ROUND_ONE, rate_per_minute: 60, rate_per_day: 2000 });
  });
});

test("scope guard: unknown tools, duplicates, empty and customer-owned health tools are refused", async () => {
  await asOwner(async (q) => {
    await rejectsIn(q, () => issueTools(q, OPERATOR, ["get_series", "get_made_up"]), /unknown tool\(s\): get_made_up/);
    await rejectsIn(q, () => issueTools(q, OPERATOR, ["get_series", "get_series"]), /duplicates/);
    await rejectsIn(q, () => issueTools(q, OPERATOR, []), /allowed_tools_nonempty/);
    await rejectsIn(q, () => issueTools(q, CUSTOMER, ["get_series", "get_system_health"]), /only be granted to a key whose owner is an operator/);
    const ok = await issueTools(q, CUSTOMER, DATA_NINE);
    assert.deepEqual(ok.allowed_tools, DATA_NINE);
    const op = await issueTools(q, OPERATOR, [...DATA_NINE, ...HEALTH]);
    assert.equal(op.allowed_tools.length, 12);
    // re-pointing a health-scoped key at a customer is refused too
    await rejectsIn(q, () => q("update public.agent_api_keys set user_id=$1 where id=$2", [CUSTOMER, op.id]), /operator/);
  });
});

test("agent_key_set_tools: active keys only, validated, audited old -> new", async () => {
  await asOwner(async (q) => {
    const k = await issueOwner(q, OPERATOR, "widen me", 30);
    const [r] = await q("select * from public.agent_key_set_tools($1, $2, 'owner via test')", [k.id, [...DATA_NINE, ...HEALTH]]);
    assert.equal(r.allowed_tools.length, 12);
    const [log] = await q("select old_tools, new_tools, changed_by from public.agent_api_key_scope_changes where key_id=$1", [k.id]);
    assert.deepEqual(log, { old_tools: ROUND_ONE, new_tools: [...DATA_NINE, ...HEALTH], changed_by: "owner via test" });
    await rejectsIn(q, () => q("select * from public.agent_key_set_tools($1, $2, 'x')", [k.id, ["get_nope"]]), /unknown tool/);
    await q("select * from public.agent_key_revoke($1)", [k.id]);
    await rejectsIn(q, () => q("select * from public.agent_key_set_tools($1, $2, 'x')", [k.id, ROUND_ONE]), /no active key/);
  });
});

test("mcp_key_scope + mcp_authorize_call: scope enforced and refusals audited", async () => {
  await db.exec("begin");
  try {
    const k = (await db.query("select * from public.agent_key_issue($1, 'gw', 30, 'test', false, $2)", [OPERATOR, ["get_series", "get_system_health"]])).rows[0];
    const hash = await sha256Hex(k.key);
    await db.exec("set local role mcp_gateway");
    const [scope] = (await db.query("select * from public.mcp_key_scope($1)", [hash])).rows;
    assert.deepEqual([scope.allowed_tools, scope.rate_per_minute, scope.owner_role], [["get_series", "get_system_health"], 60, "operator"]);
    const ok = (await db.query("select * from public.mcp_authorize_call($1, 'get_series')", [hash])).rows[0];
    assert.deepEqual(ok, { allowed: true, http_status: 200, reason: "ok", retry_after_seconds: null });
    const no = (await db.query("select * from public.mcp_authorize_call($1, 'get_vessels')", [hash])).rows[0];
    assert.deepEqual([no.allowed, no.http_status], [false, 403]);
    assert.match(no.reason, /not permitted for this key: get_vessels/);
    const unknown = (await db.query("select * from public.mcp_authorize_call($1, 'drop_table')", [hash])).rows[0];
    assert.equal(unknown.http_status, 403);
    const dead = (await db.query("select * from public.mcp_authorize_call($1, 'get_series')", ["0".repeat(64)])).rows[0];
    assert.deepEqual([dead.allowed, dead.http_status], [false, 401]);
    await db.exec("reset role");
    const audit = (await db.query("select tool, is_error, outcome from public.agent_api_key_calls where key_id=$1 order by id", [k.id])).rows;
    assert.deepEqual(audit, [{ tool: "get_vessels", is_error: true, outcome: "rejected_scope" }, { tool: "drop_table", is_error: true, outcome: "rejected_scope" }]);
    // a demoted owner loses health tools at call time, even though the key still lists them
    await db.query("update public.user_profiles set role='customer' where id=$1", [OPERATOR]);
    await db.exec("set local role mcp_gateway");
    const demoted = (await db.query("select * from public.mcp_authorize_call($1, 'get_system_health')", [hash])).rows[0];
    assert.equal(demoted.http_status, 403);
  } finally {
    await db.exec("rollback");
  }
});

test("rate limits: per-minute and per-day, 429 with retry-after, throttles audited and not counted", async () => {
  await db.exec("begin");
  try {
    const k = (await db.query("select * from public.agent_key_issue($1, 'rl', 30, 'test', false, $2)", [OPERATOR, ["get_series"]])).rows[0];
    await db.query("update public.agent_api_keys set rate_per_minute=3, rate_per_day=5 where id=$1", [k.id]);
    const hash = await sha256Hex(k.key);
    const call = async () => { await db.exec("set local role mcp_gateway"); const r = (await db.query("select * from public.mcp_authorize_call($1, 'get_series')", [hash])).rows[0]; await db.exec("reset role"); return r; };
    const logOk = () => db.query("insert into public.agent_api_key_calls (key_id, tool, args, is_error) values ($1, 'get_series', '{}', false)", [k.id]);
    for (let i = 0; i < 3; i++) { assert.equal((await call()).allowed, true); await logOk(); }
    const t = await call();
    assert.deepEqual([t.allowed, t.http_status], [false, 429]);
    assert.match(t.reason, /3 calls per minute/);
    assert.ok(t.retry_after_seconds >= 1 && t.retry_after_seconds <= 60, String(t.retry_after_seconds));
    // age the three calls out of the minute window; the throttle row itself must not count
    await db.query("update public.agent_api_key_calls set called_at = now() - interval '2 minutes' where key_id=$1 and outcome is null", [k.id]);
    for (let i = 0; i < 2; i++) { assert.equal((await call()).allowed, true); await logOk(); }
    const d = await call();
    assert.deepEqual([d.http_status], [429]);
    assert.match(d.reason, /5 calls per day/);
    const outcomes = (await db.query("select outcome, count(*)::int n from public.agent_api_key_calls where key_id=$1 group by 1 order by 1", [k.id])).rows;
    assert.deepEqual(outcomes, [{ outcome: "throttled", n: 2 }, { outcome: null, n: 5 }]);
  } finally {
    await db.exec("rollback");
  }
});

test("grants: gateway functions for mcp_gateway only; scope setter and catalogue owner-only; admin wrappers unchanged", async () => {
  const exec = async (role, fn) => (await db.query("select has_function_privilege($1, $2, 'EXECUTE') ok", [role, fn])).rows[0].ok;
  for (const fn of ["public.mcp_key_scope(text)", "public.mcp_authorize_call(text,text)"]) {
    assert.equal(await exec("mcp_gateway", fn), true, fn);
    for (const r of ["anon", "authenticated", "service_role", "mcp_reader"]) assert.equal(await exec(r, fn), false, `${r} ${fn}`);
  }
  for (const fn of ["public.agent_key_set_tools(uuid,text[],text)", "public.agent_key_issue(uuid,text,integer,text,boolean,text[])", "public.agent_key_list()", "public.agent_key_calls(uuid,integer)"]) {
    for (const r of ["anon", "authenticated", "service_role", "mcp_gateway", "mcp_reader"]) assert.equal(await exec(r, fn), false, `${r} ${fn}`);
  }
  for (const fn of ["public.admin_list_agent_keys()", "public.admin_list_agent_key_calls(uuid,integer)", "public.admin_issue_agent_key(uuid,text,integer,text[])",
                    "public.admin_update_agent_key_tools(uuid,text[])", "public.admin_list_agent_key_scope_changes(uuid)", "public.admin_list_mcp_tools()"]) {
    assert.equal(await exec("authenticated", fn), true, fn);
    for (const r of ["anon", "service_role", "mcp_gateway"]) assert.equal(await exec(r, fn), false, `${r} ${fn}`);
  }
  for (const t of ["public.mcp_tool_catalogue", "public.agent_api_key_scope_changes"]) {
    for (const r of ["anon", "authenticated", "service_role", "mcp_gateway", "mcp_reader"]) {
      const { rows: [p] } = await db.query("select has_table_privilege($1, $2, 'SELECT,INSERT,UPDATE,DELETE') ok", [r, t]);
      assert.equal(p.ok, false, `${r} ${t}`);
    }
  }
});

test("the admin wrappers still work through the new functions (list shows scopes; issue takes the chosen tools)", async () => {
  const listed = await as("authenticated", adminClaims(), (q) => q("select key_prefix, allowed_tools, rate_per_minute from public.admin_list_agent_keys()"));
  assert.ok(Array.isArray(listed));
  const issued = await as("authenticated", adminClaims(), (q) => q("select * from public.admin_issue_agent_key($1, 'via web', 30, $2)", [OPERATOR, ["get_vessels"]]));
  assert.match(issued[0].key, /^mtk_/);
  assert.deepEqual(issued[0].allowed_tools, ["get_vessels"]);
  const calls = await as("authenticated", adminClaims(), (q) => q("select * from public.admin_list_agent_key_calls($1, 10)", ["00000000-0000-4000-8000-000000000000"]));
  assert.deepEqual(calls, []);
});

// ---- admin UI tool selection (20260930120000) ---------------------------------
const ORIGINAL5 = ["get_berry_maturity", "get_smoke_markers", "get_wine_lab_results", "get_lot_analyses", "get_labour_summary"];
const DATA9 = [...ORIGINAL5, "get_series", "get_derived_series", "get_anomalies", "get_vessels"];
const FULL12 = [...DATA9, "get_system_health", "get_health_history", "get_health_baselines"];
const NON_ADMIN = { sub: OPERATOR, role: "authenticated", email: "op@example.test", amr: pwAmr(30) };

test("admin issue: tools are required (no silent default); the old 3-argument signature is gone", async () => {
  for (const tools of [null, []]) {
    const e = await errorAs("authenticated", adminClaims(), "select * from public.admin_issue_agent_key($1, 'x', 30, $2)", [OPERATOR, tools]);
    assert.match(e ?? "", /choose at least one tool/);
  }
  const { rows: [{ n }] } = await db.query("select count(*)::int n from pg_proc where proname = 'admin_issue_agent_key'");
  assert.equal(n, 1);
  assert.equal((await db.query("select to_regprocedure('public.admin_issue_agent_key(uuid,text,integer)') r")).rows[0].r, null);
});

test("admin issue: the chosen tools are stored and returned; 12 for an operator-owned key", async () => {
  const [k] = await as("authenticated", adminClaims(), (q) => q("select * from public.admin_issue_agent_key($1, 'svc full', 30, $2)", [OPERATOR, FULL12]));
  assert.deepEqual(k.allowed_tools, FULL12);
  const listed = await as("authenticated", adminClaims(), async (q) => {
    const [k2] = await q("select * from public.admin_issue_agent_key($1, 'svc full 2', 30, $2)", [OPERATOR, FULL12]);
    return q("select allowed_tools from public.admin_list_agent_keys() where id = $1", [k2.id]);
  });
  assert.deepEqual(listed[0].allowed_tools, FULL12, "stored, as the admin list shows it");
});

test("a customer-owned key can never get a health tool, even from an admin (issue and edit)", async () => {
  const e1 = await errorAs("authenticated", adminClaims(), "select * from public.admin_issue_agent_key($1, 'c', 30, $2)", [CUSTOMER, [...DATA9, "get_system_health"]]);
  assert.match(e1 ?? "", /only be granted to a key whose owner is an operator/);
  const e2 = await as("authenticated", adminClaims(), async (q) => {
    const [k] = await q("select * from public.admin_issue_agent_key($1, 'c', 30, $2)", [CUSTOMER, DATA9]);
    try { await q("savepoint s"); await q("select * from public.admin_update_agent_key_tools($1, $2)", [k.id, FULL12]); return null; }
    catch (err) { await q("rollback to savepoint s"); return err.message; }
  });
  assert.match(e2 ?? "", /only be granted to a key whose owner is an operator/);
});

test("admin edit: changes tools through agent_key_set_tools, audited and listed in the history", async () => {
  const out = await as("authenticated", adminClaims(), async (q) => {
    const [k] = await q("select * from public.admin_issue_agent_key($1, 'widen me', 30, $2)", [OPERATOR, ORIGINAL5]);
    const [u] = await q("select * from public.admin_update_agent_key_tools($1, $2)", [k.id, FULL12]);
    const hist = await q("select * from public.admin_list_agent_key_scope_changes($1)", [k.id]);
    return { u, hist };
  });
  assert.deepEqual(out.u.allowed_tools, FULL12);
  assert.equal(out.hist.length, 1);
  assert.deepEqual([out.hist[0].old_tools, out.hist[0].new_tools], [ORIGINAL5, FULL12]);
  assert.match(out.hist[0].changed_by, /via web admin$/);
  const empty = await errorAs("authenticated", adminClaims(), "select * from public.admin_update_agent_key_tools($1, $2)", ["00000000-0000-4000-8000-000000000000", []]);
  assert.match(empty ?? "", /choose at least one tool/);
});

test("catalogue for the picker: 5 original, 4 more data, 3 health (operator only)", async () => {
  const rows = await as("authenticated", adminClaims(), (q) => q("select tool, preset, requires_operator from public.admin_list_mcp_tools()"));
  const by = (p) => rows.filter((r) => r.preset === p).map((r) => r.tool).sort();
  assert.deepEqual(by("original"), [...ORIGINAL5].sort());
  assert.deepEqual(by("data"), ["get_anomalies", "get_derived_series", "get_series", "get_vessels"]);
  assert.deepEqual(by("health"), ["get_health_baselines", "get_health_history", "get_system_health"]);
  assert.ok(rows.filter((r) => r.preset === "health").every((r) => r.requires_operator));
});

test("every new admin function refuses non-admins", async () => {
  for (const [sql, params] of [
    ["select * from public.admin_issue_agent_key($1, 'x', 30, $2)", [OPERATOR, ORIGINAL5]],
    ["select * from public.admin_update_agent_key_tools($1, $2)", ["00000000-0000-4000-8000-000000000000", ORIGINAL5]],
    ["select * from public.admin_list_agent_key_scope_changes($1)", ["00000000-0000-4000-8000-000000000000"]],
    ["select * from public.admin_list_mcp_tools()", []],
  ]) {
    assert.match(await errorAs("authenticated", NON_ADMIN, sql, params) ?? "", /forbidden/, sql);
  }
});
