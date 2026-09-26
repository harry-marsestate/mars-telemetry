// Offline tests for supabase/migrations/20260926160000_agent_keys_admin.sql,
// run against PGlite (real Postgres compiled to WASM -- roles, GRANTs,
// SECURITY DEFINER and pgcrypto all behave as they do on the server).
//
//   (cd scripts && npm install) && node --test tests/agent-keys-sql.test.mjs
//
// The database is a minimal Supabase shape (auth.users, auth.uid()/auth.jwt()
// exactly as Supabase defines them, the API roles, user_profiles) with the
// REAL migrations applied on top: is_admin_user() (20260810164048),
// agent_api_keys + mcp_authenticate() (20260926150001) and the migration under
// test. Keys generated in SQL are checked against supabase/functions/mcp/auth.ts
// itself, so the gateway and the issuer can't drift apart.
//
// scripts/agent-keys-admin-verify.mjs repeats the access/fresh-auth checks
// against the live database; this file is the fast, no-network version.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { parseBearerKey, sha256Hex } from "../supabase/functions/mcp/auth.ts";

// PGlite is a dev dependency of scripts/ (the only package.json in the repo).
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
    create table auth.users (id uuid primary key, email text);
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
      role text not null default 'customer' check (role in ('operator','customer')),
      status text not null default 'pending',
      first_name text, last_name text,
      data_mode text not null default 'all',
      customer_account_id text
    );
    alter table public.user_profiles enable row level security;
    -- 20260926150000 minus its view grants (the views don't exist here).
    create role mcp_reader nologin noinherit nobypassrls;
    create role mcp_gateway nologin noinherit nobypassrls;
    grant mcp_reader to mcp_gateway;
  `);
  await db.exec(migration("20260810164048_admin_manages_profiles.sql"));
  await db.exec(migration("20260926150001_agent_api_keys.sql"));
  await db.exec(migration("20260926160000_agent_keys_admin.sql"));
  await db.exec(`
    insert into auth.users values
      ('${ADMIN}', '${ADMIN_EMAIL}'), ('${OPERATOR}', 'op@example.test'), ('${CUSTOMER}', 'cust@example.test'),
      ('${PENDING}', 'pending@example.test'), ('${REJECTED}', 'rejected@example.test');
    insert into public.user_profiles (id, role, status, is_admin, first_name, last_name, data_mode) values
      ('${ADMIN}', 'operator', 'approved', true, 'Ada', 'Admin', 'all'),
      ('${OPERATOR}', 'operator', 'approved', false, 'Otto', 'Operator', 'real_only'),
      ('${CUSTOMER}', 'customer', 'approved', false, 'Cora', 'Customer', 'all'),
      ('${PENDING}', 'customer', 'pending', false, 'Pat', 'Pending', 'all'),
      ('${REJECTED}', 'operator', 'rejected', false, 'Rex', 'Rejected', 'all');
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

// ---- key shape: one generator, matching the gateway exactly ------------------
test("SQL-generated keys are exactly what mcp/auth.ts accepts, hashed exactly as mcp_authenticate compares", async () => {
  await asOwner(async (q) => {
    const row = await issueOwner(q, OPERATOR, "shape check", 30);
    assert.match(row.key, /^mtk_[A-Za-z0-9_-]{43}$/);
    assert.equal(parseBearerKey(`Bearer ${row.key}`), row.key, "gateway's own parser accepts it");
    assert.equal(row.key_prefix, row.key.slice(0, 12));
    assert.equal(row.label, `shape check [user ${OPERATOR.slice(0, 8)}]`, "CLI label suffix kept");
    const [stored] = await q("select encode(key_hash, 'hex') hex, created_by, expires_at - created_at as ttl from public.agent_api_keys where id = $1", [row.id]);
    assert.equal(stored.hex, await sha256Hex(row.key), "stored hash == gateway's sha256Hex(key)");
    assert.equal(stored.created_by, "test");
    const [{ days }] = await q("select extract(day from $1::interval)::int days", [stored.ttl]);
    assert.equal(days, 30);
  });
});

test("keys are unique and the plaintext is stored nowhere in the row", async () => {
  await asOwner(async (q) => {
    const keys = [];
    for (let i = 0; i < 40; i++) keys.push((await issueOwner(q, OPERATOR, `k${i}`)).key);
    assert.equal(new Set(keys).size, keys.length);
    for (const k of keys) {
      const [{ n }] = await q(
        "select count(*)::int n from public.agent_api_keys t where t::text like '%' || $1 || '%' or t::text like '%' || $2 || '%'",
        [k, k.slice(4)],
      );
      assert.equal(n, 0, "no column contains the plaintext");
    }
  });
});

test("an issued key authenticates through mcp_authenticate as mcp_gateway, and stops after revoke", async () => {
  await asOwner(async (q) => {
    const row = await issueOwner(q, OPERATOR);
    const hash = await sha256Hex(row.key);
    await q("set local role mcp_gateway");
    const [hit] = await q("select key_id, user_id from public.mcp_authenticate($1)", [hash]);
    assert.deepEqual(hit, { key_id: row.id, user_id: OPERATOR });
    await q("reset role");
    const revoked = await q("select * from public.agent_key_revoke($1)", [row.id]);
    assert.equal(revoked.length, 1);
    await q("set local role mcp_gateway");
    assert.equal((await q("select * from public.mcp_authenticate($1)", [hash])).length, 0);
    await q("reset role");
    assert.equal((await q("select * from public.agent_key_revoke($1)", [row.id])).length, 0, "second revoke is a no-op");
  });
});

// ---- eligibility and input validation (shared by CLI and UI) ----------------
test("eligibility mirrors mcp_authenticate: approved operator/customer only, unless the CLI's negative-test flag", async () => {
  for (const [user, ok] of [[OPERATOR, true], [CUSTOMER, true], [ADMIN, true], [PENDING, false], [REJECTED, false]]) {
    const err = await asOwner(async (q) => { try { await issueOwner(q, user); return null; } catch (e) { return e.message; } });
    assert.equal(err === null, ok, `${user}: ${err}`);
  }
  await asOwner(async (q) => assert.ok((await issueOwner(q, PENDING, "neg", 90, true)).key));
  const unknown = await asOwner(async (q) => { try { await issueOwner(q, "ffffffff-0000-4000-8000-000000000009"); } catch (e) { return e.message; } });
  assert.match(unknown, /no user_profiles row/);
});

test("expiry is required, 1 to 365 days; label required, max 100 chars", async () => {
  const tryIssue = (label, days) => asOwner(async (q) => { try { await issueOwner(q, OPERATOR, label, days); return null; } catch (e) { return e.message; } });
  for (const d of [0, -1, 366, null]) assert.match(await tryIssue("x", d), /1 to 365/);
  for (const d of [1, 365]) assert.equal(await tryIssue("x", d), null);
  for (const l of ["", "   ", null]) assert.match(await tryIssue(l, 90), /label is required/);
  assert.match(await tryIssue("x".repeat(101), 90), /100 characters/);
  assert.equal(await tryIssue("x".repeat(100), 90), null);
});

// ---- access control -----------------------------------------------------------
const ADMIN_CALLS = [
  ["admin_list_agent_keys", "select * from public.admin_list_agent_keys()", []],
  ["admin_issue_agent_key", "select * from public.admin_issue_agent_key($1, 'x', 90)", [OPERATOR]],
  ["admin_revoke_agent_key", "select * from public.admin_revoke_agent_key($1)", ["ffffffff-0000-4000-8000-000000000009"]],
];
const INTERNAL_CALLS = [
  "select * from public.agent_key_list()",
  `select * from public.agent_key_issue('${OPERATOR}', 'x', 90, 'x', false)`,
  "select * from public.agent_key_revoke('ffffffff-0000-4000-8000-000000000009')",
];

test("non-admin API roles cannot call the admin RPCs", async () => {
  const cases = [
    ["anon", null, /permission denied for function/],
    ["service_role", null, /permission denied for function/],
    ["mcp_gateway", null, /permission denied for function/],
    ["mcp_reader", { sub: ADMIN, amr: pwAmr(1) }, /permission denied for function/],
    ["authenticated", { sub: OPERATOR, role: "authenticated", amr: pwAmr(1) }, /^forbidden$/],
    ["authenticated", { sub: CUSTOMER, role: "authenticated", amr: pwAmr(1) }, /^forbidden$/],
    ["authenticated", { sub: PENDING, role: "authenticated", amr: pwAmr(1) }, /^forbidden$/],
    ["authenticated", null, /^forbidden$/],
  ];
  for (const [role, claims, expected] of cases) {
    for (const [name, sql, params] of ADMIN_CALLS) {
      const err = await errorAs(role, claims, sql, params);
      assert.match(err ?? "(succeeded)", expected, `${role} ${claims?.sub ?? ""} -> ${name}`);
    }
  }
});

test("nobody but the owner can reach the internal functions or the tables -- including an admin", async () => {
  for (const [role, claims] of [["anon", null], ["authenticated", adminClaims()], ["service_role", null], ["mcp_gateway", null], ["mcp_reader", null]]) {
    for (const sql of INTERNAL_CALLS) assert.match(await errorAs(role, claims, sql) ?? "(succeeded)", /permission denied for function/, `${role}: ${sql}`);
    for (const t of ["agent_api_keys", "agent_api_key_calls"]) {
      assert.match(await errorAs(role, claims, `select * from public.${t}`) ?? "(succeeded)", /permission denied for table/, `${role}: ${t}`);
    }
  }
});

// ---- fresh auth for issue only ----------------------------------------------------
test("issue requires a password sign-in within 10 minutes; list and revoke do not", async () => {
  const issue = (claims) => errorAs("authenticated", claims, "select * from public.admin_issue_agent_key($1, 'fresh', 90)", [OPERATOR]);
  const reauth = /recent sign-in required/;
  assert.match(await issue({ sub: ADMIN, role: "authenticated", email: ADMIN_EMAIL }) ?? "", reauth, "admin claims without amr");
  assert.match(await issue({ sub: ADMIN, role: "authenticated" }) ?? "", reauth, "no amr");
  assert.match(await issue(adminClaims([])) ?? "", reauth, "empty amr");
  assert.match(await issue(adminClaims("password")) ?? "", reauth, "non-array amr");
  assert.match(await issue(adminClaims(pwAmr(11 * 60))) ?? "", reauth, "password 11 min ago");
  assert.match(await issue(adminClaims([{ method: "recovery", timestamp: now() }])) ?? "", reauth, "fresh non-password method");
  assert.match(await issue(adminClaims([{ method: "password", timestamp: String(now()) }])) ?? "", reauth, "string timestamp");
  assert.equal(await issue(adminClaims(pwAmr(9 * 60))), null, "password 9 min ago");
  assert.equal(await issue(adminClaims([{ method: "password", timestamp: now() - 3600 }, { method: "password", timestamp: now() - 5 }])), null, "latest entry counts");

  const stale = { sub: ADMIN, role: "authenticated", email: ADMIN_EMAIL, amr: pwAmr(24 * 3600) };
  assert.equal(await errorAs("authenticated", stale, "select * from public.admin_list_agent_keys()"), null, "list: no re-auth");
  assert.equal(await errorAs("authenticated", stale, "select * from public.admin_revoke_agent_key($1)", ["ffffffff-0000-4000-8000-000000000009"]), null, "revoke: no re-auth");
});

test("admin issue records created_by from the JWT and returns the plaintext only in its own result", async () => {
  await as("authenticated", adminClaims(), async (q) => {
    const [row] = await q("select * from public.admin_issue_agent_key($1, 'from ui', 45)", [CUSTOMER]);
    assert.deepEqual(Object.keys(row).sort(), ["expires_at", "id", "key", "key_prefix", "label"]);
    assert.equal(parseBearerKey(`Bearer ${row.key}`), row.key);
    const listed = (await q("select * from public.admin_list_agent_keys()")).find((r) => r.id === row.id);
    assert.equal(listed.created_by, `${ADMIN_EMAIL} (${ADMIN}) via web admin`);
    assert.ok(!Object.keys(listed).some((c) => /hash|^key$/.test(c)), "list never exposes a hash or key");
    assert.ok(!Object.values(listed).some((v) => typeof v === "string" && v.includes(row.key.slice(12))), "no list value contains key material beyond the prefix");
  });
});

test("list: every key with computed status, owner eligibility and the account's data_mode; revoked keys stay listed", async () => {
  await asOwner(async (q) => {
    const active = await issueOwner(q, OPERATOR, "active one");
    const expired = await issueOwner(q, CUSTOMER, "expired one");
    const revoked = await issueOwner(q, CUSTOMER, "revoked one");
    const demoted = await issueOwner(q, CUSTOMER, "owner demoted");
    await q("update public.agent_api_keys set created_at = now() - interval '2 days', expires_at = now() - interval '1 day' where id = $1", [expired.id]);
    await q("select public.agent_key_revoke($1)", [revoked.id]);
    await q(`update public.user_profiles set status = 'suspended' where id = '${CUSTOMER}'`);

    const ownerRows = await q("select * from public.agent_key_list()");
    await q("select set_config('request.jwt.claims', $1, true)", [JSON.stringify(adminClaims(pwAmr(86400)))]);
    await q("set local role authenticated");
    const viaAdmin = await q("select * from public.admin_list_agent_keys()");
    assert.deepEqual(viaAdmin, ownerRows, "the admin RPC returns exactly the shared list");

    const by = Object.fromEntries(viaAdmin.map((r) => [r.id, r]));
    assert.equal(by[active.id].status, "active");
    assert.equal(by[active.id].account_data_mode, "real_only");
    assert.equal(by[active.id].account_first_name, "Otto");
    assert.equal(by[active.id].owner_eligible, true);
    assert.equal(by[expired.id].status, "expired");
    assert.equal(by[revoked.id].status, "revoked");
    assert.ok(by[revoked.id].revoked_at);
    assert.equal(by[demoted.id].status, "active");
    assert.equal(by[demoted.id].owner_eligible, false, "active but owner no longer approved");
    assert.equal(by[demoted.id].account_status, "suspended");
  });
});

test("admin revoke: first call returns the row, second returns nothing, and it's still listed as revoked", async () => {
  await as("authenticated", adminClaims(), async (q) => {
    const [row] = await q("select * from public.admin_issue_agent_key($1, 'to revoke', 90)", [OPERATOR]);
    const first = await q("select * from public.admin_revoke_agent_key($1)", [row.id]);
    assert.equal(first.length, 1);
    assert.equal(first[0].key_prefix, row.key_prefix);
    assert.equal((await q("select * from public.admin_revoke_agent_key($1)", [row.id])).length, 0);
    const listed = (await q("select * from public.admin_list_agent_keys()")).find((r) => r.id === row.id);
    assert.equal(listed.status, "revoked");
  });
});

// ---- static: one implementation, and the page never touches the secret material -------
test("scripts/agent-keys.mjs generates/hashes/inserts nothing itself -- it calls the shared functions", () => {
  const cli = readFileSync(new URL("../scripts/agent-keys.mjs", import.meta.url), "utf8");
  const own = cli.match(/randomBytes|createHash|insert\s+into|update\s+public\.agent_api_keys/i);
  assert.equal(own, null, `agent-keys.mjs has its own key logic: ${own?.[0]}`);
  for (const fn of ["agent_key_issue", "agent_key_revoke", "agent_key_list"]) {
    assert.ok(cli.includes(`public.${fn}(`), `agent-keys.mjs does not call public.${fn}()`);
  }
});

test("web/index.html never names key_hash, never reads the key tables directly, never logs the one-time key", () => {
  const html = readFileSync(new URL("../web/index.html", import.meta.url), "utf8");
  assert.doesNotMatch(html, /key_hash/);
  assert.doesNotMatch(html, /from\(['"]agent_api_key/);
  assert.doesNotMatch(html, /rpc\(['"]agent_key_/, "only the admin_* wrappers are callable");
  const logs = html.match(/console\.\w+\([^;]*\)/g) ?? [];
  assert.ok(!logs.some((l) => /issued\.key\b|plaintext|newKey/.test(l)), logs.filter((l) => /issued|plaintext|newKey/.test(l)).join("\n"));
});
