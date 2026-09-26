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
  ["admin_update_agent_key_expiry", "select * from public.admin_update_agent_key_expiry($1, 30)", ["ffffffff-0000-4000-8000-000000000009"]],
  ["admin_list_agent_key_calls", "select * from public.admin_list_agent_key_calls($1)", ["ffffffff-0000-4000-8000-000000000009"]],
  ["admin_list_agent_key_expiry_changes", "select * from public.admin_list_agent_key_expiry_changes($1)", ["ffffffff-0000-4000-8000-000000000009"]],
  ["admin_list_agent_keys", "select * from public.admin_list_agent_keys()", []],
  ["admin_issue_agent_key", "select * from public.admin_issue_agent_key($1, 'x', 90)", [OPERATOR]],
  ["admin_revoke_agent_key", "select * from public.admin_revoke_agent_key($1)", ["ffffffff-0000-4000-8000-000000000009"]],
];
const INTERNAL_CALLS = [
  "select * from public.agent_key_set_expiry('ffffffff-0000-4000-8000-000000000009', 30, 'x')",
  "select * from public.agent_key_calls('ffffffff-0000-4000-8000-000000000009')",
  "select * from public.agent_key_expiry_changes('ffffffff-0000-4000-8000-000000000009')",
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
    for (const t of ["agent_api_keys", "agent_api_key_calls", "agent_api_key_expiry_changes"]) {
      assert.match(await errorAs(role, claims, `select * from public.${t}`) ?? "(succeeded)", /permission denied for table/, `${role}: ${t}`);
    }
  }
});

// ---- fresh auth for issue only ----------------------------------------------------
// amr shapes are GoTrue's (supabase/auth internal/models/sessions.go AMREntry:
// {method, timestamp: int unix seconds}); "oauth" is what a Google sign-in writes.
const oauthAmr = (secondsAgo) => [{ method: "oauth", timestamp: now() - secondsAgo }];

test("issue requires a password or Google (oauth) sign-in within 10 minutes; list and revoke do not", async () => {
  const issue = (claims) => errorAs("authenticated", claims, "select * from public.admin_issue_agent_key($1, 'fresh', 90)", [OPERATOR]);
  const reauth = /recent sign-in required/;
  assert.match(await issue({ sub: ADMIN, role: "authenticated", email: ADMIN_EMAIL }) ?? "", reauth, "admin claims without amr");
  assert.match(await issue({ sub: ADMIN, role: "authenticated" }) ?? "", reauth, "no amr");
  assert.match(await issue(adminClaims([])) ?? "", reauth, "empty amr");
  assert.match(await issue(adminClaims("password")) ?? "", reauth, "non-array amr");
  assert.match(await issue(adminClaims(pwAmr(11 * 60))) ?? "", reauth, "password 11 min ago");
  assert.match(await issue(adminClaims([{ method: "recovery", timestamp: now() }])) ?? "", reauth, "fresh recovery link");
  assert.match(await issue(adminClaims([{ method: "otp", timestamp: now() }])) ?? "", reauth, "fresh otp");
  assert.match(await issue(adminClaims([{ method: "magiclink", timestamp: now() }])) ?? "", reauth, "fresh magic link");
  assert.match(await issue(adminClaims(oauthAmr(11 * 60))) ?? "", reauth, "Google 11 min ago");
  assert.match(await issue(adminClaims([{ method: "oauth", timestamp: String(now()) }])) ?? "", reauth, "Google, string timestamp");
  assert.equal(await issue(adminClaims(oauthAmr(9 * 60))), null, "Google 9 min ago");
  assert.equal(await issue(adminClaims(oauthAmr(1))), null, "Google just now");
  assert.equal(await issue(adminClaims([...oauthAmr(5), ...pwAmr(3 * 3600)])), null, "fresh Google + stale password");
  assert.equal(await issue(adminClaims([...pwAmr(5), ...oauthAmr(3 * 3600)])), null, "fresh password + stale Google");
  assert.match(await issue(adminClaims([...pwAmr(20 * 60), ...oauthAmr(20 * 60)])) ?? "", reauth, "both stale");
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
    await q(`update public.user_profiles set status = 'rejected' where id = '${CUSTOMER}'`);

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
    assert.equal(by[demoted.id].account_status, "rejected");
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

// ---- round 2: audit trail and editable expiry --------------------------------------
const STALE_ADMIN = () => ({ sub: ADMIN, role: "authenticated", email: ADMIN_EMAIL, amr: pwAmr(24 * 3600) });

test("audit trail: the gateway's own mcp_log_call rows for that key only, newest first, with total and a capped limit", async () => {
  await asOwner(async (q) => {
    const a = await issueOwner(q, OPERATOR, "calls a");
    const b = await issueOwner(q, OPERATOR, "calls b");
    const ha = await sha256Hex(a.key), hb = await sha256Hex(b.key);
    await q("set local role mcp_gateway");
    for (let i = 0; i < 5; i++) await q("select public.mcp_log_call($1, $2, $3::jsonb, $4)", [ha, `tool_${i}`, { n: i }, i === 4]);
    await q("select public.mcp_log_call($1, 'other_key_tool', null, false)", [hb]);
    await q("reset role");
    // Spread the timestamps so ordering is by time, not insertion luck.
    await q("update public.agent_api_key_calls c set called_at = now() - make_interval(mins => 10 - (c.args->>'n')::int) where c.key_id = $1", [a.id]);
    await q("select set_config('request.jwt.claims', $1, true)", [JSON.stringify(STALE_ADMIN())]);
    await q("set local role authenticated");
    const rows = await q("select * from public.admin_list_agent_key_calls($1, 3)", [a.id]);
    assert.deepEqual(rows.map((r) => r.tool), ["tool_4", "tool_3", "tool_2"], "newest first, limited");
    assert.equal(Number(rows[0].total_calls), 5, "total counts every call for the key");
    assert.equal(rows[0].is_error, true);
    assert.deepEqual(rows[1].args, { n: 3 });
    assert.deepEqual(Object.keys(rows[0]).sort(), ["args", "called_at", "is_error", "tool", "total_calls"], "no key material");
    assert.equal((await q("select * from public.admin_list_agent_key_calls($1, 1000)", [a.id])).length, 5, "limit clamps to <= 200");
    assert.equal((await q("select * from public.admin_list_agent_key_calls($1)", [b.id])).length, 1, "other key's calls stay separate");
  });
});

test("expiry: admin sets 1-365 days from now with no re-auth, capped at 365 days from issue, and every change is logged", async () => {
  await asOwner(async (q) => {
    const k = await issueOwner(q, OPERATOR, "expiry", 90);
    await q("select set_config('request.jwt.claims', $1, true)", [JSON.stringify(STALE_ADMIN())]);
    await q("set local role authenticated");
    const [short] = await q("select * from public.admin_update_agent_key_expiry($1, 7)", [k.id]);
    assert.equal(short.key_prefix, k.key_prefix);
    const [{ days: d7 }] = await q("select round(extract(epoch from ($1::timestamptz - now())) / 86400)::int days", [short.expires_at]);
    assert.equal(d7, 7, "shortened to 7 days from now");
    const [long] = await q("select * from public.admin_update_agent_key_expiry($1, 365)", [k.id]);
    assert.equal(new Date(long.old_expires_at).getTime(), new Date(short.expires_at).getTime(), "old value recorded");
    const log = await q("select * from public.admin_list_agent_key_expiry_changes($1)", [k.id]);
    assert.equal(log.length, 2);
    assert.equal(log[0].changed_by, `${ADMIN_EMAIL} (${ADMIN}) via web admin`, "who, from the JWT");
    assert.equal(new Date(log[0].new_expires_at).getTime(), new Date(long.expires_at).getTime(), "newest first");
    const listed = (await q("select * from public.admin_list_agent_keys()")).find((r) => r.id === k.id);
    assert.equal(new Date(listed.expires_at).getTime(), new Date(long.expires_at).getTime(), "list reflects it");
  });
});

test("expiry: range, lifetime cap, and only active keys", async () => {
  const tryAs = (fn) => asOwner(async (q) => { try { return await fn(q); } catch (e) { return e.message; } });
  // 300 days into a key's life, at most 65 more days are possible.
  const capped = await tryAs(async (q) => {
    const k = await issueOwner(q, OPERATOR);
    await q("update public.agent_api_keys set created_at = now() - interval '300 days' where id = $1", [k.id]);
    const results = [];
    for (const d of [66, 65]) {
      try { await q("savepoint s"); await q("select * from public.agent_key_set_expiry($1, $2, 'test')", [k.id, d]); results.push(`${d}:ok`); }
      catch (e) { await q("rollback to savepoint s"); results.push(`${d}:${e.message}`); }
    }
    return results;
  });
  assert.match(capped[0], /^66:a key can live at most 365 days from issue: mtk_\S+ can be set at most 65 days from now$/);
  assert.equal(capped[1], "65:ok");
  for (const d of [0, 366, null]) {
    assert.match(await tryAs(async (q) => { const k = await issueOwner(q); await q("select * from public.agent_key_set_expiry($1, $2, 'test')", [k.id, d]); }), /1 to 365 days/);
  }
  assert.match(await tryAs(async (q) => {
    const k = await issueOwner(q); await q("select public.agent_key_revoke($1)", [k.id]);
    await q("select * from public.agent_key_set_expiry($1, 30, 'test')", [k.id]);
  }), /is revoked/);
  assert.match(await tryAs(async (q) => {
    const k = await issueOwner(q); await q("update public.agent_api_keys set expires_at = now() - interval '1 minute' where id = $1", [k.id]);
    await q("select * from public.agent_key_set_expiry($1, 30, 'test')", [k.id]);
  }), /has expired; issue a new key/);
  assert.match(await tryAs((q) => q("select * from public.agent_key_set_expiry('ffffffff-0000-4000-8000-000000000009', 30, 'test')")), /no key with id/);
  // A rejected change writes nothing.
  const unchanged = await asOwner(async (q) => {
    const k = await issueOwner(q);
    await q("update public.agent_api_keys set created_at = now() - interval '360 days' where id = $1", [k.id]);
    await q("savepoint s");
    try { await q("select * from public.agent_key_set_expiry($1, 30, 'test')", [k.id]); } catch { await q("rollback to savepoint s"); }
    const [{ n }] = await q("select count(*)::int n from public.agent_api_key_expiry_changes where key_id = $1", [k.id]);
    const [{ same }] = await q("select expires_at = $2::timestamptz same from public.agent_api_keys where id = $1", [k.id, k.expires_at]);
    return { n, same };
  });
  assert.deepEqual(unchanged, { n: 0, same: true });
});

test("an expiry change doesn't touch the credential: same hash, still authenticates, and stops at the new expiry", async () => {
  await asOwner(async (q) => {
    const k = await issueOwner(q);
    const hash = await sha256Hex(k.key);
    await q("select * from public.agent_key_set_expiry($1, 3, 'test')", [k.id]);
    const [{ hex }] = await q("select encode(key_hash, 'hex') hex from public.agent_api_keys where id = $1", [k.id]);
    assert.equal(hex, hash);
    await q("set local role mcp_gateway");
    assert.equal((await q("select * from public.mcp_authenticate($1)", [hash])).length, 1);
    await q("reset role");
    // Simulate time passing past the new expiry.
    await q("update public.agent_api_keys set expires_at = now() - interval '1 second' where id = $1", [k.id]);
    await q("set local role mcp_gateway");
    assert.equal((await q("select * from public.mcp_authenticate($1)", [hash])).length, 0);
    await q("reset role");
  });
});

// ---- banned / deleted Supabase Auth users (20260926165000) -----------------------------
const gatewayAuth = async (q, hash) => {
  await q("set local role mcp_gateway");
  const rows = await q("select key_id from public.mcp_authenticate($1)", [hash]);
  await q("reset role");
  return rows.length;
};

test("a banned or soft-deleted owner's key stops authenticating immediately, like a revoked key", async () => {
  await asOwner(async (q) => {
    const k = await issueOwner(q, OPERATOR, "ban");
    const hash = await sha256Hex(k.key);
    assert.equal(await gatewayAuth(q, hash), 1, "works before");
    await q(`update auth.users set banned_until = now() + interval '100 years' where id = '${OPERATOR}'`);
    assert.equal(await gatewayAuth(q, hash), 0, "banned -> rejected");
    await q(`update auth.users set banned_until = now() - interval '1 minute' where id = '${OPERATOR}'`);
    assert.equal(await gatewayAuth(q, hash), 1, "ban expired -> works again (nothing cached)");
    await q(`update auth.users set banned_until = null, deleted_at = now() where id = '${OPERATOR}'`);
    assert.equal(await gatewayAuth(q, hash), 0, "soft-deleted -> rejected");
  });
});

test("mcp_log_call writes nothing for a banned owner's key", async () => {
  await asOwner(async (q) => {
    const k = await issueOwner(q, OPERATOR, "ban log");
    const hash = await sha256Hex(k.key);
    await q(`update auth.users set banned_until = now() + interval '1 day' where id = '${OPERATOR}'`);
    await q("set local role mcp_gateway");
    await q("select public.mcp_log_call($1, 'get_x', null, false)", [hash]);
    await q("reset role");
    const [{ n }] = await q("select count(*)::int n from public.agent_api_key_calls where key_id = $1", [k.id]);
    assert.equal(n, 0);
  });
});

test("issue refuses a banned or deleted owner (unless the CLI's negative-test flag); list marks existing keys as won't-work", async () => {
  const err = await asOwner(async (q) => {
    await q(`update auth.users set banned_until = now() + interval '1 day' where id = '${CUSTOMER}'`);
    try { await issueOwner(q, CUSTOMER); return null; } catch (e) { return e.message; }
  });
  assert.match(err ?? "(issued)", /banned or deleted in Supabase Auth/);
  const deleted = await asOwner(async (q) => {
    await q(`update auth.users set deleted_at = now() where id = '${CUSTOMER}'`);
    try { await issueOwner(q, CUSTOMER); return null; } catch (e) { return e.message; }
  });
  assert.match(deleted ?? "(issued)", /banned or deleted/);
  await asOwner(async (q) => {
    await q(`update auth.users set banned_until = now() + interval '1 day' where id = '${CUSTOMER}'`);
    assert.ok((await issueOwner(q, CUSTOMER, "neg", 90, true)).key, "negative-test flag still issues");
  });
  await asOwner(async (q) => {
    const k = await issueOwner(q, CUSTOMER, "listed");
    await q(`update auth.users set banned_until = now() + interval '1 day' where id = '${CUSTOMER}'`);
    const row = (await q("select * from public.agent_key_list()")).find((r) => r.id === k.id);
    assert.equal(row.status, "active");
    assert.equal(row.owner_eligible, false);
    await q(`update auth.users set banned_until = null where id = '${CUSTOMER}'`);
    assert.equal((await q("select * from public.agent_key_list()")).find((r) => r.id === k.id).owner_eligible, true);
  });
});

test("the fix keeps every grant: still mcp_gateway-only for the gateway functions, owner-only for the implementation", async () => {
  for (const [role, ok] of [["mcp_gateway", true], ["anon", false], ["authenticated", false], ["service_role", false], ["mcp_reader", false]]) {
    const r = await errorAs(role, null, "select * from public.mcp_authenticate(repeat('0', 64))");
    assert.equal(r === null, ok, `${role} mcp_authenticate: ${r}`);
    const l = await errorAs(role, null, "select public.mcp_log_call(repeat('0', 64), 'x', null, false)");
    assert.equal(l === null, ok, `${role} mcp_log_call: ${l}`);
  }
  for (const role of ["anon", "authenticated", "service_role", "mcp_gateway", "mcp_reader"]) {
    assert.match(await errorAs(role, null, "select * from public.agent_key_list()") ?? "(ok)", /permission denied/);
  }
});

// ---- service accounts (20260926180000) ------------------------------------------------
// GoTrue's Admin API create, as read from supabase/auth: INSERT the user
// unconfirmed (handle_new_user fires), then Confirm() as a separate UPDATE
// (handle_user_confirmed fires).
async function gotrueCreate(q, { id, email, appMeta = {}, userMeta = {}, confirm = true }) {
  await q("insert into auth.users (id, email, raw_app_meta_data, raw_user_meta_data) values ($1, $2, $3::jsonb, $4::jsonb)", [id, email, appMeta, userMeta]);
  if (confirm) await q("update auth.users set email_confirmed_at = now() where id = $1", [id]);
  return (await q("select * from public.user_profiles where id = $1", [id]))[0];
}
const SVC = "5e5e5e5e-0000-4000-8000-00000000000a";
const HUMAN_NEW = "4e4e4e4e-0000-4000-8000-00000000000b";
const svcCreate = (q) => gotrueCreate(q, { id: SVC, email: "svc-nightly@service.invalid", appMeta: { account_type: "service" }, userMeta: { first_name: "Service", last_name: "Nightly" } });
const errOf = async (q, sql, params = []) => { await q("savepoint e"); try { await q(sql, params); await q("release savepoint e"); return null; } catch (e) { await q("rollback to savepoint e"); return e.message; } };

test("account_type comes only from app_metadata (Admin API); a signup's own user_metadata can't claim 'service'", async () => {
  await asOwner(async (q) => {
    const svc = await svcCreate(q);
    assert.equal(svc.account_type, "service");
    assert.equal(svc.status, "pending"); assert.equal(svc.role, "customer"); assert.equal(svc.is_admin, false);
    assert.ok(svc.confirmed_at, "confirmed like a normal account (so the CLI must approve it and notify must skip it)");
    assert.deepEqual([svc.first_name, svc.last_name], ["Service", "Nightly"]);
    const sneaky = await gotrueCreate(q, { id: HUMAN_NEW, email: "sneaky@example.test", userMeta: { account_type: "service", first_name: "S", last_name: "N" } });
    assert.equal(sneaky.account_type, "human", "user_metadata is user-controlled and ignored");
    for (const [i, v] of ["Service", "admin", "", null, 7].entries()) {
      const id = `6e6e6e6e-0000-4000-8000-00000000000${i}`;
      assert.equal((await gotrueCreate(q, { id, email: `x${i}@example.test`, appMeta: { account_type: v } })).account_type, "human", `app_metadata ${JSON.stringify(v)}`);
    }
  });
});

test("a service account can never be an admin -- as the owner, or as an admin through the REST path", async () => {
  await asOwner(async (q) => {
    await svcCreate(q);
    await q("update public.user_profiles set status = 'approved', role = 'operator' where id = $1", [SVC]);
    assert.match(await errOf(q, "update public.user_profiles set is_admin = true where id = $1", [SVC]) ?? "(allowed)", /user_profiles_service_never_admin/);
    await q("select set_config('request.jwt.claims', $1, true)", [JSON.stringify(adminClaims())]);
    await q("set local role authenticated");
    assert.match(await errOf(q, "update public.user_profiles set is_admin = true where id = $1", [SVC]) ?? "(allowed)", /user_profiles_service_never_admin/, "admin via REST");
    assert.equal(await errOf(q, "update public.user_profiles set is_admin = true where id = $1", [OPERATOR]), null, "control: a human operator can still be made admin");
    assert.equal(await errOf(q, "update public.user_profiles set data_mode = 'all', status = 'rejected' where id = $1", [SVC]), null, "other fields stay editable");
    await q("reset role");
  });
});

test("account_type can't change after creation, in either direction, for anyone", async () => {
  await asOwner(async (q) => {
    await svcCreate(q);
    assert.match(await errOf(q, "update public.user_profiles set account_type = 'human' where id = $1", [SVC]) ?? "(allowed)", /cannot change/, "owner: service -> human");
    assert.match(await errOf(q, "update public.user_profiles set account_type = 'service' where id = $1", [OPERATOR]) ?? "(allowed)", /cannot change/, "owner: human -> service");
    assert.equal(await errOf(q, "update public.user_profiles set account_type = 'service', data_mode = 'all' where id = $1", [SVC]), null, "same value is fine");
    await q("select set_config('request.jwt.claims', $1, true)", [JSON.stringify(adminClaims())]);
    await q("set local role authenticated");
    assert.match(await errOf(q, "update public.user_profiles set account_type = 'human', is_admin = true where id = $1", [SVC]) ?? "(allowed)", /cannot change|service_never_admin/, "admin: flip + promote in one statement");
    assert.match(await errOf(q, "update public.user_profiles set account_type = 'human' where id = $1", [SVC]) ?? "(allowed)", /cannot change/, "admin: flip alone");
    await q("reset role");
  });
});

test("a service account's keys work through the gateway exactly like a person's, with its own scope and data_mode", async () => {
  await asOwner(async (q) => {
    await svcCreate(q);
    await q("update public.user_profiles set status = 'approved', role = 'operator', data_mode = 'real_only' where id = $1", [SVC]);
    const k = await issueOwner(q, SVC, "agent 1");
    const hash = await sha256Hex(k.key);
    await q("set local role mcp_gateway");
    const [hit] = await q("select user_id from public.mcp_authenticate($1)", [hash]);
    await q("reset role");
    assert.equal(hit?.user_id, SVC, "no gateway change needed");
    const row = (await q("select * from public.agent_key_list()")).find((r) => r.id === k.id);
    assert.equal(row.account_type, "service"); assert.equal(row.account_data_mode, "real_only"); assert.equal(row.owner_eligible, true);
    // Kill switches: un-approve the account, or ban it -- all its keys stop.
    await q("update public.user_profiles set status = 'rejected' where id = $1", [SVC]);
    await q("set local role mcp_gateway");
    assert.equal((await q("select * from public.mcp_authenticate($1)", [hash])).length, 0, "un-approved");
    await q("reset role");
    await q("update public.user_profiles set status = 'approved' where id = $1", [SVC]);
    await q("update auth.users set banned_until = now() + interval '1 day' where id = $1", [SVC]);
    await q("set local role mcp_gateway");
    assert.equal((await q("select * from public.mcp_authenticate($1)", [hash])).length, 0, "banned");
    await q("reset role");
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

test("web/index.html's Google re-auth asks for interactive account selection for the signed-in email", () => {
  const html = readFileSync(new URL("../web/index.html", import.meta.url), "utf8");
  const start = html.indexOf("function keysReauthWithGoogle");
  assert.ok(start > 0, "keysReauthWithGoogle() exists");
  const body = html.slice(start, html.indexOf("\n}\n", start));
  assert.match(body, /signInWithOAuth\(\{\s*provider:'google'/);
  assert.match(body, /prompt:'select_account'/, "forces the Google account chooser");
  assert.match(body, /login_hint:\s*session\.user\.email/, "pre-selects the signed-in admin's own account");
});

test("web/index.html never names key_hash, never reads the key tables directly, never logs the one-time key", () => {
  const html = readFileSync(new URL("../web/index.html", import.meta.url), "utf8");
  assert.doesNotMatch(html, /key_hash/);
  assert.doesNotMatch(html, /from\(['"]agent_api_key/);
  assert.doesNotMatch(html, /rpc\(['"]agent_key_/, "only the admin_* wrappers are callable");
  const logs = html.match(/console\.\w+\([^;]*\)/g) ?? [];
  assert.ok(!logs.some((l) => /issued\.key\b|plaintext|newKey/.test(l)), logs.filter((l) => /issued|plaintext|newKey/.test(l)).join("\n"));
});
