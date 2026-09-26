#!/usr/bin/env node
// Live verification harness for the web app's API-key admin surface
// (migration 20260926160000_agent_keys_admin.sql). Same spirit as
// scripts/mcp-verify.mjs:
//
//   node scripts/agent-keys-admin-verify.mjs [--no-rest]
//
// DATABASE_URL from the environment wins over .env (as in agent-keys.mjs);
// --no-rest skips section 6 (the live REST calls), e.g. for a dry run
// against a local database.
//
// It is READ-ONLY in effect. Every write -- including the end-to-end
// issue -> authenticate -> revoke case -- runs inside an explicit transaction
// that is always rolled back, using the SET LOCAL pattern from
// docs/SECURITY.md (never a bare SET ROLE across the transaction pooler).
// The one key it generates exists only inside that rolled-back transaction;
// it is held in memory, never printed (every output line is scanned and any
// key text is replaced with [REDACTED], with a loud warning if that happens),
// and it never authenticated anything outside the transaction.
//
// Test accounts are picked from the live user_profiles table by shape (an
// admin, a non-admin approved operator, an approved customer, a pending
// account) and shown by their first 8 id characters only.
//
// Sections:
//   1. The functions exist as SECURITY DEFINER with an empty search_path
//   2. Catalog: who can EXECUTE what; the key tables are still deny-all
//   3. Function-level auth as each real role (anon, service_role, the MCP
//      roles, non-admin authenticated, admin), fresh-auth rule for issue
//   4. End to end as an admin: issue -> hash matches -> mcp_authenticate
//      (as mcp_gateway) accepts it -> a gateway call shows in the key's audit
//      trail -> expiry change (no re-auth, logged, lifetime cap) -> revoke ->
//      rejected -> still listed
//   5. The plaintext never reached pg_stat_statements
//   6. The real REST API (anon key only): every new function and the tables
//      are refused
import { readFileSync } from "node:fs";
import pg from "pg";
import { parseBearerKey, sha256Hex } from "../supabase/functions/mcp/auth.ts";

const env = Object.fromEntries(
  readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
    .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "")]),
);
const ORIGIN = new URL(env.SUPABASE_URL).origin;
const DATABASE_URL = process.env.DATABASE_URL ?? env.DATABASE_URL;
const NO_REST = process.argv.includes("--no-rest");

const ADMIN_FNS = ["admin_list_agent_keys()", "admin_issue_agent_key(uuid,text,integer)", "admin_revoke_agent_key(uuid)",
  "admin_update_agent_key_expiry(uuid,integer)", "admin_list_agent_key_calls(uuid,integer)", "admin_list_agent_key_expiry_changes(uuid)"];
const INTERNAL_FNS = ["agent_key_list()", "agent_key_issue(uuid,text,integer,text,boolean)", "agent_key_revoke(uuid)",
  "agent_key_set_expiry(uuid,integer,text)", "agent_key_calls(uuid,integer)", "agent_key_expiry_changes(uuid)"];
const FN_NAMES = [...ADMIN_FNS, ...INTERNAL_FNS].map((f) => f.slice(0, f.indexOf("(")));
const KEY_TABLES = ["agent_api_keys", "agent_api_key_calls", "agent_api_key_expiry_changes"];
const API_ROLES = ["anon", "authenticated", "service_role", "mcp_gateway", "mcp_reader"];
const NO_SUCH_KEY = "00000000-0000-4000-8000-000000000000";

// ---- output with redaction ------------------------------------------------
const secrets = [];
let redactions = 0;
function out(...parts) {
  let line = parts.map((p) => (typeof p === "string" ? p : JSON.stringify(p))).join(" ");
  for (const s of secrets) if (s && line.includes(s)) { line = line.split(s).join("[REDACTED]"); redactions++; }
  console.log(line);
}
const results = [];
function verdict(name, pass, detail = "") {
  results.push({ name, pass });
  out(`${pass ? "PASS" : "FAIL"}  ${name}${detail ? ` -- ${detail}` : ""}`);
}
const short = (id) => (id ? id.slice(0, 8) : "(none)");
const target0 = (...candidates) => candidates.find(Boolean).id;

// ---- db -------------------------------------------------------------------
async function withDb(fn) {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
// Runs fn inside a transaction that is always rolled back. `as(role, claims)`
// switches role/claims transaction-locally; `owner()` switches back.
async function rolledBack(db, fn) {
  await db.query("begin");
  const granted = new Set();
  try {
    const q = (sql, params = []) => db.query(sql, params).then((r) => r.rows);
    const as = async (role, claims = null) => {
      await db.query("reset role");
      // The mcp_* roles aren't granted to postgres; a transaction-local
      // self-grant (rolled back below) lets this session take them on --
      // the same move scripts/mcp-verify.mjs makes.
      if ((role === "mcp_gateway" || role === "mcp_reader") && !granted.has(role)) {
        await db.query(`grant ${role} to postgres with inherit false, set true`);
        granted.add(role);
      }
      await db.query("select set_config('request.jwt.claims', $1, true)", [claims ? JSON.stringify(claims) : ""]);
      await db.query(`set local role ${role}`);
    };
    const owner = () => db.query("reset role");
    return await fn({ q, as, owner });
  } finally {
    await db.query("rollback");
  }
}
// One statement as role/claims in its own rolled-back transaction; returns
// { rows } or { error }.
async function attempt(db, role, claims, sql, params = []) {
  return rolledBack(db, async ({ q, as }) => {
    await as(role, claims);
    try { return { rows: await q(sql, params) }; } catch (e) { return { error: e.message }; }
  });
}

const nowS = () => Math.floor(Date.now() / 1000);
const claimsFor = (id, email, amr) => ({ sub: id, role: "authenticated", email, ...(amr === undefined ? {} : { amr }) });
const fresh = () => [{ method: "password", timestamp: nowS() - 30 }];

// ===========================================================================
await withDb(async (db) => {
  out(`# agent-keys admin live verification -- ${new Date().toISOString()}`);
  out(`# project: ${ORIGIN}`);

  // ---- 1. functions exist, definer, empty search_path ------------------------
  out("\n## 1. Functions (pg_proc)");
  const { rows: procs } = await db.query(
    `select p.oid::regprocedure::text sig, p.prosecdef definer, p.proconfig config, pg_get_userbyid(p.proowner) owner
       from pg_proc p where p.pronamespace = 'public'::regnamespace and p.proname = any($1)
      order by 1`, [FN_NAMES],
  );
  for (const p of procs) out(`  ${p.sig}  definer=${p.definer}  config=${JSON.stringify(p.config)}  owner=${p.owner}`);
  verdict(`all ${FN_NAMES.length} functions exist, SECURITY DEFINER, search_path=''`,
    procs.length === FN_NAMES.length && procs.every((p) => p.definer && (p.config ?? []).some((c) => c === 'search_path=""' || c === "search_path=")),
    `${procs.length}/${FN_NAMES.length} found`);
  if (procs.length !== FN_NAMES.length) {
    out("\nMigrations 20260926160000 + 20260926170000 are not both applied -- stopping.");
    process.exitCode = 1;
    return;
  }

  // ---- 2. catalog: EXECUTE and table grants ------------------------------------
  out("\n## 2. Catalog: EXECUTE and table privileges");
  const priv = async (role, fn) => (await db.query("select has_function_privilege($1, $2, 'EXECUTE') ok", [role, `public.${fn}`])).rows[0].ok;
  const execMatrix = {};
  for (const fn of [...ADMIN_FNS, ...INTERNAL_FNS]) {
    execMatrix[fn] = {};
    for (const role of API_ROLES) execMatrix[fn][role] = await priv(role, fn);
    out(`  ${fn.padEnd(56)} ${API_ROLES.map((r) => `${r}=${execMatrix[fn][r] ? "X" : "-"}`).join(" ")}`);
  }
  verdict("admin_* wrappers: EXECUTE for authenticated only (not anon/service_role/mcp_gateway/mcp_reader)",
    ADMIN_FNS.every((fn) => API_ROLES.every((r) => execMatrix[fn][r] === (r === "authenticated"))));
  verdict("agent_key_* implementation: no API role can EXECUTE (owner only)",
    INTERNAL_FNS.every((fn) => API_ROLES.every((r) => !execMatrix[fn][r])));
  const { rows: acls } = await db.query(
    `select p.oid::regprocedure::text sig, coalesce(array_to_string(p.proacl, ','), '(default)') acl
       from pg_proc p where p.pronamespace='public'::regnamespace and p.proname = any($1)`, [FN_NAMES],
  );
  verdict("no PUBLIC EXECUTE entry on any of them", acls.every((a) => a.acl !== "(default)" && !/(^|,)=X/.test(a.acl)),
    acls.filter((a) => a.acl === "(default)" || /(^|,)=X/.test(a.acl)).map((a) => a.sig).join(", "));

  const tablePrivs = [];
  for (const t of KEY_TABLES) {
    for (const role of API_ROLES) {
      for (const p of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
        if ((await db.query("select has_table_privilege($1, $2, $3) ok", [role, `public.${t}`, p])).rows[0].ok) tablePrivs.push(`${role}:${p}:${t}`);
      }
    }
  }
  const { rows: [rls] } = await db.query(
    `select bool_and(c.relrowsecurity) rls_on, count(*)::int n,
            (select count(*)::int from pg_policies where schemaname='public' and tablename = any($1)) policies
       from pg_class c where c.relnamespace = 'public'::regnamespace and c.relname = any($1)`, [KEY_TABLES],
  );
  verdict(`${KEY_TABLES.join(" / ")}: no table privilege for any API role, RLS on, zero policies`,
    tablePrivs.length === 0 && rls.rls_on && rls.policies === 0 && rls.n === KEY_TABLES.length,
    `privileges=${tablePrivs.join(" ") || "none"} rls_on=${rls.rls_on} policies=${rls.policies}`);

  // ---- 3. function-level auth as real roles ------------------------------------------
  out("\n## 3. Function-level auth");
  const pick = async (where) => (await db.query(
    `select p.id::text id, u.email from public.user_profiles p join auth.users u on u.id = p.id where ${where} order by p.id limit 1`)).rows[0] ?? null;
  const admin = await pick("p.is_admin and p.status = 'approved'");
  const operator = await pick("p.role = 'operator' and p.status = 'approved' and not p.is_admin");
  const customer = await pick("p.role = 'customer' and p.status = 'approved' and not p.is_admin");
  const pending = await pick("p.status = 'pending' and not p.is_admin");
  out(`  accounts: admin=${short(admin?.id)} operator=${short(operator?.id)} customer=${short(customer?.id)} pending=${short(pending?.id)}`);
  if (!admin) {
    verdict("an approved admin account exists to test with", false);
    return;
  }

  const calls = [
    ["list", "select * from public.admin_list_agent_keys()", []],
    ["issue", "select id, key_prefix from public.admin_issue_agent_key($1, 'agent-keys-admin-verify (rolled back)', 1)", [operator?.id ?? admin.id]],
    ["revoke", "select * from public.admin_revoke_agent_key($1)", [NO_SUCH_KEY]],
    ["expiry", "select * from public.admin_update_agent_key_expiry($1, 30)", [NO_SUCH_KEY]],
    ["calls", "select * from public.admin_list_agent_key_calls($1)", [NO_SUCH_KEY]],
    ["expiry log", "select * from public.admin_list_agent_key_expiry_changes($1)", [NO_SUCH_KEY]],
  ];
  const denialCases = [
    ["anon", null, /permission denied for function/],
    ["service_role", null, /permission denied for function/],
    ["mcp_gateway", null, /permission denied for function/],
    // mcp_reader holding an ADMIN's claims -- the shape of an MCP tool
    // transaction for an admin's key. Still refused at EXECUTE.
    ["mcp_reader", { sub: admin.id, amr: fresh() }, /permission denied for function/],
  ];
  for (const who of [operator, customer, pending]) {
    if (who) denialCases.push(["authenticated", claimsFor(who.id, who.email, fresh()), /^forbidden$/]);
  }
  denialCases.push(["authenticated", null, /^forbidden$/]);
  for (const [role, claims, expected] of denialCases) {
    const got = [];
    for (const [name, sql, params] of calls) got.push([name, await attempt(db, role, claims, sql, params)]);
    const ok = got.every(([, r]) => r.error && expected.test(r.error));
    verdict(`${role}${claims ? ` as ${short(claims.sub)}` : " (no claims)"}: all ${calls.length} admin RPCs refused`, ok,
      got.map(([n, r]) => `${n}: ${r.error ?? `SUCCEEDED (${r.rows.length} rows)`}`).join("; "));
  }
  for (const [name, sql] of [
    ["agent_key_list()", "select * from public.agent_key_list()"],
    ["agent_key_issue()", `select * from public.agent_key_issue('${target0(operator, admin)}', 'x', 1, 'x', true)`],
    ["agent_key_revoke()", `select * from public.agent_key_revoke('${NO_SUCH_KEY}')`],
    ["agent_key_set_expiry()", `select * from public.agent_key_set_expiry('${NO_SUCH_KEY}', 30, 'x')`],
    ["agent_key_calls()", `select * from public.agent_key_calls('${NO_SUCH_KEY}')`],
    ["agent_key_expiry_changes()", `select * from public.agent_key_expiry_changes('${NO_SUCH_KEY}')`],
  ]) {
    const r = await attempt(db, "authenticated", claimsFor(admin.id, admin.email, fresh()), sql);
    verdict(`admin cannot call the implementation directly: ${name}`, /permission denied for function/.test(r.error ?? ""), r.error ?? "SUCCEEDED");
  }
  for (const t of KEY_TABLES) {
    const r = await attempt(db, "authenticated", claimsFor(admin.id, admin.email, fresh()), `select count(*) from public.${t}`);
    verdict(`admin cannot read ${t} directly`, /permission denied for table/.test(r.error ?? ""), r.error ?? "SUCCEEDED");
  }

  // Fresh-auth rule on issue; list/revoke need none.
  const target = operator ?? admin;
  const issueAs = (amr) => attempt(db, "authenticated", claimsFor(admin.id, admin.email, amr),
    "select id from public.admin_issue_agent_key($1, 'agent-keys-admin-verify (rolled back)', 1)", [target.id]);
  const reauth = /recent sign-in required/;
  for (const [desc, amr] of [
    ["no amr claim", undefined],
    ["password 11 minutes ago", [{ method: "password", timestamp: nowS() - 660 }]],
    ["Google (oauth) 11 minutes ago", [{ method: "oauth", timestamp: nowS() - 660 }]],
    ["fresh but other method (recovery)", [{ method: "recovery", timestamp: nowS() }]],
    ["fresh but other method (otp)", [{ method: "otp", timestamp: nowS() }]],
  ]) {
    const r = await issueAs(amr);
    verdict(`admin issue refused: ${desc}`, reauth.test(r.error ?? ""), r.error ?? "SUCCEEDED");
  }
  for (const [desc, amr] of [
    ["password 9 minutes ago", [{ method: "password", timestamp: nowS() - 540 }]],
    ["Google (oauth) 9 minutes ago", [{ method: "oauth", timestamp: nowS() - 540 }]],
  ]) {
    const r = await issueAs(amr);
    verdict(`admin issue allowed: ${desc}`, !r.error, r.error ?? `${r.rows.length} row`);
  }
  const stale = [{ method: "password", timestamp: nowS() - 86400 }];
  const staleList = await attempt(db, "authenticated", claimsFor(admin.id, admin.email, stale), "select count(*)::int n from public.admin_list_agent_keys()");
  const staleRevoke = await attempt(db, "authenticated", claimsFor(admin.id, admin.email, stale), "select * from public.admin_revoke_agent_key($1)", [NO_SUCH_KEY]);
  const staleCalls = await attempt(db, "authenticated", claimsFor(admin.id, admin.email, stale), "select * from public.admin_list_agent_key_calls($1)", [NO_SUCH_KEY]);
  const staleLog = await attempt(db, "authenticated", claimsFor(admin.id, admin.email, stale), "select * from public.admin_list_agent_key_expiry_changes($1)", [NO_SUCH_KEY]);
  verdict("list, revoke and the audit reads need no re-auth (day-old sign-in)",
    !staleList.error && !staleRevoke.error && !staleCalls.error && !staleLog.error,
    staleList.error ?? staleRevoke.error ?? staleCalls.error ?? staleLog.error ?? `list=${staleList.rows[0].n} rows`);

  // List shape and parity with the CLI's own function.
  const parity = await rolledBack(db, async ({ q, as, owner }) => {
    const ownerRows = await q("select * from public.agent_key_list()");
    const [{ n }] = await q("select count(*)::int n from public.agent_api_keys");
    await as("authenticated", claimsFor(admin.id, admin.email, stale));
    const adminRows = await q("select * from public.admin_list_agent_keys()");
    await owner();
    return { ownerRows, adminRows, n };
  });
  const cols = Object.keys(parity.adminRows[0] ?? {});
  verdict("admin list == CLI list (agent_key_list), row for row, and covers every key",
    JSON.stringify(parity.adminRows) === JSON.stringify(parity.ownerRows) && parity.adminRows.length === parity.n,
    `${parity.adminRows.length} listed / ${parity.n} in table`);
  verdict("list exposes no hash or key column", parity.adminRows.length === 0 || !cols.some((c) => /hash|^key$/.test(c)), cols.join(","));
  const statusCounts = parity.adminRows.reduce((m, r) => ((m[r.status] = (m[r.status] ?? 0) + 1), m), {});
  out(`  current keys by status: ${JSON.stringify(statusCounts)}`);

  // ---- 4. end to end, rolled back --------------------------------------------------
  out(`\n## 4. End to end as admin ${short(admin.id)} for account ${short(target.id)} (one transaction, rolled back)`);
  const e2e = await rolledBack(db, async ({ q, as, owner }) => {
    const r = {};
    await as("authenticated", claimsFor(admin.id, admin.email, fresh()));
    const [issued] = await q("select * from public.admin_issue_agent_key($1, 'agent-keys-admin-verify (rolled back)', 1)", [target.id]);
    secrets.push(issued.key, issued.key.slice(4), issued.key.slice(12));
    r.issued = { id: issued.id, prefix: issued.key_prefix, label: issued.label, expires: issued.expires_at, cols: Object.keys(issued) };
    r.shapeOk = parseBearerKey(`Bearer ${issued.key}`) === issued.key && issued.key_prefix === issued.key.slice(0, 12);
    r.hash = await sha256Hex(issued.key);
    await owner();
    const [stored] = await q("select encode(key_hash,'hex') hex, created_by, label from public.agent_api_keys where id = $1", [issued.id]);
    r.hashOk = stored.hex === r.hash;
    r.createdBy = stored.created_by;
    const [{ n: plainHits }] = await q("select count(*)::int n from public.agent_api_keys t where t::text like '%' || $1 || '%'", [issued.key.slice(12)]);
    r.plainHits = plainHits;
    await as("mcp_gateway");
    r.authBefore = await q("select key_id, user_id from public.mcp_authenticate($1)", [r.hash]);
    // Banned owner (20260926165000): ban the linked account's auth row inside
    // this rolled-back transaction, check the key dies, then lift it. Needs
    // UPDATE on auth.users for the connecting role; SKIP if not granted.
    await owner();
    await q("savepoint ban");
    try {
      await q("update auth.users set banned_until = now() + interval '1 day' where id = $1", [target.id]);
      await as("mcp_gateway");
      r.authBanned = (await q("select key_id from public.mcp_authenticate($1)", [r.hash])).length;
      await owner();
      await q("update auth.users set banned_until = null where id = $1", [target.id]);
      await as("mcp_gateway");
      r.authUnbanned = (await q("select key_id from public.mcp_authenticate($1)", [r.hash])).length;
      await owner();
      await q("rollback to savepoint ban");
    } catch (e) {
      await owner().catch(() => {});
      await q("rollback to savepoint ban");
      r.banSkip = e.message;
    }
    await as("mcp_gateway");
    await q("select public.mcp_log_call($1, 'agent-keys-admin-verify', $2::jsonb, false)", [r.hash, { rolled_back: true }]);
    const dayOld = claimsFor(admin.id, admin.email, [{ method: "password", timestamp: nowS() - 86400 }]);
    await as("authenticated", dayOld);
    r.calls = await q("select * from public.admin_list_agent_key_calls($1)", [issued.id]);
    // Expiry, with a day-old sign-in: no re-auth required.
    [r.expiry] = await q("select * from public.admin_update_agent_key_expiry($1, 30)", [issued.id]);
    r.expiryLog = await q("select * from public.admin_list_agent_key_expiry_changes($1)", [issued.id]);
    // Lifetime cap: pretend the key is 300 days old; 66 more days is over.
    await owner();
    await q("update public.agent_api_keys set created_at = now() - interval '300 days' where id = $1", [issued.id]);
    await as("authenticated", dayOld);
    await q("savepoint cap");
    try { await q("select * from public.admin_update_agent_key_expiry($1, 66)", [issued.id]); r.capError = null; }
    catch (e) { r.capError = e.message; await q("rollback to savepoint cap"); }
    r.capOk = (await q("select * from public.admin_update_agent_key_expiry($1, 65)", [issued.id])).length;
    await as("mcp_gateway");
    r.authAfterExpiry = await q("select key_id from public.mcp_authenticate($1)", [r.hash]);
    await as("authenticated", dayOld);
    r.revoked = await q("select * from public.admin_revoke_agent_key($1)", [issued.id]);
    r.expiryAfterRevoke = await q("savepoint rv").then(() => q("select * from public.admin_update_agent_key_expiry($1, 5)", [issued.id]))
      .then(() => null, async (e) => { await q("rollback to savepoint rv"); return e.message; });
    r.revokedAgain = await q("select * from public.admin_revoke_agent_key($1)", [issued.id]);
    await as("mcp_gateway");
    r.authAfter = await q("select key_id, user_id from public.mcp_authenticate($1)", [r.hash]);
    await as("authenticated", claimsFor(admin.id, admin.email, [{ method: "password", timestamp: nowS() - 86400 }]));
    r.listed = (await q("select * from public.admin_list_agent_keys()")).find((x) => x.id === issued.id);
    await owner();
    return r;
  });
  out(`  issued ${e2e.issued.prefix}... label="${e2e.issued.label}" expires=${e2e.issued.expires.toISOString()} result columns=${e2e.issued.cols.join(",")}`);
  verdict("key has the gateway's exact shape (mcp/auth.ts parseBearerKey) and prefix = first 12 chars", e2e.shapeOk);
  verdict("stored key_hash == mcp/auth.ts sha256Hex(key)", e2e.hashOk);
  verdict("plaintext appears in no column of the stored row", e2e.plainHits === 0, `${e2e.plainHits} hits`);
  verdict("created_by comes from the admin's JWT", e2e.createdBy === `${admin.email} (${admin.id}) via web admin`,
    e2e.createdBy.replace(admin.email, "<admin email>").replace(admin.id, `${short(admin.id)}...`));
  if (e2e.banSkip) out(`SKIP  banned-owner behaviour (cannot update auth.users here: ${e2e.banSkip}) -- definition check below still runs`);
  else {
    verdict("owner banned in Supabase Auth -> mcp_authenticate returns zero rows", e2e.authBanned === 0, `${e2e.authBanned} rows`);
    verdict("ban lifted -> the same key authenticates again (nothing cached)", e2e.authUnbanned === 1, `${e2e.authUnbanned} rows`);
  }
  verdict("mcp_authenticate (as mcp_gateway) accepts the new key and resolves the linked account",
    e2e.authBefore.length === 1 && e2e.authBefore[0].user_id === target.id && e2e.authBefore[0].key_id === e2e.issued.id);
  verdict("audit trail shows the gateway call just logged (mcp_log_call as mcp_gateway), no key material",
    e2e.calls.length === 1 && e2e.calls[0].tool === "agent-keys-admin-verify" && Number(e2e.calls[0].total_calls) === 1
      && !Object.keys(e2e.calls[0]).some((c) => /hash|^key$/.test(c)),
    `${e2e.calls.length} call(s): ${e2e.calls.map((c) => c.tool).join(",")}`);
  verdict("expiry change with a day-old sign-in (no re-auth): 30 days from now, old value returned",
    !!e2e.expiry && Math.round((new Date(e2e.expiry.expires_at) - Date.now()) / 864e5) === 30 && !!e2e.expiry.old_expires_at);
  verdict("expiry change logged with who (from the JWT), old and new values",
    e2e.expiryLog.length === 1 && e2e.expiryLog[0].changed_by === `${admin.email} (${admin.id}) via web admin`
      && new Date(e2e.expiryLog[0].new_expires_at).getTime() === new Date(e2e.expiry.expires_at).getTime(),
    `${e2e.expiryLog.length} row(s)`);
  verdict("lifetime cap: 300 days into a key's life, +66 days refused, +65 allowed",
    /at most 65 days from now/.test(e2e.capError ?? "") && e2e.capOk === 1, e2e.capError ?? "66 SUCCEEDED");
  verdict("the key still authenticates after its expiry was changed", e2e.authAfterExpiry.length === 1);
  verdict("admin revoke returns the row once, then nothing", e2e.revoked.length === 1 && e2e.revokedAgain.length === 0);
  verdict("a revoked key's expiry can't be changed", /is revoked/.test(e2e.expiryAfterRevoke ?? ""), e2e.expiryAfterRevoke ?? "SUCCEEDED");
  verdict("revoked key: mcp_authenticate returns zero rows", e2e.authAfter.length === 0);
  verdict("revoked key stays listed with status 'revoked'", e2e.listed?.status === "revoked" && !!e2e.listed?.revoked_at);
  const [{ gone }] = (await db.query("select count(*)::int gone from public.agent_api_keys where id = $1", [e2e.issued.id])).rows;
  verdict("rolled back: the test key does not exist after the transaction", gone === 0);

  // ---- 5. plaintext never in statement history ------------------------------------------
  out("\n## 4b. Banned/deleted-owner predicate in the live function definitions");
  for (const fn of ["public.mcp_authenticate(text)", "public.mcp_log_call(text,text,jsonb,boolean)", "public.agent_key_issue(uuid,text,integer,text,boolean)", "public.agent_key_list()"]) {
    const [{ def }] = (await db.query("select pg_get_functiondef($1::regprocedure) def", [fn])).rows;
    verdict(`${fn.split("(")[0]} checks auth.users banned_until and deleted_at`, /banned_until/.test(def) && /deleted_at/.test(def));
  }
  const [gacl] = (await db.query(
    `select array_to_string(p.proacl, ',') acl from pg_proc p where p.oid = 'public.mcp_authenticate(text)'::regprocedure`)).rows;
  verdict("mcp_authenticate still EXECUTE for mcp_gateway only", /mcp_gateway=X/.test(gacl.acl) && !/(^|,)=X|anon=X|authenticated=X|service_role=X/.test(gacl.acl), gacl.acl);

  out("\n## 4c. Service accounts (20260926180000)");
  const [col] = (await db.query(
    `select c.column_default, pg_get_constraintdef(k.oid) chk
       from information_schema.columns c
       left join pg_constraint k on k.conrelid = 'public.user_profiles'::regclass and k.conname = 'user_profiles_account_type_check'
      where c.table_schema = 'public' and c.table_name = 'user_profiles' and c.column_name = 'account_type'`)).rows;
  verdict("user_profiles.account_type exists, default 'human', only human/service",
    !!col && /'human'/.test(col.column_default ?? "") && /human/.test(col.chk ?? "") && /service/.test(col.chk ?? ""), JSON.stringify(col ?? null));
  const [never] = (await db.query(
    "select pg_get_constraintdef(oid) def, convalidated from pg_constraint where conrelid = 'public.user_profiles'::regclass and conname = 'user_profiles_service_never_admin'")).rows;
  verdict("constraint: a service account can never be admin (validated)", !!never && never.convalidated && /service/.test(never.def) && /is_admin/.test(never.def), never?.def ?? "missing");
  const [trig] = (await db.query(
    "select tgenabled from pg_trigger where tgrelid = 'public.user_profiles'::regclass and tgname = 'guard_account_type' and not tgisinternal")).rows;
  verdict("trigger guard_account_type exists and is enabled", trig?.tgenabled === "O", JSON.stringify(trig ?? null));
  const [{ def: hnu }] = (await db.query("select pg_get_functiondef('public.handle_new_user()'::regprocedure) def")).rows;
  verdict("handle_new_user takes account_type from raw_app_meta_data only (users control raw_user_meta_data)",
    /raw_app_meta_data->>'account_type'/.test(hnu) && !/raw_user_meta_data->>'account_type'/.test(hnu));
  const types = (await db.query("select account_type, count(*)::int n from public.user_profiles group by 1 order by 1")).rows;
  out(`  profiles by account_type: ${types.map((t) => `${t.account_type}=${t.n}`).join(" ")}`);

  // Flip a HUMAN profile to 'service' (and, below, a service one to 'human'):
  // a same-value update is allowed, so the ids must be chosen by type.
  const [human] = (await db.query("select id from public.user_profiles where account_type = 'human' and id <> $1 order by id limit 1", [admin.id])).rows;
  const flipAs = (id, to) => rolledBack(db, async ({ q, as }) => {
    const r = {};
    await q("savepoint a");
    try { await q("update public.user_profiles set account_type = $2 where id = $1", [id, to]); r.owner = "SUCCEEDED"; }
    catch (e) { r.owner = e.message; await q("rollback to savepoint a"); }
    await as("authenticated", claimsFor(admin.id, admin.email, fresh()));
    await q("savepoint b");
    try { await q("update public.user_profiles set account_type = $2 where id = $1", [id, to]); r.admin = "SUCCEEDED"; }
    catch (e) { r.admin = e.message; await q("rollback to savepoint b"); }
    return r;
  });
  const flip = await flipAs(human.id, "service");
  verdict(`human ${short(human.id)} can't be turned into a service account -- as the owner`, /cannot change/.test(flip.owner), flip.owner);
  verdict(`human ${short(human.id)} can't be turned into a service account -- as an admin via the REST path`, /cannot change/.test(flip.admin), flip.admin);

  const [svc] = (await db.query("select id from public.user_profiles where account_type = 'service' order by id limit 1")).rows;
  if (!svc) out("SKIP  never-admin behaviour: no service account exists yet (re-run after the first `service-accounts.mjs create`)");
  else {
    const promote = await rolledBack(db, async ({ q, as }) => {
      const r = {};
      await q("savepoint a");
      try { await q("update public.user_profiles set is_admin = true where id = $1", [svc.id]); r.owner = "SUCCEEDED"; }
      catch (e) { r.owner = e.message; await q("rollback to savepoint a"); }
      await as("authenticated", claimsFor(admin.id, admin.email, fresh()));
      await q("savepoint b");
      try { await q("update public.user_profiles set is_admin = true where id = $1", [svc.id]); r.admin = "SUCCEEDED"; }
      catch (e) { r.admin = e.message; await q("rollback to savepoint b"); }
      return r;
    });
    verdict(`service account ${short(svc.id)} can't be made admin -- owner and admin`,
      /service_never_admin/.test(promote.owner) && /service_never_admin/.test(promote.admin), `${promote.owner} | ${promote.admin}`);
    const back = await flipAs(svc.id, "human");
    verdict(`service account ${short(svc.id)} can't be turned human (then promoted) -- owner and admin`,
      /cannot change/.test(back.owner) && /cannot change/.test(back.admin), `${back.owner} | ${back.admin}`);
  }

  out("\n## 5. pg_stat_statements");
  if (secrets.length < 3) {
    verdict("pg_stat_statements check had a generated key to search for", false);
    return;
  }
  try {
    const { rows: [{ n }] } = await db.query(
      "select count(*)::int n from pg_stat_statements where query like '%' || $1 || '%' or query like '%' || $2 || '%'",
      [secrets[1], secrets[2]]);
    verdict("the generated key appears in no recorded statement text", n === 0, `${n} matches`);
  } catch (e) {
    out(`SKIP  pg_stat_statements not readable here (${e.message})`);
  }
});

// ---- 6. real REST API with the public anon key ------------------------------------------
out("\n## 6. REST API (anon key, no session)");
if (NO_REST) out("SKIP  --no-rest");
const rest = async (path, body) => {
  const res = await fetch(`${ORIGIN}/rest/v1/${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { apikey: env.SUPABASE_ANON_KEY, Authorization: `Bearer ${env.SUPABASE_ANON_KEY}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, text: text.slice(0, 160) };
};
for (const [path, body] of NO_REST ? [] : [
  ["rpc/admin_list_agent_keys", {}],
  ["rpc/admin_issue_agent_key", { p_user_id: NO_SUCH_KEY, p_label: "x", p_days: 1 }],
  ["rpc/admin_revoke_agent_key", { p_id: NO_SUCH_KEY }],
  ["rpc/agent_key_list", {}],
  ["rpc/agent_key_issue", { p_user_id: NO_SUCH_KEY, p_label: "x", p_days: 1, p_created_by: "x", p_allow_unapproved: true }],
  ["rpc/agent_key_revoke", { p_id: NO_SUCH_KEY }],
  ["rpc/admin_update_agent_key_expiry", { p_id: NO_SUCH_KEY, p_days: 30 }],
  ["rpc/admin_list_agent_key_calls", { p_id: NO_SUCH_KEY }],
  ["rpc/admin_list_agent_key_expiry_changes", { p_id: NO_SUCH_KEY }],
  ["rpc/agent_key_set_expiry", { p_id: NO_SUCH_KEY, p_days: 30, p_changed_by: "x" }],
  ["rpc/agent_key_calls", { p_id: NO_SUCH_KEY }],
  ["rpc/agent_key_expiry_changes", { p_id: NO_SUCH_KEY }],
  ["agent_api_keys?select=*", undefined],
  ["agent_api_key_calls?select=*", undefined],
  ["agent_api_key_expiry_changes?select=*", undefined],
]) {
  const r = await rest(path, body);
  verdict(`anon ${body === undefined ? "GET" : "POST"} /rest/v1/${path.split("?")[0]} refused`, r.status >= 400 && r.status < 500 && !/^\[/.test(r.text),
    `HTTP ${r.status} ${r.text}`);
}

const failed = results.filter((r) => !r.pass);
out(`\n# ${results.length - failed.length}/${results.length} passed${failed.length ? `; FAILED: ${failed.map((f) => f.name).join(" | ")}` : ""}`);
if (redactions) console.log(`\n!!! WARNING: ${redactions} line(s) contained key material and were redacted -- investigate before sharing output.`);
if (failed.length) process.exitCode = 1;
