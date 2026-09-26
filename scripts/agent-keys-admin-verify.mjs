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
//      (as mcp_gateway) accepts it -> revoke -> rejected -> still listed
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

const ADMIN_FNS = ["admin_list_agent_keys()", "admin_issue_agent_key(uuid,text,integer)", "admin_revoke_agent_key(uuid)"];
const INTERNAL_FNS = ["agent_key_list()", "agent_key_issue(uuid,text,integer,text,boolean)", "agent_key_revoke(uuid)"];
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
       from pg_proc p where p.pronamespace = 'public'::regnamespace
        and p.proname in ('admin_list_agent_keys','admin_issue_agent_key','admin_revoke_agent_key','agent_key_list','agent_key_issue','agent_key_revoke')
      order by 1`,
  );
  for (const p of procs) out(`  ${p.sig}  definer=${p.definer}  config=${JSON.stringify(p.config)}  owner=${p.owner}`);
  verdict("all six functions exist, SECURITY DEFINER, search_path=''",
    procs.length === 6 && procs.every((p) => p.definer && (p.config ?? []).some((c) => c === 'search_path=""' || c === "search_path=")),
    `${procs.length}/6 found`);
  if (procs.length !== 6) {
    out("\nMigration 20260926160000 is not applied -- stopping.");
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
    out(`  ${fn.padEnd(52)} ${API_ROLES.map((r) => `${r}=${execMatrix[fn][r] ? "X" : "-"}`).join(" ")}`);
  }
  verdict("admin_* wrappers: EXECUTE for authenticated only (not anon/service_role/mcp_gateway/mcp_reader)",
    ADMIN_FNS.every((fn) => API_ROLES.every((r) => execMatrix[fn][r] === (r === "authenticated"))));
  verdict("agent_key_* implementation: no API role can EXECUTE (owner only)",
    INTERNAL_FNS.every((fn) => API_ROLES.every((r) => !execMatrix[fn][r])));
  const { rows: acls } = await db.query(
    `select p.oid::regprocedure::text sig, coalesce(array_to_string(p.proacl, ','), '(default)') acl
       from pg_proc p where p.pronamespace='public'::regnamespace
        and p.proname in ('admin_list_agent_keys','admin_issue_agent_key','admin_revoke_agent_key','agent_key_list','agent_key_issue','agent_key_revoke')`,
  );
  verdict("no PUBLIC EXECUTE entry on any of them", acls.every((a) => a.acl !== "(default)" && !/(^|,)=X/.test(a.acl)),
    acls.filter((a) => a.acl === "(default)" || /(^|,)=X/.test(a.acl)).map((a) => a.sig).join(", "));

  const tablePrivs = [];
  for (const t of ["agent_api_keys", "agent_api_key_calls"]) {
    for (const role of API_ROLES) {
      for (const p of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
        if ((await db.query("select has_table_privilege($1, $2, $3) ok", [role, `public.${t}`, p])).rows[0].ok) tablePrivs.push(`${role}:${p}:${t}`);
      }
    }
  }
  const { rows: [rls] } = await db.query(
    `select bool_and(c.relrowsecurity) rls_on, (select count(*)::int from pg_policies where schemaname='public' and tablename in ('agent_api_keys','agent_api_key_calls')) policies
       from pg_class c where c.oid in ('public.agent_api_keys'::regclass, 'public.agent_api_key_calls'::regclass)`,
  );
  verdict("agent_api_keys / agent_api_key_calls: still no table privilege for any API role, RLS on, zero policies",
    tablePrivs.length === 0 && rls.rls_on && rls.policies === 0,
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
    verdict(`${role}${claims ? ` as ${short(claims.sub)}` : " (no claims)"}: list/issue/revoke all refused`, ok,
      got.map(([n, r]) => `${n}: ${r.error ?? `SUCCEEDED (${r.rows.length} rows)`}`).join("; "));
  }
  for (const [name, sql] of [
    ["agent_key_list()", "select * from public.agent_key_list()"],
    ["agent_key_issue()", `select * from public.agent_key_issue('${target0(operator, admin)}', 'x', 1, 'x', true)`],
    ["agent_key_revoke()", `select * from public.agent_key_revoke('${NO_SUCH_KEY}')`],
  ]) {
    const r = await attempt(db, "authenticated", claimsFor(admin.id, admin.email, fresh()), sql);
    verdict(`admin cannot call the implementation directly: ${name}`, /permission denied for function/.test(r.error ?? ""), r.error ?? "SUCCEEDED");
  }
  const adminSel = await attempt(db, "authenticated", claimsFor(admin.id, admin.email, fresh()), "select count(*) from public.agent_api_keys");
  verdict("admin cannot read agent_api_keys directly", /permission denied for table/.test(adminSel.error ?? ""), adminSel.error ?? "SUCCEEDED");

  // Fresh-auth rule on issue; list/revoke need none.
  const target = operator ?? admin;
  const issueAs = (amr) => attempt(db, "authenticated", claimsFor(admin.id, admin.email, amr),
    "select id from public.admin_issue_agent_key($1, 'agent-keys-admin-verify (rolled back)', 1)", [target.id]);
  const reauth = /recent sign-in required/;
  for (const [desc, amr] of [
    ["no amr claim", undefined],
    ["password 11 minutes ago", [{ method: "password", timestamp: nowS() - 660 }]],
    ["fresh but non-password method (recovery)", [{ method: "recovery", timestamp: nowS() }]],
    ["fresh oauth (Google)", [{ method: "oauth", timestamp: nowS() }]],
  ]) {
    const r = await issueAs(amr);
    verdict(`admin issue refused: ${desc}`, reauth.test(r.error ?? ""), r.error ?? "SUCCEEDED");
  }
  const okIssue = await issueAs([{ method: "password", timestamp: nowS() - 540 }]);
  verdict("admin issue allowed: password 9 minutes ago", !okIssue.error, okIssue.error ?? `${okIssue.rows.length} row`);
  const stale = [{ method: "password", timestamp: nowS() - 86400 }];
  const staleList = await attempt(db, "authenticated", claimsFor(admin.id, admin.email, stale), "select count(*)::int n from public.admin_list_agent_keys()");
  const staleRevoke = await attempt(db, "authenticated", claimsFor(admin.id, admin.email, stale), "select * from public.admin_revoke_agent_key($1)", [NO_SUCH_KEY]);
  verdict("list and revoke need no re-auth (day-old sign-in)", !staleList.error && !staleRevoke.error, staleList.error ?? staleRevoke.error ?? `list=${staleList.rows[0].n} rows`);

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
    await as("authenticated", claimsFor(admin.id, admin.email, [{ method: "password", timestamp: nowS() - 86400 }]));
    r.revoked = await q("select * from public.admin_revoke_agent_key($1)", [issued.id]);
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
  verdict("mcp_authenticate (as mcp_gateway) accepts the new key and resolves the linked account",
    e2e.authBefore.length === 1 && e2e.authBefore[0].user_id === target.id && e2e.authBefore[0].key_id === e2e.issued.id);
  verdict("admin revoke returns the row once, then nothing", e2e.revoked.length === 1 && e2e.revokedAgain.length === 0);
  verdict("revoked key: mcp_authenticate returns zero rows", e2e.authAfter.length === 0);
  verdict("revoked key stays listed with status 'revoked'", e2e.listed?.status === "revoked" && !!e2e.listed?.revoked_at);
  const [{ gone }] = (await db.query("select count(*)::int gone from public.agent_api_keys where id = $1", [e2e.issued.id])).rows;
  verdict("rolled back: the test key does not exist after the transaction", gone === 0);

  // ---- 5. plaintext never in statement history ------------------------------------------
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
  ["agent_api_keys?select=*", undefined],
  ["agent_api_key_calls?select=*", undefined],
]) {
  const r = await rest(path, body);
  verdict(`anon ${body === undefined ? "GET" : "POST"} /rest/v1/${path.split("?")[0]} refused`, r.status >= 400 && r.status < 500 && !/^\[/.test(r.text),
    `HTTP ${r.status} ${r.text}`);
}

const failed = results.filter((r) => !r.pass);
out(`\n# ${results.length - failed.length}/${results.length} passed${failed.length ? `; FAILED: ${failed.map((f) => f.name).join(" | ")}` : ""}`);
if (redactions) console.log(`\n!!! WARNING: ${redactions} line(s) contained key material and were redacted -- investigate before sharing output.`);
if (failed.length) process.exitCode = 1;
