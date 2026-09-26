#!/usr/bin/env node
// Live verification harness for the deployed mcp Edge Function.
//
//   node scripts/mcp-verify.mjs [--revoke-prefix <mtk_ prefix>]
//
// Keys are read from the macOS Keychain (stored there by
// `agent-keys.mjs issue --keychain`), held in memory only, and never printed:
// every line of output is scanned and any key text is replaced with
// [REDACTED], with a loud warning if that ever happens. Output shows key
// prefixes only.
//
// DB cross-checks use the SET LOCAL pattern from docs/SECURITY.md (inside an
// explicit transaction, always rolled back) -- never a bare SET ROLE.
//
// --revoke-prefix revokes that key for the revocation test (a real,
// committed revoke). Omit it to skip that case.
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import pg from "pg";

const env = Object.fromEntries(
  readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
    .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "")]),
);
// .env's SUPABASE_URL is the REST endpoint ("https://<ref>.supabase.co/rest/v1/"),
// not the bare project URL -- appending to it produced ".../rest/v1//functions/v1/mcp".
// Always build from the origin.
const FN_URL = `${new URL(env.SUPABASE_URL).origin}/functions/v1/mcp`;
const COLIN_A = "87b9d9a0-9f1f-4609-8950-c92906c5029c";
const COLIN_B = "03b52829-645c-4b40-9842-ecbf81e4338d";
const CUSTOMER = "9782853b-f6be-40a9-83cd-47407b3de7f1";
const PENDING = "749d26a6-068a-43ed-ac23-c9ecefeab5fa";

const args = process.argv.slice(2);
const revokePrefix = args.includes("--revoke-prefix") ? args[args.indexOf("--revoke-prefix") + 1] : null;

// ---- output with redaction ------------------------------------------------
const secrets = [];
let redactions = 0;
function out(...parts) {
  let line = parts.map((p) => (typeof p === "string" ? p : JSON.stringify(p))).join(" ");
  for (const s of secrets) if (line.includes(s)) { line = line.split(s).join("[REDACTED]"); redactions++; }
  console.log(line);
}
const results = [];
function verdict(name, pass, detail = "") {
  results.push({ name, pass });
  out(`${pass ? "PASS" : "FAIL"}  ${name}${detail ? ` -- ${detail}` : ""}`);
}

// ---- db -------------------------------------------------------------------
async function withDb(fn) {
  const client = new pg.Client({ connectionString: env.DATABASE_URL });
  await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}
// Runs `sql` as `role` with the given user's claims, inside a transaction that
// is always rolled back.
async function asUser(db, userId, sql, params = [], role = "authenticated") {
  await db.query("begin");
  try {
    await db.query("select set_config('request.jwt.claims', $1, true)", [JSON.stringify({ sub: userId, role })]);
    await db.query(`set local role ${role}`);
    return (await db.query(sql, params)).rows;
  } finally {
    await db.query("rollback");
  }
}

// ---- mcp ------------------------------------------------------------------
let rpcId = 0;
async function mcp(authHeader, method, params) {
  const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18" };
  if (authHeader !== null) headers.Authorization = authHeader;
  const t0 = Date.now();
  const res = await fetch(FN_URL, { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }) });
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch { /* non-JSON */ }
  return { status: res.status, body, text, ms: Date.now() - t0, at: new Date(t0).toISOString() };
}
const INIT = { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "mcp-verify", version: "1" } };
const toolCall = (key, name, a) => mcp(`Bearer ${key}`, "tools/call", { name, arguments: a });
const md5 = (s) => createHash("md5").update(s).digest("hex");
const payloadOf = (text) => text.split("\n\n")[0];

const PROBES = [
  ["get_berry_maturity", { vintage: 2026 }],
  ["get_smoke_markers", { vintage: 2025 }],
  ["get_wine_lab_results", { sample_description: "MA23CS", limit: 20 }],
  ["get_lot_analyses", { lot_code: "MA23CSV3", analysis_type: "brix" }],
  ["get_labour_summary", { vintage: 2024 }],
];

function keychain(prefix) {
  try {
    return execFileSync("security", ["find-generic-password", "-s", "mars-telemetry-mcp", "-a", prefix, "-w"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch { return null; }
}

// ===========================================================================
await withDb(async (db) => {
  out(`# mcp live verification -- ${new Date().toISOString()}`);
  out(`# endpoint: ${FN_URL}`);

  // ---- keys: load from keychain, show storage is hash-only --------------------
  const { rows: keyRows } = await db.query(
    `select id, user_id, label, key_prefix, octet_length(key_hash) as hash_bytes, encode(key_hash,'hex') as hash_hex,
            created_at, last_used_at, expires_at, revoked_at from public.agent_api_keys order by created_at`,
  );
  const keys = [];
  for (const r of keyRows) {
    const plaintext = keychain(r.key_prefix);
    if (plaintext) { secrets.push(plaintext); keys.push({ ...r, plaintext }); }
  }
  out(`\n## 1. Storage: agent_api_keys (${keyRows.length} rows; ${keys.length} have a keychain entry on this machine)`);
  for (const r of keyRows) {
    out(`  ${r.key_prefix}  ${r.label}  user=${r.user_id}  hash=${r.hash_bytes}B ${r.hash_hex.slice(0, 16)}...  expires=${r.expires_at.toISOString()}  revoked=${r.revoked_at?.toISOString() ?? "no"}`);
  }
  const { rows: cols } = await db.query(
    `select column_name, data_type from information_schema.columns where table_schema='public' and table_name='agent_api_keys' order by ordinal_position`,
  );
  out(`  columns: ${cols.map((c) => `${c.column_name}:${c.data_type}`).join(", ")}`);
  for (const k of keys) {
    const hashMatches = createHash("sha256").update(k.plaintext).digest("hex") === k.hash_hex;
    const { rows: [{ n }] } = await db.query(
      `select count(*)::int as n from public.agent_api_keys
        where label like '%'||$1||'%' or key_prefix = $1 or coalesce(created_by,'') like '%'||$1||'%'
           or position(convert_to($1,'UTF8') in key_hash) > 0 or encode(key_hash,'hex') = $1`,
      [k.plaintext],
    );
    verdict(`storage ${k.key_prefix}: key_hash = sha256(key), plaintext in no column`, hashMatches && n === 0, `sha256 match=${hashMatches}, rows containing plaintext=${n}`);
  }

  const active = (uid) => keys.find((k) => k.user_id === uid && !k.revoked_at && k.expires_at > new Date());
  const colinKeys = [COLIN_A, COLIN_B].map(active);
  if (colinKeys.some((k) => !k)) {
    out("\nFAIL: missing an active keychain key for one of the Colin accounts -- issue with --keychain first.");
    process.exitCode = 1;
    return;
  }

  // ---- 2. positive -----------------------------------------------------------
  out("\n## 2. Positive: initialize, tools/list, and each of the 5 tools, per Colin key");
  const outputs = {};
  for (const k of colinKeys) {
    out(`\n### key ${k.key_prefix} (${k.label})`);
    const init = await mcp(`Bearer ${k.plaintext}`, "initialize", INIT);
    verdict(`${k.key_prefix} initialize`, init.status === 200 && init.body?.result?.serverInfo?.name === "mars-telemetry", `HTTP ${init.status}, ${init.ms}ms, server=${init.body?.result?.serverInfo?.name}`);
    const list = await mcp(`Bearer ${k.plaintext}`, "tools/list", {});
    const names = (list.body?.result?.tools ?? []).map((t) => t.name).sort();
    verdict(`${k.key_prefix} tools/list = exactly the 5 round-one tools`, JSON.stringify(names) === JSON.stringify(PROBES.map((p) => p[0]).sort()), names.join(", "));
    for (const [name, a] of PROBES) {
      const r = await toolCall(k.plaintext, name, a);
      const text = r.body?.result?.content?.[0]?.text ?? "";
      outputs[`${k.user_id}:${name}`] = text;
      let rows = "?";
      try { const p = JSON.parse(payloadOf(text)); rows = Array.isArray(p) ? p.length : `${p.categories?.length} categories`; } catch { /* note-only */ }
      verdict(`${k.key_prefix} ${name}(${JSON.stringify(a)})`, r.status === 200 && r.body?.result?.isError === false && text.length > 0,
        `HTTP ${r.status}, ${r.ms}ms, isError=${r.body?.result?.isError}, rows=${rows}, md5=${md5(text)}`);
      out(`    text[0..400]: ${text.slice(0, 400).replace(/\n/g, "\\n")}`);
      const tail = text.split("\n\n").slice(1).join(" ");
      if (tail) out(`    notes: ${tail.slice(0, 600)}`);
    }
  }
  for (const [name] of PROBES) {
    const a = outputs[`${COLIN_A}:${name}`], b = outputs[`${COLIN_B}:${name}`];
    verdict(`both Colin keys return identical ${name} output (both approved operators)`, a === b, `md5 ${md5(a)} vs ${md5(b)}`);
  }

  // ---- 2b. cross-check against the SET LOCAL transaction pattern -------------
  out("\n## 2b. Cross-check vs SET LOCAL role authenticated + request.jwt.claims (rolled back)");
  for (const uid of [COLIN_A, COLIN_B]) {
    const [who] = await asUser(db, uid, "select auth.uid() as uid, public.current_role_name() as role, public.is_admin_user() as admin, public.current_data_mode() as mode");
    out(`  as ${uid.slice(0, 8)}: auth.uid()=${who.uid} current_role_name()=${who.role} is_admin_user()=${who.admin} current_data_mode()=${who.mode}`);

    const berrySql = `select block_id, collected_on::text, vintage, brix, ph, titratable_acidity, l_malic_acid, glucose_fructose,
                             berry_weight_g, berry_volume_ml, berry_volume_variability_pct, sugar_per_berry_mg
                        from public.berry_maturity_by_block where vintage = 2026 order by block_id, collected_on`;
    const dbBerry = await asUser(db, uid, berrySql);
    const mcpBerry = JSON.parse(payloadOf(outputs[`${uid}:get_berry_maturity`]));
    const norm = (rows) => JSON.stringify(rows.map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, v === null ? null : (typeof v === "string" && /^-?\d+(\.\d+)?$/.test(v) && k !== "block_id" ? Number(v) : v)]))));
    verdict(`${uid.slice(0, 8)} get_berry_maturity(2026) == SET LOCAL query`, norm(dbBerry) === norm(mcpBerry), `${dbBerry.length} db rows vs ${mcpBerry.length} mcp rows`);

    const [lab] = await asUser(db, uid, `select sum(labor_hours)::text h, sum(labor_cost)::text c, sum(expense_cost)::text e, count(*)::int n
                                          from public.labour_actuals_by_category where vintage = 2024`);
    const mcpLab = JSON.parse(payloadOf(outputs[`${uid}:get_labour_summary`]));
    const eqDec = (x, y) => Number(x) === Number(y);
    verdict(`${uid.slice(0, 8)} get_labour_summary(2024) totals == SET LOCAL sums`,
      eqDec(lab.h, mcpLab.totals.labor_hours) && eqDec(lab.c, mcpLab.totals.labor_cost) && eqDec(lab.e, mcpLab.totals.expense_cost) && lab.n === mcpLab.categories.length,
      `db hours=${lab.h} labor=${lab.c} expense=${lab.e} (${lab.n} cats); mcp hours=${mcpLab.totals.labor_hours} labor=${mcpLab.totals.labor_cost} expense=${mcpLab.totals.expense_cost} display.total=${mcpLab.totals.display.total_cost}`);

    const dbLot = await asUser(db, uid, `select lot_code, analysis_type, value, recorded_at from public.lot_analyses
                                          where lot_code = 'MA23CSV3' and analysis_type = 'brix' order by recorded_at desc limit 50`);
    const mcpLot = JSON.parse(payloadOf(outputs[`${uid}:get_lot_analyses`]));
    const lotSig = (rows) => JSON.stringify(rows.map((r) => [r.lot_code, r.analysis_type, Number(r.value), new Date(r.recorded_at).toISOString()]));
    verdict(`${uid.slice(0, 8)} get_lot_analyses(MA23CSV3, brix) == SET LOCAL query`, lotSig(dbLot) === lotSig(mcpLot), `${dbLot.length} db rows vs ${mcpLot.length} mcp rows`);
  }

  out("\n## 2c. RLS actually restricts: same relations under non-operator claims (rolled back)");
  const REL_COUNTS = `select (select count(*) from public.berry_maturity_by_block)::int berry,
                             (select count(*) from public.lab_results_current)::int lab_results,
                             (select count(*) from public.lab_samples_current)::int lab_samples,
                             (select count(*) from public.lot_analyses)::int lot_analyses,
                             (select count(*) from public.labour_actuals_by_category)::int labour,
                             public.current_role_name() as role`;
  const counts = {};
  for (const [label, uid] of [["colin-a", COLIN_A], ["colin-b", COLIN_B], ["customer", CUSTOMER], ["pending", PENDING]]) {
    const [c] = await asUser(db, uid, REL_COUNTS);
    counts[label] = c;
    out(`  ${label.padEnd(9)} ${uid.slice(0, 8)}: ${JSON.stringify(c)}`);
  }
  const zero = (c) => c.berry === 0 && c.lab_results === 0 && c.lab_samples === 0 && c.lot_analyses === 0 && c.labour === 0;
  verdict("operator claims see rows in all 5 tool relations", !zero(counts["colin-a"]) && counts["colin-a"].berry > 0 && counts["colin-a"].lot_analyses > 0);
  verdict("customer claims see 0 rows in all 5 tool relations", zero(counts.customer), `role=${counts.customer.role}`);
  verdict("pending claims see 0 rows in all 5 tool relations", zero(counts.pending), `role=${counts.pending.role}`);

  // ---- 3. negative -----------------------------------------------------------
  out("\n## 3. Negative");
  const colin = colinKeys[0];
  for (const [label, header] of [
    ["no Authorization header", null],
    ["malformed: Bearer mtk_short", "Bearer mtk_short"],
    ["malformed: key with trailing char", `Bearer ${colin.plaintext}x`],
    ["malformed: wrong scheme", `Basic ${colin.plaintext}`],
    ["the public anon key as bearer", `Bearer ${env.SUPABASE_ANON_KEY}`],
  ]) {
    const r = await mcp(header, "tools/list", {});
    verdict(`${label} -> 401`, r.status === 401, `HTTP ${r.status} ${r.text.slice(0, 120)}`);
  }
  const unknown = "mtk_" + randomBytes(32).toString("base64url"); // random, never stored anywhere
  secrets.push(unknown);
  const u = await mcp(`Bearer ${unknown}`, "tools/list", {});
  verdict("well-formed but unknown key -> 401", u.status === 401, `HTTP ${u.status} ${u.text.slice(0, 120)}`);

  for (const name of ["get_series", "get_vessels", "get_derived_series", "get_anomalies"]) {
    const argsFor = name === "get_series" ? { metric: "air_temp", start: "2026-07-01T00:00:00Z", end: "2026-07-02T00:00:00Z", bucket_hours: 24 } : {};
    const r = await toolCall(colin.plaintext, name, argsFor);
    verdict(`non-allowlisted ${name} rejected by the function`, r.status === 200 && r.body?.error?.code === -32602 && !r.body?.result,
      `HTTP ${r.status} ${JSON.stringify(r.body?.error ?? r.body?.result)?.slice(0, 160)}`);
  }
  const bad = await toolCall(colin.plaintext, "get_lot_analyses", { lot_code: 5 });
  verdict("invalid argument type rejected before runTool", bad.body?.result?.isError === true, bad.body?.result?.content?.[0]?.text);

  // pending/unapproved account's key: rejected by mcp_authenticate itself
  const pendingKeys = keys.filter((k) => k.user_id === PENDING);
  if (!pendingKeys.length) {
    out("SKIP  pending-account key: none issued with --keychain (issue one with --allow-unapproved to run this case)");
  }
  for (const k of pendingKeys) {
    const r = await mcp(`Bearer ${k.plaintext}`, "tools/list", {});
    const [after] = (await db.query("select last_used_at from public.agent_api_keys where id = $1", [k.id])).rows;
    const [direct] = await asUser(db, null, "select count(*)::int n from public.mcp_authenticate($1)", [k.hash_hex], "anon");
    const [contrast] = await asUser(db, null, "select count(*)::int n from public.mcp_authenticate($1)", [colin.hash_hex], "anon");
    verdict(`pending-account key ${k.key_prefix} -> 401, rejected inside mcp_authenticate()`,
      r.status === 401 && after.last_used_at === null && direct.n === 0 && contrast.n === 1,
      `HTTP ${r.status}; mcp_authenticate(its hash) as anon = ${direct.n} rows (Colin key contrast = ${contrast.n}); last_used_at=${after.last_used_at ?? "null (never passed the function's checks)"}`);
  }

  // revoked key: revoke, then immediately re-call; nothing cached
  if (revokePrefix) {
    const k = keys.find((x) => x.key_prefix === revokePrefix);
    if (!k) {
      out(`FAIL: --revoke-prefix ${revokePrefix} has no keychain entry`);
      process.exitCode = 1;
    } else {
      const before = await mcp(`Bearer ${k.plaintext}`, "tools/list", {});
      out(`  before revoke: ${before.at} HTTP ${before.status}`);
      const { rows: [rv] } = await db.query(
        "update public.agent_api_keys set revoked_at = now() where id = $1 and revoked_at is null returning revoked_at", [k.id]);
      const revokedAt = rv?.revoked_at ?? (await db.query("select revoked_at from public.agent_api_keys where id=$1", [k.id])).rows[0].revoked_at;
      const afterCall = await mcp(`Bearer ${k.plaintext}`, "tools/list", {});
      const gap = new Date(afterCall.at).getTime() - revokedAt.getTime();
      verdict(`revoked key ${k.key_prefix} -> 401 on the very next request`, before.status === 200 && afterCall.status === 401,
        `revoked_at=${revokedAt.toISOString()} (db), next request sent ${afterCall.at} (+${gap}ms), HTTP ${afterCall.status}`);
      const tool = await toolCall(k.plaintext, "get_berry_maturity", {});
      verdict(`revoked key ${k.key_prefix} tools/call -> 401`, tool.status === 401, `HTTP ${tool.status}`);
    }
  } else {
    out("SKIP  revocation case (pass --revoke-prefix <prefix>)");
  }

  // ---- audit log ---------------------------------------------------------------
  out("\n## 4. agent_api_key_calls (most recent 15)");
  const { rows: log } = await db.query(
    `select c.called_at, k.key_prefix, c.tool, c.is_error, c.args from public.agent_api_key_calls c
       join public.agent_api_keys k on k.id = c.key_id order by c.id desc limit 15`,
  );
  for (const r of log) out(`  ${r.called_at.toISOString()} ${r.key_prefix} ${r.is_error ? "ERR" : "ok "} ${r.tool} ${JSON.stringify(r.args)}`);
  verdict("non-allowlisted attempts are audited as errors", log.some((r) => r.tool === "get_series" && r.is_error));
});

const failed = results.filter((r) => !r.pass);
out(`\n# ${results.length - failed.length}/${results.length} passed${failed.length ? `; FAILED: ${failed.map((f) => f.name).join(" | ")}` : ""}`);
if (redactions) console.log(`\n!!! WARNING: ${redactions} line(s) contained key material and were redacted -- investigate before sharing output.`);
if (failed.length) process.exitCode = 1;
