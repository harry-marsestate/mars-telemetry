#!/usr/bin/env node
// SPIKE ONLY (branch spike/oauth21-o1): does Supabase Auth's OAuth 2.1 server
// work for a ChatGPT-shaped MCP client on THIS project?
//
//   node scripts/oauth-spike.mjs run --public-client <id> [--confidential-client <id>] [--email monitor@marsestates.com]
//   node scripts/oauth-spike.mjs refresh      # the >=24h refresh-token check, run the next day
//   node scripts/oauth-spike.mjs discover     # discovery chain only; no credentials involved
//
// Run it in YOUR OWN terminal (not via Claude Code's `!`): it prompts for the
// test account's password with echo off and holds every token in memory only.
// Output and the results file are scrubbed of all tokens, codes, the password
// and the client secret (any hit is replaced with [REDACTED] and counted).
//
// No browser and no hosted consent page: Supabase only redirects to
// <Site URL> + <authorization path>, so a Vercel preview can't receive it. The
// consent step is the same two calls a consent page makes via supabase-js
// (auth.oauth.getAuthorizationDetails / approveAuthorization):
//   GET  /auth/v1/oauth/authorizations/{id}            (as the signed-in user)
//   POST /auth/v1/oauth/authorizations/{id}/consent    {action:"approve"}
//
// Matrix (supabase/auth#2820 reports public client, offline_access and
// `resource` as three INDEPENDENT triggers of a 400; a ChatGPT connector uses
// all three -- row R7).
//
// Secrets: the confidential client's secret (optional) is read from the macOS
// Keychain (service "mars-telemetry-oauth-spike", account "confidential-secret").
// The refresh token kept for the 24h check is stored there too
// (account "refresh-24h"); `refresh` reads, uses and rotates it.
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import readline from "node:readline";

const env = Object.fromEntries(
  readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
    .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "")]),
);
const ORIGIN = new URL(env.SUPABASE_URL).origin; // .env's SUPABASE_URL ends in /rest/v1/
const ANON = env.SUPABASE_ANON_KEY;
const RESOURCE = `${ORIGIN}/functions/v1/oauth-spike`;
const REDIRECT_URI = "http://localhost:8765/callback"; // never served; the code is read from the redirect URL
const KC = "mars-telemetry-oauth-spike";
const RESULTS = new URL("./.oauth-spike-results.json", import.meta.url);

// ---- scrubbed output ---------------------------------------------------------
const secrets = new Set();
let redactions = 0;
const keep = (s) => { if (s && typeof s === "string" && s.length >= 8) secrets.add(s); return s; };
function scrub(text) {
  let out = text;
  for (const s of secrets) if (out.includes(s)) { out = out.split(s).join("[REDACTED]"); redactions++; }
  return out;
}
const log = (...a) => console.log(scrub(a.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(" ")));

function keychainGet(account) {
  try {
    return keep(execFileSync("security", ["find-generic-password", "-s", KC, "-a", account, "-w"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim());
  } catch { return null; }
}
function keychainSet(account, value, label) {
  execFileSync("security", ["add-generic-password", "-U", "-s", KC, "-a", account, "-l", label, "-w", value], { stdio: "ignore" });
}

function args() {
  const a = process.argv.slice(2);
  const o = { _: a.filter((x, i) => !x.startsWith("--") && !(a[i - 1] ?? "").startsWith("--")) };
  a.forEach((x, i) => { if (x.startsWith("--")) o[x.slice(2)] = a[i + 1]; });
  return o;
}

function promptHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(question)) rl.output.write(s); };
    rl.question(question, (answer) => { rl.close(); process.stdout.write("\n"); resolve(answer); });
  });
}

const b64url = (buf) => buf.toString("base64url");
function pkce() {
  const verifier = keep(b64url(randomBytes(32)));
  return { verifier, challenge: b64url(createHash("sha256").update(verifier).digest()) };
}
async function http(url, init = {}) {
  const t0 = Date.now();
  const res = await fetch(url, { redirect: "manual", ...init });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, headers: res.headers, text, json, ms: Date.now() - t0 };
}
const short = (r) => scrub(`HTTP ${r.status} ${(r.text || "").slice(0, 220).replace(/\s+/g, " ")}`);

// ---- 1. discovery ------------------------------------------------------------
async function discovery() {
  log("\n## Discovery chain (no credentials)");
  const d = { steps: [] };
  const r1 = await http(RESOURCE, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
  const www = r1.headers.get("www-authenticate");
  const prmUrl = www?.match(/resource_metadata="([^"]+)"/)?.[1] ?? null;
  d.steps.push({ step: "unauthenticated MCP call", status: r1.status, www_authenticate: www });
  log(`  POST ${RESOURCE} -> ${r1.status}; WWW-Authenticate: ${www}`);
  if (!prmUrl) return { ...d, ok: false, broke_at: "no resource_metadata in WWW-Authenticate" };

  const r2 = await http(prmUrl);
  d.steps.push({ step: "protected-resource metadata", url: prmUrl, status: r2.status, body: r2.json });
  log(`  GET ${prmUrl} -> ${r2.status} ${r2.text}`);
  const as = r2.json?.authorization_servers?.[0];
  if (r2.status !== 200 || !as) return { ...d, ok: false, broke_at: "protected-resource metadata" };
  const resourceMatches = r2.json.resource === RESOURCE;

  const asUrl = new URL(as);
  const rfc8414 = `${asUrl.origin}/.well-known/oauth-authorization-server${asUrl.pathname.replace(/\/$/, "")}`;
  const r3 = await http(rfc8414);
  d.steps.push({ step: "RFC 8414 authorization-server metadata", url: rfc8414, status: r3.status, body: r3.json ?? r3.text.slice(0, 300) });
  log(`  GET ${rfc8414} -> ${r3.status}`);
  if (r3.status !== 200 || !r3.json?.authorization_endpoint) return { ...d, ok: false, broke_at: "RFC 8414 metadata" };
  const m = r3.json;
  log(`    issuer=${m.issuer}\n    authorization_endpoint=${m.authorization_endpoint}\n    token_endpoint=${m.token_endpoint}`);
  log(`    token_endpoint_auth_methods_supported=${JSON.stringify(m.token_endpoint_auth_methods_supported)} code_challenge_methods_supported=${JSON.stringify(m.code_challenge_methods_supported)}`);
  log(`    grant_types_supported=${JSON.stringify(m.grant_types_supported)} scopes_supported=${JSON.stringify(m.scopes_supported)} registration_endpoint=${m.registration_endpoint ?? "(none)"}`);
  log(`    resource in PRM equals the URL called: ${resourceMatches}; issuer equals advertised AS: ${m.issuer === as}`);
  return { ...d, ok: true, resource_matches: resourceMatches, issuer_matches: m.issuer === as, metadata: m };
}

// ---- 2. matrix -----------------------------------------------------------------
async function signIn(email, password) {
  const r = await http(`${ORIGIN}/auth/v1/token?grant_type=password`, {
    method: "POST", headers: { apikey: ANON, "Content-Type": "application/json" }, body: JSON.stringify({ email, password }),
  });
  if (r.status !== 200) throw new Error(`sign-in failed: ${short(r)}`);
  keep(r.json.access_token); keep(r.json.refresh_token);
  return r.json;
}

async function callWhoami(accessToken) {
  const headers = { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
  const init = await http(RESOURCE, { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "oauth-spike", version: "0" } } }) });
  const call = await http(RESOURCE, { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "whoami", arguments: {} } }) });
  let report = null;
  try { report = JSON.parse(call.json?.result?.content?.[0]?.text); } catch { /* */ }
  return { init_status: init.status, call_status: call.status, report, raw: report ? undefined : short(call) };
}

async function tokenRequest(meta, client, form) {
  const headers = { "Content-Type": "application/x-www-form-urlencoded", apikey: ANON };
  const body = new URLSearchParams(form);
  if (client.secret) headers.Authorization = `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`;
  else body.set("client_id", client.id);
  const r = await http(meta.token_endpoint, { method: "POST", headers, body });
  if (r.json) { keep(r.json.access_token); keep(r.json.refresh_token); keep(r.json.id_token); }
  return r;
}

async function runRow(meta, userJwt, row) {
  const out = { row: row.name, client: row.client.kind, scope: row.scope, resource: row.resource, stages: {} };
  const { verifier, challenge } = pkce();
  const state = keep(b64url(randomBytes(16)));
  const q = new URLSearchParams({ response_type: "code", client_id: row.client.id, redirect_uri: REDIRECT_URI, scope: row.scope, state, code_challenge: challenge, code_challenge_method: "S256" });
  if (row.resource) q.set("resource", RESOURCE);

  // authorize: a browser-facing redirect endpoint, called the way a browser would (no apikey header)
  let a = await http(`${meta.authorization_endpoint}?${q}`);
  out.stages.authorize = { status: a.status, location: a.headers.get("location") ? scrub(a.headers.get("location")) : null, body: a.headers.get("location") ? undefined : short(a) };
  const loc = a.headers.get("location");
  const authorizationId = loc ? new URL(loc, ORIGIN).searchParams.get("authorization_id") : null;
  if (!authorizationId) { out.result = "FAIL at authorize"; return out; }
  keep(authorizationId);

  const det = await http(`${ORIGIN}/auth/v1/oauth/authorizations/${authorizationId}`, { headers: { apikey: ANON, Authorization: `Bearer ${userJwt}` } });
  out.stages.authorization_details = { status: det.status, body: short(det) };
  if (det.status !== 200) { out.result = `FAIL at authorization details (the supabase/auth#2820 step): HTTP ${det.status}`; return out; }

  const con = await http(`${ORIGIN}/auth/v1/oauth/authorizations/${authorizationId}/consent`, {
    method: "POST", headers: { apikey: ANON, Authorization: `Bearer ${userJwt}`, "Content-Type": "application/json" }, body: JSON.stringify({ action: "approve" }),
  });
  const redirectUrl = con.json?.redirect_url ? new URL(con.json.redirect_url) : null;
  const code = keep(redirectUrl?.searchParams.get("code") ?? null);
  out.stages.consent = {
    status: con.status,
    redirect_target: redirectUrl ? `${redirectUrl.origin}${redirectUrl.pathname}` : null,
    state_echoed: redirectUrl?.searchParams.get("state") === state,
    error: redirectUrl?.searchParams.get("error") ?? (code ? null : short(con)),
  };
  if (!code) { out.result = "FAIL at consent"; return out; }

  const form = { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier };
  if (row.resource) form.resource = RESOURCE;
  const tok = await tokenRequest(meta, row.client, form);
  out.stages.token = { status: tok.status, token_type: tok.json?.token_type, expires_in: tok.json?.expires_in, scope: tok.json?.scope, has_refresh_token: !!tok.json?.refresh_token, has_id_token: !!tok.json?.id_token, error: tok.status === 200 ? null : short(tok) };
  if (tok.status !== 200 || !tok.json?.access_token) { out.result = "FAIL at token exchange"; return out; }

  // code is single-use: replaying it must fail
  const replay = await tokenRequest(meta, row.client, form);
  out.stages.code_replay = { status: replay.status, rejected: replay.status !== 200 };

  out.stages.api_call = await callWhoami(tok.json.access_token);
  const ok = out.stages.api_call.call_status === 200 && out.stages.api_call.report?.sub;
  if (!ok) { out.result = "FAIL at API call"; return out; }

  if (tok.json.refresh_token) {
    const rform = { grant_type: "refresh_token", refresh_token: tok.json.refresh_token };
    if (row.resource) rform.resource = RESOURCE;
    const ref = await tokenRequest(meta, row.client, rform);
    out.stages.refresh_immediate = { status: ref.status, rotated: !!ref.json?.refresh_token && ref.json.refresh_token !== tok.json.refresh_token, expires_in: ref.json?.expires_in, error: ref.status === 200 ? null : short(ref) };
    if (ref.status === 200) {
      const again = await callWhoami(ref.json.access_token);
      out.stages.api_call_after_refresh = { call_status: again.call_status, same_sub: again.report?.sub === out.stages.api_call.report.sub, client_id: again.report?.client_id };
      out._latest_refresh = ref.json.refresh_token;
    }
  } else {
    out.stages.refresh_immediate = { skipped: "no refresh_token issued" };
  }
  out.result = out.stages.refresh_immediate?.status === 200 || out.stages.refresh_immediate?.skipped ? "PASS" : "PASS (auth code flow) / FAIL (refresh)";
  return out;
}

async function run(o) {
  if (!o["public-client"]) throw new Error("--public-client <client_id> is required");
  const email = o.email ?? "monitor@marsestates.com";
  const pub = { kind: "public", id: o["public-client"] };
  const conf = o["confidential-client"] ? { kind: "confidential", id: o["confidential-client"], secret: keychainGet("confidential-secret") } : null;
  if (conf && !conf.secret) throw new Error(`confidential client given but no Keychain secret (security add-generic-password -s ${KC} -a confidential-secret -w)`);

  const results = { started_at: new Date().toISOString(), resource: RESOURCE, redirect_uri: REDIRECT_URI };
  results.discovery = await discovery();
  if (!results.discovery.ok) { log(`\nDISCOVERY BROKE at: ${results.discovery.broke_at}`); }
  // If our function's leg of discovery broke, still run the matrix against
  // Supabase's own metadata so one failure doesn't mask the other.
  let meta = results.discovery.metadata;
  if (!meta) {
    const direct = await http(`${ORIGIN}/.well-known/oauth-authorization-server/auth/v1`);
    meta = direct.status === 200 && direct.json?.authorization_endpoint ? direct.json : null;
    log(`  (fallback) GET ${ORIGIN}/.well-known/oauth-authorization-server/auth/v1 -> ${direct.status}${meta ? "" : " -- cannot run the matrix"}`);
  }

  const password = keep(await promptHidden(`Password for ${email} (not echoed): `));
  const session = await signIn(email, password);
  log(`\n## Signed in as ${email} (password grant, session held in memory only)`);

  const base = "openid email";
  const rows = [
    ...(conf ? [
      { name: "R1", client: conf, scope: base, resource: false },
      { name: "R2", client: conf, scope: base, resource: true },
      { name: "R3", client: conf, scope: `${base} offline_access`, resource: false },
    ] : []),
    { name: "R4", client: pub, scope: base, resource: false },
    { name: "R5", client: pub, scope: base, resource: true },
    { name: "R6", client: pub, scope: `${base} offline_access`, resource: false },
    { name: "R7 (ChatGPT-shaped)", client: pub, scope: `${base} offline_access`, resource: true },
  ];
  results.matrix = [];
  let keepForLater = null;
  for (const row of rows) {
    const r = meta ? await runRow(meta, session.access_token, row) : { row: row.name, result: "SKIPPED (no AS metadata)" };
    if (r._latest_refresh) {
      if (row.name.startsWith("R7") || (!keepForLater && row.client.kind === "public")) keepForLater = { row: row.name, client: row.client, token: r._latest_refresh, resource: row.resource };
      delete r._latest_refresh;
    }
    results.matrix.push(r);
    log(`\n### ${r.row}: ${r.client ?? ""} client, scope="${r.scope ?? ""}", resource=${r.resource ?? ""} -> ${r.result}`);
    for (const [k, v] of Object.entries(r.stages ?? {})) log(`    ${k}: ${JSON.stringify(v)}`);
  }

  if (keepForLater) {
    keychainSet("refresh-24h", keepForLater.token, `oauth-spike ${keepForLater.row} refresh token`);
    writeFileSync(new URL("./.oauth-spike-24h.json", import.meta.url), JSON.stringify({ row: keepForLater.row, client_kind: keepForLater.client.kind, client_id: keepForLater.client.id, resource: keepForLater.resource, stored_at: new Date().toISOString() }, null, 2));
    log(`\nStored ${keepForLater.row}'s latest refresh token in the Keychain for the >=24h check (node scripts/oauth-spike.mjs refresh).`);
  } else {
    log("\nNo refresh token was obtained from any public-client row -- nothing stored for the 24h check.");
  }

  await http(`${ORIGIN}/auth/v1/logout?scope=local`, { method: "POST", headers: { apikey: ANON, Authorization: `Bearer ${session.access_token}` } });
  results.redactions = redactions;
  writeFileSync(RESULTS, scrub(JSON.stringify(results, null, 2)));
  log(`\nResults (no tokens) written to scripts/.oauth-spike-results.json. Redactions applied: ${redactions}.`);
}

async function refresh() {
  const info = JSON.parse(readFileSync(new URL("./.oauth-spike-24h.json", import.meta.url), "utf8"));
  const token = keychainGet("refresh-24h");
  if (!token) throw new Error("no stored refresh token");
  const idleHours = ((Date.now() - Date.parse(info.stored_at)) / 3600000).toFixed(2);
  const disc = await http(`${ORIGIN}/.well-known/oauth-authorization-server/auth/v1`);
  const client = { kind: info.client_kind, id: info.client_id, secret: info.client_kind === "confidential" ? keychainGet("confidential-secret") : null };
  const form = { grant_type: "refresh_token", refresh_token: token };
  if (info.resource) form.resource = RESOURCE;
  const r = await tokenRequest(disc.json, client, form);
  const out = { checked_at: new Date().toISOString(), row: info.row, idle_hours_since_last_use: Number(idleHours), status: r.status, rotated: !!r.json?.refresh_token && r.json.refresh_token !== token, error: r.status === 200 ? null : short(r) };
  if (r.status === 200) {
    out.api_call = await callWhoami(r.json.access_token);
    keychainSet("refresh-24h", r.json.refresh_token, `oauth-spike ${info.row} refresh token`);
    writeFileSync(new URL("./.oauth-spike-24h.json", import.meta.url), JSON.stringify({ ...info, stored_at: new Date().toISOString() }, null, 2));
  }
  log(JSON.stringify(out, null, 2));
  writeFileSync(new URL("./.oauth-spike-refresh-result.json", import.meta.url), scrub(JSON.stringify(out, null, 2)));
}

const o = args();
async function discover() {
  const d = await discovery();
  log(`\ndiscovery ${d.ok ? "OK" : `BROKE at: ${d.broke_at}`}`);
  if (!d.ok) process.exitCode = 1;
}

const cmd = { run, refresh, discover }[o._[0]];
if (!cmd) { console.error("usage: node scripts/oauth-spike.mjs run --public-client <id> [--confidential-client <id>] | refresh | discover"); process.exit(2); }
cmd(o).then(() => { if (redactions) console.log(`(note: ${redactions} redaction(s) applied to output)`); })
  .catch((e) => { console.error(scrub(`error: ${e.message}`)); process.exit(1); });
