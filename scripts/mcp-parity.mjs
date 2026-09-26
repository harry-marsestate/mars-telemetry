#!/usr/bin/env node
// PARITY TEST: does the MCP adapter (supabase/functions/mcp/adapter.ts) return
// exactly what the real REST API returns to a real, logged-in browser session?
//
// 1. record   Runs chat/tools.ts runTool() -- the five round-one tools over a
//             fixed set of inputs, plus direct max-rows probes -- through the
//             adapter, on a direct connection, inside a rolled-back
//             transaction per call: claims.sub = --user, `set local role
//             <--role>` (authenticated before the roles migration exists;
//             mcp_reader after it, via a transaction-local self-grant).
//             Every builder chain and rpc the tools issue is recorded with
//             the adapter's row count and a canonical SHA-256.
// 2. snippet  Emits a JS snippet that replays every recorded chain through
//             the web app's own supabase-js client (`sb`, a live operator
//             session at telemetry.marsestates.com) and returns
//             {user, results:[{count, hash, error}]} -- no row data leaves
//             the page.
// 3. compare  Compares the two. Ordered / single / uncapped results must match
//             byte-for-byte (same SHA-256 of the same canonical JSON);
//             unordered results that hit the cap can legitimately be different
//             row subsets on each side, so those compare counts only (and say
//             so).
//
//   node scripts/mcp-parity.mjs record  --user <uuid> --role authenticated|mcp_reader --out <file>
//   node scripts/mcp-parity.mjs snippet --in <file> > replay.js
//   node scripts/mcp-parity.mjs compare --in <file> --browser <browser-results.json>
//   node scripts/mcp-parity.mjs outputs --a <record file> --b <record file>   (runTool output equality)
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import pg from "pg";
import { runTool } from "../supabase/functions/chat/tools.ts";
import { MAX_ROWS, PostgrestAdapter } from "../supabase/functions/mcp/adapter.ts";

const env = Object.fromEntries(
  readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
    .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "")]),
);

// Inputs chosen to walk every query path in the five tools: filters of every
// kind, the lot_name not-in exclusion + uncapped scope query, the unfiltered
// capped scope query, maybeSingle (labour coverage), empty results.
const INPUTS = [
  ["get_berry_maturity", {}],
  ["get_berry_maturity", { vintage: 2026, block_id: "B2" }],
  ["get_smoke_markers", {}],
  ["get_smoke_markers", { vintage: 2025 }],
  ["get_wine_lab_results", { sample_description: "MA22CS" }],
  ["get_wine_lab_results", { vintage: 2023, analysis_code: "ph", start_date: "2023-01-01", end_date: "2024-12-31" }],
  ["get_wine_lab_results", { sample_type: "wine", limit: 300 }],
  ["get_lot_analyses", { lot_name: "Cabernet Sauvignon, V3" }],
  ["get_lot_analyses", { lot_code: "MA23CSV3", analysis_type: "brix" }],
  ["get_lot_analyses", {}],
  ["get_lot_analyses", { start_date: "2024-01-01", end_date: "2024-06-30", limit: 200 }],
  ["get_labour_summary", { vintage: 2024 }],
  ["get_labour_summary", { vintage: 2026, period_month: "2026-08" }],
  ["get_labour_summary", { period_month: "2026-01" }],
  ["get_labour_summary", { job_category: "Canopy" }],
];
// Direct max-rows probes: lot_analyses has more rows than MAX_ROWS.
const PROBES = [
  { rel: "lot_analyses", calls: [["select", ["id"]]] },                                   // no order, no limit
  { rel: "lot_analyses", calls: [["select", ["id"]], ["order", ["id", { ascending: true }]]] }, // ordered, no limit
  { rel: "lot_analyses", calls: [["select", ["id"]], ["order", ["id", { ascending: true }]], ["limit", [5000]]] }, // limit above cap
];

const canonical = (data, ordered) => {
  if (!Array.isArray(data) || ordered) return JSON.stringify(data);
  return JSON.stringify(data.map((r) => JSON.stringify(r)).sort().map((s) => JSON.parse(s)));
};
const sha = (s) => createHash("sha256").update(s).digest("hex");
const arg = (name) => { const i = process.argv.indexOf(`--${name}`); return i > -1 ? process.argv[i + 1] : undefined; };

// Wraps the adapter so every chain the tools build is recorded as data the
// browser can replay verbatim.
function recorder(adapter, specs, tool) {
  return {
    from(rel) {
      const spec = { tool, kind: "from", rel, calls: [] };
      let inner = adapter.from(rel);
      const proxy = new Proxy({}, {
        get(_, prop) {
          if (prop === "then") {
            return (res, rej) => inner.then((r) => { note(spec, r); specs.push(spec); return r; }).then(res, rej);
          }
          return (...a) => { spec.calls.push([prop, a]); inner = inner[prop](...a); return proxy; };
        },
      });
      return proxy;
    },
    async rpc(name, params) {
      const spec = { tool, kind: "rpc", name, params: params ?? {} };
      const r = await adapter.rpc(name, params);
      note(spec, r);
      specs.push(spec);
      return r;
    },
  };
}
function note(spec, r) {
  const ordered = spec.kind === "rpc" ? false : spec.calls.some(([m]) => m === "order");
  const single = spec.kind === "from" && spec.calls.some(([m]) => m === "maybeSingle");
  const lim = spec.kind === "from" ? Math.min(...spec.calls.filter(([m]) => m === "limit").map(([, a]) => a[0]), MAX_ROWS) : MAX_ROWS;
  const count = Array.isArray(r.data) ? r.data.length : r.data == null ? 0 : 1;
  spec.adapter = {
    count,
    hash: r.error ? null : sha(canonical(r.data, ordered || single)),
    error: r.error ? r.error.message : null,
    deterministic: ordered || single || count < lim,
  };
}

async function inScope(db, role, user, fn) {
  await db.query("begin");
  try {
    if (role === "mcp_reader") await db.query("grant mcp_reader to postgres with inherit false, set true"); // transaction-local: rolled back below
    await db.query("select set_config('request.jwt.claims', $1, true)", [JSON.stringify({ sub: user, role })]);
    await db.query(`set local role ${role === "mcp_reader" ? "mcp_reader" : "authenticated"}`);
    const [{ current_user }] = (await db.query("select current_user")).rows;
    if (current_user !== role) throw new Error(`scope check failed: current_user=${current_user}`);
    return await fn((text, params) => db.query(text, params).then((r) => r.rows));
  } finally {
    await db.query("rollback");
  }
}

async function record() {
  const user = arg("user"), role = arg("role"), out = arg("out");
  if (!user || !["authenticated", "mcp_reader"].includes(role) || !out) throw new Error("record --user <uuid> --role authenticated|mcp_reader --out <file>");
  const db = new pg.Client({ connectionString: env.DATABASE_URL });
  await db.connect();
  const specs = [];
  const outputs = [];
  try {
    for (const [tool, input] of INPUTS) {
      await inScope(db, role, user, async (query) => {
        const client = recorder(new PostgrestAdapter(query), specs, `${tool}(${JSON.stringify(input)})`);
        const result = await runTool(client, tool, input, "all", new Map());
        outputs.push({ tool, input, isError: result.isError, content_sha256: sha(result.content), content_head: result.content.slice(0, 160) });
      });
    }
    for (const probe of PROBES) {
      await inScope(db, role, user, async (query) => {
        const client = recorder(new PostgrestAdapter(query), specs, `probe ${JSON.stringify(probe.calls)}`);
        let q = client.from(probe.rel);
        for (const [m, a] of probe.calls) q = q[m](...a);
        await q;
      });
    }
    for (const rpc of [["current_data_mode", undefined], ["domain_reality", { p_vintages: [2022, 2023, 2024, 2025, 2026] }]]) {
      await inScope(db, role, user, async (query) => { await recorder(new PostgrestAdapter(query), specs, `rpc ${rpc[0]}`).rpc(...rpc); });
    }
  } finally {
    await db.end();
  }
  writeFileSync(out, JSON.stringify({ recorded_at: new Date().toISOString(), user, role, max_rows: MAX_ROWS, specs, outputs }, null, 2));
  console.log(`recorded ${specs.length} queries from ${INPUTS.length} tool calls + ${PROBES.length} probes + 2 rpcs as ${role} for ${user} -> ${out}`);
  for (const o of outputs) console.log(`  ${o.isError ? "ERR" : "ok "} ${o.tool}(${JSON.stringify(o.input)}) content sha256 ${o.content_sha256.slice(0, 16)}`);
}

function snippet() {
  const rec = JSON.parse(readFileSync(arg("in"), "utf8"));
  const replay = rec.specs.map((s) => (s.kind === "rpc" ? { kind: "rpc", name: s.name, params: s.params } : { kind: "from", rel: s.rel, calls: s.calls }));
  // Output is the JSON the compare step reads. If the browser tool truncates
  // long results, shorten each hash with .slice(0, 20) -- compare accepts
  // prefixes of 16+ hex chars.
  process.stdout.write(`(async () => {
  const specs = ${JSON.stringify(replay)};
  const sha = async (s) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const canonical = (data, ordered) => (!Array.isArray(data) || ordered) ? JSON.stringify(data)
    : JSON.stringify(data.map((r) => JSON.stringify(r)).sort().map((s) => JSON.parse(s)));
  const user = (await sb.auth.getUser()).data.user?.id ?? null;
  const results = [];
  for (const s of specs) {
    let q = s.kind === "rpc" ? sb.rpc(s.name, s.params) : sb.from(s.rel);
    if (s.kind === "from") for (const [m, a] of s.calls) q = q[m](...a);
    const { data, error } = await q;
    const ordered = s.kind === "from" && s.calls.some(([m]) => m === "order" || m === "maybeSingle");
    results.push({ count: Array.isArray(data) ? data.length : data == null ? 0 : 1, hash: error ? null : await sha(canonical(data, ordered)), error: error ? error.message : null });
  }
  return JSON.stringify({ user, results });
})()
`);
}

function compare() {
  const rec = JSON.parse(readFileSync(arg("in"), "utf8"));
  const browser = JSON.parse(readFileSync(arg("browser"), "utf8"));
  if (browser.results.length !== rec.specs.length) throw new Error(`length mismatch ${browser.results.length} vs ${rec.specs.length}`);
  console.log(`adapter: role=${rec.role} user=${rec.user} | browser session user=${browser.user} ${browser.user === rec.user ? "(same identity)" : "(DIFFERENT identity)"}`);
  let exact = 0, countOnly = 0, fail = 0;
  rec.specs.forEach((s, i) => {
    const a = s.adapter, b = browser.results[i];
    // The browser may return a hash PREFIX (javascript tool output limits);
    // compare on the browser's length -- 20 hex chars = 80 bits.
    const sameHash = a.hash && b.hash && b.hash.length >= 16 && a.hash.startsWith(b.hash);
    const label = s.kind === "rpc" ? `rpc ${s.name}` : `${s.rel} ${s.calls.map(([m, x]) => `${m}(${JSON.stringify(x).slice(1, -1)})`).join(".")}`;
    let verdict;
    if (a.error || b.error) verdict = a.error === b.error ? "MATCH(error)" : "FAIL";
    else if (a.deterministic) verdict = sameHash && a.count === b.count ? "MATCH" : "FAIL";
    else verdict = a.count === b.count ? "MATCH(count; unordered+capped)" : "FAIL";
    if (verdict === "MATCH" || verdict === "MATCH(error)") exact++; else if (verdict.startsWith("MATCH")) countOnly++; else fail++;
    console.log(`${verdict.padEnd(31)} rows ${String(a.count).padStart(4)} vs ${String(b.count).padStart(4)}  ${a.hash?.slice(0, 12) ?? a.error} vs ${b.hash?.slice(0, 12) ?? b.error}  ${s.tool} :: ${label.slice(0, 150)}`);
  });
  console.log(`\n${rec.specs.length} queries: ${exact} byte-identical, ${countOnly} count-only (unordered + capped), ${fail} FAILED${browser.user === rec.user ? "" : " -- AND identities differ"}`);
  if (fail || browser.user !== rec.user) process.exitCode = 1;
}

function outputs() {
  const a = JSON.parse(readFileSync(arg("a"), "utf8")), b = JSON.parse(readFileSync(arg("b"), "utf8"));
  let same = 0;
  a.outputs.forEach((o, i) => {
    const eq = o.content_sha256 === b.outputs[i].content_sha256;
    if (eq) same++;
    console.log(`${eq ? "SAME" : "DIFF"} ${o.tool}(${JSON.stringify(o.input)})  ${a.role}/${a.user.slice(0, 8)} vs ${b.role}/${b.user.slice(0, 8)}`);
  });
  console.log(`\n${same}/${a.outputs.length} runTool outputs identical`);
  if (same !== a.outputs.length) process.exitCode = 1;
}

const cmd = { record, snippet, compare, outputs }[process.argv[2]];
if (!cmd) { console.error("usage: see header"); process.exit(2); }
Promise.resolve(cmd()).catch((e) => { console.error(`error: ${e.message}`); process.exit(1); });
