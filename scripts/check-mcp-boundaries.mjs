#!/usr/bin/env node
// Static boundary checks for supabase/functions/mcp/. Exits non-zero, loudly,
// on any violation. Run before every deploy of the mcp function:
//   node scripts/check-mcp-boundaries.mjs
//
// 1. No RLS-bypassing credential, PostgREST client, or token-signing secret
//    anywhere in the mcp directory (revised auth, Option B': there is nothing
//    to sign with and no REST client to hold).
// 2. The gateway connection secret is read at exactly one site.
// 3. Every table/view/RPC reachable from the MCP path -- this directory
//    (builder calls AND raw SQL text), plus the chat/tools.ts functions behind
//    the round-one allowlisted tools -- is in the explicit allowlist
//    (allowlist.ts), not a bare "no base tables" pattern, so the named
//    exceptions (lot_analyses, lot_canonical_map) are visible, and no
//    VIEW_DEPENDENCIES table is ever named directly.
// 4. mcp_reader's SELECT grants, across every migration and including
//    column-level grants, equal TABLES_AND_VIEWS + VIEW_DEPENDENCIES +
//    RPC_DEPENDENCIES exactly -- no more, no less; RPC_DEPENDENCIES are
//    column-level only; no write, blanket or default-privilege grant to an mcp
//    role anywhere. 4b: data-tools.ts's RULE_METRIC_DOMAIN == chat's.
// 5. Per-key scoping is wired: every exposed tool is in the database's
//    mcp_tool_catalogue; the handler routes tools/list through deps.scope()
//    and tools/call through deps.authorize() before the transport runs; and
//    mcp_key_scope/mcp_authorize_call are EXECUTE for mcp_gateway only.
import { readdirSync, readFileSync } from "node:fs";
import { MCP_TOOLS, RELATIONS, RPC_DEPENDENCIES, TABLES_AND_VIEWS, VIEW_DEPENDENCIES } from "../supabase/functions/mcp/allowlist.ts";

const MCP_DIR = new URL("../supabase/functions/mcp/", import.meta.url);
const TOOLS_FILE = new URL("../supabase/functions/chat/tools.ts", import.meta.url);

const failures = [];
const files = readdirSync(MCP_DIR).filter((f) => /\.(ts|js|mjs|json)$/.test(f));
const sources = Object.fromEntries(files.map((f) => [f, readFileSync(new URL(f, MCP_DIR), "utf8")]));

// --- 1. RLS-bypassing credentials/clients ---------------------------------
const FORBIDDEN = [
  /service[_ -]?role/i,
  /SUPABASE_SECRET_KEYS?/,
  /sb_secret_/,
  /supabaseAdmin/,
  /SUPABASE_DB_URL/,
  /withPostgres(Admin)?Client/,
  /createAdminClient/,
  /JWT_SECRET/,                 // no token signing exists in this design
  /signAccessToken|SignJWT|importKey\(/,
  /@supabase\/supabase-js|createClient\(/, // no PostgREST client either
  /SUPABASE_ANON_KEY|SUPABASE_PUBLISHABLE/,
];
for (const [file, src] of Object.entries(sources)) {
  src.split("\n").forEach((line, i) => {
    for (const re of FORBIDDEN) if (re.test(line)) failures.push(`${file}:${i + 1}: forbidden credential/client pattern ${re}: ${line.trim()}`);
  });
}
console.log(`[1] RLS-bypass credential scan: ${files.length} files, patterns ${FORBIDDEN.map(String).join(" ")}`);

// --- 2. Gateway secret read site -----------------------------------------
const secretSites = [];
for (const [file, src] of Object.entries(sources)) {
  src.split("\n").forEach((line, i) => {
    if (/MCP_GATEWAY_DB_URL|Deno\.env\.get\(/.test(line)) secretSites.push(`${file}:${i + 1}: ${line.trim()}`);
  });
}
const expectedSite = /^index\.ts:\d+: const GATEWAY_DB_URL = Deno\.env\.get\("MCP_GATEWAY_DB_URL"\) \?\? "";$/;
if (secretSites.length !== 1 || !expectedSite.test(secretSites[0])) {
  failures.push(`the only env read must be the gateway secret, at exactly one site in index.ts; found ${secretSites.length}: ${secretSites.join(" | ")}`);
}
console.log(`[2] Env read sites: ${secretSites.length}\n    ${secretSites.join("\n    ")}`);

// --- 3. Relations reachable from the MCP path ----------------------------
const toolsSrc = readFileSync(TOOLS_FILE, "utf8");
const topLevelFns = new Map();
for (const m of toolsSrc.matchAll(/^(?:export )?(?:async )?function (\w+)\(/gm)) {
  const end = toolsSrc.indexOf("\n}\n", m.index);
  topLevelFns.set(m[1], toolsSrc.slice(m.index, end === -1 ? undefined : end + 2));
}
const dispatch = new Map([...toolsSrc.matchAll(/case "(\w+)":\s*return await (\w+)\(/g)].map((m) => [m[1], m[2]]));

const roots = MCP_TOOLS.map((tool) => {
  const fn = dispatch.get(tool);
  if (!fn) failures.push(`allowlisted tool ${tool} has no runTool dispatch in chat/tools.ts`);
  return fn;
}).filter(Boolean);
// Functions the mcp directory imports from chat/tools.ts directly (runTool is
// covered by its allowlisted cases above, not its whole switch).
for (const src of Object.values(sources)) {
  for (const m of src.matchAll(/import \{([^}]+)\} from "\.\.\/chat\/tools\.ts"/g)) {
    for (const name of m[1].split(",").map((s) => s.trim().replace(/^type\s+/, ""))) {
      if (topLevelFns.has(name) && name !== "runTool") roots.push(name);
    }
  }
}
const reachable = new Set();
const queue = [...roots];
while (queue.length) {
  const fn = queue.shift();
  if (reachable.has(fn) || !topLevelFns.has(fn)) continue;
  reachable.add(fn);
  for (const other of topLevelFns.keys()) {
    if (other !== fn && new RegExp(`\\b${other}\\(`).test(topLevelFns.get(fn))) queue.push(other);
  }
}

const RELATION_RE = /\.(from|rpc)\(\s*"([^"]+)"/g;
const found = new Map(); // relation -> [where]
const note = (rel, where) => found.set(rel, [...(found.get(rel) ?? []), where]);
for (const fn of reachable) for (const m of topLevelFns.get(fn).matchAll(RELATION_RE)) note(m[2], `chat/tools.ts ${fn}() .${m[1]}`);
for (const [file, src] of Object.entries(sources)) for (const m of src.matchAll(RELATION_RE)) note(m[2], `mcp/${file} .${m[1]}`);
// Raw SQL in this directory: every public.<name> reference (the adapter builds
// `public.<relation>` from already-allowlisted names; this catches literals).
for (const [file, src] of Object.entries(sources)) {
  if (file.endsWith(".json")) continue;
  for (const m of src.matchAll(/\bpublic\.([a-z_][a-z0-9_]*)\b/g)) note(m[1], `mcp/${file} SQL`);
}
for (const rel of [...Object.keys(VIEW_DEPENDENCIES), ...Object.keys(RPC_DEPENDENCIES)]) {
  if (found.has(rel)) failures.push(`dependency table "${rel}" is named directly (${found.get(rel).join("; ")}) -- tool code must go through its view/function`);
}

console.log(`[3] Reachable chat/tools.ts functions: ${[...reachable].join(", ")}`);
for (const [rel, where] of [...found].sort()) {
  const ok = rel in RELATIONS;
  if (!ok) failures.push(`relation "${rel}" is not in allowlist.ts RELATIONS (${where.join("; ")})`);
  console.log(`    ${ok ? "ALLOWED    " : "NOT ALLOWED"} ${rel}  <- ${[...new Set(where)].join("; ")}`);
}
for (const rel of Object.keys(RELATIONS)) if (!found.has(rel)) console.log(`    (allowlisted but not referenced: ${rel})`);

// --- 4. mcp_reader grants == allowlist ---------------------------------------
// Every migration, table-wide AND column-level grants. RPC_DEPENDENCIES (read
// only inside the SECURITY INVOKER functions / RLS policies) must be
// column-level: no table-wide SELECT on sensor_readings & co.
const MIGRATIONS_DIR = new URL("../supabase/migrations/", import.meta.url);
const granted = new Map(); // relation -> Set of "*" or column names
const grantSites = [];
for (const f of readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort()) {
  const sqlText = readFileSync(new URL(f, MIGRATIONS_DIR), "utf8").replace(/--[^\n]*/g, "");
  for (const m of sqlText.matchAll(/grant\s+select\s*(\(([^)]*)\))?\s+on\s+(?:table\s+)?([\s\S]*?)\s+to\s+([^;]*?)\s*;/gi)) {
    if (!/\bmcp_reader\b/i.test(m[4])) continue;
    const cols = m[2] ? m[2].split(",").map((c) => c.trim()) : ["*"];
    for (const rel of m[3].split(",")) {
      const name = rel.trim().replace(/^public\./, "");
      granted.set(name, new Set([...(granted.get(name) ?? []), ...cols]));
    }
    grantSites.push(f);
  }
  if (/grant\s+(insert|update|delete|truncate|all)\b[^;]*to\s+[^;]*\bmcp_(reader|gateway)\b/i.test(sqlText)) failures.push(`${f}: a write/ALL privilege is granted to an mcp role`);
  if (/on\s+all\s+tables[^;]*\bmcp_(reader|gateway)\b/i.test(sqlText)) failures.push(`${f}: blanket 'on all tables' grant to an mcp role`);
  if (/alter\s+default\s+privileges[^;]*\bmcp_(reader|gateway)\b/i.test(sqlText)) failures.push(`${f}: default privileges for an mcp role`);
}
{
  const expected = new Set([...Object.keys(TABLES_AND_VIEWS), ...Object.keys(VIEW_DEPENDENCIES), ...Object.keys(RPC_DEPENDENCIES)]);
  const extra = [...granted.keys()].filter((r) => !expected.has(r));
  const missing = [...expected].filter((r) => !granted.has(r));
  if (extra.length) failures.push(`mcp_reader is granted SELECT on relations outside the allowlist: ${extra.join(", ")}`);
  if (missing.length) failures.push(`allowlisted relations missing from mcp_reader's grants: ${missing.join(", ")}`);
  for (const rel of Object.keys(RPC_DEPENDENCIES)) {
    if (granted.get(rel)?.has("*")) failures.push(`RPC dependency "${rel}" has a table-wide SELECT grant to mcp_reader -- column-level only`);
  }
  console.log(`[4] mcp_reader SELECT grants across ${new Set(grantSites).size} migration(s): ${granted.size} relations; expected ${expected.size}`);
  for (const [rel, cols] of [...granted].sort()) console.log(`    ${rel}: ${cols.has("*") ? "table-wide" : `columns (${[...cols].join(", ")})`}`);
}

// --- 4b. data-tool wrapper mirrors chat's RULE_METRIC_DOMAIN -----------------
{
  const parse = (src, where) => {
    const m = src.match(/RULE_METRIC_DOMAIN[^=]*=\s*\{([\s\S]*?)\};/);
    if (!m) { failures.push(`RULE_METRIC_DOMAIN not found in ${where}`); return {}; }
    return Object.fromEntries([...m[1].matchAll(/(\w+):\s*"([^"]+)"/g)].map((x) => [x[1], x[2]]));
  };
  const chat = parse(toolsSrc, "chat/tools.ts");
  const gw = parse(sources["data-tools.ts"] ?? "", "mcp/data-tools.ts");
  const same = JSON.stringify(Object.entries(chat).sort()) === JSON.stringify(Object.entries(gw).sort());
  if (!same || !Object.keys(chat).length) failures.push("mcp/data-tools.ts RULE_METRIC_DOMAIN differs from chat/tools.ts's");
  console.log(`[4b] RULE_METRIC_DOMAIN: gateway copy ${same ? "==" : "!="} chat (${Object.keys(chat).length} entries)`);
}

// --- 5. per-key scoping ---------------------------------------------------------
{
  const migDir = new URL("../supabase/migrations/", import.meta.url);
  const migs = readdirSync(migDir).filter((f) => f.endsWith(".sql")).sort();
  const allSql = migs.map((f) => readFileSync(new URL(f, migDir), "utf8").replace(/--[^\n]*/g, "")).join("\n");
  const catalogue = new Set();
  for (const m of allSql.matchAll(/insert\s+into\s+public\.mcp_tool_catalogue[\s\S]*?values([\s\S]*?\));/gi)) {
    for (const t of m[1].matchAll(/\(\s*'(get_[a-z_]+)'/g)) catalogue.add(t[1]);
  }
  const notCatalogued = MCP_TOOLS.filter((t) => !catalogue.has(t));
  if (!catalogue.size) failures.push("no mcp_tool_catalogue inserts found in migrations");
  if (notCatalogued.length) failures.push(`exposed tools missing from mcp_tool_catalogue: ${notCatalogued.join(", ")}`);
  const handler = sources["handler.ts"] ?? "";
  if (!/ListToolsRequestSchema[\s\S]{0,200}deps\.scope\(keyHash\)/.test(handler)) failures.push("handler.ts: tools/list is not filtered by deps.scope(keyHash)");
  const authIdx = handler.indexOf("deps.authorize(keyHash");
  const transportIdx = handler.indexOf("transport.handleRequest(req)");
  if (authIdx < 0 || transportIdx < 0 || authIdx > transportIdx) failures.push("handler.ts: tools/call is not authorized (deps.authorize) before the transport handles the request");
  for (const fn of ["mcp_key_scope", "mcp_authorize_call"]) {
    const grants = [...allSql.matchAll(new RegExp(`grant\\s+execute\\s+on\\s+function\\s+([^;]*?\\b${fn}\\b[^;]*?)\\s+to\\s+([a-z_, ]+);`, "gi"))].map((m) => m[2].split(",").map((r) => r.trim()));
    const roles = new Set(grants.flat());
    if (roles.size !== 1 || !roles.has("mcp_gateway")) failures.push(`${fn} must be EXECUTE for mcp_gateway only (granted to: ${[...roles].join(", ") || "none"})`);
  }
  console.log(`[5] Per-key scoping: ${MCP_TOOLS.length} exposed tools all in mcp_tool_catalogue (${catalogue.size} catalogued); tools/list via deps.scope; tools/call via deps.authorize before the transport; scope/authorize functions mcp_gateway-only`);
}

if (failures.length) {
  console.error(`\nFAIL: ${failures.length} boundary violation(s):\n  ${failures.join("\n  ")}`);
  process.exit(1);
}
console.log("\nPASS: all mcp boundary checks");
