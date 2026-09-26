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
// 4. mcp_reader's SELECT grants in the roles migration equal
//    TABLES_AND_VIEWS + VIEW_DEPENDENCIES exactly -- no more, no less.
import { readdirSync, readFileSync } from "node:fs";
import { MCP_TOOLS, RELATIONS, TABLES_AND_VIEWS, VIEW_DEPENDENCIES } from "../supabase/functions/mcp/allowlist.ts";

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
for (const rel of Object.keys(VIEW_DEPENDENCIES)) {
  if (found.has(rel)) failures.push(`view-dependency table "${rel}" is named directly (${found.get(rel).join("; ")}) -- tool code must go through its view`);
}

console.log(`[3] Reachable chat/tools.ts functions: ${[...reachable].join(", ")}`);
for (const [rel, where] of [...found].sort()) {
  const ok = rel in RELATIONS;
  if (!ok) failures.push(`relation "${rel}" is not in allowlist.ts RELATIONS (${where.join("; ")})`);
  console.log(`    ${ok ? "ALLOWED    " : "NOT ALLOWED"} ${rel}  <- ${[...new Set(where)].join("; ")}`);
}
for (const rel of Object.keys(RELATIONS)) if (!found.has(rel)) console.log(`    (allowlisted but not referenced: ${rel})`);

// --- 4. mcp_reader grants == allowlist ---------------------------------------
const rolesMigration = readdirSync(new URL("../supabase/migrations/", import.meta.url)).find((f) => f.endsWith("_mcp_gateway_roles.sql"));
if (!rolesMigration) {
  failures.push("roles migration (*_mcp_gateway_roles.sql) not found");
} else {
  const sqlText = readFileSync(new URL(`../supabase/migrations/${rolesMigration}`, import.meta.url), "utf8").replace(/--[^\n]*/g, "");
  const granted = new Set();
  for (const m of sqlText.matchAll(/grant\s+select\s+on\s+([\s\S]*?)\s+to\s+mcp_reader\s*;/gi)) {
    for (const rel of m[1].split(",")) granted.add(rel.trim().replace(/^public\./, ""));
  }
  const expected = new Set([...Object.keys(TABLES_AND_VIEWS), ...Object.keys(VIEW_DEPENDENCIES)]);
  const extra = [...granted].filter((r) => !expected.has(r));
  const missing = [...expected].filter((r) => !granted.has(r));
  if (extra.length) failures.push(`mcp_reader is granted SELECT on relations outside the allowlist: ${extra.join(", ")}`);
  if (missing.length) failures.push(`allowlisted relations missing from mcp_reader's grants: ${missing.join(", ")}`);
  if (/grant\s+(insert|update|delete|truncate|all)\b[^;]*to\s+mcp_(reader|gateway)/i.test(sqlText)) failures.push("a write/ALL privilege is granted to an mcp role");
  if (/on\s+all\s+tables/i.test(sqlText)) failures.push("blanket 'on all tables' grant in the roles migration");
  console.log(`[4] ${rolesMigration}: mcp_reader SELECT on ${granted.size} relations (${[...granted].sort().join(", ")}); expected ${expected.size}`);
}

if (failures.length) {
  console.error(`\nFAIL: ${failures.length} boundary violation(s):\n  ${failures.join("\n  ")}`);
  process.exit(1);
}
console.log("\nPASS: all mcp boundary checks");
