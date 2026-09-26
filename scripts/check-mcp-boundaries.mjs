#!/usr/bin/env node
// Static boundary checks for supabase/functions/mcp/. Exits non-zero, loudly,
// on any violation. Run before every deploy of the mcp function:
//   node scripts/check-mcp-boundaries.mjs
//
// 1. No RLS-bypassing credential or client anywhere in the mcp directory.
// 2. The signing secret's env var is read at exactly one site.
// 3. Every table/view/RPC reachable from the MCP path -- this directory, plus
//    the chat/tools.ts functions behind the round-one allowlisted tools -- is
//    in RELATIONS (allowlist.ts). This checks against the explicit allowlist,
//    not a bare "no base tables" pattern, so the named exceptions
//    (lot_analyses, lot_canonical_map) are visible rather than hidden.
import { readdirSync, readFileSync } from "node:fs";
import { MCP_TOOLS, RELATIONS } from "../supabase/functions/mcp/allowlist.ts";

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
];
for (const [file, src] of Object.entries(sources)) {
  src.split("\n").forEach((line, i) => {
    for (const re of FORBIDDEN) if (re.test(line)) failures.push(`${file}:${i + 1}: forbidden credential/client pattern ${re}: ${line.trim()}`);
  });
}
console.log(`[1] RLS-bypass credential scan: ${files.length} files, patterns ${FORBIDDEN.map(String).join(" ")}`);

// --- 2. Signing secret read site -----------------------------------------
const secretSites = [];
for (const [file, src] of Object.entries(sources)) {
  src.split("\n").forEach((line, i) => {
    if (/JWT_SECRET/.test(line) && /MCP_JWT_SECRET|SUPABASE_JWT_SECRET|["']JWT_SECRET/.test(line)) secretSites.push(`${file}:${i + 1}: ${line.trim()}`);
  });
}
const expectedSite = /^index\.ts:\d+: const JWT_SECRET = Deno\.env\.get\("MCP_JWT_SECRET"\) \?\? "";$/;
if (secretSites.length !== 1 || !expectedSite.test(secretSites[0])) {
  failures.push(`signing secret must be read at exactly one site (index.ts), found ${secretSites.length}: ${secretSites.join(" | ")}`);
}
const secretUses = Object.entries(sources).flatMap(([file, src]) =>
  src.split("\n").map((line, i) => [file, i + 1, line]).filter(([, , l]) => /\bJWT_SECRET\b/.test(l)).map(([f, n, l]) => `${f}:${n}: ${l.trim()}`)
);
console.log(`[2] Signing secret env read sites: ${secretSites.length}\n    ${secretSites.join("\n    ")}\n    all uses of the JWT_SECRET binding:\n    ${secretUses.join("\n    ")}`);

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

console.log(`[3] Reachable chat/tools.ts functions: ${[...reachable].join(", ")}`);
for (const [rel, where] of [...found].sort()) {
  const ok = rel in RELATIONS;
  if (!ok) failures.push(`relation "${rel}" is not in allowlist.ts RELATIONS (${where.join("; ")})`);
  console.log(`    ${ok ? "ALLOWED    " : "NOT ALLOWED"} ${rel}  <- ${[...new Set(where)].join("; ")}`);
}
for (const rel of Object.keys(RELATIONS)) if (!found.has(rel)) console.log(`    (allowlisted but not referenced: ${rel})`);

if (failures.length) {
  console.error(`\nFAIL: ${failures.length} boundary violation(s):\n  ${failures.join("\n  ")}`);
  process.exit(1);
}
console.log("\nPASS: all mcp boundary checks");
