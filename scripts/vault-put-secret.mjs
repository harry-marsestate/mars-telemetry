#!/usr/bin/env node
// Store (or replace) a Vault secret by name, reading the value from STDIN only
// -- never argv, never a file, never echoed. Prints the name and the first 12
// hex chars of the value's SHA-256, nothing else.
//
//   pbpaste | node scripts/vault-put-secret.mjs github_p3_dispatch_token
//
// Used for the P3 backup trigger's GitHub token (docs/SECURITY.md, "Nightly
// health checks"): system_health.p3_backup_dispatch() reads it by name at
// call time.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";

const NAMES = { github_p3_dispatch_token: /^github_pat_[A-Za-z0-9_]{40,}$/ };
const name = process.argv[2];
if (!(name in NAMES)) { console.error(`usage: <value on stdin> | node scripts/vault-put-secret.mjs ${Object.keys(NAMES).join("|")}`); process.exit(2); }
const value = readFileSync(0, "utf8").trim();
if (!NAMES[name].test(value)) { console.error(`${name}: stdin doesn't look like the expected secret (fine-grained PAT, github_pat_...); nothing stored`); process.exit(1); }
const env = Object.fromEntries(readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
  .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "")]));
const db = new pg.Client({ connectionString: env.DATABASE_URL });
await db.connect();
try {
  const { rows: [have] } = await db.query("select id from vault.secrets where name = $1", [name]);
  if (have) await db.query("select vault.update_secret($1, $2)", [have.id, value]);
  else await db.query("select vault.create_secret($1, $2, $3)", [value, name, "fine-grained PAT: harry-marsestate/mars-telemetry only, Actions read/write only; read by system_health.p3_backup_dispatch()"]);
  const { rows: [chk] } = await db.query("select count(*)::int n from vault.decrypted_secrets where name = $1 and decrypted_secret = $2", [name, value]);
  console.log(`${name}: ${have ? "updated" : "created"} in Vault (sha256 ${createHash("sha256").update(value).digest("hex").slice(0, 12)}…), read-back ${chk.n === 1 ? "ok" : "FAILED"}`);
} finally {
  await db.end();
}
