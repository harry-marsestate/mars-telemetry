#!/usr/bin/env node
// Create or rotate the ingest-ets-report key (docs/ETS-INGEST.md, "Auth").
//
//   node scripts/ets-ingest-key.mjs            # create, or rotate if one exists
//   node scripts/ets-ingest-key.mjs --digest   # print the stored key's digest only
//
// Generates 32 random bytes, stores them in Vault as 'ets_ingest_key' (the
// only copy Supabase keeps; public.ets_ingest_key_ok() reads it), reads it
// back, and copies the key to the macOS clipboard so it can be pasted into the
// cloud task's environment. Never printed, never written to disk or argv:
// stdout gets only the first 12 hex chars of its SHA-256. A rotation takes
// effect immediately -- the old key stops working on the next request.
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import pg from "pg";

const NAME = "ets_ingest_key";
const digest = (v) => createHash("sha256").update(v).digest("hex").slice(0, 12);
const envFile = process.env.MARS_ENV_FILE ?? new URL("../.env", import.meta.url);
const env = Object.fromEntries(readFileSync(envFile, "utf8").split("\n")
  .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "")]));
const db = new pg.Client({ connectionString: env.DATABASE_URL });
await db.connect();
try {
  const { rows: [have] } = await db.query("select s.id, d.decrypted_secret v from vault.secrets s join vault.decrypted_secrets d using (id) where s.name = $1", [NAME]);
  if (process.argv.includes("--digest")) {
    console.log(have ? `${NAME}: sha256 ${digest(have.v)}…` : `${NAME}: not in Vault`);
  } else {
    const value = `ets_ingest_${randomBytes(32).toString("base64url")}`;
    if (have) await db.query("select vault.update_secret($1, $2)", [have.id, value]);
    else await db.query("select vault.create_secret($1, $2, $3)", [value, NAME, "ingest-ets-report caller key (x-ets-ingest-key); checked by public.ets_ingest_key_ok()"]);
    const { rows: [chk] } = await db.query("select public.ets_ingest_key_ok(encode(sha256(convert_to($1, 'UTF8')), 'hex')) ok", [value]);
    execFileSync("pbcopy", { input: value });
    console.log(`${NAME}: ${have ? "rotated" : "created"} in Vault (sha256 ${digest(value)}…), key check ${chk.ok ? "ok" : "FAILED"}; copied to the clipboard`);
  }
} finally {
  await db.end();
}
