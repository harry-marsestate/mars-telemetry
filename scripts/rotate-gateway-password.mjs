#!/usr/bin/env node
// Rotate the mcp_gateway Postgres role's password and the MCP_GATEWAY_DB_URL
// function secret together, without the new password ever being printed,
// written to a file, or sent to Postgres in plaintext.
//
//   node scripts/rotate-gateway-password.mjs            # rotate (then redeploy mcp yourself)
//
// 1. Generate: `openssl rand -hex 32`, captured into memory only.
// 2. Hash locally to a SCRAM-SHA-256 verifier (what psql's \password does) and
//    `ALTER ROLE mcp_gateway PASSWORD '<verifier>'` -- Postgres stores a
//    pre-hashed verifier as-is, so no plaintext can reach the server's
//    statement log.
// 3. Prove the new password authenticates THROUGH THE POOLER as mcp_gateway
//    (retrying briefly for pooler auth caching) BEFORE touching the secret.
//    If that fails, stop: the secret still holds the old value.
// 4. `supabase secrets set MCP_GATEWAY_DB_URL=...` (argv, never a file).
// Prints only step outcomes. Redeploy the mcp function afterwards so no warm
// instance keeps a connection opened with the old password.
import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import pg from "pg";

const REF = "wwdpunaefaiazsjamrkc";
const POOLER = "aws-0-us-west-1.pooler.supabase.com:6543";

const env = Object.fromEntries(
  readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
    .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "")]),
);

function scramVerifier(password) {
  const salt = randomBytes(16);
  const iterations = 4096;
  const salted = pbkdf2Sync(password, salt, iterations, 32, "sha256");
  const clientKey = createHmac("sha256", salted).update("Client Key").digest();
  const storedKey = createHash("sha256").update(clientKey).digest();
  const serverKey = createHmac("sha256", salted).update("Server Key").digest();
  return `SCRAM-SHA-256$${iterations}:${salt.toString("base64")}$${storedKey.toString("base64")}:${serverKey.toString("base64")}`;
}

const password = execFileSync("openssl", ["rand", "-hex", "32"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
if (!/^[0-9a-f]{64}$/.test(password)) throw new Error("openssl did not return 64 hex chars");
const scrub = (s) => String(s).split(password).join("[REDACTED]");
console.log("1. generated: 64 hex chars via openssl rand -hex 32 (in memory only)");

const verifier = scramVerifier(password);
const admin = new pg.Client({ connectionString: env.DATABASE_URL });
await admin.connect();
try {
  await admin.query(`alter role mcp_gateway with password '${verifier}'`);
  const { rows: [r] } = await admin.query("select rolcanlogin from pg_roles where rolname = 'mcp_gateway'");
  console.log(`2. ALTER ROLE mcp_gateway PASSWORD <SCRAM-SHA-256 verifier>: ok (rolcanlogin=${r.rolcanlogin}; plaintext never sent)`);
} finally {
  await admin.end();
}

const url = `postgresql://mcp_gateway.${REF}:${password}@${POOLER}/postgres`;
let proven = false;
for (let attempt = 1; attempt <= 8 && !proven; attempt++) {
  const c = new pg.Client({ connectionString: url, connectionTimeoutMillis: 10000 });
  try {
    await c.connect();
    const { rows: [r] } = await c.query("select current_user, (select count(*) from pg_stat_activity where usename = 'mcp_gateway')::int as gw_sessions");
    console.log(`3. pooler login as mcp_gateway with the NEW password: ok on attempt ${attempt} (current_user=${r.current_user})`);
    proven = true;
  } catch (e) {
    console.log(`3. pooler login attempt ${attempt}: ${scrub(e.message)}`);
    await new Promise((res) => setTimeout(res, 5000));
  } finally {
    await c.end().catch(() => {});
  }
}
if (!proven) {
  console.log("STOP: the new password does not authenticate through the pooler. The secret was NOT changed.");
  process.exit(1);
}

const out = execFileSync("supabase", ["secrets", "set", `MCP_GATEWAY_DB_URL=${url}`, "--project-ref", REF], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
console.log(`4. supabase secrets set MCP_GATEWAY_DB_URL: ${scrub(out).trim().split("\n").pop()}`);
console.log("Next: redeploy the mcp function, then re-verify.");
