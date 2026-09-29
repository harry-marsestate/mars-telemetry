#!/usr/bin/env node
// Enable/rotate the health_writer Postgres role's password and store its
// connection string as HEALTH_WRITER_DB_URL in BOTH places that use it -- the
// Supabase function secrets (health-probe Edge Function) and the GitHub
// Actions secrets (nightly frontend check) -- without the password ever being
// printed, written to disk, put on a command line, or sent to Postgres in
// plaintext.
//
//   node scripts/rotate-health-writer-password.mjs
//
// 1. Generate 32 random bytes (hex) in memory.
// 2. ALTER ROLE health_writer LOGIN PASSWORD '<SCRAM-SHA-256 verifier>'.
// 3. Prove the new password logs in THROUGH THE TRANSACTION POOLER (the only
//    route a GitHub runner has: the direct host is IPv6-only) and can call
//    system_health.record_run inside a rolled-back transaction. Stop if not;
//    no secret has changed yet.
// 4. Supabase: POST /v1/projects/<ref>/secrets (JSON body) using the Supabase
//    CLI's own login token from the macOS Keychain -- no argv, no file.
// 5. GitHub: `gh secret set HEALTH_WRITER_DB_URL` with the value on stdin.
// Prints step outcomes only. Redeploy health-probe afterwards.
import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import pg from "pg";

const REF = "wwdpunaefaiazsjamrkc";
const POOLER = "aws-0-us-west-1.pooler.supabase.com:6543";
const REPO = "harry-marsestate/mars-telemetry";
const SECRET = "HEALTH_WRITER_DB_URL";

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

const password = randomBytes(32).toString("hex");
const scrub = (s) => String(s).split(password).join("[REDACTED]");
console.log("1. generated: 64 hex chars, in memory only");

const admin = new pg.Client({ connectionString: env.DATABASE_URL });
await admin.connect();
try {
  await admin.query(`alter role health_writer with login password '${scramVerifier(password)}'`);
  const { rows: [r] } = await admin.query("select rolcanlogin, rolbypassrls from pg_roles where rolname = 'health_writer'");
  console.log(`2. ALTER ROLE health_writer LOGIN PASSWORD <SCRAM verifier>: ok (rolcanlogin=${r.rolcanlogin}, rolbypassrls=${r.rolbypassrls})`);
} finally {
  await admin.end();
}

const url = `postgresql://health_writer.${REF}:${password}@${POOLER}/postgres`;
let proven = false;
for (let attempt = 1; attempt <= 8 && !proven; attempt++) {
  const c = new pg.Client({ connectionString: url, connectionTimeoutMillis: 10000 });
  try {
    await c.connect();
    await c.query("begin");
    const { rows: [r] } = await c.query("select current_user, system_health.record_run('p2_probes') is not null as can_write");
    await c.query("rollback");
    console.log(`3. pooler login as health_writer: ok on attempt ${attempt} (current_user=${r.current_user}, record_run=${r.can_write}, rolled back)`);
    proven = true;
  } catch (e) {
    console.log(`3. pooler login attempt ${attempt}: ${scrub(e.message)}`);
    await new Promise((res) => setTimeout(res, 5000));
  } finally {
    await c.end().catch(() => {});
  }
}
if (!proven) {
  console.log("STOP: the new password does not authenticate through the pooler. No secret was changed.");
  process.exit(1);
}

let token = execFileSync("security", ["find-generic-password", "-s", "Supabase CLI", "-w"], { encoding: "utf8" }).trim();
if (token.startsWith("go-keyring-base64:")) token = Buffer.from(token.slice(18), "base64").toString("utf8").trim();
const resp = await fetch(`https://api.supabase.com/v1/projects/${REF}/secrets`, {
  method: "POST",
  headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  body: JSON.stringify([{ name: SECRET, value: url }]),
});
console.log(`4. Supabase secret ${SECRET}: HTTP ${resp.status}${resp.ok ? "" : " " + scrub(await resp.text()).slice(0, 200)}`);
if (!resp.ok) process.exit(1);

execFileSync("gh", ["secret", "set", SECRET, "--repo", REPO], { input: url, stdio: ["pipe", "ignore", "pipe"] });
console.log(`5. GitHub Actions secret ${SECRET}: set (value via stdin)`);
console.log("Next: redeploy health-probe so warm instances pick up the new value.");
