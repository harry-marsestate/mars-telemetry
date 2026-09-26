#!/usr/bin/env node
// Issue, revoke and list MCP agent API keys (public.agent_api_keys).
//
// Run by the project owner, directly against DATABASE_URL -- never through
// PostgREST (the tables are deny-all to anon/authenticated/service_role).
//
//   node scripts/agent-keys.mjs issue  --user <uuid> --label "<text>" [--days 90] [--keychain] [--no-print] [--allow-unapproved]
//   node scripts/agent-keys.mjs revoke --id <key uuid>
//   node scripts/agent-keys.mjs list
//   node scripts/agent-keys.mjs calls  [--limit 20]
//
// Generation, hashing, eligibility and revocation live in Postgres
// (public.agent_key_issue/agent_key_revoke/agent_key_list, migration
// 20260926160000) -- the SAME functions the web app's User Management "API
// keys" tab reaches through its admin_* wrappers, so there is one
// implementation, not two. Those functions are owner-only; this script calls
// them as the owner, exactly as it used to run its own SQL. The key (32 bytes
// from pgcrypto's gen_random_bytes) is generated inside the function, only its
// SHA-256 is stored, and the plaintext comes back once in the result row. It
// is printed to this terminal once and not written to any file or log by this
// script.
//
// --keychain additionally stores the plaintext in the macOS login Keychain
// (service "mars-telemetry-mcp", account = the key's prefix) so
// scripts/mcp-verify.mjs can use it without it ever being printed or
// written to disk. Delete it afterwards with:
//   security delete-generic-password -s mars-telemetry-mcp -a <prefix>
//
// Every label gets "[user <first 8 of uuid>]" appended so it's always
// obvious which account a key acts as.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import os from "node:os";
import pg from "pg";

const KEYCHAIN_SERVICE = "mars-telemetry-mcp";

function databaseUrl() {
  if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
  const envPath = new URL("../.env", import.meta.url);
  const line = readFileSync(envPath, "utf8").split("\n").find((l) => l.startsWith("DATABASE_URL="));
  if (!line) throw new Error("DATABASE_URL not set and not found in .env");
  return line.slice("DATABASE_URL=".length).trim().replace(/^["']|["']$/g, "");
}

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) { out._.push(a); continue; }
    const name = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) out[name] = true;
    else { out[name] = next; i++; }
  }
  return out;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

async function withDb(fn) {
  const client = new pg.Client({ connectionString: databaseUrl() });
  await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}

async function issue(args) {
  const userId = args.user;
  if (!UUID.test(userId ?? "")) throw new Error("--user <uuid> is required");
  if (typeof args.label !== "string") throw new Error("--label is required");
  // Range (1-365) and label rules are enforced by agent_key_issue() itself.
  const days = args.days === undefined ? 90 : Number(args.days);
  if (!Number.isInteger(days)) throw new Error("--days must be an integer");
  if (args["no-print"] && !args.keychain) throw new Error("--no-print requires --keychain (the key would otherwise be lost)");

  const row = await withDb(async (db) => {
    const createdBy = `${os.userInfo().username}@${os.hostname()} via scripts/agent-keys.mjs`;
    const { rows: [issued] } = await db.query(
      "select * from public.agent_key_issue($1, $2, $3, $4, $5)",
      [userId, args.label, days, createdBy, Boolean(args["allow-unapproved"])],
    );
    return issued;
  });
  const { key, key_prefix: prefix, label } = row;

  if (args.keychain) {
    execFileSync("security", ["add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", prefix, "-l", label, "-w", key], { stdio: "ignore" });
  }

  console.log(`Issued key ${row.id}`);
  console.log(`  label:    ${label}`);
  console.log(`  acts as:  ${userId} (${row.account_role}/${row.account_status})`);
  console.log(`  prefix:   ${prefix}`);
  console.log(`  expires:  ${row.expires_at.toISOString()}`);
  if (args.keychain) console.log(`  keychain: stored (service ${KEYCHAIN_SERVICE}, account ${prefix})`);
  if (!args["no-print"]) {
    console.log("");
    console.log("  KEY (shown once; only its SHA-256 hash is stored):");
    console.log(`  ${key}`);
  }
}

async function revoke(args) {
  if (!UUID.test(args.id ?? "")) throw new Error("--id <key uuid> is required");
  await withDb(async (db) => {
    const { rows } = await db.query("select * from public.agent_key_revoke($1)", [args.id]);
    if (!rows.length) throw new Error(`no active key with id ${args.id} (unknown or already revoked)`);
    const r = rows[0];
    console.log(`Revoked ${r.id} (${r.key_prefix}, ${r.label}) at ${r.revoked_at.toISOString()}`);
  });
}

async function list() {
  await withDb(async (db) => {
    // agent_key_list() is newest first (the web tab's order); the CLI has
    // always listed oldest first.
    const rows = (await db.query("select * from public.agent_key_list()")).rows.reverse();
    if (!rows.length) return console.log("(no keys)");
    for (const r of rows) {
      console.log(`${r.status.padEnd(7)} ${r.key_prefix}  ${r.id}  ${r.label}`);
      console.log(`        user ${r.user_id}  created ${r.created_at.toISOString()}  last used ${r.last_used_at?.toISOString() ?? "never"}  expires ${r.expires_at.toISOString()}${r.revoked_at ? `  revoked ${r.revoked_at.toISOString()}` : ""}`);
    }
  });
}

async function calls(args) {
  const limit = args.limit === undefined ? 20 : Number(args.limit);
  await withDb(async (db) => {
    const { rows } = await db.query(
      `select c.called_at, k.key_prefix, c.tool, c.is_error, c.args
         from public.agent_api_key_calls c join public.agent_api_keys k on k.id = c.key_id
        order by c.called_at desc limit $1`,
      [limit],
    );
    for (const r of rows) console.log(`${r.called_at.toISOString()} ${r.key_prefix} ${r.is_error ? "ERR" : "ok "} ${r.tool} ${JSON.stringify(r.args)}`);
    if (!rows.length) console.log("(no calls)");
  });
}

const args = parseArgs(process.argv.slice(2));
const commands = { issue, revoke, list, calls };
const command = commands[args._[0]];
if (!command) {
  console.error("usage: node scripts/agent-keys.mjs <issue|revoke|list|calls> [options] -- see the header comment");
  process.exit(2);
}
command(args).catch((err) => {
  console.error(`error: ${err.message}`);
  process.exit(1);
});
