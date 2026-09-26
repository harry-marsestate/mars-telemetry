#!/usr/bin/env node
// Create and manage service accounts: non-human identities that AI agents'
// MCP API keys act as. See docs/SECURITY.md's "Service accounts" entry.
//
// Run by the project owner. Uses the Supabase Admin API (service-role key) to
// create the auth user and DATABASE_URL (owner) to set up its profile -- the
// only creation path; there is deliberately no browser-reachable equivalent.
//
//   node scripts/service-accounts.mjs create --name <slug> --label "<what it's for>" --role operator|customer
//                                            [--customer-account <ACCT-..>] [--data-mode real_only|all]
//   node scripts/service-accounts.mjs list
//   node scripts/service-accounts.mjs disable --id <uuid>    # un-approve: every key it holds stops working
//   node scripts/service-accounts.mjs enable  --id <uuid>
//
// A service account is svc-<name>@service.invalid, email confirmed, with NO
// password and no ban (a ban would kill its keys -- migration 20260926165000),
// and app_metadata.account_type = 'service' (handle_new_user() copies that into
// user_profiles.account_type, which then can never change and never be admin).
// Nobody can sign in as it: no password, and .invalid can't receive a magic
// link, OTP or recovery email. Default data_mode is real_only.
//
// One service account per distinct scope (role + customer scope + data_mode);
// issue one key per agent under it, in the web app's API keys tab or with
// scripts/agent-keys.mjs.
//
// Environment variables override .env (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// DATABASE_URL). The service-role key is never printed.
import { readFileSync } from "node:fs";
import pg from "pg";

function loadEnv() {
  let file = {};
  try {
    file = Object.fromEntries(
      readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
        .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "")]),
    );
  } catch { /* env vars only */ }
  const get = (k) => process.env[k] ?? file[k];
  for (const k of ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "DATABASE_URL"]) if (!get(k)) throw new Error(`${k} not set (env or .env)`);
  // .env's SUPABASE_URL is the REST endpoint; the Admin API lives at the origin.
  return { origin: new URL(get("SUPABASE_URL")).origin, serviceKey: get("SUPABASE_SERVICE_ROLE_KEY"), databaseUrl: get("DATABASE_URL") };
}

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) { out._.push(a); continue; }
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) out[a.slice(2)] = true;
    else { out[a.slice(2)] = next; i++; }
  }
  return out;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;

async function withDb(env, fn) {
  const client = new pg.Client({ connectionString: env.databaseUrl });
  await client.connect();
  try { return await fn(client); } finally { await client.end(); }
}

async function adminApi(env, method, path, body) {
  const res = await fetch(`${env.origin}/auth/v1/admin/${path}`, {
    method,
    headers: { apikey: env.serviceKey, Authorization: `Bearer ${env.serviceKey}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-JSON */ }
  if (!res.ok) throw new Error(`Admin API ${method} ${path} -> HTTP ${res.status}: ${json?.msg ?? json?.message ?? json?.error_description ?? text.slice(0, 200)}`);
  return json;
}

async function create(env, args) {
  const name = args.name, label = typeof args.label === "string" ? args.label.trim() : "";
  const role = args.role, dataMode = args["data-mode"] ?? "real_only";
  const account = typeof args["customer-account"] === "string" ? args["customer-account"].trim() : null;
  if (!SLUG.test(name ?? "")) throw new Error("--name must be 1-40 chars of a-z, 0-9 and inner hyphens (it becomes svc-<name>@service.invalid)");
  if (!label || label.length > 60) throw new Error("--label is required (what the account is for, max 60 chars)");
  if (!["operator", "customer"].includes(role)) throw new Error("--role must be operator or customer");
  if (!["real_only", "all"].includes(dataMode)) throw new Error("--data-mode must be real_only or all");
  if (role === "customer" && !account) throw new Error("--customer-account is required for a customer-scoped service account");
  if (role === "operator" && account) throw new Error("--customer-account only applies to --role customer");
  const email = `svc-${name}@service.invalid`;

  await withDb(env, async (db) => {
    const { rows: [dupe] } = await db.query("select id from auth.users where lower(email) = $1", [email]);
    if (dupe) throw new Error(`${email} already exists (${dupe.id})`);
    if (account) {
      const { rows: [{ n }] } = await db.query("select count(*)::int n from public.customer_block_access where customer_account_id = $1", [account]);
      if (!n) throw new Error(`customer account ${account} has no block access rows -- a key for it would see nothing`);
    }
  });

  // No password, no ban. email_confirm: true, like any working account.
  const user = await adminApi(env, "POST", "users", {
    email,
    email_confirm: true,
    app_metadata: { account_type: "service" },
    user_metadata: { first_name: "Service", last_name: label },
  });
  const id = user?.id;
  if (!UUID.test(id ?? "")) throw new Error("Admin API returned no user id");

  try {
    const profile = await withDb(env, async (db) => {
      const { rows } = await db.query(
        `update public.user_profiles
            set status = 'approved', role = $2, data_mode = $3, customer_account_id = $4
          where id = $1 and account_type = 'service' and not is_admin
          returning id, role, status, data_mode, customer_account_id, account_type`,
        [id, role, dataMode, account],
      );
      if (rows.length !== 1) throw new Error("profile was not created as a service account (is migration 20260926180000 applied?)");
      return rows[0];
    });
    console.log(`Created service account ${id}`);
    console.log(`  email:     ${email}  (no password, cannot sign in)`);
    console.log(`  name:      Service ${label}`);
    console.log(`  scope:     ${profile.role}${profile.customer_account_id ? ` / ${profile.customer_account_id}` : ""}, ${profile.status}, data_mode ${profile.data_mode}`);
    console.log("");
    console.log("Next: issue one key per agent -- web app, User Management -> API keys, or");
    console.log(`  node scripts/agent-keys.mjs issue --user ${id} --label "<agent>" --keychain`);
  } catch (err) {
    // Never leave a half-made account behind.
    await adminApi(env, "DELETE", `users/${id}`).catch((e) => console.error(`cleanup failed, delete ${id} by hand: ${e.message}`));
    throw err;
  }
}

async function list(env) {
  await withDb(env, async (db) => {
    const { rows } = await db.query(
      `select p.id, u.email, p.last_name as label, p.role, p.status, p.data_mode, p.customer_account_id,
              count(k.id) filter (where k.revoked_at is null and k.expires_at > now())::int as active_keys,
              count(k.id)::int as all_keys
         from public.user_profiles p
         join auth.users u on u.id = p.id
         left join public.agent_api_keys k on k.user_id = p.id
        where p.account_type = 'service'
        group by p.id, u.email order by u.email`,
    );
    if (!rows.length) return console.log("(no service accounts)");
    for (const r of rows) {
      console.log(`${r.status.padEnd(8)} ${r.email}  ${r.id}`);
      console.log(`         "${r.label}"  ${r.role}${r.customer_account_id ? `/${r.customer_account_id}` : ""}  data_mode ${r.data_mode}  keys ${r.active_keys} active / ${r.all_keys} total`);
    }
  });
}

async function setStatus(env, args, status) {
  if (!UUID.test(args.id ?? "")) throw new Error("--id <uuid> is required");
  await withDb(env, async (db) => {
    const { rows } = await db.query(
      "update public.user_profiles set status = $2 where id = $1 and account_type = 'service' returning id, status",
      [args.id, status],
    );
    if (!rows.length) throw new Error(`${args.id} is not a service account`);
    console.log(`${rows[0].id} is now ${rows[0].status}${status === "rejected" ? " -- every key it holds is rejected from the next request" : ""}`);
  });
}

const args = parseArgs(process.argv.slice(2));
const commands = { create, list, disable: (e, a) => setStatus(e, a, "rejected"), enable: (e, a) => setStatus(e, a, "approved") };
const command = commands[args._[0]];
if (!command) {
  console.error("usage: node scripts/service-accounts.mjs <create|list|disable|enable> [options] -- see the header comment");
  process.exit(2);
}
Promise.resolve().then(() => command(loadEnv(), args)).catch((err) => {
  console.error(`error: ${err.message}`);
  process.exit(1);
});
