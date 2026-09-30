#!/usr/bin/env node
// Synthetic users for the nightly frontend check (P3) -- an explicit, approved
// exception to docs/SECURITY.md's "never create accounts to manufacture a
// verification case" rule (see "Nightly health checks").
//
//   node scripts/health-test-users.mjs            # create + approve any that don't exist yet
//
// For each user:
// 1. Create it through the Supabase Auth Admin API, email confirmed, with
//    first/last name in user_metadata (handle_new_user() copies them), exactly
//    as a real signup ends up. A random password is generated in memory and
//    written ONLY to its GitHub Actions secret (gh, stdin) -- never printed,
//    never on disk, never on a command line. An existing user is left alone
//    (its password is not reset).
// 2. Approve it the way User Management's Approve form does -- the same
//    UPDATE on user_profiles and INSERTs into customer_block_access, run as
//    `authenticated` with the approving admin's claims, so RLS
//    (admin_manages_profiles, customer_block_access_admin_insert) decides, as
//    it would for the browser. None of them is ever an admin.
// Prints user ids (first 8 chars), roles and blocks only.
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";

const REPO = "harry-marsestate/mars-telemetry";
const APPROVING_ADMIN_PREFIX = "5bb6b29e"; // the project owner's admin account
const USERS = [
  { email: "harry.c+health-operator@marscap.investments", first: "Health", last: "Operator", role: "operator", account: null, blocks: [], secret: "P3_OPERATOR_PASSWORD" },
  { email: "harry.c+health-customer@marscap.investments", first: "Health", last: "Customer", role: "customer", account: "HEALTH-CUST", blocks: ["B1", "B2", "B3"], secret: "P3_CUSTOMER_PASSWORD" },
  { email: "harry.c+health-customer-b2@marscap.investments", first: "Health", last: "CustomerB2", role: "customer", account: "HEALTH-CUST-B2", blocks: ["B2"], secret: "P3_CUSTOMER_B2_PASSWORD" },
];

const env = Object.fromEntries(
  readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
    .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "")]),
);
const origin = new URL(env.SUPABASE_URL).origin;
const serviceKey = env.SUPABASE_SERVICE_ROLE_KEY;

const db = new pg.Client({ connectionString: env.DATABASE_URL });
await db.connect();
try {
  const { rows: [admin] } = await db.query("select id from public.user_profiles where id::text like $1 and is_admin", [`${APPROVING_ADMIN_PREFIX}%`]);
  if (!admin) throw new Error("approving admin not found");

  for (const u of USERS) {
    let { rows: [existing] } = await db.query("select id from auth.users where lower(email) = lower($1)", [u.email]);
    if (existing) {
      console.log(`${u.email}: exists (${existing.id.slice(0, 8)}), not recreated; password unchanged`);
    } else {
      // A password that satisfies the app's own rules (lower/upper/digit/symbol).
      const password = `${randomBytes(24).toString("base64url")}aA1!`;
      const resp = await fetch(`${origin}/auth/v1/admin/users`, {
        method: "POST",
        headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ email: u.email, password, email_confirm: true, user_metadata: { first_name: u.first, last_name: u.last } }),
      });
      const body = await resp.json().catch(() => ({}));
      if (!resp.ok || !body.id) throw new Error(`${u.email}: Admin API ${resp.status} ${JSON.stringify(body).split(password).join("[REDACTED]").slice(0, 200)}`);
      execFileSync("gh", ["secret", "set", u.secret, "--repo", REPO], { input: password, stdio: ["pipe", "ignore", "pipe"] });
      existing = { id: body.id };
      console.log(`${u.email}: created ${body.id.slice(0, 8)}; password -> GitHub secret ${u.secret} (stdin)`);
    }

    // Approve as the admin, through RLS, exactly like the Approve form.
    await db.query("begin");
    try {
      await db.query("select set_config('request.jwt.claims', $1, true)", [JSON.stringify({ sub: admin.id, role: "authenticated" })]);
      await db.query("set local role authenticated");
      const { rows: [p] } = await db.query("select status, role, customer_account_id, is_admin, first_name, last_name from public.user_profiles where id = $1", [existing.id]);
      if (!p) throw new Error(`${u.email}: no user_profiles row`);
      if (p.status !== "approved" || p.role !== u.role || p.customer_account_id !== u.account || p.is_admin) {
        await db.query("update public.user_profiles set status = 'approved', role = $2, is_admin = false, customer_account_id = $3 where id = $1",
          [existing.id, u.role, u.account]);
      }
      for (const b of u.blocks) {
        const { rows: [have] } = await db.query("select 1 from public.customer_block_access where customer_account_id = $1 and block_id = $2", [u.account, b]);
        if (!have) await db.query("insert into public.customer_block_access (customer_account_id, block_id) values ($1, $2)", [u.account, b]);
      }
      await db.query("commit");
    } catch (e) {
      await db.query("rollback");
      throw e;
    }
    const { rows: [after] } = await db.query(
      `select p.status, p.role, p.is_admin, p.customer_account_id, p.first_name, p.last_name, p.data_mode, p.confirmed_at is not null as confirmed,
              (select array_agg(block_id order by block_id) from public.customer_block_access c where c.customer_account_id = p.customer_account_id) as blocks
         from public.user_profiles p where p.id = $1`, [existing.id]);
    console.log(`  -> ${after.status} ${after.role} admin=${after.is_admin} account=${after.customer_account_id ?? "-"} blocks=${after.blocks?.join(",") ?? "-"} name=${after.first_name} ${after.last_name} data_mode=${after.data_mode} confirmed=${after.confirmed}`);
  }
} finally {
  await db.end();
}
