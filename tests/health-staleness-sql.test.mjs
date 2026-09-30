// Offline test for public.health_producer_stale() (migration
// 20260930090000): schedule-aware staleness with a 30-minute grace, plus the
// 26-hour rule.
//   (cd scripts && npm install) && node --test tests/health-staleness-sql.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const requireFromScripts = createRequire(new URL("../scripts/package.json", import.meta.url));
const { PGlite } = await import(pathToFileURL(requireFromScripts.resolve("@electric-sql/pglite")).href);
const mig = readFileSync(new URL("../supabase/migrations/20260930090000_health_schedule_staleness_p3_backup.sql", import.meta.url), "utf8");
const fn = mig.slice(mig.indexOf("create function public.health_producer_stale"), mig.indexOf("$$;", mig.indexOf("create function public.health_producer_stale")) + 3);

let db;
before(async () => {
  db = new PGlite();
  await db.exec("create role anon; create role authenticated; create role service_role;");
  await db.exec(fn);
});
const stale = async (last, slot, now) => (await db.query("select public.health_producer_stale($1::timestamptz, $2::time, $3::timestamptz) s", [last, slot, now])).rows[0].s;

test("before today's grace ends, yesterday's run is enough", async () => {
  assert.equal(await stale("2026-09-30T12:17:05Z", "12:17", "2026-10-01T12:40:00Z"), false);   // P3 due 12:17, grace to 12:47
  assert.equal(await stale("2026-09-30T12:00:01Z", "12:00", "2026-10-01T12:29:59Z"), false);
});
test("after the grace, no run since today's slot = stale", async () => {
  assert.equal(await stale("2026-09-30T12:17:05Z", "12:17", "2026-10-01T12:47:00Z"), true);
  assert.equal(await stale("2026-09-30T12:00:01Z", "12:00", "2026-10-01T12:30:00Z"), true);
  assert.equal(await stale("2026-10-01T12:36:10Z", "12:17", "2026-10-01T13:00:00Z"), false, "a backup-dispatched P3 run after the slot counts");
});
test("a run slightly before the slot does not satisfy that slot", async () => {
  assert.equal(await stale("2026-10-01T12:16:59Z", "12:17", "2026-10-01T12:48:00Z"), true);
});
test("26-hour rule still applies on its own", async () => {
  assert.equal(await stale("2026-09-30T10:00:00Z", "12:00", "2026-10-01T12:10:00Z"), true);   // grace not over, but > 26 h old
  assert.equal(await stale(null, "12:00", "2026-10-01T12:10:00Z"), true);
});
test("works across midnight UTC and month ends", async () => {
  assert.equal(await stale("2026-10-31T12:10:30Z", "12:10", "2026-11-01T00:05:00Z"), false);
  assert.equal(await stale("2026-12-31T12:10:30Z", "12:10", "2027-01-01T12:41:00Z"), true);
});
