// health-probe: P2 of the nightly health checks (docs/SECURITY.md, "Nightly
// health checks"). pg_cron calls it at 12:10 UTC with the Vault key, like the
// ingest jobs. It probes every upstream production depends on (probes.ts) and
// records one result per probe as health_writer -- the least-privileged
// writer role (EXECUTE on record_run/record_result only), never the service
// role. Probe results never contain a secret or a response body.
import "@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "@supabase/server";
import postgres from "postgres";
import { runProbes } from "./probes.ts";

export default {
  fetch: withSupabase({ auth: ["secret:*"] }, async (_req, _ctx) => {
    const writerUrl = Deno.env.get("HEALTH_WRITER_DB_URL");
    if (!writerUrl) {
      console.error("health-probe: HEALTH_WRITER_DB_URL is not set");
      return Response.json({ ok: false, reason: "writer not configured" }, { status: 500 });
    }
    const startedAt = new Date();
    const results = await runProbes((n) => Deno.env.get(n), fetch, startedAt);

    const sql = postgres(writerUrl, { prepare: false, max: 1, idle_timeout: 5, connect_timeout: 10 });
    try {
      const [{ id }] = await sql`select system_health.record_run('p2_probes', ${startedAt.toISOString()}::timestamptz) as id`;
      for (const r of results) {
        await sql`select system_health.record_result(${id}::bigint, 'source', ${r.check_id}, ${r.status},
                    ${sql.json(r.observed as never)}, ${sql.json(r.expected as never)}, ${r.detail ?? null})`;
      }
      return Response.json({ ok: true, run_id: Number(id), results: results.map((r) => ({ check_id: r.check_id, status: r.status })) });
    } catch (err) {
      console.error("health-probe: could not record results", err instanceof Error ? err.message : String(err));
      return Response.json({ ok: false, reason: "could not record results", results: results.map((r) => ({ check_id: r.check_id, status: r.status })) }, { status: 500 });
    } finally {
      await sql.end({ timeout: 5 });
    }
  }),
};
