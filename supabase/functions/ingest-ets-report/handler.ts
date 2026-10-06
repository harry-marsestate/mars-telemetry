import { summarizeEtsReport, withIngestionLog } from "../_shared/ingestion-log.ts";

// Request flow for ingest-ets-report (index.ts wires it to the platform).
// docs/ETS-INGEST.md describes the payload and the mapping; docs/SECURITY.md,
// "ETS PDF report ingestion", the auth model.
//
//   1. The caller's key arrives in KEY_HEADER. Only its SHA-256 is sent on, to
//      public.ets_ingest_key_ok(), which compares it with the Vault secret
//      'ets_ingest_key'. A refused key gets 401 and is not logged as a run,
//      the same as a key rejected by withSupabase in the other ingests.
//   2. From there every request is one ingestion_runs row (withIngestionLog).
//   3. The payload goes unchanged to public.ets_ingest_apply(), which
//      validates, quarantines and writes in one transaction and returns the
//      per-row result and the HTTP status to answer with.
//
// The caller never holds a Supabase key: the admin client used for the two
// RPCs is the platform's own, inside this function.

export const KEY_HEADER = "x-ets-ingest-key";
const MAX_BODY_BYTES = 256 * 1024;

// deno-lint-ignore no-explicit-any
type Rpc = (fn: string, args: Record<string, unknown>) => PromiseLike<{ data: any; error: { message: string } | null }>;

export async function sha256Hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function createHandler(ctx: { supabaseAdmin: { rpc: Rpc } }) {
  return async (req: Request): Promise<Response> => {
    if (req.method !== "POST") return Response.json({ ok: false, reason: "POST only" }, { status: 405, headers: { allow: "POST" } });

    const key = req.headers.get(KEY_HEADER) ?? "";
    if (!key || key.length > 256) return Response.json({ ok: false, reason: `missing or invalid ${KEY_HEADER}` }, { status: 401 });
    const keySha = await sha256Hex(key);
    const auth = await ctx.supabaseAdmin.rpc("ets_ingest_key_ok", { p_key_sha256: keySha });
    if (auth.error) {
      console.error("ingest-ets-report: key check failed", auth.error.message);
      return Response.json({ ok: false, reason: "key check unavailable" }, { status: 503 });
    }
    if (auth.data !== true) return Response.json({ ok: false, reason: `missing or invalid ${KEY_HEADER}` }, { status: 401 });

    return withIngestionLog(ctx, "ingest-ets-report", () => ingest(req, keySha, ctx.supabaseAdmin.rpc), summarizeEtsReport);
  };
}

async function ingest(req: Request, keySha: string, rpc: Rpc): Promise<Response> {
  const text = await req.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) {
    return Response.json({ ok: false, reason: `body over ${MAX_BODY_BYTES} bytes` }, { status: 413 });
  }
  let payload: unknown;
  try { payload = JSON.parse(text); } catch { return Response.json({ ok: false, reason: "body is not JSON" }, { status: 400 }); }

  // A weekly run with no new report still checks in, so P1 can tell "no
  // reports this week" from "the job stopped running".
  // deno-lint-ignore no-explicit-any
  const p = payload as any;
  if (p && typeof p === "object" && p.heartbeat === true) {
    if (p.source !== "ets_pdf_email") return Response.json({ ok: false, reason: 'source must be "ets_pdf_email"' }, { status: 400 });
    return Response.json({ ok: true, heartbeat: true, written: 0, quarantined: 0 });
  }

  const { data, error } = await rpc("ets_ingest_apply", { p_key_sha256: keySha, p_payload: payload });
  if (error) {
    console.error("ingest-ets-report: ets_ingest_apply failed", error.message);
    return Response.json({ ok: false, reason: "database error", detail: error.message }, { status: 500 });
  }
  const { http_status: status, ...body } = data ?? {};
  return Response.json(body, { status: typeof status === "number" ? status : 500 });
}
