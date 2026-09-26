import "@supabase/functions-js/edge-runtime.d.ts";
import postgres from "postgres";
import { fetchDomainReality, runTool, TOOLS } from "../chat/tools.ts";
import { PostgrestAdapter } from "./adapter.ts";
import { runAsKeyOwner, type Sql } from "./gateway.ts";
import { createMcpHandler } from "./handler.ts";

// MCP-over-HTTP for external agents, authenticated by a per-user API key
// (agent_api_keys, issued by scripts/agent-keys.mjs). See handler.ts for the
// request flow and docs/SECURITY.md's MCP entries for the auth model.
//
// ONE credential: the connection string for the mcp_gateway Postgres role
// (Supavisor transaction pooler), set by hand as this function's secret and
// read at exactly one site below. That role can resolve/log API keys and
// switch to mcp_reader -- SELECT-only on the round-one allowlist, under RLS.
// It cannot write, cannot bypass RLS, and cannot become any other role.
// No PostgREST client, no API key, and no token-signing secret exists here;
// scripts/check-mcp-boundaries.mjs fails if one ever appears.

const GATEWAY_DB_URL = Deno.env.get("MCP_GATEWAY_DB_URL") ?? "";

// prepare: false -- the transaction pooler does not support named prepared
// statements. One small pool per isolate, reused across requests.
const pg = GATEWAY_DB_URL
  ? postgres(GATEWAY_DB_URL, { prepare: false, max: 3, idle_timeout: 20, connect_timeout: 10 })
  : null;

// deno-lint-ignore no-explicit-any
const unsafe = (text: string, params: unknown[] = []) => pg!.unsafe(text, params as any[]) as unknown as Promise<Record<string, unknown>[]>;

const handler = createMcpHandler({
  async authenticate(keyHash) {
    const [row] = await unsafe("select key_id, user_id from public.mcp_authenticate($1)", [keyHash]);
    return row ? { keyId: String(row.key_id), userId: String(row.user_id) } : null;
  },
  async logCall(keyHash, tool, args, isError) {
    // Pass the object itself: postgres.js JSON-encodes values bound to a jsonb
    // parameter. Pre-stringifying double-encoded it -- the first live audit row
    // stored args as a JSON *string* ("{\"vintage\":2026,...}"), not an object.
    await unsafe("select public.mcp_log_call($1, $2, $3::jsonb, $4)", [keyHash, tool, args ?? null, isError]);
  },
  runScoped: (userId, keyId, fn) =>
    runAsKeyOwner(pg as unknown as Sql, userId, keyId, (query) => fn(new PostgrestAdapter(query))),
  runTool,
  fetchDomainReality,
  tools: TOOLS as never,
});

export default {
  async fetch(req: Request): Promise<Response> {
    if (!pg) {
      console.error("mcp: missing the gateway connection secret");
      return Response.json({ error: "mcp function is misconfigured" }, { status: 500 });
    }
    try {
      return await handler(req);
    } catch (err) {
      console.error("mcp: unhandled error", err instanceof Error ? err.message : String(err));
      return Response.json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null }, { status: 500 });
    }
  },
};
