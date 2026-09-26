import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { fetchDomainReality, runTool, TOOLS } from "../chat/tools.ts";
import { signAccessToken } from "./auth.ts";
import { createMcpHandler } from "./handler.ts";

// MCP-over-HTTP for external agents, authenticated by a per-user API key
// (agent_api_keys, issued by scripts/agent-keys.mjs). See handler.ts for the
// request flow and docs/SECURITY.md's MCP entry for the auth model.
//
// Two credentials only, both deliberately narrow:
//   - the ANON key: for mcp_authenticate()/mcp_log_call(), and as the apikey
//     header PostgREST requires on the user-scoped client;
//   - the signing secret (the project's legacy JWT secret, set by hand as
//     this function's secret, read at exactly one site below): used ONLY to
//     sign the 60s per-request user token.
// No RLS-bypassing client or key exists here; scripts/check-mcp-boundaries.mjs
// fails if one ever appears.

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
const JWT_SECRET = Deno.env.get("MCP_JWT_SECRET") ?? "";

const NO_SESSION = { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false };
const anon = createClient(SUPABASE_URL, ANON_KEY, { auth: NO_SESSION });

const handler = createMcpHandler({
  async authenticate(keyHash) {
    const { data, error } = await anon.rpc("mcp_authenticate", { p_key_hash: keyHash });
    if (error) throw new Error(error.message);
    const row = (data as { key_id: string; user_id: string }[] | null)?.[0];
    return row ? { keyId: row.key_id, userId: row.user_id } : null;
  },
  async logCall(keyHash, tool, args, isError) {
    const { error } = await anon.rpc("mcp_log_call", { p_key_hash: keyHash, p_tool: tool, p_args: args, p_is_error: isError });
    if (error) throw new Error(error.message);
  },
  signToken: (userId, keyId) => signAccessToken(JWT_SECRET, SUPABASE_URL, userId, keyId),
  scopedClient: (token) =>
    createClient(SUPABASE_URL, ANON_KEY, {
      global: { headers: { Authorization: `Bearer ${token}` } },
      auth: NO_SESSION,
    }),
  runTool,
  fetchDomainReality,
  tools: TOOLS as never,
});

export default {
  async fetch(req: Request): Promise<Response> {
    if (!SUPABASE_URL || !ANON_KEY || !JWT_SECRET) {
      console.error("mcp: missing SUPABASE_URL, SUPABASE_ANON_KEY or the signing secret");
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
