import "@supabase/functions-js/edge-runtime.d.ts";
import { fromSupabaseUrl, withOAuthProtectedResource, withSupabase } from "@supabase/server";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { type CallToolRequest, CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

// SPIKE ONLY (branch spike/oauth21-o1). Never merge; delete after the spike.
//
// The smallest resource server that exercises the real O1 chain: Supabase's
// own withOAuthProtectedResource (RFC 9728 metadata + WWW-Authenticate on 401)
// around withSupabase({auth:"user"}) (JWKS verification of the bearer token),
// with ONE read-only MCP tool that reports who the token says the caller is
// and what RLS resolves them to. No data tables are read. No token is signed
// here -- whatever reaches the tool was issued by Supabase Auth.

// Explicit rather than the alpha zero-config derivation: served locally, the
// derivation produced ".../functions/v1/functions/v1/oauth-spike" and pointed
// the authorization server at the local origin. SUPABASE_URL on the hosted
// runtime is the project origin.
const ORIGIN = new URL(Deno.env.get("SUPABASE_URL") ?? "http://invalid").origin;

export default {
  fetch: withOAuthProtectedResource(
    {
      resourceServer: `${ORIGIN}/functions/v1/oauth-spike`,
      authorizationServer: fromSupabaseUrl(ORIGIN),
    },
    withSupabase({ auth: ["user"] }, async (req, ctx) => {
      const server = new Server({ name: "mars-telemetry-oauth-spike", version: "0.0.1" }, { capabilities: { tools: {} } });
      server.setRequestHandler(ListToolsRequestSchema, () => ({
        tools: [{
          name: "whoami",
          description: "Spike: echoes the verified token's identity claims and the caller's RLS role.",
          inputSchema: { type: "object", properties: {} },
        }],
      }));
      server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
        if (request.params.name !== "whoami") throw new Error("unknown tool");
        const claims = (ctx.jwtClaims ?? {}) as Record<string, unknown>;
        const { data: role, error } = await ctx.supabase.rpc("current_role_name");
        // Identity claims only -- never the token itself.
        const report = {
          sub: claims.sub, role: claims.role, aud: claims.aud, iss: claims.iss,
          client_id: claims.client_id ?? null, scope: claims.scope ?? null,
          session_id: claims.session_id ?? null, aal: claims.aal ?? null,
          ttl_seconds: typeof claims.exp === "number" && typeof claims.iat === "number" ? claims.exp - claims.iat : null,
          claim_keys: Object.keys(claims).sort(),
          current_role_name: error ? `error: ${error.message}` : role,
        };
        return { content: [{ type: "text", text: JSON.stringify(report) }] };
      });
      const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      await server.connect(transport);
      return await transport.handleRequest(req);
    }),
  ),
};
