import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { type CallToolRequest, CallToolRequestSchema, ErrorCode, ListToolsRequestSchema, McpError } from "@modelcontextprotocol/sdk/types.js";
import type { DomainReality, ToolResult } from "../chat/tools.ts";
import { MCP_TOOLS } from "./allowlist.ts";
import { parseBearerKey, sha256Hex } from "./auth.ts";

// The request flow (docs/SECURITY.md, MCP entry):
//   bearer key -> sha256 -> mcp_authenticate() via the ANON client
//   -> sign a 60s token for that user -> RLS-scoped supabase-js client
//   -> chat/tools.ts runTool(), unchanged.
// Every data query therefore goes through PostgREST under the key owner's
// own auth.uid(), exactly as their browser session would -- never an
// RLS-bypassing client (none exists in this directory). Everything
// environment-specific is injected so this file can be tested without a
// deployed function.

interface ToolDef {
  name: string;
  description?: string;
  input_schema: { type: "object"; properties?: Record<string, JsonSchemaProp>; required?: string[] };
}
interface JsonSchemaProp {
  type?: string;
  enum?: unknown[];
}

export interface McpDeps {
  // Resolves a key hash to (keyId, userId), or null when mcp_authenticate()
  // returns no row. Throws on an infrastructure failure -- which fails
  // closed as a 500, never as an unauthenticated pass-through.
  authenticate(keyHash: string): Promise<{ keyId: string; userId: string } | null>;
  logCall(keyHash: string, tool: string, args: unknown, isError: boolean): Promise<void>;
  signToken(userId: string, keyId: string): Promise<string>;
  // deno-lint-ignore no-explicit-any
  scopedClient(token: string): any;
  // deno-lint-ignore no-explicit-any
  runTool(supabase: any, name: string, input: Record<string, unknown>, dataMode: string, domainReality: DomainReality): Promise<ToolResult>;
  // deno-lint-ignore no-explicit-any
  fetchDomainReality(supabase: any): Promise<DomainReality>;
  tools: ToolDef[];
}

const JSON_HEADERS = { "Content-Type": "application/json" };

function jsonRpcError(status: number, code: number, message: string, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null }), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  });
}

// One response for every authentication failure -- malformed, unknown,
// revoked, expired, or bound to an unapproved account -- so the response
// never tells a caller which of those it hit.
function unauthorized(): Response {
  return jsonRpcError(401, -32001, "Unauthorized", { "WWW-Authenticate": 'Bearer realm="mars-telemetry-mcp"' });
}

const MAX_STRING_ARG = 200;

// chat's tools were written for a model constrained by these same schemas;
// an MCP caller is an arbitrary program, so the schema is enforced here
// before runTool() ever sees the input. Covers exactly the subset of JSON
// Schema TOOLS uses (object properties, required, type, enum).
export function validateArgs(tool: ToolDef, args: unknown): string | null {
  if (args === undefined || args === null) args = {};
  if (typeof args !== "object" || Array.isArray(args)) return "arguments must be a JSON object";
  const props = tool.input_schema.properties ?? {};
  const input = args as Record<string, unknown>;
  for (const key of Object.keys(input)) {
    if (!(key in props)) return `unknown argument '${key}'`;
  }
  for (const key of tool.input_schema.required ?? []) {
    if (input[key] === undefined) return `missing required argument '${key}'`;
  }
  for (const [key, value] of Object.entries(input)) {
    if (value === undefined) continue;
    const prop = props[key];
    const ok = prop.type === "string"
      ? typeof value === "string" && value.length <= MAX_STRING_ARG
      : prop.type === "integer"
      ? Number.isInteger(value)
      : prop.type === "number"
      ? typeof value === "number" && Number.isFinite(value)
      : prop.type === "boolean"
      ? typeof value === "boolean"
      : false;
    if (!ok) return `argument '${key}' must be ${prop.type === "string" ? `a string of at most ${MAX_STRING_ARG} characters` : `a${prop.type === "integer" ? "n" : ""} ${prop.type}`}`;
    if (prop.enum && !prop.enum.includes(value)) return `argument '${key}' must be one of ${prop.enum.join(", ")}`;
  }
  return null;
}

export function createMcpHandler(deps: McpDeps): (req: Request) => Promise<Response> {
  const exposed = deps.tools.filter((t) => MCP_TOOLS.includes(t.name));
  // Fail at startup, not per request, if chat/tools.ts ever renames or drops
  // a tool this server promises to expose.
  if (exposed.length !== MCP_TOOLS.length) {
    const missing = MCP_TOOLS.filter((n) => !exposed.some((t) => t.name === n));
    throw new Error(`mcp: allowlisted tools missing from chat/tools.ts: ${missing.join(", ")}`);
  }
  const byName = new Map(exposed.map((t) => [t.name, t]));

  return async (req: Request): Promise<Response> => {
    const key = parseBearerKey(req.headers.get("authorization"));
    if (!key) return unauthorized();
    const keyHash = await sha256Hex(key);

    let identity: { keyId: string; userId: string } | null;
    try {
      identity = await deps.authenticate(keyHash);
    } catch (err) {
      console.error("mcp: key lookup failed", err instanceof Error ? err.message : String(err));
      return jsonRpcError(500, -32603, "Authentication backend unavailable");
    }
    if (!identity) return unauthorized();
    const { keyId, userId } = identity;

    // Stateless: a fresh server + transport per HTTP request, no session ids,
    // plain JSON responses (every tool here is a single request/response).
    const server = new Server({ name: "mars-telemetry", version: "1.0.0" }, { capabilities: { tools: {} } });

    server.setRequestHandler(ListToolsRequestSchema, () => ({
      tools: exposed.map((t) => ({ name: t.name, description: t.description, inputSchema: t.input_schema })),
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
      const name = String(request.params.name).slice(0, 100);
      const args = request.params.arguments ?? {};
      const log = (isError: boolean) =>
        deps.logCall(keyHash, name, args, isError).catch((err) =>
          console.error("mcp: audit log write failed", err instanceof Error ? err.message : String(err))
        );

      const tool = byName.get(name);
      if (!tool) {
        // Rejected here even though runTool() could dispatch get_series,
        // get_vessels, etc. -- the allowlist, not runTool's switch, decides.
        await log(true);
        throw new McpError(ErrorCode.InvalidParams, `Unknown tool: ${name}`);
      }

      const invalid = validateArgs(tool, args);
      if (invalid) {
        await log(true);
        return { content: [{ type: "text", text: `Invalid arguments: ${invalid}` }], isError: true };
      }

      // Signed only now, only for a call that will actually query, and held
      // in this closure alone: not logged, not returned, not cached.
      const client = deps.scopedClient(await deps.signToken(userId, keyId));

      // Same per-request resolution chat/index.ts does, through the same
      // RLS-scoped client, with the same fail-open-to-'all' default.
      const { data: dataModeResult, error: dataModeErr } = await client.rpc("current_data_mode");
      if (dataModeErr) console.error("mcp: could not resolve caller data_mode", dataModeErr.message);
      const dataMode = dataModeResult || "all";
      const domainReality = await deps.fetchDomainReality(client);

      const result = await deps.runTool(client, name, args as Record<string, unknown>, dataMode, domainReality);
      await log(result.isError);
      return { content: [{ type: "text", text: result.content }], isError: result.isError };
    });

    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await server.connect(transport);
    return await transport.handleRequest(req);
  };
}
