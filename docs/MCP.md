# mars-telemetry MCP gateway

Read-only MCP server that lets external agents query mars-telemetry lab, winery
and labour data **as a specific user, under that user's own RLS**. Design,
threat model and every verification result live in `docs/SECURITY.md` (the
"MCP" entries); this file is the how-to.

## What it is

| | |
|---|---|
| Endpoint | `https://wwdpunaefaiazsjamrkc.supabase.co/functions/v1/mcp` |
| Transport | MCP Streamable HTTP, stateless, JSON responses. `POST` only; `GET` (standalone SSE) -> `405` by design |
| Auth | `Authorization: Bearer mtk_<43 base64url chars>` -- a per-user API key from `agent_api_keys`. Not OAuth, not a Supabase key |
| Acts as | the key's owner: every query runs under their `auth.uid()` and RLS, as the SELECT-only `mcp_reader` role, in a read-only transaction |
| Tools | `get_berry_maturity`, `get_smoke_markers`, `get_wine_lab_results`, `get_lot_analyses`, `get_labour_summary` -- the chat tools, unchanged (`supabase/functions/chat/tools.ts`) |
| Not exposed | `get_series`, `get_derived_series`, `get_anomalies` (simulated-history risk), `get_vessels` (deferred). Calls to them are rejected (`-32602`) and audited |
| Data rules | real data only, no simulated fallback; derived values (totals, date ranges, coverage) computed server-side; empty results say so |
| Limits | 1,000 rows per query (same as the REST API), 10s statement timeout, keys expire (default 90 days) |

Only **approved operators/customers** can hold a working key. Operators see all
five tools' data; a customer's key returns zero rows for all five (they are
operator-only by RLS).

## Connecting a client

The key is a credential: keep it in the macOS Keychain, not in config files or
shell history.

**Claude Code** -- a project `.mcp.json` that reads the key from the
environment (the file itself contains no secret):

```json
{
  "mcpServers": {
    "mars-telemetry": {
      "type": "http",
      "url": "https://wwdpunaefaiazsjamrkc.supabase.co/functions/v1/mcp",
      "headers": { "Authorization": "Bearer ${MARS_TELEMETRY_MCP_KEY}" }
    }
  }
}
```

and in `~/.zshrc` (or wherever you launch agents from):

```zsh
export MARS_TELEMETRY_MCP_KEY="$(security find-generic-password -s mars-telemetry-mcp -a <your key prefix> -w 2>/dev/null)"
```

Then run `claude` in that project once to approve the server. Avoid
`claude mcp add ... --header "Authorization: Bearer mtk_..."`: it writes the key
into `~/.claude.json` in plaintext.

**Any MCP SDK** (TypeScript shown; verified live against this endpoint):

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
const transport = new StreamableHTTPClientTransport(
  new URL("https://wwdpunaefaiazsjamrkc.supabase.co/functions/v1/mcp"),
  { requestInit: { headers: { Authorization: `Bearer ${process.env.MARS_TELEMETRY_MCP_KEY}` } } },
);
const client = new Client({ name: "my-agent", version: "1.0.0" });
await client.connect(transport);
console.log(await client.callTool({ name: "get_berry_maturity", arguments: { vintage: 2026 } }));
```

**claude.ai custom connectors / ChatGPT connectors** need OAuth and will not
work with a static bearer key -- see the O1/OAuth design in `docs/SECURITY.md`.

## Keys (`scripts/agent-keys.mjs`, run by the owner against `DATABASE_URL`)

```zsh
cd scripts && npm install && cd ..          # once
node scripts/agent-keys.mjs issue  --user <uuid> --label "<who/what>" --keychain [--days 90]
node scripts/agent-keys.mjs list             # prefixes, owners, last used, expiry, state
node scripts/agent-keys.mjs revoke --id <key uuid>
node scripts/agent-keys.mjs calls  --limit 20   # audit log
```

- Run `issue` in **your own terminal**, not through an assistant's shell: the
  plaintext prints once. `--keychain` also stores it for the verification
  harness and the zsh snippet above.
- Labels get `[user <first 8 of uuid>]` appended automatically.
- Revocation takes effect on the very next request (nothing is cached).
- A key whose owner is demoted, suspended, or no longer approved stops working
  immediately -- RLS follows the owner's live profile.
- Keys expire (default 90 days, max 365). `list` shows each expiry; re-issue
  before then.

## Operations

**Rotate the gateway's database password** (`mcp_gateway` role +
`MCP_GATEWAY_DB_URL` secret, together, without exposing the value):

```zsh
node scripts/rotate-gateway-password.mjs
supabase functions deploy mcp --use-api --project-ref wwdpunaefaiazsjamrkc
```

The script sends Postgres only a SCRAM verifier (no plaintext in server logs)
and proves the new password through the pooler before updating the secret.
The pooler caches credentials for a few seconds after a change -- the script
retries; a manual rotation can see `password authentication failed` briefly.

**Verify** (read-only unless `--revoke-prefix` is passed, which revokes that key):

```zsh
node scripts/check-mcp-boundaries.mjs        # static: allowlists, no RLS-bypassing credential
node scripts/mcp-verify.mjs                  # live: storage, role boundaries, both keys x 5 tools, negatives, audit
npx deno test --no-lock --config supabase/functions/mcp/deno.json tests/mcp-handler.test.ts tests/mcp-adapter.test.ts
```

**Troubleshooting**

| Symptom | Meaning |
|---|---|
| `401 Unauthorized` | key missing, malformed, unknown, revoked, expired, or owner not approved -- deliberately indistinguishable |
| `500 "Authentication backend unavailable"` | the function can't reach Postgres as `mcp_gateway`. Check the function log (Dashboard -> Edge Functions -> mcp -> Logs; the Supabase CLI has no `functions logs` command): `password authentication failed` = secret/role password mismatch |
| tool result `Tool execution failed unexpectedly.` | the scoped transaction failed (connection, timeout, or the read-only/role assertion) -- see the function log |
| tool result with 0 rows + a coverage note | genuinely no data for that scope, or the key's owner isn't an operator |

## Adding a tool later

Deliberate, reviewed work -- not a config change: add it to `MCP_TOOLS` in
`supabase/functions/mcp/allowlist.ts`, add every relation it reads to the
allowlist **and** to `mcp_reader`'s grants in a new migration (the boundary
check fails if the two disagree), extend `adapter.ts` if it uses a builder call
not yet supported (it throws rather than guess), add it to the parity test
inputs, and re-run parity against the live REST API.
