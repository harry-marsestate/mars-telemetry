// Key parsing and hashing for the MCP function. Dependency-free (WebCrypto).
// No token signing exists anywhere in this function (revised auth, Option B').

// scripts/agent-keys.mjs issues "mtk_" + base64url(32 random bytes) = 43 chars.
const KEY_PATTERN = /^mtk_[A-Za-z0-9_-]{43}$/;

// Returns the API key from `Authorization: Bearer mtk_...`, or null for a
// missing header, another scheme, or anything not shaped like an issued key.
// A malformed key never reaches the database.
export function parseBearerKey(header: string | null): string | null {
  if (!header) return null;
  const match = header.match(/^Bearer\s+(\S+)\s*$/i);
  if (!match) return null;
  return KEY_PATTERN.test(match[1]) ? match[1] : null;
}

// Lowercase hex SHA-256 -- the exact form mcp_authenticate()/mcp_log_call()
// accept (they decode it to the bytea stored in agent_api_keys.key_hash).
export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
