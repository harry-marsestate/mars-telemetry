// Key parsing, hashing, and per-request access-token signing for the MCP
// function. Dependency-free (WebCrypto only) so the signing path is small
// enough to read in full and to verify independently in tests.

// scripts/agent-keys.mjs issues "mtk_" + base64url(32 random bytes) = 43 chars.
const KEY_PATTERN = /^mtk_[A-Za-z0-9_-]{43}$/;

export const TOKEN_TTL_SECONDS = 60;

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

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Signs a 60-second HS256 access token for ONE user, in the shape PostgREST
// accepts from a normal Supabase Auth session. `role` is hard-coded to
// 'authenticated' and `sub` is only ever the user_id mcp_authenticate()
// returned -- nothing caller-supplied reaches the claims. The caller must
// hold the result in memory for a single request only: never log it, never
// return it, never cache it (docs/SECURITY.md, MCP entry).
export async function signAccessToken(
  secret: string,
  supabaseUrl: string,
  userId: string,
  keyId: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    iss: `${supabaseUrl}/auth/v1`,
    sub: userId,
    aud: "authenticated",
    role: "authenticated",
    iat: nowSeconds,
    exp: nowSeconds + TOKEN_TTL_SECONDS,
    is_anonymous: false,
    app_metadata: { provider: "mcp_api_key" },
    mcp_key_id: keyId,
  };
  const enc = new TextEncoder();
  const signingInput = `${base64url(enc.encode(JSON.stringify(header)))}.${base64url(enc.encode(JSON.stringify(payload)))}`;
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(signingInput)));
  return `${signingInput}.${base64url(signature)}`;
}
