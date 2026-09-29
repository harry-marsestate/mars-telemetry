// How @supabase/server's withSupabase() treats auth modes against
// SUPABASE_SECRET_KEYS, with the library itself (not a re-implementation).
//   npx deno test --no-lock --allow-env --allow-net=127.0.0.1 tests/secret-auth-mode.test.ts
import { assertEquals } from "jsr:@std/assert@1";
import { withSupabase } from "npm:@supabase/server@^1";

Deno.env.set("SUPABASE_URL", "http://127.0.0.1:9");
Deno.env.set("SUPABASE_SECRET_KEYS", JSON.stringify({ default: "sb_secret_OLDKEY_default_xxxxxxxxxx", edge_functions_2026_09_29: "sb_secret_NEWKEY_rotated_xxxxxxxxxx" }));
Deno.env.set("SUPABASE_PUBLISHABLE_KEYS", JSON.stringify({ default: "sb_publishable_TESTTESTTEST" }));
Deno.env.set("SUPABASE_JWKS", JSON.stringify({ keys: [] }));

const call = async (auth: string[], apikey: string) => {
  const h = withSupabase({ auth: auth as never }, async () => Response.json({ ok: true }));
  const r = await h(new Request("http://x/", { method: "POST", headers: { apikey, "content-type": "application/json" }, body: "{}" }));
  await r.body?.cancel();
  return r.status;
};

Deno.test("bare 'secret' accepts only the key named default (why rotation 401'd)", async () => {
  assertEquals(await call(["secret"], "sb_secret_OLDKEY_default_xxxxxxxxxx"), 200);
  assertEquals(await call(["secret"], "sb_secret_NEWKEY_rotated_xxxxxxxxxx"), 401);
});

Deno.test("'secret:*' accepts any configured secret key, and nothing else", async () => {
  assertEquals(await call(["secret:*"], "sb_secret_OLDKEY_default_xxxxxxxxxx"), 200);
  assertEquals(await call(["secret:*"], "sb_secret_NEWKEY_rotated_xxxxxxxxxx"), 200);
  assertEquals(await call(["secret:*"], "sb_secret_UNKNOWN_xxxxxxxxxxxxxxxxxx"), 401);
  assertEquals(await call(["secret:*"], "sb_publishable_TESTTESTTEST"), 401);
});
