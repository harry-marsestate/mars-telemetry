import type { Query } from "./adapter.ts";

// Runs one tools/call as the API key's real owner, under their own RLS, in a
// single READ ONLY transaction on the mcp_gateway connection:
//
//   begin;
//   set transaction read only;                         -- no write can succeed, whatever is called
//   set local statement_timeout = '10s';
//   select set_config('request.jwt.claims', {sub: <owner uid>, ...}, true);   -- auth.uid() resolves
//   set local role mcp_reader;                         -- SELECT-only on the allowlist; RLS applies
//   <assert current_user = mcp_reader and claims.sub = owner>
//   <the tool's queries>
//   commit;
//
// Everything is transaction-local (SET LOCAL / set_config(..., true)), so
// nothing survives onto the pooled Supavisor connection -- the rule
// docs/SECURITY.md's "Adversarial `set role` leaks across the transaction
// pooler" entry established. The same shape as @supabase/server's
// Postgres-client middleware, written out here because that helper only
// accepts the `authenticated`/`anon` roles, and mcp_reader is deliberately
// neither.

export interface Tx {
  unsafe(text: string, params?: unknown[]): Promise<Record<string, unknown>[]>;
}
export interface Sql {
  begin<T>(fn: (tx: Tx) => Promise<T>): Promise<T>;
}

export async function runAsKeyOwner<T>(sql: Sql, userId: string, keyId: string, fn: (query: Query) => Promise<T>): Promise<T> {
  return await sql.begin(async (tx) => {
    await tx.unsafe("set transaction read only");
    await tx.unsafe("set local statement_timeout = '10s'");
    await tx.unsafe("select set_config('request.jwt.claims', $1, true)", [
      JSON.stringify({ sub: userId, role: "mcp_reader", mcp_key_id: keyId }),
    ]);
    await tx.unsafe("set local role mcp_reader");
    const [who] = await tx.unsafe(
      "select current_user as role, current_setting('request.jwt.claims', true)::json->>'sub' as sub, current_setting('transaction_read_only') as ro",
    );
    if (who?.role !== "mcp_reader" || who?.sub !== userId || who?.ro !== "on") {
      throw new Error("mcp gateway: transaction scope assertion failed");
    }
    return await fn((text, params) => tx.unsafe(text, params));
  });
}
