// A PostgREST-compatible query builder over a direct Postgres transaction --
// just the subset of the supabase-js API that chat/tools.ts's five round-one
// tools actually call, so their runTool() code runs UNCHANGED against the
// read-only mcp_reader transaction instead of PostgREST.
//
// Fidelity rules (each checked by scripts/mcp-parity.mjs against the live
// REST API through a real operator browser session):
//   - JSON is produced by Postgres itself (`json_agg` over the select
//     subquery), exactly as PostgREST builds its response, so numeric,
//     timestamptz, date and null encodings are Postgres's own -- never
//     re-encoded in JS.
//   - Filter values are sent as text and cast to the column's catalog type,
//     matching PostgREST's untyped-literal coercion (e.g. gte('recorded_at',
//     '2026-01-01') compares as timestamptz, not text).
//   - `ilike` treats `*` as `%`, as PostgREST does.
//   - Every read is capped at MAX_ROWS, PostgREST's db-max-rows: an explicit
//     .limit() can lower it, never raise it.
//   - maybeSingle(): 0 rows -> null, 1 -> the row, >1 -> PGRST116 error, as
//     postgrest-js does.
//   - Errors come back as { data: null, error: { message, code, details,
//     hint } }, never thrown -- tools.ts checks `error`.
//
// Anything outside this subset throws: a new builder method in tools.ts
// must be added here deliberately (and to the parity test), not silently
// mis-translated.
import { RPCS, TABLES_AND_VIEWS } from "./allowlist.ts";

// PostgREST's db-max-rows for this project. The parity test asserts the
// live REST API caps at exactly this.
export const MAX_ROWS = 1000;

export type Query = (text: string, params: unknown[]) => Promise<Record<string, unknown>[]>;

export interface PgrstError {
  message: string;
  code: string | null;
  details: string | null;
  hint: string | null;
}
export interface PgrstResult {
  data: unknown;
  error: PgrstError | null;
}

const IDENT = /^[a-z_][a-z0-9_]*$/;
const SELECT_ITEM = /^([a-z_][a-z0-9_]*)(?:::([a-z_][a-z0-9_ ]*))?$/;
// format_type() output we accept as a cast target: names, spaces, (n,m), [].
const CATALOG_TYPE = /^[a-z_][a-z0-9_ ]*(\(\d+(,\d+)?\))?(\[\])?$/;

type Filter =
  | { op: "eq" | "gte" | "lte"; col: string; value: unknown }
  | { op: "ilike"; col: string; value: string }
  | { op: "in"; col: string; values: unknown[] }
  | { op: "not_in"; col: string; values: string[] };

function pgError(err: unknown): PgrstError {
  const e = err as { message?: string; code?: string; detail?: string; hint?: string };
  return { message: e?.message ?? String(err), code: e?.code ?? null, details: e?.detail ?? null, hint: e?.hint ?? null };
}

function unsupported(what: string): never {
  throw new Error(`mcp adapter: unsupported ${what} -- add it to adapter.ts and the parity test deliberately`);
}

// PostgREST list syntax as supabase-js's .not(col, "in", ...) passes it:
// `("A","B")` or `(A,B)`. Double-quoted items may contain commas and \" / \\.
export function parsePostgrestList(raw: string): string[] {
  const s = raw.trim();
  if (!s.startsWith("(") || !s.endsWith(")")) unsupported(`in-list syntax ${raw}`);
  const body = s.slice(1, -1);
  const out: string[] = [];
  let i = 0;
  while (i < body.length) {
    if (body[i] === '"') {
      let v = "";
      i++;
      while (i < body.length && body[i] !== '"') {
        if (body[i] === "\\" && i + 1 < body.length) i++;
        v += body[i++];
      }
      i++; // closing quote
      out.push(v);
      if (body[i] === ",") i++;
    } else {
      const end = body.indexOf(",", i);
      out.push(body.slice(i, end === -1 ? undefined : end).trim());
      i = end === -1 ? body.length : end + 1;
    }
  }
  return out;
}

class SelectBuilder implements PromiseLike<PgrstResult> {
  private columns: { name: string; cast?: string }[] = [];
  private filters: Filter[] = [];
  private orders: { col: string; asc: boolean }[] = [];
  private rowLimit: number | null = null;
  private single = false;

  private readonly adapter: PostgrestAdapter;
  private readonly relation: string;

  constructor(adapter: PostgrestAdapter, relation: string) {
    this.adapter = adapter;
    this.relation = relation;
  }

  select(cols: string): this {
    this.columns = cols.split(",").map((c) => {
      const m = c.trim().match(SELECT_ITEM);
      if (!m) unsupported(`select item '${c.trim()}'`);
      return { name: m[1], cast: m[2] };
    });
    return this;
  }
  eq(col: string, value: unknown): this { this.filters.push({ op: "eq", col, value }); return this; }
  gte(col: string, value: unknown): this { this.filters.push({ op: "gte", col, value }); return this; }
  lte(col: string, value: unknown): this { this.filters.push({ op: "lte", col, value }); return this; }
  ilike(col: string, pattern: string): this { this.filters.push({ op: "ilike", col, value: pattern }); return this; }
  in(col: string, values: unknown[]): this { this.filters.push({ op: "in", col, values }); return this; }
  not(col: string, operator: string, value: string): this {
    if (operator !== "in") unsupported(`not(${operator})`);
    this.filters.push({ op: "not_in", col, values: parsePostgrestList(value) });
    return this;
  }
  order(col: string, opts?: { ascending?: boolean; nullsFirst?: boolean; foreignTable?: string; referencedTable?: string }): this {
    if (opts && (opts.nullsFirst !== undefined || opts.foreignTable || opts.referencedTable)) unsupported("order option");
    this.orders.push({ col, asc: opts?.ascending ?? true });
    return this;
  }
  limit(n: number): this {
    if (!Number.isInteger(n) || n < 0) unsupported(`limit(${n})`);
    this.rowLimit = n;
    return this;
  }
  maybeSingle(): this { this.single = true; return this; }

  then<A = PgrstResult, B = never>(onfulfilled?: ((v: PgrstResult) => A | PromiseLike<A>) | null, onrejected?: ((r: unknown) => B | PromiseLike<B>) | null): PromiseLike<A | B> {
    return this.execute().then(onfulfilled, onrejected);
  }

  private async execute(): Promise<PgrstResult> {
    if (this.columns.length === 0) unsupported("from() without select()");
    try {
      const types = await this.adapter.columnTypes(this.relation);
      const typeOf = (col: string): string => {
        const t = types.get(col);
        if (!t) throw Object.assign(new Error(`column ${this.relation}.${col} does not exist`), { code: "42703" });
        if (!CATALOG_TYPE.test(t)) throw new Error(`mcp adapter: unexpected column type '${t}'`);
        return t;
      };
      const ident = (col: string) => {
        if (!IDENT.test(col)) unsupported(`identifier '${col}'`);
        return `"${col}"`;
      };

      const params: unknown[] = [];
      const p = (v: unknown) => { params.push(v); return `$${params.length}`; };
      const where = this.filters.map((f) => {
        const c = ident(f.col);
        switch (f.op) {
          case "eq": return `${c} = ${p(String(f.value))}::${typeOf(f.col)}`;
          case "gte": return `${c} >= ${p(String(f.value))}::${typeOf(f.col)}`;
          case "lte": return `${c} <= ${p(String(f.value))}::${typeOf(f.col)}`;
          case "ilike": typeOf(f.col); return `${c} ilike ${p(f.value.replace(/\*/g, "%"))}`;
          case "in": return `${c} = any(${p(f.values.map(String))}::${typeOf(f.col)}[])`;
          case "not_in": return `not (${c} = any(${p(f.values)}::${typeOf(f.col)}[]))`;
        }
      });
      const select = this.columns.map(({ name, cast }) => {
        typeOf(name);
        return cast ? `${ident(name)}::${cast} as ${ident(name)}` : ident(name);
      }).join(", ");
      const order = this.orders.map((o) => { typeOf(o.col); return `${ident(o.col)} ${o.asc ? "asc" : "desc"}`; }).join(", ");
      const limit = Math.min(this.rowLimit ?? MAX_ROWS, MAX_ROWS);

      const inner = `select ${select} from public.${ident(this.relation)}` +
        (where.length ? ` where ${where.join(" and ")}` : "") +
        (order ? ` order by ${order}` : "") +
        ` limit ${limit}`;
      const rows = await this.adapter.query(`select coalesce(json_agg(t), '[]'::json)::text as body from (${inner}) t`, params);
      const data = JSON.parse(String(rows[0].body)) as unknown[];

      if (this.single) {
        if (data.length > 1) {
          return {
            data: null,
            error: {
              message: "JSON object requested, multiple (or no) rows returned",
              code: "PGRST116",
              details: `Results contain ${data.length} rows, application/vnd.pgrst.object+json requires 1 row`,
              hint: null,
            },
          };
        }
        return { data: data[0] ?? null, error: null };
      }
      return { data, error: null };
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("mcp adapter: unsupported")) throw err;
      return { data: null, error: pgError(err) };
    }
  }
}

export class PostgrestAdapter {
  private readonly types = new Map<string, Promise<Map<string, string>>>();
  readonly query: Query;

  // Plain fields, not TS parameter properties: scripts/mcp-parity.mjs loads
  // this file under Node's type stripping, which rejects those.
  constructor(query: Query) {
    this.query = query;
  }

  from(relation: string): SelectBuilder {
    if (!IDENT.test(relation) || !(relation in TABLES_AND_VIEWS)) {
      throw new Error(`mcp adapter: relation '${relation}' is not in the MCP allowlist`);
    }
    return new SelectBuilder(this, relation);
  }

  async rpc(name: string, params: Record<string, unknown> = {}): Promise<PgrstResult> {
    if (!(name in RPCS) || name === "mcp_authenticate" || name === "mcp_log_call") {
      throw new Error(`mcp adapter: rpc '${name}' is not callable from tool code`);
    }
    try {
      if (name === "current_data_mode") {
        if (Object.keys(params).length) unsupported("current_data_mode params");
        const rows = await this.query(`select to_json(public.current_data_mode())::text as body`, []);
        return { data: JSON.parse(String(rows[0].body)), error: null };
      }
      if (name === "domain_reality") {
        const v = params.p_vintages;
        if (!Array.isArray(v) || !v.every(Number.isInteger) || Object.keys(params).length !== 1) unsupported("domain_reality params");
        const rows = await this.query(
          `select coalesce(json_agg(t), '[]'::json)::text as body from (select * from public.domain_reality($1::int[]) limit ${MAX_ROWS}) t`,
          [v.map(String)],
        );
        return { data: JSON.parse(String(rows[0].body)), error: null };
      }
      return unsupported(`rpc ${name}`);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("mcp adapter: unsupported")) throw err;
      return { data: null, error: pgError(err) };
    }
  }

  // Catalog column types, once per relation per adapter (i.e. per transaction).
  columnTypes(relation: string): Promise<Map<string, string>> {
    let cached = this.types.get(relation);
    if (!cached) {
      cached = this.query(
        `select a.attname as name, format_type(a.atttypid, a.atttypmod) as type
           from pg_attribute a
          where a.attrelid = to_regclass($1) and a.attnum > 0 and not a.attisdropped`,
        [`public.${relation}`],
      ).then((rows) => new Map(rows.map((r) => [String(r.name), String(r.type)])));
      this.types.set(relation, cached);
    }
    return cached;
  }
}
