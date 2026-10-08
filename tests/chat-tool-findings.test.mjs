// Regression tests for Colin's 5 Oct 2026 agentic-test findings against the
// chat tools (docs/SECURITY.md, "Chat tool findings"), one or more per
// confirmed item, through runTool() with a fake supabase client that applies
// the builder filters to fixture rows (so a wrong bound or a wrong case
// actually changes what comes back, as it did in production).
//
//   node --test tests/chat-tool-findings.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runTool, TOOLS, setToolClockForTests } from "../supabase/functions/chat/tools.ts";
import { analyteFamily, ANSWER_RULES, describeChange, pacificMidnightUtc, resolveDateBounds } from "../supabase/functions/chat/query-rules.ts";

setToolClockForTests(() => new Date("2026-10-07T12:00:00Z"));

// ── fake client ─────────────────────────────────────────────────────────
const cmp = (a, b) => {
  const da = Date.parse(a), dbb = Date.parse(b);
  return typeof a === "string" && /^\d{4}-\d{2}-\d{2}/.test(a) && !Number.isNaN(da) && !Number.isNaN(dbb) ? da - dbb : a < b ? -1 : a > b ? 1 : 0;
};
function fake(tables = {}, rpcs = {}) {
  const calls = [];
  return {
    calls,
    rpc(name, params) {
      calls.push(["rpc", name, params]);
      const r = rpcs[name];
      return Promise.resolve(r ? { data: typeof r === "function" ? r(params) : r, error: null } : { data: null, error: { message: `no rpc ${name}` } });
    },
    from(rel) {
      let rows = [...(tables[rel] ?? [])];
      let lim = Infinity;
      const orders = [];
      const q = {
        select(s) { calls.push(["select", rel, s]); return q; },
        eq(k, v) { calls.push(["eq", rel, k, v]); rows = rows.filter((r) => r[k] === v); return q; },
        gte(k, v) { calls.push(["gte", rel, k, v]); rows = rows.filter((r) => cmp(r[k], v) >= 0); return q; },
        lt(k, v) { calls.push(["lt", rel, k, v]); rows = rows.filter((r) => cmp(r[k], v) < 0); return q; },
        lte(k, v) { calls.push(["lte", rel, k, v]); rows = rows.filter((r) => cmp(r[k], v) <= 0); return q; },
        ilike(k, v) { calls.push(["ilike", rel, k, v]); const n = v.replace(/^%|%$/g, "").toLowerCase(); rows = rows.filter((r) => String(r[k] ?? "").toLowerCase().includes(n)); return q; },
        in(k, vs) { calls.push(["in", rel, k, vs]); rows = rows.filter((r) => vs.includes(r[k])); return q; },
        not(k, _op, list) { calls.push(["not", rel, k, list]); const vs = list.slice(1, -1).split(",").map((x) => x.replace(/"/g, "")); rows = rows.filter((r) => !vs.includes(r[k])); return q; },
        order(k, o) { orders.push([k, o?.ascending ?? true]); return q; },
        limit(n) { calls.push(["limit", rel, n]); lim = n; return q; },
        maybeSingle() { return Promise.resolve({ data: rows[0] ?? null, error: null }); },
        then(resolve) {
          for (const [k, asc] of [...orders].reverse()) rows.sort((a, b) => (asc ? 1 : -1) * cmp(a[k], b[k]));
          resolve({ data: rows.slice(0, lim), error: null });
        },
      };
      return q;
    },
  };
}
const run = (db, name, input) => runTool(db, name, input, "all", new Map());
const rowsOf = (r) => JSON.parse(r.content.slice(0, r.content.indexOf("\n\n") === -1 ? undefined : r.content.indexOf("\n\n")));
const desc = (name) => TOOLS.find((t) => t.name === name).description;

const lotScope = (over = {}) => ({ total: 0, lots: [], analysis_types: [], ets_samples: [], ...over });
const etsScope = (over = {}) => ({ samples: [], total: 0, analysis_codes: [], vineyard_samples: [], innovint_lots: [], ...over });
const sample = (id, no, d, type, vintage, collected_on, source = "inferred_from_receipt") =>
  ({ id, lab_sample_no: no, sample_description_raw: d, sample_type: type, vintage, collected_on, collected_on_source: source, fruit_source: null });
const result = (id, sample_id, code, raw, at, units = "% vol") =>
  ({ id, sample_id, analysis_name_raw: code.replace(/_/g, " "), analysis_code: code, result_raw: raw, result_numeric: Number(raw), result_operator: "=", units, analyzed_at: at });

// ── 1a. source selection ────────────────────────────────────────────────
test("1a: an InnoVint miss points at the ETS sample the identifier names, before asking the user", async () => {
  const db = fake({ lot_canonical_map: [], lot_analyses: [] }, {
    chat_lot_analyses_scope: lotScope({ ets_samples: [{ lab_sample_no: "310310429", sample_description_raw: "T-7 V-2 (fermenting)", sample_type: "ferment", block_id: "B2", vintage: 2023, collected_on: "2023-10-31", n_results: 2, analysis_codes: "ethanol_at_20c, glucose_fructose" }] }),
  });
  const r = await run(db, "get_lot_analyses", { lot_name: "T-7 V-2" });
  assert.equal(r.isError, false);
  assert.match(r.content, /No InnoVint lot matches lot_name "T-7 V-2", but ETS Labs holds 1 sample/);
  assert.match(r.content, /310310429 "T-7 V-2 \(fermenting\)" \(ferment, 2023, collected October 31, 2023; 2 result\(s\): ethanol_at_20c, glucose_fructose\)/);
  assert.match(r.content, /get_wine_lab_results with lab_sample_no for these before asking the user/);
  assert.deepEqual(db.calls.find((c) => c[0] === "rpc")[2].p_lot_name, "T-7 V-2");
});

test("1a: an ETS miss points at InnoVint lots and vineyard samples", async () => {
  const db = fake({}, {
    chat_ets_winery_scope: etsScope({
      vineyard_samples: [{ lab_sample_no: "609220727", sample_description_raw: "Mars 2 (berries)", sample_type: "berry_maturity", block_id: "B2", vintage: 2026, collected_on: "2026-09-22" }],
      innovint_lots: [{ lot_code: "MA22CS", lot_name: "Estate Blend", n: 120, first_at: "2022-10-03T07:00:00Z", last_at: "2024-06-28T00:30:00Z" }],
    }),
  });
  const r = await run(db, "get_wine_lab_results", { sample_description: "MA22CS" });
  assert.match(r.content, /No ETS winery sample matches sample_description "MA22CS"/);
  assert.match(r.content, /609220727 "Mars 2 \(berries\)" \(berry_maturity, B2, 2026, September 22, 2026\) -- call get_berry_maturity/);
  // last_at 2024-06-28T00:30Z is the evening of June 27 Pacific.
  assert.match(r.content, /MA22CS \(Estate Blend, 120 analyses, October 3, 2022 through June 27, 2024\) -- call get_lot_analyses/);
});

test("1a: the descriptions say which source holds what and point across", () => {
  assert.match(desc("get_lot_analyses"), /SOURCE: InnoVint only/);
  assert.match(desc("get_lot_analyses"), /ETS Labs results by lab sample number .* are in get_wine_lab_results/);
  assert.match(desc("get_wine_lab_results"), /SOURCE: ETS only -- InnoVint's own per-lot cellar analyses are in get_lot_analyses/);
  assert.match(desc("get_wine_lab_results"), /fermentation checks/);
});

// ── 1b. temperature variants ────────────────────────────────────────────
const MA24 = [sample(1, "602250939", "MA24CS", "wine", 2024, "2026-02-25"), sample(2, "411131659", "MA24CSV2", "wine", 2024, "2024-11-13")];
const MA24_RESULTS = [
  result(10, 1, "ethanol_at_20c", "15.22", "2026-02-25T15:39:00+00:00"), result(11, 1, "ethanol_at_60f", "15.14", "2026-02-25T15:56:00+00:00"),
  result(12, 2, "ethanol_at_20c", "14.85", "2024-11-13T10:00:00+00:00"), result(13, 2, "ethanol_at_60f", "14.77", "2024-11-13T10:00:00+00:00"),
];
test("1b: a request for ethanol at 20°C surfaces the 60°F variant, with values", async () => {
  const db = fake({ lab_results_current: MA24_RESULTS, ets_lot_analyses_reconciliation: [] }, {
    chat_ets_winery_scope: etsScope({ samples: MA24, total: 2, analysis_codes: [{ analysis_code: "ethanol_at_20c", n: 2 }, { analysis_code: "ethanol_at_60f", n: 2 }] }),
  });
  const r = await run(db, "get_wine_lab_results", { sample_description: "MA24CS", analysis_code: "Ethanol_At_20C " });
  assert.deepEqual(rowsOf(r).map((x) => x.analysis_code), ["ethanol_at_20c", "ethanol_at_20c"]);
  assert.match(r.content, /also on file for these samples at another reference temperature: ethanol_at_60f \(60°F, 2 result\(s\)\); ethanol_at_20c is 20°C/);
  assert.match(r.content, /602250939 MA24CS: ethanol at 60f 15\.14 % vol/);
  assert.equal(db.calls.find((c) => c[0] === "rpc")[2].p_analysis_code, "ethanol_at_20c");
  assert.match(desc("get_wine_lab_results"), /ethanol_at_20c AND ethanol_at_60f/);
});

test("1b: InnoVint variants (ethanol-20c / ethanol-60f / ethanol / alcohol) are listed too", async () => {
  const db = fake({ lot_canonical_map: [], lot_analyses: [] }, {
    chat_lot_analyses_scope: lotScope({ total: 0, analysis_types: [{ analysis_type: "ethanol-20c", n: 4 }, { analysis_type: "ethanol-60f", n: 3 }, { analysis_type: "brix", n: 90 }] }),
  });
  const r = await run(db, "get_lot_analyses", { lot_code: "MA24CSV3", analysis_type: "alcohol" });
  assert.match(r.content, /No "alcohol" rows match, but the same analyte is also on file .* "ethanol-20c" \(20°C, 4 row\(s\)\), "ethanol-60f" \(60°F, 3 row\(s\)\)/);
});

test("1b: analyte families group only real temperature variants, across every code in production", () => {
  const ets = JSON.parse(readFileSync(new URL("./fixtures/chat-analysis-codes.json", import.meta.url), "utf8"));
  const groups = new Map();
  for (const c of new Set([...ets.ets, ...ets.innovint])) groups.set(analyteFamily(c), [...(groups.get(analyteFamily(c)) ?? []), c]);
  const multi = [...groups.values()].filter((g) => g.length > 1);
  assert.deepEqual(multi, [["ethanol_at_20c", "ethanol_at_60f", "alcohol", "ethanol", "ethanol-20c", "ethanol-60f"]]);
});

// ── 2a. same-day date bounds ────────────────────────────────────────────
const MARCH = [sample(5, "608140601", "26MARCH", "must", 2026, "2026-08-14")];
const MARCH_RESULTS = Array.from({ length: 11 }, (_, i) => result(100 + i, 5, `code_${i}`, "1", `2026-08-14T${String(10 + i).padStart(2, "0")}:34:00+00:00`, "x"));
test("2a: ETS same-day bare dates cover the whole day: 11 rows, was 0 (wall-clock UTC bounds)", async () => {
  const db = fake({ lab_results_current: MARCH_RESULTS, ets_lot_analyses_reconciliation: [] }, { chat_ets_winery_scope: etsScope({ samples: MARCH, total: 11 }) });
  const r = await run(db, "get_wine_lab_results", { sample_description: "26MARCH", start_date: "2026-08-14", end_date: "2026-08-14" });
  assert.equal(rowsOf(r).length, 11);
  assert.ok(db.calls.some((c) => c[0] === "gte" && c[2] === "analyzed_at" && c[3] === "2026-08-14T00:00:00.000Z"));
  assert.ok(db.calls.some((c) => c[0] === "lt" && c[2] === "analyzed_at" && c[3] === "2026-08-15T00:00:00.000Z"));
  assert.ok(!db.calls.some((c) => c[0] === "lte"));
  const p = db.calls.find((c) => c[0] === "rpc")[2];
  assert.deepEqual([p.p_start, p.p_end_exclusive, p.p_end_inclusive], ["2026-08-14T00:00:00.000Z", "2026-08-15T00:00:00.000Z", null]);
  assert.match(r.content, /Effective interval: analyzed_at >= 2026-08-14T00:00:00.000Z and analyzed_at < 2026-08-15T00:00:00.000Z -- from the start of August 14, 2026 through the end of August 14, 2026/);
});

const MA22CS = Array.from({ length: 9 }, (_, i) => ({ lot_name: "Estate Blend", lot_code: "MA22CS", block_id: null, analysis_type: `t${i}`, value: 1, unit: "", recorded_at: "2024-05-01T07:00:00+00:00" }));
test("2a: InnoVint same-day bare dates are the Pacific day: 9 rows, was 0; PDT and PST offsets", async () => {
  const db = fake({ lot_canonical_map: [], lot_analyses: MA22CS }, { chat_lot_analyses_scope: lotScope({ total: 9, lots: [{ lot_code: "MA22CS", lot_name: "Estate Blend", n: 9, first_at: "2024-05-01T07:00:00Z", last_at: "2024-05-01T07:00:00Z" }] }) });
  const r = await run(db, "get_lot_analyses", { lot_code: "MA22CS", start_date: "2024-05-01", end_date: "2024-05-01", limit: 200 });
  assert.equal(rowsOf(r).length, 9);
  assert.match(r.content, /Effective interval: recorded_at >= 2024-05-01T07:00:00.000Z and recorded_at < 2024-05-02T07:00:00.000Z .* Pacific calendar days/);
  assert.equal(pacificMidnightUtc("2024-01-15"), "2024-01-15T08:00:00.000Z");
  assert.equal(pacificMidnightUtc("2026-03-08"), "2026-03-08T08:00:00.000Z", "DST starts at 02:00, midnight is still PST");
  assert.equal(pacificMidnightUtc("2026-11-01"), "2026-11-01T07:00:00.000Z", "DST ends at 02:00, midnight is still PDT");
});

test("2a: explicit timestamps are used as given; empty or invalid intervals are errors, not zero rows", async () => {
  const b = resolveDateBounds("recorded_at", "2024-05-01T00:00:00Z", "2024-05-01T23:59:59.999Z", "instant");
  assert.deepEqual([b.gte, b.lt, b.lte], ["2024-05-01T00:00:00.000Z", undefined, "2024-05-01T23:59:59.999Z"]);
  const db = fake({ lot_canonical_map: [] }, { chat_lot_analyses_scope: lotScope() });
  const reversed = await run(db, "get_lot_analyses", { lot_code: "MA22CS", start_date: "2026-08-15", end_date: "2026-08-13" });
  assert.equal(reversed.isError, true);
  assert.match(reversed.content, /is before start_date/);
  const invalid = await run(db, "get_wine_lab_results", { start_date: "not-a-date" });
  assert.equal(invalid.isError, true);
  assert.match(invalid.content, /start_date must be a calendar date 'YYYY-MM-DD'/);
});

test("2a: the same rule in get_derived_series and get_series", async () => {
  const days = [{ vintage: 2026, day: "2026-09-22T00:00:00+00:00", gdd_cumulative_calibrated: 2500, dtr_f: 30, vpd_kpa: 1, vpd_peak_kpa: 2, et0_in: 0.2 }];
  const db = fake({ daily_derived: days });
  const r = await run(db, "get_derived_series", { vintage: 2026, start_date: "2026-09-22", end_date: "2026-09-22" });
  assert.equal(rowsOf(r).length, 1);
  assert.ok(db.calls.some((c) => c[0] === "lt" && c[2] === "day" && c[3] === "2026-09-23T00:00:00.000Z"));
  const sdb = fake({}, { series_bucketed: [{ t: "2026-09-28T07:00:00+00:00", v: 20 }] });
  const s = await run(sdb, "get_series", { metric: "air_temp", block: "b2", start: "2026-09-28", end: "2026-09-28", bucket_hours: 24 });
  assert.equal(s.isError, false, s.content);
  const p = sdb.calls.find((c) => c[0] === "rpc")[2];
  assert.deepEqual([p.p_start, p.p_end, p.p_block], ["2026-09-28T07:00:00.000Z", "2026-09-29T06:59:59.999Z", "B2"]);
});

// ── 2b. exact lab-sample lookup ─────────────────────────────────────────
test("2b: get_wine_lab_results looks a sample up by lab_sample_no (and lot_code)", async () => {
  const db = fake({ lab_results_current: MARCH_RESULTS, ets_lot_analyses_reconciliation: [] }, { chat_ets_winery_scope: etsScope({ samples: MARCH, total: 11 }) });
  const r = await run(db, "get_wine_lab_results", { lab_sample_no: " 608140601 ", lot_code: "26march" });
  assert.equal(rowsOf(r).length, 11);
  const p = db.calls.find((c) => c[0] === "rpc")[2];
  assert.deepEqual([p.p_lab_sample_no, p.p_lot_code], ["608140601", "26MARCH"]);
  assert.ok(db.calls.some((c) => c[0] === "in" && c[1] === "lab_results_current" && c[2] === "sample_id" && c[3].join() === "5"));
});

test("2b: an unknown argument is an error in-app too, never silently unfiltered", async () => {
  const r = await run(fake(), "get_lot_analyses", { lab_sample_no: "608140601" });
  assert.equal(r.isError, true);
  assert.match(r.content, /Unknown argument for get_lot_analyses: lab_sample_no\. Valid arguments: lot_code, lot_name/);
});

// ── 2c. case and whitespace ─────────────────────────────────────────────
test("2c: block ids, lot codes, analysis types/codes and vessel types are normalised to their stored case", async () => {
  const smoke = [{ id: 1, lab_sample_no: "508260303", sample_description_raw: "x", sample_type: "berry_smoke", block_id: "B2", vintage: 2025, collected_on: "2025-08-26", collected_on_source: "inferred_from_receipt" }];
  const smokeResults = Array.from({ length: 30 }, (_, i) => ({ sample_id: 1, analysis_name_raw: "guaiacol", analysis_code: "guaiacol", result_raw: "<1", result_numeric: 1, result_operator: "<", units: "µg/kg", analyzed_at: `2025-08-27T12:${String(i).padStart(2, "0")}:00Z` }));
  const s = await run(fake({ lab_samples_current: smoke, lab_results_current: smokeResults }), "get_smoke_markers", { vintage: 2025, block_id: " b2 " });
  assert.equal(rowsOf(s).length, 30, "was 0 for 'b2' vs 30 for 'B2'");

  const berry = [{ block_id: "B2", collected_on: "2026-08-25", vintage: 2026, brix: 23 }];
  const b = await run(fake({ berry_maturity_by_block: berry, lab_samples_current: [] }), "get_berry_maturity", { vintage: 2026, block_id: "b2" });
  assert.equal(rowsOf(b).length, 1);

  const lots = [{ lot_name: "x", lot_code: "MA24CSV3", block_id: null, analysis_type: "brix", value: 20, unit: "Brix", recorded_at: "2024-10-02T18:00:00Z" }];
  const ldb = fake({ lot_canonical_map: [], lot_analyses: lots }, { chat_lot_analyses_scope: lotScope({ total: 1 }) });
  const l = await run(ldb, "get_lot_analyses", { lot_code: " ma24csv3 ", analysis_type: "Brix" });
  assert.equal(rowsOf(l).length, 1);
  assert.deepEqual([ldb.calls.find((c) => c[0] === "rpc")[2].p_lot_code, ldb.calls.find((c) => c[0] === "rpc")[2].p_analysis_type], ["MA24CSV3", "brix"]);

  const v = await run(fake({ vessels: [{ code: "T1", vessel_type: "tank", archived: false }] }), "get_vessels", { vessel_type: "Tank" });
  assert.equal(rowsOf(v).length, 1);
});

// ── 3a. coverage computed in full; capped scans say so ──────────────────
test("3a: lot date ranges and totals come from the database scope, not a capped row scan", async () => {
  const shown = [
    { lot_name: "2024 Cabernet Sauvignon, V3", lot_code: "MA24CSV3", block_id: null, analysis_type: "brix", value: 0, unit: "Brix", recorded_at: "2025-03-27T18:00:00Z" },
    { lot_name: "2024 Cabernet Sauvignon, V3", lot_code: "MA24CSV3", block_id: null, analysis_type: "brix", value: 1, unit: "Brix", recorded_at: "2025-03-26T18:00:00Z" },
  ];
  const db = fake({ lot_canonical_map: [], lot_analyses: shown }, {
    chat_lot_analyses_scope: lotScope({ total: 1302, lots: [{ lot_code: "MA24CSV3", lot_name: "2024 Cabernet Sauvignon, V3", n: 1302, first_at: "2024-10-01T07:00:00+00:00", last_at: "2026-02-03T08:00:00+00:00" }] }),
  });
  const r = await run(db, "get_lot_analyses", { lot_code: "MA24CSV3", limit: 2 });
  assert.match(r.content, /MA24CSV3 lab-analysis date range across every matching row \(1302, computed in the database\): October 1, 2024 through February 3, 2026/);
  assert.match(r.content, /returned 2 of 1302 matching row\(s\), most recent first; truncated: true/);
  // The old scope scan -- an unordered .limit(1000) read of lot_analyses -- is gone.
  assert.ok(!db.calls.some((c) => c[0] === "select" && c[1] === "lot_analyses" && c[2] === "lot_code, lot_name, recorded_at"));
  assert.ok(!db.calls.some((c) => c[0] === "limit" && c[1] === "lot_analyses" && c[2] === 1000));
});

test("3a: a coverage scan that reaches the 1000-row cap reports itself INCOMPLETE", async () => {
  const many = Array.from({ length: 1000 }, (_, i) => ({ block_id: "B2", collected_on: `2026-08-25`, vintage: 2026, brix: i }));
  const r = await run(fake({ berry_maturity_by_block: many, lab_samples_current: [] }), "get_berry_maturity", {});
  assert.match(r.content, /INCOMPLETE: the coverage scan reached the 1000-row cap/);
  const v = await run(fake({ vessels: Array.from({ length: 1000 }, (_, i) => ({ code: `T${i}`, archived: false })) }), "get_vessels", {});
  assert.match(v.content, /returned 500 of at least 1000 .* truncated: true/);
  const few = await run(fake({ vessels: Array.from({ length: 241 }, (_, i) => ({ code: `T${i}`, archived: false })) }), "get_vessels", {});
  assert.match(few.content, /returned 241 of 241 matching vessel\(s\); truncated: false/);
});

// ── 3b. no hard-coded counts in descriptions ────────────────────────────
test("3b: tool descriptions carry no data counts that drift; coverage is computed", async () => {
  const all = TOOLS.map((t) => t.description).join("\n");
  for (const re of [/four collection dates/i, /exactly ONE collection date/i, /two berry-mass/i, /\bTwo rows\b/, /\(8 months\)/, /full Jan-Dec/]) {
    assert.doesNotMatch(all, re);
  }
  const dates = ["2026-08-25", "2026-09-01", "2026-09-08", "2026-09-15", "2026-09-22", "2026-09-30"];
  const rows = dates.map((d, i) => ({ block_id: "B2", collected_on: d, vintage: 2026, brix: 23 + i, ph: 3.3, titratable_acidity: 7, l_malic_acid: 2, glucose_fructose: 200, berry_weight_g: 1, berry_volume_ml: 1, berry_volume_variability_pct: 30, sugar_per_berry_mg: 200 }));
  const r = await run(fake({ berry_maturity_by_block: rows, lab_samples_current: [] }), "get_berry_maturity", { vintage: 2026, block_id: "B2" });
  assert.match(r.content, /2026: full nine-analyte panel across 6 collection dates \(August 25, 2026, .*September 30, 2026\)/);
});

// ── 4. provenance ───────────────────────────────────────────────────────
test("4: berry rows carry lab_sample_no and whether the date was recorded or inferred; so do ETS winery rows", async () => {
  const db = fake({ berry_maturity_by_block: [{ block_id: "B2", collected_on: "2026-09-22", vintage: 2026, brix: 25.4, lab_sample_no: "609220727", collected_on_source: "inferred_from_receipt", collected_on_inferred: true }], lab_samples_current: [] });
  const r = await run(db, "get_berry_maturity", { vintage: 2026 });
  const sel = db.calls.find((c) => c[0] === "select" && c[1] === "berry_maturity_by_block")[2];
  assert.match(sel, /lab_sample_no, collected_on_source, collected_on_inferred$/);
  assert.deepEqual(rowsOf(r)[0].lab_sample_no, "609220727");
  assert.match(r.content, /collected_on_inferred=true means the collection date was inferred/);
  const w = await run(fake({ lab_results_current: MA24_RESULTS, ets_lot_analyses_reconciliation: [] }, { chat_ets_winery_scope: etsScope({ samples: MA24, total: 4 }) }), "get_wine_lab_results", { sample_description: "MA24CS" });
  assert.deepEqual(rowsOf(w).map((x) => [x.lab_sample_no, x.collected_on_source, x.collected_on_inferred])[0], ["602250939", "inferred_from_receipt", true]);
});

// ── 5. answer support ───────────────────────────────────────────────────
test("5: rates are computed server-side -- 2.4 Brix over 28 days is +0.086/day, not ~0.3", async () => {
  const series = [["2026-08-25", 23, 8.2], ["2026-09-01", 23.6, 7.3], ["2026-09-08", 23.9, 7], ["2026-09-15", 24.8, 7.5], ["2026-09-22", 25.4, 6.1]];
  const rows = series.map(([d, brix, ta]) => ({ block_id: "B2", collected_on: d, vintage: 2026, brix, titratable_acidity: ta }));
  const r = await run(fake({ berry_maturity_by_block: rows, lab_samples_current: [] }), "get_berry_maturity", { vintage: 2026, block_id: "B2" });
  assert.match(r.content, /B2 2026 brix: 23 \(August 25, 2026\) -> 25\.4 \(September 22, 2026\): \+2\.4 Brix over 28 days = \+0\.086 Brix\/day/);
  assert.match(r.content, /September 8, 2026 -> September 15, 2026 \+0\.9 Brix over 7 days = \+0\.129 Brix\/day/);
  // The deployed assistant said "TA 8.2 -> 7.5 over the window"; the window ends at 6.1.
  assert.match(r.content, /B2 2026 titratable acidity: 8\.2 \(August 25, 2026\) -> 6\.1 \(September 22, 2026\): -2\.1 g\/L over 28 days = -0\.075 g\/L\/day/);
  assert.equal(describeChange([{ date: "2026-08-25", value: 23 }, { date: "2026-09-22", value: 25.4 }], "", false), "23 (August 25, 2026) -> 25.4 (September 22, 2026): +2.4 over 28 days = +0.086/day");
});

test("5: GDD gained per period comes from the tool (the assistant said +81; the week gained +73.9)", async () => {
  const days = [["2026-09-01", 2194.4], ["2026-09-08", 2268.3]].map(([d, g]) => ({ vintage: 2026, day: `${d}T00:00:00+00:00`, gdd_cumulative_calibrated: g, dtr_f: 30, vpd_kpa: 1, vpd_peak_kpa: 2, et0_in: 0.2 }));
  const r = await run(fake({ daily_derived: days }), "get_derived_series", { vintage: 2026, start_date: "2026-09-01", end_date: "2026-09-08" });
  assert.match(r.content, /GDD \(calibrated\) 2194\.4 on September 1, 2026 -> 2268\.3 on September 8, 2026: \+73\.9 over 7 days = \+10\.6\/day/);
});

test("5: the no-causal-claims rule is in the system prompt and the MCP instructions", () => {
  assert.match(ANSWER_RULES, /No causal explanations \(weather, irrigation, cellar or vineyard actions, or anything else\) unless a tool result in this conversation contains the supporting event/);
  assert.match(ANSWER_RULES, /Never compute a rate, difference, average or total yourself/);
  const index = readFileSync(new URL("../supabase/functions/chat/index.ts", import.meta.url), "utf8");
  assert.match(index, /\$\{ANSWER_RULES\}/);
  assert.match(index, /a number you derive yourself \(a rate, difference, average or total\) did not come from a tool call/);
  const handler = readFileSync(new URL("../supabase/functions/mcp/handler.ts", import.meta.url), "utf8");
  assert.match(handler, /instructions: ANSWER_RULES/);
});

// ── pagination / truncation ─────────────────────────────────────────────
test("pagination: get_wine_lab_results states the exact total and a truncated flag", async () => {
  const many = Array.from({ length: 250 }, (_, i) => result(1000 + i, 5, "ph", "3.5", new Date(Date.UTC(2026, 7, 14, 0, i)).toISOString(), ""));
  const db = fake({ lab_results_current: many, ets_lot_analyses_reconciliation: [] }, { chat_ets_winery_scope: etsScope({ samples: MARCH, total: 250 }) });
  const r = await run(db, "get_wine_lab_results", { lab_sample_no: "608140601" });
  assert.equal(rowsOf(r).length, 100);
  assert.match(r.content, /returned 100 of 250 matching result\(s\), most recent first; truncated: true/);
});

test("lot readings are labelled by their Pacific date (a 5 pm PDT reading is not 'the next day')", async () => {
  const rows = [
    { lot_name: "x", lot_code: "MA22CS", block_id: null, analysis_type: "ph", value: 3.6, unit: "", recorded_at: "2024-05-02T00:00:00+00:00" },
    { lot_name: "x", lot_code: "MA22CS", block_id: null, analysis_type: "ph", value: 3.5, unit: "", recorded_at: "2024-05-01T07:00:00+00:00" },
  ];
  const r = await run(fake({ lot_canonical_map: [], lot_analyses: rows }, { chat_lot_analyses_scope: lotScope({ total: 2, lots: [{ lot_code: "MA22CS", lot_name: "x", n: 2, first_at: "2024-05-01T07:00:00Z", last_at: "2024-05-02T00:00:00Z" }] }) }), "get_lot_analyses", { lot_code: "MA22CS" });
  assert.deepEqual(rowsOf(r).map((x) => x.recorded_on_pacific), ["2024-05-01", "2024-05-01"]);
  assert.match(r.content, /MA22CS ph on May 1, 2024 has 2 readings \(3\.6, 3\.5\)/);
  // One Pacific day, so no first-to-last change; under UTC labels it was two days.
  assert.match(r.content, /date range across every matching row \(2, computed in the database\): May 1, 2024\./);
  assert.doesNotMatch(r.content, /No InnoVint lot matches/);
});

test("coverage: winery samples are not reported as a vintage's berry sampling", async () => {
  const samples = [{ vintage: 2022, sample_type: "wine" }, { vintage: 2022, sample_type: "stability_trial" }, { vintage: 2025, sample_type: "berry_smoke" }, { vintage: 2025, sample_type: "wine" }];
  const r = await run(fake({ berry_maturity_by_block: [], lab_samples_current: samples }), "get_berry_maturity", {});
  assert.match(r.content, /2022: no berry sampling of any kind -- genuinely absent, not simulated\./);
  assert.match(r.content, /2025: no maturity\/ripening panel -- that vintage's only berry sampling was smoke-taint screening \(see get_smoke_markers\)/);
});

test("5: get_berry_maturity takes a collection-date window, so the Changes note covers exactly the span asked about", async () => {
  const series = [["2026-08-25", 23], ["2026-09-01", 23.6], ["2026-09-22", 25.4], ["2026-09-30", 26.7]];
  const db = fake({ berry_maturity_by_block: series.map(([d, brix]) => ({ block_id: "B2", collected_on: d, vintage: 2026, brix })), lab_samples_current: [] });
  const r = await run(db, "get_berry_maturity", { vintage: 2026, block_id: "B2", start_date: "2026-08-25", end_date: "2026-09-22" });
  assert.deepEqual(rowsOf(r).map((x) => x.collected_on), ["2026-08-25", "2026-09-01", "2026-09-22"]);
  assert.ok(db.calls.some((c) => c[0] === "lte" && c[2] === "collected_on" && c[3] === "2026-09-22"));
  assert.match(r.content, /Effective interval: collected_on >= 2026-08-25 and collected_on <= 2026-09-22 \(calendar dates, both inclusive\)/);
  assert.match(r.content, /B2 2026 brix: 23 \(August 25, 2026\) -> 25\.4 \(September 22, 2026\): \+2\.4 Brix over 28 days = \+0\.086 Brix\/day/);
});
