# ETS Labs ingestion: the single source of truth

How ETS Labs results get into the database, by either path:

- **CSV path** (`ingestion/ets_labs/`): reviewed backfills, run by hand.
- **PDF path** (`ingest-ets-report`): parsed PDF reports, posted weekly by a cloud task.

Both paths write the same tables and use the same conventions. If this file
disagrees with the code, the code wins and this file is the bug. The tests
listed at the end keep the two in agreement.

## Where the data lives

| Table | One row per | Natural key | Written by |
|---|---|---|---|
| `lab_samples` | ETS sample (`Sample #`) | `lab_sample_no` (unique) | CSV `db.upsert_lab_samples`, PDF `ets_ingest_apply` |
| `lab_results` | analyte result | `(sample_id, analysis_name_raw, analyzed_at)` unique; the PDF path upserts on `(sample_id, analysis_name_raw)` | both |
| `berry_volume_histogram` | Dyostem bin | `(sample_id, bin_ml)` | both |
| `ets_report_samples` | PDF-ingested sample | `lab_sample_no` | PDF only (provenance: `report_no`, `received_at`, `reported_at`) |
| `ets_ingest_quarantine` | refused analyte | `(report_no, sample_id, analyte_name)` | PDF only |
| `ets_analyte_spec` | accepted analyte | `analysis_code` | migration (the PDF path's allow-list) |
| `ets_description_block` | sample description | `description` | migration (from `parse.py` `DESCRIPTION_BLOCK`) |

The data is stored as entity-attribute-value rows (EAV), not one column per
metric. Each result is a `lab_results` row with an `analysis_code`. The
read-side columns come from the views:

- **`berry_maturity_by_block`**: one row per (block, collected_on, vintage).
  It pivots the nine maturity codes below into `brix`, `ph`,
  `titratable_acidity`, `l_malic_acid`, `glucose_fructose`, `berry_weight_g`,
  `berry_volume_ml`, `berry_volume_variability_pct` and `sugar_per_berry_mg`.
  It includes only `sample_type = 'berry_maturity'` samples, and only current
  ones (a superseded sample is excluded).
- **`lab_samples_current`, `lab_results_current` and
  `berry_volume_histogram_current`**: these drop any sample that another
  sample's `reissue_of` supersedes.
- **`ets_lot_analyses_reconciliation`**: flags winery ETS results that overlap
  InnoVint `lot_analyses`.

**Readers:**

| Reader | Reads | Filtered to |
|---|---|---|
| `get_berry_maturity` (chat `tools.ts`, MCP gateway) | `berry_maturity_by_block` | — |
| `get_smoke_markers` | `lab_samples_current` / `lab_results_current` | `berry_smoke` and `trial_ferment` |
| `get_wine_lab_results` | `lab_samples_current` / `lab_results_current` | winery sample types |

`domain_reality()` reports `berry_sampling` as real for a vintage if any berry
`lab_samples` row exists for it.

## Access (RLS)

These rules are unchanged by the PDF path:

- **`lab_samples`, `lab_results`, `berry_volume_histogram`:** RLS is on.
  SELECT is allowed only where `current_role_name() = 'operator'` (an approved
  operator), with a `select` grant to `authenticated`. No API role can write.
  The views are `security_invoker`, so they inherit this.
- **`ets_report_samples`, `ets_ingest_quarantine`:** the same operator-only
  SELECT gate. No API role can write.
- **`ets_analyte_spec`, `ets_description_block`:** RLS is on, with no policy
  and no grant to any API role. Only the SECURITY DEFINER functions read them.
- **`ets_ingest_apply()`, `ets_ingest_key_ok()`:** EXECUTE for `service_role`
  only. That is the Edge Function's in-platform client, which never leaves
  Supabase.

## Analyte → code, unit, valid range

`analysis_code = analysis_code_for(name)` (`parse.py`; SQL
`public.ets_analysis_code`) works in four steps:

1. Strip a `" (GC/MS)"` or `" GC MS/MS"` method suffix.
2. Lower-case the name and turn `µg` into `ug`.
3. Turn each run of characters other than `[a-z0-9]` into `_`.
4. Trim `_` from both ends.

`analysis_name_raw` and `units` keep the original text. **µg/kg and µg/L are
never converted into each other.**

### Accepted by the PDF path (`ets_analyte_spec`)

The first unit listed is the one that is stored. "(none)" means unitless,
stored as NULL. The ranges are plausibility bounds I chose, deliberately wide:
a value outside them is most likely a parse error.

| ETS analysis name (as in the CSVs) | analysis_code | sample_type | unit | valid range | view column |
|---|---|---|---|---|---|
| brix | `brix` | berry_maturity | degrees | 0–40 | brix |
| pH | `ph` | berry_maturity | (none) | 2.5–4.5 | ph |
| titratable acidity | `titratable_acidity` | berry_maturity | g/L | 1–25 | titratable_acidity |
| L-malic acid | `l_malic_acid` | berry_maturity | g/L | 0–15 | l_malic_acid |
| glucose + fructose | `glucose_fructose` | berry_maturity | g/L | 0–350 | glucose_fructose |
| berry weight | `berry_weight` | berry_maturity | g/berry | 0.1–5 | berry_weight_g |
| berry volume | `berry_volume` | berry_maturity | mL/berry | 0.1–5 | berry_volume_ml |
| berry volume variability | `berry_volume_variability` | berry_maturity | % | 0–100 | berry_volume_variability_pct |
| sugar per berry (by volume) | `sugar_per_berry_by_volume` | berry_maturity | mg/berry | 0–1000 | sugar_per_berry_mg |
| Dyostem Histogram: 0.1 … 2.0 | `dyostem_histogram` → `berry_volume_histogram` | berry_maturity | (none); value = berry count, whole number | 0–200 per bin; bin must be 0.1–2.0 in 0.1 steps | — |
| guaiacol, 4-methylguaiacol, 4-methylsyringol, m-cresol, o-cresol, p-cresol, cresols (sum), phenol, syringol — each as `X (GC/MS)` or `X GC MS/MS` | `guaiacol`, `4_methylguaiacol`, `4_methylsyringol`, `m_cresol`, `o_cresol`, `p_cresol`, `cresols_sum`, `phenol`, `syringol` | berry_smoke | µg/kg (berries) or µg/L (fruit/juice) | 0–1000 | — |
| Smoke Glycosylated Markers LCMS/MS (QQQ) : guaiacol rutinoside, 4-methylguaiacol rutinoside, 4-methylsyringol gentiobioside, cresol rutinoside, phenol rutinoside, syringol gentiobioside | `smoke_glycosylated_markers_lcms_ms_qqq_<compound>` | berry_smoke | µg/kg or µg/L | 0–5000 | — |

These spellings are accepted as the same unit: `µg` (micro sign), `μg` (Greek
mu) and `ug`. Every other unit must match exactly, and an empty or missing
unit counts as "(none)".

**Values** can be a JSON number, or a string `"n"` or `"< n"`. A censored
value (`< n`, below the detection limit) is stored as `result_operator '<'`,
`result_numeric n` and `result_raw "< n"`, the same as in the CSV path.

### Found in the CSVs but not accepted by the PDF path (winery side)

These analytes are quarantined as "unknown analyte" if they arrive. Winery
samples keep the **wine's** vintage, which comes from the lot code (for
example `MA23*` → 2023). The harvest-year rule cannot derive that, so they
stay with the reviewed CSV path. See `parse_winery.py` `_SAMPLE_META`.

- **Ethanol:** `ethanol_at_20c` and `ethanol_at_60f` (% vol).
- **Acids, pH and sugars:** `volatile_acidity_acetic_acid`, `tartaric_acid`,
  plus `brix`, `ph`, `titratable_acidity`, `l_malic_acid` and
  `glucose_fructose` on wine samples.
- **SO₂:** `free_sulfur_dioxide` and `molecular_sulfur_dioxide` (mg/L).
- **Nitrogen and potassium:** `alpha_amino_compounds_as_n`, `ammonia`,
  `potassium` (mg/L) and `yeast_assimilable_nitrogen` (mg/L (as N)).
- **Microbial panel:** the nine `scorpion_yeast_bacteria_panel_*` codes
  (cells/mL).
- **Stability and fining trials:** `heat_stab_{1..5}_0_lbs_kgal_bent`,
  `fining_trial_pocock_waters_control` (NTU), plus two free-text rows,
  `conductivity_test_dit` and `heat_stability_trial_kwk_krystal_klear`.

The full name → code list is in `tests/fixtures/ets-analysis-codes.json`,
generated from `parse.py`.

## Sample → block, type, dates, vintage

| Field | CSV path | PDF path (`ets_ingest_apply`) |
|---|---|---|
| `lab_sample_no` | `Sample #` | `sample_id`; must be 9 digits. A lettered number (`…A`, a possible reissue) is quarantined for an operator decision, because the CSV path decides each one by hand (`511110861A` was a reissue, `606050014A` was not). |
| `lab_group_no` | `Group #` | `report_no` (see Ambiguities) |
| `sample_description_raw` | `Sample Description` | `sample_name` |
| `block_id` | `DESCRIPTION_BLOCK[description]`; an unknown description raises | `block` if given (`B2`, `2`, `Blk 2` and `Block 2` normalise to `B2`; the block must exist in `blocks`), else `ets_description_block[sample_name]`, else quarantined. A given block that disagrees with a mapped `sample_name` is quarantined. |
| `sample_type` | listed per sample number | from the analytes: all maturity → `berry_maturity`, all smoke → `berry_smoke`; a mix is quarantined |
| `collected_on` / `_source` | the description's embedded date (`description`), else the receipt date decoded from the sample number (`inferred_from_receipt`) | `sample_date` / `report` |
| `received_on` | decoded from the sample number (`[Y][MM][DD][seq]`) | the Pacific date of `received_at` |
| `vintage` | berry: `collected_on.year`; winery: from the lot code | `public.harvest_vintage(sample_date at 12:00 Pacific)`: the harvest-year rule (Nov 1 Pacific starts the next vintage). The vintage must exist in `public.vintages`. For August–October berry samples this equals the calendar year, so the two paths agree. |
| `fruit_source` | `estate` (berry) | `estate` |
| `source_system` / `source_file` | `ets_labs` / CSV file name | `ets_labs` / `ets_pdf_email` |
| `reissue_of` | base number for lettered reissues | always null (lettered numbers are quarantined) |

`lab_samples` gets no new columns. P1's `database.checksum.winery_closed_vintages`
hashes whole rows, so a new column would change every closed-vintage
checksum. The PDF's report fields go in `ets_report_samples` instead.

## Timestamps

- **`analyzed_at`:** the CSV `Date` column is wall-clock text with no zone
  (`2026-09-22 16:34`). `psycopg2` passes it as text, and the database
  session's zone (UTC on Supabase) labels it, so **the wall-clock ETS prints
  is stored as UTC**. The PDF path does the same thing deliberately:
  `analysis_date` must be `YYYY-MM-DD` or `YYYY-MM-DD HH:MM[:SS]`, has no
  offset, and is stored `at time zone 'UTC'`. A date alone means 00:00.
- **`collected_on` and `received_on`:** dates.
- **`received_at` and `reported_at`** (stored in `ets_report_samples`): an ISO
  8601 timestamp with an offset, or a date alone, meaning Pacific midnight.

## The PDF path

### Request

`POST https://wwdpunaefaiazsjamrkc.supabase.co/functions/v1/ingest-ets-report`
with the header `x-ets-ingest-key: <key>` and
`Content-Type: application/json`. Send one sample per request:

```json
{
  "source": "ets_pdf_email",
  "report_no": "2338065R",
  "sample_id": "609290801",
  "sample_name": "Mars 2 (berries)",
  "block": null,
  "sample_date": "2026-09-29",
  "received_at": "2026-09-29T16:10:00-07:00",
  "reported_at": "2026-09-30T09:00:00-07:00",
  "analytes": [
    {"name": "brix", "value": 24.6, "unit": "degrees", "analysis_date": "2026-09-29 16:34"},
    {"name": "pH", "value": "3.52", "unit": "", "analysis_date": "2026-09-29 16:34"},
    {"name": "L-malic acid", "value": "< 0.5", "unit": "g/L", "analysis_date": "2026-09-29"},
    {"name": "Dyostem Histogram: 0.5", "value": 12, "unit": null, "analysis_date": "2026-09-29 16:58"}
  ]
}
```

Use the **analysis names exactly as ETS prints them** (the left column of the
table above). The name is part of the idempotency key, and the code is
derived from it.

A week with no new report still sends `{"source": "ets_pdf_email",
"heartbeat": true}`. This lets P1 tell "no reports" apart from "the job
stopped".

### Response

| Status | Meaning |
|---|---|
| **200** | Every analyte was written. |
| **207** | Some or all analytes were quarantined; `rows` says which and why. |
| **400** | The payload is malformed as a whole, so nothing was written and nothing quarantined (a parser bug). |
| **401** | Bad key. |
| **413** | The body is over 256 KB. |
| **500/503** | A server or database error, so nothing was written. Retry later. |

A 207 body looks like this:

```json
{"ok": true, "report_no": "...", "sample_id": "...",
 "sample": {"status": "written", "lab_sample_no": "...", "block_id": "B2", "vintage": 2026, "sample_type": "berry_maturity"},
 "written": 3, "quarantined": 1,
 "rows": [{"analyte": "brix", "status": "written", "analysis_code": "brix", "target": "lab_results", "action": "inserted"},
          {"analyte": "ethanol at 20C", "status": "quarantined", "reason": "unknown analyte (analysis_code ethanol_at_20c): not in ets_analyte_spec"}]}
```

### Rules

1. **Idempotent.** The key is report_no + sample_id + analyte name. A re-send
   updates rows in place (`action: "updated"`), and a corrected
   `analysis_date` moves the row instead of adding a second one. A quarantined
   analyte that later passes is written, and its quarantine row is deleted.
2. **Never overwrites the CSV path.** A `sample_id` that already exists
   without an `ets_report_samples` row is quarantined. So is one that already
   belongs to a different `report_no`.
3. **Sample-level problems quarantine every analyte**, and no sample row is
   written. These are: a lettered or non-ETS sample number, an unknown or
   conflicting block, a vintage missing from `vintages`, an analyte mix, or a
   collision.
4. **Per-analyte problems** quarantine only that analyte: an unknown analyte,
   a wrong unit, a non-numeric value, an out-of-range value, a bad Dyostem
   bin, or a bad `analysis_date`.
5. **One transaction per request**, with an advisory lock per sample number.
6. **One `system_health.ingestion_runs` row per authenticated request** (asset
   `ingest-ets-report`): 200 → `success`, 207 → `partial`, anything else →
   `error`. A 401 is not logged.

### Auth

The key is in Vault under the name **`ets_ingest_key`**. It is created and
rotated by `node scripts/ets-ingest-key.mjs`, run from the repo with the
project `.env`. The script stores the key in Vault, checks it, and copies it
to the macOS clipboard. It prints only a SHA-256 prefix. To check what is
stored, run `--digest`.

The Edge Function sends only the SHA-256 of the presented key to
`ets_ingest_key_ok()`, which compares it with the Vault secret's hash. A
rotation takes effect on the next request; nothing needs redeploying.

The key can do exactly one thing: call this function. It is not a Supabase
key, so it cannot reach PostgREST, Storage, Auth or any other function.

### Quarantine: operating it

- **Read it** as an operator: `select * from ets_ingest_quarantine order by
  first_seen_at`. P1 `ingestion.ets_report.quarantine` warns while any row
  exists.
- **Fix it.** Correct the parser and re-send the report. If the analyte or
  unit is genuinely new, add it to `ets_analyte_spec` (or a description to
  `ets_description_block`) in a migration, update this file, and re-send.
  The successful write clears the row.
- **Drop it.** If the row should not be ingested, delete it with SQL.

## Tests that keep this file true

- **`tests/ets-ingest-sql.test.mjs` (PGlite).** Runs the real
  `lab_samples`/`lab_results`/`berry_volume_histogram` DDL and RLS from their
  migrations. It checks four things:
  - `ets_analysis_code` equals `parse.py` on all 59 seed analysis names.
  - `ets_description_block` equals `DESCRIPTION_BLOCK`.
  - The spec's maturity codes equal `parse_report_0924.MATURITY_CODES`.
  - Validation, quarantine, idempotency, the vintage rollover, and the
    grants/RLS behave as described.
- **`tests/ingest-ets-report.test.ts` (Deno).** Covers the HTTP flow, the key
  handling and the run logging.
- **`tests/p1-ets-ingest.test.mjs`.** Covers the two P1 checks.

If `parse.py` changes, regenerate the fixture with:

```sh
python3 -c "import csv,json,sys;sys.path.insert(0,'ingestion');from ets_labs.parse import analysis_code_for as f,DESCRIPTION_BLOCK as d;n=sorted({r['Analysis Name'] for p in ['ETSLabsReport_17798_09_20_2026.csv','ETSLabsReport_17798_09_24_2026.csv'] for r in csv.DictReader(open('seed-data/lab_raw/'+p,encoding='utf-8')) if not r['Analysis Name'].startswith('Dyostem Histogram')});json.dump({'codes':{x:f(x) for x in n},'description_block':d},open('tests/fixtures/ets-analysis-codes.json','w'),indent=1,ensure_ascii=False)"
```

## Ambiguities (decide and update this file)

1. **`report_no` vs ETS's `Group #`.** The CSV has `Group #` (e.g.
   `2338065R`) but no report number. The PDF path stores `report_no` in
   `lab_group_no`, which is NOT NULL and has no other source, and also in
   `ets_report_samples.report_no`. If the PDF's report number is not the
   group number, `lab_group_no` holds a different kind of identifier for
   PDF-ingested rows.
2. **`analyzed_at` is wall-clock time labelled UTC.** This is inferred from
   the CSV code path, not checked against live rows. It was not checked
   because production reads were not permitted in the session that built
   this. If live rows turn out to be true UTC instants, both paths need the
   same fix.
3. **The valid ranges are mine, not ETS's.** They are plausibility bounds, not
   lab specification limits.
4. **Lettered sample numbers are always quarantined.** Reissues therefore need
   an operator step.
5. **Winery samples are not accepted.** Their vintage cannot come from the
   harvest-year rule.
6. **`BUCKET FERMENT`-style samples are quarantined** unless the payload names
   a block. Even then they are typed `berry_smoke`, not `trial_ferment`.
