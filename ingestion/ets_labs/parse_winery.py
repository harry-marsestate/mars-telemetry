"""Parses ETSLabsReport_17798_09_20_2026.csv's WINERY-side rows (the 25
sample numbers outside Phase 1's vineyard-side scope) into
lab_samples/lab_results rows -- Phase 2.

Per the owner's explicit decision (docs/SECURITY.md's Phase 2
investigation): ingest ALL of it losslessly, flag overlap with
lot_analyses in a view, rather than skipping analytes lot_analyses
already has. Overlap is small and well-characterized by that
investigation (5 rows, all same-day ethanol, zero value conflicts, zero
date-near matches) -- re-verified here at the row-count level, not
re-litigated.

Reuses Phase 1's decode_sample_no()/base_sample_no()/analysis_code_for()
unchanged from parse.py -- same CSV, same conventions, no reason to
duplicate them. Phase 1 rows are explicitly excluded (PHASE1_SAMPLE_NOS
below is that round's own set, imported for the exclusion, not
re-ingested).

Mapping decisions, each checked against the raw data before being
encoded here (not asserted):

- Block: 'V2'/'V3' in a lot code = block B2/B3 (owner-confirmed).
  MA22CS/MA23CS/MA24CS are estate blends -- no single block, block_id
  NULL. 'T-7 V-2 (fermenting)' -- 'T-7' is a tank, 'V-2' is block 2
  (owner-confirmed) -- block_id='B2'. '23 Zinfandel'/'23 Zin 90/10' (a
  blend trial) and the Chardonnay lineage get block_id NULL -- no
  single-block claim justified by the data for either.
- Vintage, from lot code per the owner's rule: MA22*->2022;
  MA23*/'23 Zinfandel'/'23 Zin 90/10'->2023; MA24*->2024;
  MA25CH/25CHMR-LF->2025; 26MARCH->2026. T-7 V-2 is the one non-'MA'
  description -- dated Nov 2023 (both by its own Date column and its
  sample-number-encoded receipt date), so vintage=2023, consistent with
  the owner's own framing of it as a 2023 trial in the Phase 2
  investigation.
- sample_type: 'must' for the one pre-fermentation juice sample
  (26MARCH). 'ferment' for the one active-fermentation sample (T-7 V-2,
  the only description carrying "(fermenting)"). 'stability_trial' for
  every sample whose CSV rows are a specialty QC panel with no routine-
  chemistry content at all -- confirmed per sample, not assumed: the two
  Scorpion microbial-panel samples (402070908, 402070909; 606150055 is
  MA25CH's own Scorpion sample), MA25CH's heat-stability/fining-trial
  sample (606050013), and MA25CH's conductivity-test sample
  (606050014A). Every other sample -- routine ethanol/VA/TA/pH/SO2/YAN
  chemistry checks -- is 'wine'.
- fruit_source: 'purchased' for the Chardonnay lineage (26MARCH, MA25CH,
  25CHMR-LF/25CH MR-LF) -- no Chardonnay block or harvest receipt exists
  anywhere (confirmed in the original Phase 0 reconciliation). 'estate'
  for everything else (default).
- collected_on: none of the 25 winery descriptions embed a collection
  date the way several Phase-1 berry descriptions did (checked, not
  assumed -- no "MM/DD/YY" or similar substring in any of them), so
  collected_on_source is 'inferred_from_receipt' for all 25, same as
  Phase 1's own fallback rule.
- Reissue: 606050014A's trailing-letter shape matches Phase 1's reissue
  pattern (base_sample_no() would strip it to 606050014), but checked
  rather than assumed: 606050014 (ethanol, 2 rows) and 606050014A
  (a conductivity-test free-text note, 1 row) share ZERO analytes and
  sit 3 days apart (Jun 5 vs Jun 8, 2026), unlike Phase 1's actual
  reissue (511110861/511110861A), which shared two byte-identical
  values at the same recorded_at. This is not a reissue -- two
  independent lab deliverables, plausibly the same submitted bottle
  routed through two lab workflows, not a corrected/expanded report of
  one. reissue_of is NOT set for it.

Two rows carry multi-line, non-numeric Result text (MA25CH's
conductivity-test disclaimer and its Heat Stability Trial protocol
description) -- result_raw keeps the full text, result_numeric and
result_operator are NULL (schema widened for this in the accompanying
migration), never dropped or coerced.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

from .parse import DEFAULT_PATH, analysis_code_for, base_sample_no, decode_sample_no

import csv

PHASE1_SAMPLE_NOS = {
    "608250190", "608250191", "609010427", "609010428", "609080462", "609080463", "609150514", "609150515",
    "409070336", "409070337", "310180098", "310180099",
    "508260303", "508260304", "509181100", "509181101", "511110861", "511110861A",
}

# description -> (block_id, vintage, default sample_type, fruit_source)
_SAMPLE_META: dict[str, tuple[str | None, int, str, str]] = {
    "T-7 V-2 (fermenting)": ("B2", 2023, "ferment", "estate"),
    "MA22CS": (None, 2022, "wine", "estate"),
    "MA22CSV2": ("B2", 2022, "stability_trial", "estate"),
    "MA22CSV3": ("B3", 2022, "stability_trial", "estate"),
    "MA22ZIN": ("B1", 2022, "wine", "estate"),
    "MA23CSV2": ("B2", 2023, "wine", "estate"),
    "MA23CSV3": ("B3", 2023, "wine", "estate"),
    "MA23ZIN": ("B1", 2023, "wine", "estate"),
    "23 Zinfandel": (None, 2023, "wine", "estate"),
    "23 Zin 90/10": (None, 2023, "wine", "estate"),
    "MA24CS": (None, 2024, "wine", "estate"),
    "MA24CSV2": ("B2", 2024, "wine", "estate"),
    "MA24CSV3": ("B3", 2024, "wine", "estate"),
    "MA25CH": (None, 2025, "wine", "purchased"),
    "25CHMR-LF": (None, 2025, "wine", "purchased"),
    "25CH MR-LF": (None, 2025, "wine", "purchased"),
    "26MARCH": (None, 2026, "must", "purchased"),
}

# Per-sample_no override where MA25CH's own description covers more than
# one sample_type (routine ethanol checks are 'wine'; these three are not).
_SAMPLE_TYPE_OVERRIDE = {
    "606050013": "stability_trial",  # heat stab + fining trial panel
    "606050014A": "stability_trial",  # conductivity test
    "606150055": "stability_trial",  # Scorpion microbial panel
}

_RESULT_RE = re.compile(r"^\s*(<)?\s*([+-]?\d+(?:\.\d+)?)\s*$")

# The exact two (sample_no, analysis_name) pairs known to carry free-text,
# non-numeric Result content -- asserted, not inferred, so a THIRD
# unexpectedly-non-numeric row fails loudly instead of being silently
# coerced.
_KNOWN_TEXT_RESULTS = {
    ("606050013", "Heat Stability Trial - KWK Krystal Klear"),
    ("606050014A", "conductivity test-DIT"),
}

CHECKSUMS = {
    "total_csv_rows": 414,
    "winery_rows": 93,
    "distinct_samples": 25,
    "non_reissue_samples": 25,  # none of the 25 are a real reissue (see module docstring)
    "text_result_rows": 2,
    "lab_result_rows": 93,  # winery rows have no Dyostem-equivalent split-out table
    "censored_count": None,  # computed and asserted >= 0 at parse time, not a fixed target (see evaluate())
}
_TOL = 0.001


def parse_result(raw: str) -> tuple[str | None, float | None]:
    m = _RESULT_RE.match(raw)
    if m:
        operator = "<" if m.group(1) else "="
        return operator, float(m.group(2))
    return None, None


def parse_winery(path: Path = DEFAULT_PATH) -> tuple[list[dict], list[dict], dict]:
    with open(path, encoding="utf-8", newline="") as f:
        all_rows = list(csv.DictReader(f))

    winery_rows = [r for r in all_rows if r["Sample #"].strip() not in PHASE1_SAMPLE_NOS]

    by_sample: dict[str, list[dict]] = {}
    for row in winery_rows:
        by_sample.setdefault(row["Sample #"].strip(), []).append(row)

    samples: list[dict] = []
    results: list[dict] = []
    censored_count = 0
    text_count = 0

    for sample_no, rows in by_sample.items():
        desc = rows[0]["Sample Description"]
        if desc not in _SAMPLE_META:
            raise ValueError(f"unmapped winery description {desc!r} for {sample_no} -- add it to _SAMPLE_META")
        block_id, vintage, default_type, fruit_source = _SAMPLE_META[desc]
        sample_type = _SAMPLE_TYPE_OVERRIDE.get(sample_no, default_type)
        received_on = decode_sample_no(sample_no)
        reissue_of = base_sample_no(sample_no)
        if sample_no == "606050014A":
            # Checked, not assumed: zero analyte overlap with 606050014,
            # unlike Phase 1's real reissue case -- see module docstring.
            reissue_of = None

        samples.append({
            "lab_sample_no": sample_no,
            "lab_group_no": rows[0]["Group #"],
            "sample_description_raw": desc,
            "sample_type": sample_type,
            "block_id": block_id,
            "vintage": vintage,
            "collected_on": received_on.isoformat(),
            "collected_on_source": "inferred_from_receipt",
            "received_on": received_on.isoformat(),
            "reissue_of": reissue_of,
            "fruit_source": fruit_source,
            "source_system": "ets_labs",
            "source_file": path.name,
        })

        for row in rows:
            name = row["Analysis Name"]
            raw_result = row["Result"].replace("\r\n", " / ").replace("\n", " / ")
            operator, numeric = parse_result(row["Result"])
            if operator is None:
                if (sample_no, name) not in _KNOWN_TEXT_RESULTS:
                    raise ValueError(f"unexpected non-numeric result for {sample_no}/{name!r}: {row['Result']!r}")
                text_count += 1
            elif operator == "<":
                censored_count += 1

            results.append({
                "lab_sample_no": sample_no,
                "analysis_name_raw": name,
                "analysis_code": analysis_code_for(name),
                "result_raw": raw_result,
                "result_numeric": numeric,
                "result_operator": operator,
                "units": row["Units"] or None,
                "analyzed_at": row["Date"],
            })

    check = {
        "label": f"ETS Labs Phase 2 winery ({path.name})",
        "checks": [
            ("total_csv_rows", len(all_rows), CHECKSUMS["total_csv_rows"]),
            ("winery_rows", len(winery_rows), CHECKSUMS["winery_rows"]),
            ("distinct_samples", len(samples), CHECKSUMS["distinct_samples"]),
            ("non_reissue_samples", sum(1 for s in samples if s["reissue_of"] is None), CHECKSUMS["non_reissue_samples"]),
            ("text_result_rows", text_count, CHECKSUMS["text_result_rows"]),
            ("lab_result_rows", len(results), CHECKSUMS["lab_result_rows"]),
        ],
        "censored_count": censored_count,
    }
    return samples, results, check


def evaluate(check: dict) -> bool:
    ok = True
    print(f"  self-check ({check['label']}):")
    for name, computed, target in check["checks"]:
        passed = computed == target
        ok = ok and passed
        print(f"    {name}: computed={computed}, target={target}  [{'OK' if passed else 'FAIL'}]")
    print(f"    censored_count (informational, no fixed target): {check['censored_count']}")
    return ok
