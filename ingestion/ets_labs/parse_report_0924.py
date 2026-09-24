"""Parses ETSLabsReport_17798_09_24_2026.csv -- the first incremental ETS
report after the 09_20 backfill (Phase 1 berry + Phase 2 winery). Two
vineyard-side Dyostem berry-maturity samples, nothing else:

    609220727  "Mars 2 (berries)"  -> B2
    609220728  "Mars 3 (berries)"  -> B3

Same assertion-not-adaptation stance as parse.py: the sample inventory,
the analyte set and every checksum below were computed against the raw
CSV before this module was written, and parse() raises rather than
adapting if the file doesn't match them.

Reuses parse.py's decode_sample_no()/base_sample_no()/analysis_code_for()/
parse_result() and its DESCRIPTION_BLOCK map unchanged -- both
descriptions here are verbatim keys already there ("Mars 2 (berries)" /
"Mars 3 (berries)", the same spelling as 609150514/609150515), so no new
block mapping is introduced.

Every non-Dyostem Analysis Name must map (via analysis_code_for) to one
of the nine codes berry_maturity_by_block already pivots on
(MATURITY_CODES). Anything else raises -- a new analyte gets reported and
decided on, not silently ingested into a sample_type whose downstream
view would drop it.

Reissues: neither sample number carries a trailing reissue letter, so
base_sample_no() gives reissue_of=None for both. backfill_report_0924
additionally checks both numbers against the live lab_samples table
before writing (neither existed at ingest time).

collected_on: neither description embeds a collection date, so it falls
back to the sample-number-encoded receipt date (2026-09-22,
source='inferred_from_receipt') -- which also matches every row's own
Date column.

Dyostem berry_count sums: 609220728=98 (in the typical 97-100 range),
609220727=104 (outside it, like 608250191's 103 in the 09_20 report --
all 20 bins present, confirmed against the raw CSV, non-blocking flag).
"""

from __future__ import annotations

import csv
from pathlib import Path

from .parse import (
    DESCRIPTION_BLOCK, RAW_DIR, _TOL, analysis_code_for, base_sample_no,
    decode_sample_no, parse_result,
)

DEFAULT_PATH = RAW_DIR / "ETSLabsReport_17798_09_24_2026.csv"

SAMPLE_TYPE_BY_SAMPLE_NO: dict[str, str] = {
    "609220727": "berry_maturity",
    "609220728": "berry_maturity",
}

# The nine codes berry_maturity_by_block (20260920140000) pivots on.
MATURITY_CODES = {
    "brix", "ph", "titratable_acidity", "l_malic_acid", "glucose_fructose",
    "berry_weight", "berry_volume", "berry_volume_variability", "sugar_per_berry_by_volume",
}

CHECKSUMS = {
    "total_csv_rows": 58,
    "distinct_samples": 2,
    "non_reissue_samples": 2,
    "dyostem_samples": 2,
    "dyostem_bin_rows": 40,
    "lab_result_rows": 18,  # 58 rows - 40 Dyostem bin rows
    "censored_count": 0,
    "dyostem_berry_count_sums": {"609220727": 104, "609220728": 98},
}


def parse(path: Path = DEFAULT_PATH) -> tuple[list[dict], list[dict], list[dict], dict]:
    with open(path, encoding="utf-8", newline="") as f:
        all_rows = list(csv.DictReader(f))

    by_sample: dict[str, list[dict]] = {}
    for row in all_rows:
        by_sample.setdefault(row["Sample #"].strip(), []).append(row)

    expected = set(SAMPLE_TYPE_BY_SAMPLE_NO)
    found = set(by_sample.keys())
    if found != expected:
        raise ValueError(
            f"sample inventory changed: missing {expected - found}, unexpected {found - expected}. "
            f"Refusing to adapt -- re-verify the source file."
        )

    samples: list[dict] = []
    results: list[dict] = []
    histogram: list[dict] = []
    dyostem_sums: dict[str, int] = {}

    for sample_no, rows in by_sample.items():
        desc = rows[0]["Sample Description"]
        if desc not in DESCRIPTION_BLOCK:
            raise ValueError(f"unmapped berry sample description {desc!r} for {sample_no} -- add it to DESCRIPTION_BLOCK")
        if {r["Sample Description"] for r in rows} != {desc} or {r["Group #"] for r in rows} != {rows[0]["Group #"]}:
            raise ValueError(f"{sample_no}: description/group # not constant across its rows")
        statuses = {r["Sample Status"] for r in rows}
        if statuses != {"Reported"}:
            raise ValueError(f"{sample_no}: unexpected Sample Status {statuses - {'Reported'}}")
        received_on = decode_sample_no(sample_no)

        samples.append({
            "lab_sample_no": sample_no,
            "lab_group_no": rows[0]["Group #"],
            "sample_description_raw": desc,
            "sample_type": SAMPLE_TYPE_BY_SAMPLE_NO[sample_no],
            "block_id": DESCRIPTION_BLOCK[desc],
            "vintage": received_on.year,
            "collected_on": received_on.isoformat(),
            "collected_on_source": "inferred_from_receipt",
            "received_on": received_on.isoformat(),
            "reissue_of": base_sample_no(sample_no),
            "fruit_source": "estate",
            "source_system": "ets_labs",
            "source_file": path.name,
        })

        dyostem_total = 0
        for row in rows:
            name = row["Analysis Name"]
            if name.startswith("Dyostem Histogram"):
                bin_ml = float(name.split(":", 1)[1].strip())
                count = int(row["Result"].strip())
                dyostem_total += count
                histogram.append({
                    "lab_sample_no": sample_no,
                    "bin_ml": bin_ml,
                    "berry_count": count,
                    "analyzed_at": row["Date"],
                })
                continue

            code = analysis_code_for(name)
            if code not in MATURITY_CODES:
                raise ValueError(f"{sample_no}: unrecognized analyte {name!r} -> {code!r}, not in MATURITY_CODES -- report it, don't guess")
            operator, numeric = parse_result(row["Result"])
            results.append({
                "lab_sample_no": sample_no,
                "analysis_name_raw": name,
                "analysis_code": code,
                "result_raw": row["Result"],
                "result_numeric": numeric,
                "result_operator": operator,
                "units": row["Units"] or None,
                "analyzed_at": row["Date"],
            })
        if dyostem_total:
            dyostem_sums[sample_no] = dyostem_total

    check = {
        "label": f"ETS Labs incremental ({path.name})",
        "checks": [
            ("total_csv_rows", len(all_rows), CHECKSUMS["total_csv_rows"]),
            ("distinct_samples", len(samples), CHECKSUMS["distinct_samples"]),
            ("non_reissue_samples", sum(1 for s in samples if s["reissue_of"] is None), CHECKSUMS["non_reissue_samples"]),
            ("dyostem_samples", len(dyostem_sums), CHECKSUMS["dyostem_samples"]),
            ("dyostem_bin_rows", len(histogram), CHECKSUMS["dyostem_bin_rows"]),
            ("lab_result_rows", len(results), CHECKSUMS["lab_result_rows"]),
            ("censored_count", sum(1 for r in results if r["result_operator"] == "<"), CHECKSUMS["censored_count"]),
        ],
        "dyostem_sums": dyostem_sums,
    }
    for sn in SAMPLE_TYPE_BY_SAMPLE_NO:
        codes = sorted(r["analysis_code"] for r in results if r["lab_sample_no"] == sn)
        check["checks"].append((f"maturity_codes:{sn}", codes, sorted(MATURITY_CODES)))
        bins = sorted(h["bin_ml"] for h in histogram if h["lab_sample_no"] == sn)
        check["checks"].append((f"dyostem_bins:{sn}", bins, [round(0.1 * i, 1) for i in range(1, 21)]))
    for sn, expected_sum in CHECKSUMS["dyostem_berry_count_sums"].items():
        check["checks"].append((f"dyostem_sum:{sn}", dyostem_sums.get(sn), expected_sum))

    return samples, results, histogram, check


def evaluate(check: dict) -> bool:
    ok = True
    print(f"  self-check ({check['label']}):")
    for name, computed, target in check["checks"]:
        diff = (computed - target) if isinstance(computed, (int, float)) and isinstance(target, (int, float)) else None
        passed = computed == target if diff is None else abs(diff) <= _TOL
        ok = ok and passed
        print(f"    {name}: computed={computed}, target={target}  [{'OK' if passed else 'FAIL'}]")
    outside_range = {sn: v for sn, v in check.get("dyostem_sums", {}).items() if not (97 <= v <= 100)}
    if outside_range:
        print(f"  FLAG (non-blocking, matches verified source data): Dyostem berry_count sum outside "
              f"the typical 97-100 range: {outside_range} -- confirmed against raw CSV, all 20 bins present.")
    return ok
