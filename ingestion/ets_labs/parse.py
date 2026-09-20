"""Parses ETSLabsReport_17798_09_20_2026.csv into lab_samples/lab_results/
berry_volume_histogram rows -- Phase 1 (vineyard-side berry samples) only.

Phase 1 scope is an EXPLICIT set of 18 lab_sample_no values (17 physical
samples -- 511110861A is a reissue of 511110861, not a second sample). The
other 25 sample numbers in the CSV are winery-side wine-chemistry lots
(MA22*/MA23*/MA24*/MA25CH/25CHMR-LF/23 Zinfandel/23 Zin 90/10/T-7 V-2) and
the 26MARCH Chardonnay must panel -- deliberately excluded this round, see
the migration's own comment and docs/SECURITY.md for why.

Assertion, not adaptation: parse() raises if the CSV's Phase-1 rows don't
match PHASE1_SAMPLE_NOS exactly, or if a berry sample description isn't in
DESCRIPTION_BLOCK. A changed source file should fail loudly here, not
silently ingest a different inventory than the one this module was
verified against.

Sample-number date decoding (rule confirmed across every sample in this
CSV, in and out of Phase 1): lab_sample_no is
[last digit of year][MM][DD][4-digit seq][optional reissue letter] and
encodes the LAB RECEIPT date, not collection. Year decodes as 2020 + digit
-- correct for this decade; would need revisiting for a 2030s source file.
collected_on falls back to this decoded date (source='inferred_from_receipt')
except where a sample's own description embeds an explicit collection date
(COLLECTED_ON_OVERRIDE, source='description') -- the 2024 MRS samples are
the one case this round where the two genuinely differ (collected 9/6,
received 9/7).

Two-method-string trap: ETS reports the same nine free volatile phenols
under two different Analysis Name conventions depending on sample batch --
"X (GC/MS)" (2025-08 berry samples, ug/kg) and "X GC MS/MS" (2025-09 fruit
and bucket-ferment samples, ug/L). analysis_code_for() strips either
method suffix to the same code so they aggregate as one analyte; units and
analysis_name_raw are preserved untouched (ug/kg and ug/L are never
converted into each other).

Every checksum below was independently computed against the raw CSV
(csv.DictReader over the whole file, utf-8 -- NOT latin-1, which
mis-decodes the source's embedded micro-sign bytes into 'Â\xb5') before
this module was finalized; see docs/SECURITY.md for the investigation.
backfill.py refuses to insert if evaluate() doesn't reconcile.
"""

from __future__ import annotations

import csv
import re
from datetime import date
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "seed-data" / "lab_raw"
DEFAULT_PATH = RAW_DIR / "ETSLabsReport_17798_09_20_2026.csv"

PHASE1_SAMPLE_NOS = {
    # Dyostem berry maturity, 2026 (8 samples, 20 Dyostem bins + 9 maturity analytes each)
    "608250190", "608250191", "609010427", "609010428",
    "609080462", "609080463", "609150514", "609150515",
    # Berry maturity, brix/pH/TA only (4 samples, 3 rows each)
    "409070336", "409070337", "310180098", "310180099",
    # Berry smoke screen, ug/kg (2 samples, 15 rows each)
    "508260303", "508260304",
    # Fruit smoke screen, ug/L (2 samples, 15 rows each)
    "509181100", "509181101",
    # Trial micro-ferment, 2025 Cab (base sample + lettered reissue)
    "511110861", "511110861A",
}

# lab_sample_no -> local block. Explicit, not regex-derived -- covers all
# 14 distinct berry sample descriptions across four years of ETS's own
# spelling variants ("MARS 2", "Mars 2", "MARS2", "Mars Blk 2",
# "Mars, blk: 2", "MRS 2", "Mars Estate Blk: 2"). parse() asserts every
# Phase-1 description is a key here and fails loudly otherwise.
DESCRIPTION_BLOCK: dict[str, str | None] = {
    "Mars Estate Blk: 2 (berries)": "B2",
    "Mars Estate Blk: 3 (berries)": "B3",
    "MRS 2 9/6/24": "B2",
    "MRS 3 9/6/24": "B3",
    "Mars, blk: 2 (berries)": "B2",
    "Mars, blk: 3 (berries)": "B3",
    "MARS2": "B2",
    "MARS3": "B3",
    "Mars Blk 2 08/25/26 (berries)": "B2",
    "Mars Blk 3 08/25/26 (berries)": "B3",
    "Mars 2 (berries)": "B2",
    "Mars 3 (berries)": "B3",
    "MARS 2 (berries)": "B2",
    "MARS 3 (berries)": "B3",
    # No block named in the description. Stored as None -- NOT inferred --
    # per the owner needing to confirm which block(s) fed the trial
    # micro-ferment (or whether it was a blend). Flagged in
    # docs/SECURITY.md, not silently defaulted.
    "BUCKET FERMENT": None,
}

SAMPLE_TYPE_BY_SAMPLE_NO: dict[str, str] = {
    **{sn: "berry_maturity" for sn in (
        "608250190", "608250191", "609010427", "609010428",
        "609080462", "609080463", "609150514", "609150515",
        "409070336", "409070337", "310180098", "310180099",
    )},
    **{sn: "berry_smoke" for sn in ("508260303", "508260304", "509181100", "509181101")},
    **{sn: "trial_ferment" for sn in ("511110861", "511110861A")},
}

# Samples whose own description embeds an explicit collection date,
# distinct from the lab-receipt date the sample number decodes to.
COLLECTED_ON_OVERRIDE: dict[str, date] = {
    "608250190": date(2026, 8, 25),
    "608250191": date(2026, 8, 25),
    "409070336": date(2024, 9, 6),
    "409070337": date(2024, 9, 6),
}

_SAMPLE_NO_RE = re.compile(r"^(\d)(\d{2})(\d{2})(\d{4})([A-Za-z]?)$")
_RESULT_RE = re.compile(r"^\s*(<)?\s*([+-]?\d+(?:\.\d+)?)\s*$")
_METHOD_SUFFIXES = (" (gc/ms)", " gc ms/ms")

CHECKSUMS = {
    "total_csv_rows": 414,
    "phase1_rows": 321,
    "distinct_samples": 18,
    "non_reissue_samples": 17,
    "dyostem_samples": 8,
    "dyostem_bin_rows": 160,
    "lab_result_rows": 161,  # 321 phase1 rows - 160 Dyostem bin rows
    "censored_count": 22,
    "dyostem_berry_count_sums": {
        "608250190": 100, "608250191": 103, "609010427": 97, "609010428": 98,
        "609080462": 100, "609080463": 98, "609150514": 100, "609150515": 99,
    },
}
_TOL = 0.001


def decode_sample_no(sample_no: str) -> date:
    m = _SAMPLE_NO_RE.match(sample_no)
    if not m:
        raise ValueError(f"lab_sample_no {sample_no!r} doesn't match the [Y][MM][DD][seq][suffix] shape")
    yd, mm, dd, _seq, _suf = m.groups()
    return date(2020 + int(yd), int(mm), int(dd))


def base_sample_no(sample_no: str) -> str | None:
    """511110861A -> '511110861'; 511110861 -> None (not a reissue)."""
    m = _SAMPLE_NO_RE.match(sample_no)
    if m and m.group(5):
        return sample_no[: -len(m.group(5))]
    return None


def _slugify(s: str) -> str:
    s = s.strip().lower().replace("µg", "ug")
    s = re.sub(r"[^a-z0-9]+", "_", s)
    return s.strip("_")


def analysis_code_for(analysis_name: str) -> str:
    low = analysis_name.strip().lower()
    for suf in _METHOD_SUFFIXES:
        if low.endswith(suf):
            return _slugify(analysis_name[: -len(suf)])
    return _slugify(analysis_name)


def parse_result(raw: str) -> tuple[str, float]:
    m = _RESULT_RE.match(raw)
    if not m:
        raise ValueError(f"unparseable result {raw!r}")
    operator = "<" if m.group(1) else "="
    return operator, float(m.group(2))


def parse(path: Path = DEFAULT_PATH) -> tuple[list[dict], list[dict], list[dict], dict]:
    with open(path, encoding="utf-8", newline="") as f:
        all_rows = list(csv.DictReader(f))

    phase1_rows = [r for r in all_rows if r["Sample #"].strip() in PHASE1_SAMPLE_NOS]

    by_sample: dict[str, list[dict]] = {}
    for row in phase1_rows:
        by_sample.setdefault(row["Sample #"].strip(), []).append(row)

    found = set(by_sample.keys())
    if found != PHASE1_SAMPLE_NOS:
        raise ValueError(
            f"Phase-1 sample inventory changed: missing {PHASE1_SAMPLE_NOS - found}, "
            f"unexpected {found - PHASE1_SAMPLE_NOS}. Refusing to adapt -- re-verify the source file."
        )

    samples: list[dict] = []
    results: list[dict] = []
    histogram: list[dict] = []
    dyostem_sums: dict[str, int] = {}

    for sample_no, rows in by_sample.items():
        desc = rows[0]["Sample Description"]
        if desc not in DESCRIPTION_BLOCK:
            raise ValueError(f"unmapped berry sample description {desc!r} for {sample_no} -- add it to DESCRIPTION_BLOCK")
        block_id = DESCRIPTION_BLOCK[desc]
        received_on = decode_sample_no(sample_no)
        if sample_no in COLLECTED_ON_OVERRIDE:
            collected_on, collected_on_source = COLLECTED_ON_OVERRIDE[sample_no], "description"
        else:
            collected_on, collected_on_source = received_on, "inferred_from_receipt"

        samples.append({
            "lab_sample_no": sample_no,
            "lab_group_no": rows[0]["Group #"],
            "sample_description_raw": desc,
            "sample_type": SAMPLE_TYPE_BY_SAMPLE_NO[sample_no],
            "block_id": block_id,
            "vintage": collected_on.year,
            "collected_on": collected_on.isoformat(),
            "collected_on_source": collected_on_source,
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

            operator, numeric = parse_result(row["Result"])
            results.append({
                "lab_sample_no": sample_no,
                "analysis_name_raw": name,
                "analysis_code": analysis_code_for(name),
                "result_raw": row["Result"],
                "result_numeric": numeric,
                "result_operator": operator,
                "units": row["Units"] or None,
                "analyzed_at": row["Date"],
            })
        if dyostem_total:
            dyostem_sums[sample_no] = dyostem_total

    check = {
        "label": f"ETS Labs Phase 1 ({path.name})",
        "checks": [
            ("total_csv_rows", len(all_rows), CHECKSUMS["total_csv_rows"]),
            ("phase1_rows", len(phase1_rows), CHECKSUMS["phase1_rows"]),
            ("distinct_samples", len(samples), CHECKSUMS["distinct_samples"]),
            ("non_reissue_samples", sum(1 for s in samples if s["reissue_of"] is None), CHECKSUMS["non_reissue_samples"]),
            ("dyostem_samples", len(dyostem_sums), CHECKSUMS["dyostem_samples"]),
            ("dyostem_bin_rows", len(histogram), CHECKSUMS["dyostem_bin_rows"]),
            ("lab_result_rows", len(results), CHECKSUMS["lab_result_rows"]),
            ("censored_count", sum(1 for r in results if r["result_operator"] == "<"), CHECKSUMS["censored_count"]),
        ],
        "dyostem_sums": dyostem_sums,
    }
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
              f"the typical 97-100 range: {outside_range} -- confirmed against raw CSV, all 20 bins "
              f"present, not a parsing artifact (docs/SECURITY.md).")
    return ok
