"""Parses the real Mars Irrigation {2023,2024}.xlsx event logs into
per-(block, date) gallon totals, ready to insert into sensor_readings.

Deliberately does not touch Mars Irrigation 2025.xlsx -- that file is
annual-totals-only (no dates), a structurally different shape that needs
its own summary-tile representation, not this daily-series path. See
docs/SECURITY.md for the finding that its unsuffixed rows (e.g. MRS-1)
are Primera-only, not P+S combined -- MRS-1 has no corresponding "MRS-1S"
row anywhere in that file.

BLOCK_MAP: the three vineyard blocks, as they appear in both files'
BLOCK/Data Pod columns (MRS-01/02/03), mapped to this app's block_id
convention (B1/B2/B3). Confirmed identical across both years.
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

RAW_DIR = Path(__file__).parent.parent.parent / "seed-data" / "irrigation_raw"

BLOCK_MAP = {"01": "B1", "02": "B2", "03": "B3"}

_SUBBLOCK_RE = re.compile(r"^MRS-(\d{2})-(P|S)$")

# Per-year Data sheet column names -- confirmed by direct read, not
# assumed: 2023 uses DATE/BLOCK/VALUE, 2024 uses Date/Data Pod/Value.
_DATA_SHEET_COLUMNS = {
    2023: {"sheet": "2023 Data", "date": "DATE", "block": "BLOCK", "hours": "VALUE"},
    2024: {"sheet": "2024 Data", "date": "Date", "block": "Data Pod", "hours": "Value"},
}
_SUMMARY_SHEET_NAMES = {2023: "2023 Summary", 2024: "2024 Summary"}


def _parse_subblock(code: str) -> tuple[str, str]:
    m = _SUBBLOCK_RE.match(code)
    if not m:
        raise ValueError(f"Unrecognized block code: {code!r}")
    return BLOCK_MAP[m.group(1)], m.group(2)


def _read_summary_rates(path: Path, sheet: str) -> dict[tuple[str, str], dict]:
    """Returns {(block_id, P_or_S): {"rate": gal/hr, "gallons_total": stated total}}.

    The two years' Summary sheets have different column orders and names
    (2023: Hours, Rate, Gallons -- 2024: Hours, Gallons, Rate), confirmed
    by direct read. Detecting columns by name substring, not position,
    to avoid silently swapping rate and gallons-total between years.
    """
    raw = pd.read_excel(path, sheet_name=sheet, header=None)
    header_row = None
    for i, row in raw.iterrows():
        if any(str(c).strip().lower() == "block" for c in row):
            header_row = i
            break
    if header_row is None:
        raise ValueError(f"Could not find a 'Block' header row in {path} sheet {sheet!r}")

    df = pd.read_excel(path, sheet_name=sheet, header=header_row)
    df.columns = [str(c).strip() for c in df.columns]

    block_col = next(c for c in df.columns if c.lower() == "block")
    rate_col = next(c for c in df.columns if "gallon" in c.lower() and "hour" in c.lower())
    gallons_col = next(c for c in df.columns if "gallon" in c.lower() and "hour" not in c.lower())

    out = {}
    for _, row in df.iterrows():
        block_code = row[block_col]
        if not isinstance(block_code, str) or not _SUBBLOCK_RE.match(block_code):
            continue
        key = _parse_subblock(block_code)
        out[key] = {"rate": float(row[rate_col]), "gallons_total": float(row[gallons_col])}
    return out


def _read_data_events(path: Path, year: int) -> pd.DataFrame:
    cols = _DATA_SHEET_COLUMNS[year]
    df = pd.read_excel(path, sheet_name=cols["sheet"])
    df = df[[cols["date"], cols["block"], cols["hours"]]].copy()
    df.columns = ["date", "subblock_code", "hours"]
    df["date"] = pd.to_datetime(df["date"]).dt.date
    return df


def parse_vintage(year: int, *, tolerance_gallons: float = 1.0) -> tuple[list[dict], list[dict]]:
    """Returns (rows, self_check) for one vintage.

    rows: [{"date": date, "block_id": "B1", "gallons": float}, ...] --
    exactly one row per (block, date), P and S already converted to
    gallons (each at its own rate) and summed together.

    self_check: [{"block_id", "P_or_S", "computed_gallons",
    "summary_gallons", "diff", "ok"}, ...] -- computed total per
    subblock across the whole vintage, compared against that same
    file's own Summary sheet. Does not raise on mismatch -- the caller
    decides whether to proceed, but every mismatch is surfaced, not
    silently swallowed.
    """
    path = RAW_DIR / f"Mars Irrigation {year}.xlsx"
    events = _read_data_events(path, year)
    rates = _read_summary_rates(path, _SUMMARY_SHEET_NAMES[year])

    events[["block_id", "P_or_S"]] = events["subblock_code"].apply(
        lambda c: pd.Series(_parse_subblock(c))
    )

    # Pre-aggregate same-day duplicates BEFORE any rate is applied --
    # explicit step, not left to the DB's ON CONFLICT (which would keep
    # only the last-inserted row for a given (metric_key, sensor_id,
    # recorded_at), silently dropping the other event's hours instead of
    # summing them). Confirmed one such duplicate exists in 2024.
    daily_hours = (
        events.groupby(["date", "block_id", "P_or_S"], as_index=False)["hours"].sum()
    )

    # Hours -> gallons using each subblock's OWN rate, before summing P
    # and S together -- summing raw hours across P/S first would be
    # wrong, since Primera and Secundaria irrigate at different rates.
    daily_hours["rate"] = daily_hours.apply(
        lambda r: rates[(r["block_id"], r["P_or_S"])]["rate"], axis=1
    )
    daily_hours["gallons"] = daily_hours["hours"] * daily_hours["rate"]

    rows_df = (
        daily_hours.groupby(["date", "block_id"], as_index=False)["gallons"].sum()
    )
    rows = rows_df.to_dict("records")

    self_check = []
    computed_by_subblock = daily_hours.groupby(["block_id", "P_or_S"])["gallons"].sum()
    for key, summary in rates.items():
        block_id, p_or_s = key
        computed = float(computed_by_subblock.get(key, 0.0))
        target = summary["gallons_total"]
        diff = computed - target
        self_check.append(
            {
                "block_id": block_id,
                "P_or_S": p_or_s,
                "computed_gallons": computed,
                "summary_gallons": target,
                "diff": diff,
                "ok": abs(diff) <= tolerance_gallons,
            }
        )

    return rows, self_check
