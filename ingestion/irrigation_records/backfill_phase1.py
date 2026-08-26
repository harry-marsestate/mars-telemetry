"""Irrigation-records backfill, Phase 1: insert real event-derived
sensor_readings rows alongside the existing mock data. Does NOT delete
anything.

Scope: 2023 and 2024 only (full event-level data in both, all three
blocks in 2023, B1 genuinely absent in 2024 -- replanting, not missing
data, so no B1 rows are produced for that vintage). 2025 is out of scope
entirely -- annual-totals-only, no dates, needs its own summary-tile
representation rather than this daily-series path.

Refuses to insert a vintage whose self-check doesn't reconcile against
that file's own Summary sheet -- see parse.py's parse_vintage() docstring.
This is Phase 1 catching a data problem itself, not deferring it to a
later validation pass.

Run: poetry run python -m irrigation_records.backfill_phase1
"""

from __future__ import annotations

from . import db, parse

VINTAGES = [2023, 2024]


def run() -> None:
    conn = db.get_connection()
    try:
        for year in VINTAGES:
            print(f"=== {year} ===")
            rows, self_check = parse.parse_vintage(year)

            print("  self-check (computed vs. this file's own Summary sheet):")
            any_failed = False
            for c in sorted(self_check, key=lambda c: (c["block_id"], c["P_or_S"])):
                status = "OK" if c["ok"] else "FAIL"
                if not c["ok"]:
                    any_failed = True
                print(
                    f"    {c['block_id']}-{c['P_or_S']}: computed={c['computed_gallons']:.2f} gal, "
                    f"summary={c['summary_gallons']:.2f} gal, diff={c['diff']:+.2f}  [{status}]"
                )

            if any_failed:
                print(f"  REFUSING to insert {year}: self-check failed, see above.")
                continue

            db_rows = db.rows_to_sensor_readings(rows, year)
            written = db.upsert_sensor_readings(conn, db_rows)
            print(f"  {written} rows written")

            for block_id in ("B1", "B2", "B3"):
                total = db.count_existing_real_rows(conn, year, block_id)
                print(f"  total real irrigation_volume rows now for {year}/{block_id}: {total}")
    finally:
        conn.close()


if __name__ == "__main__":
    run()
