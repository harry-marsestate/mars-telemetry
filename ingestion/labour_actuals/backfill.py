"""Real labour backfill: Silverado 2023/2024 hours + Mars Invoice Backup
(July and August 2026) labor and expenses -> labour_actuals. Idempotent
(safe to re-run; upserts on (source_file, source_row_id)).

Refuses to insert any one of the four sources whose self-check doesn't
reconcile against that file's own verified totals -- see parse.py's
CHECKSUMS and evaluate(). A refusal on one source does not block the
others.

Run: poetry run python -m labour_actuals.backfill
"""

from __future__ import annotations

from . import db, parse

SOURCES = [
    ("2023", parse.parse_2023),
    ("2024", parse.parse_2024),
    ("mars_invoice_labor", parse.parse_mars_invoice_labor),
    ("mars_invoice_expenses", parse.parse_mars_invoice_expenses),
    ("mars_invoice_labor_aug", parse.parse_mars_invoice_labor_aug),
    ("mars_invoice_expenses_aug", parse.parse_mars_invoice_expenses_aug),
]


def run() -> None:
    conn = db.get_connection()
    try:
        for name, parse_fn in SOURCES:
            print(f"=== {name} ===")
            rows, check = parse_fn()

            if not parse.evaluate(check):
                print(f"  REFUSING to insert {name}: self-check failed, see above.")
                continue

            source_file = rows[0]["source_file"]
            written = db.upsert_labour_actuals(conn, rows)
            total = db.count_existing_rows(conn, source_file)
            print(f"  {written} rows written; {total} total rows now for source_file={source_file!r}")

        print("\n=== per-vintage totals now in labour_actuals ===")
        for vintage in (2023, 2024, 2026):
            totals = db.vintage_totals(conn, vintage)
            print(f"  {vintage}: {totals}")
    finally:
        conn.close()


if __name__ == "__main__":
    run()
