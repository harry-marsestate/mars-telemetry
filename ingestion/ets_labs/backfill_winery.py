"""ETS Labs Phase 2 backfill: 25 winery-side samples (93 rows) ->
lab_samples/lab_results, same tables Phase 1 uses. Idempotent (same
upsert keys: lab_sample_no / (sample_id, analysis_name_raw, analyzed_at)).

Reuses db.py's upsert_lab_samples/upsert_lab_results unchanged --
they're already generic over the row shape, no winery-specific write
path needed. lab_results_current/lab_samples_current (Phase 1's views)
cover these rows automatically; no new *_current view needed for the
base tables, only the new ets_lot_analyses_reconciliation view
(migration 20260920180000) that reads through them.

Refuses to insert anything if parse_winery.evaluate() doesn't reconcile.

Run: poetry run python -m ets_labs.backfill_winery
"""

from __future__ import annotations

from . import db, parse_winery


def run() -> None:
    print("=== ets_labs Phase 2 (winery) ===")
    samples, results, check = parse_winery.parse_winery()

    if not parse_winery.evaluate(check):
        print("  REFUSING to insert: self-check failed, see above.")
        return

    conn = db.get_connection()
    try:
        n_samples = db.upsert_lab_samples(conn, samples)
        n_results = db.upsert_lab_results(conn, results)
        print(f"  {n_samples} lab_samples, {n_results} lab_results rows written")
        print(f"  live totals now: {db.counts(conn)}")
    finally:
        conn.close()


if __name__ == "__main__":
    run()
