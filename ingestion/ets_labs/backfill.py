"""ETS Labs Phase 1 backfill: 18 vineyard-side (berry) samples ->
lab_samples/lab_results/berry_volume_histogram. Idempotent (upserts on
lab_sample_no / (sample_id, analysis_name_raw, analyzed_at) /
(sample_id, bin_ml)).

Refuses to insert anything if parse.evaluate() doesn't reconcile against
parse.CHECKSUMS -- see parse.py's module docstring for how those were
independently verified.

lab_results itself is intentionally lossless (a reissued sample's
superseded base rows are kept, not deleted). Consumers should read
lab_results_current (20260920130000_lab_results_current.sql), not
lab_results directly, unless they specifically need the raw reissue
history -- see docs/SECURITY.md for the duplication bug that motivated
the view.

Run: poetry run python -m ets_labs.backfill
"""

from __future__ import annotations

from . import db, parse


def run() -> None:
    print("=== ets_labs Phase 1 ===")
    samples, results, histogram, check = parse.parse()

    if not parse.evaluate(check):
        print("  REFUSING to insert: self-check failed, see above.")
        return

    conn = db.get_connection()
    try:
        n_samples = db.upsert_lab_samples(conn, samples)
        n_results = db.upsert_lab_results(conn, results)
        n_hist = db.upsert_berry_volume_histogram(conn, histogram)
        print(f"  {n_samples} lab_samples, {n_results} lab_results, {n_hist} berry_volume_histogram rows written")
        print(f"  live totals now: {db.counts(conn)}")
    finally:
        conn.close()


if __name__ == "__main__":
    run()
