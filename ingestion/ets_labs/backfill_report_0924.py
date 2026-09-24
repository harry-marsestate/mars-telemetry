"""ETS Labs incremental ingest: ETSLabsReport_17798_09_24_2026.csv (2
berry-maturity samples) -> lab_samples/lab_results/berry_volume_histogram.

Reuses db.py's upserts unchanged (same keys, idempotent). Refuses to
write if parse_report_0924.evaluate() doesn't reconcile, or if any of the
file's lab_sample_no values already exists live -- a collision means a
reissue or re-send that needs deciding on, not an upsert that would
silently overwrite a pre-existing row. A lettered reissue (none in this
file) would additionally require its base sample to exist already.

Run: poetry run python -m ets_labs.backfill_report_0924
"""

from __future__ import annotations

from . import db, parse_report_0924


def run() -> None:
    print("=== ets_labs incremental (09_24_2026) ===")
    samples, results, histogram, check = parse_report_0924.parse()

    if not parse_report_0924.evaluate(check):
        print("  REFUSING to insert: self-check failed, see above.")
        return

    conn = db.get_connection()
    try:
        existing = db.sample_ids_by_no(conn, [s["lab_sample_no"] for s in samples])
        if existing:
            print(f"  REFUSING to insert: lab_sample_no already present live: {sorted(existing)}")
            return
        bases = sorted({s["reissue_of"] for s in samples if s["reissue_of"]})
        missing_bases = set(bases) - set(db.sample_ids_by_no(conn, bases))
        if missing_bases:
            print(f"  REFUSING to insert: reissue base sample(s) not present live: {sorted(missing_bases)}")
            return
        print(f"  pre-check: no collisions with existing lab_samples; reissues in file: {bases or 'none'}")

        n_samples = db.upsert_lab_samples(conn, samples)
        n_results = db.upsert_lab_results(conn, results)
        n_hist = db.upsert_berry_volume_histogram(conn, histogram)
        print(f"  {n_samples} lab_samples, {n_results} lab_results, {n_hist} berry_volume_histogram rows written")
        print(f"  live totals now: {db.counts(conn)}")
    finally:
        conn.close()


if __name__ == "__main__":
    run()
