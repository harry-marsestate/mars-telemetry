"""Direct Postgres writes for the ETS Labs berry-sampling backfill. Same
connection/upsert convention as labour_actuals/db.py and innovint/db.py --
connects via DATABASE_URL (RLS-bypassing, backend-only).

lab_samples has a genuine natural key (lab_sample_no) to upsert on. Its
generated identity id isn't known until after insert, so
upsert_lab_results/upsert_berry_volume_histogram take rows keyed by
lab_sample_no and resolve sample_id via a lookup select rather than
threading ids through parse.py.
"""

from __future__ import annotations

import os

import psycopg2
import psycopg2.extras

_SAMPLE_COLUMNS = [
    "lab_sample_no", "lab_group_no", "sample_description_raw", "sample_type",
    "block_id", "vintage", "collected_on", "collected_on_source", "received_on",
    "reissue_of", "fruit_source", "source_system", "source_file",
]
_RESULT_COLUMNS = ["sample_id", "analysis_name_raw", "analysis_code", "result_raw", "result_numeric", "result_operator", "units", "analyzed_at"]
_HISTOGRAM_COLUMNS = ["sample_id", "bin_ml", "berry_count", "analyzed_at"]


def get_connection():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def upsert_lab_samples(conn, samples: list[dict]) -> int:
    if not samples:
        return 0
    set_clause = ",\n                ".join(f"{c} = excluded.{c}" for c in _SAMPLE_COLUMNS if c != "lab_sample_no")
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            f"""
            insert into lab_samples ({", ".join(_SAMPLE_COLUMNS)})
            values %s
            on conflict (lab_sample_no) do update set
                {set_clause}
            """,
            [tuple(s[c] for c in _SAMPLE_COLUMNS) for s in samples],
        )
    conn.commit()
    return len(samples)


def sample_ids_by_no(conn, lab_sample_nos: list[str]) -> dict[str, int]:
    with conn.cursor() as cur:
        cur.execute("select lab_sample_no, id from lab_samples where lab_sample_no = any(%s)", (lab_sample_nos,))
        return dict(cur.fetchall())


def upsert_lab_results(conn, results: list[dict]) -> int:
    if not results:
        return 0
    id_by_no = sample_ids_by_no(conn, sorted({r["lab_sample_no"] for r in results}))
    rows = [{**r, "sample_id": id_by_no[r["lab_sample_no"]]} for r in results]
    set_clause = ",\n                ".join(f"{c} = excluded.{c}" for c in _RESULT_COLUMNS if c not in ("sample_id", "analysis_name_raw", "analyzed_at"))
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            f"""
            insert into lab_results ({", ".join(_RESULT_COLUMNS)})
            values %s
            on conflict (sample_id, analysis_name_raw, analyzed_at) do update set
                {set_clause}
            """,
            [tuple(r[c] for c in _RESULT_COLUMNS) for r in rows],
        )
    conn.commit()
    return len(rows)


def upsert_berry_volume_histogram(conn, histogram: list[dict]) -> int:
    if not histogram:
        return 0
    id_by_no = sample_ids_by_no(conn, sorted({h["lab_sample_no"] for h in histogram}))
    rows = [{**h, "sample_id": id_by_no[h["lab_sample_no"]]} for h in histogram]
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            f"""
            insert into berry_volume_histogram ({", ".join(_HISTOGRAM_COLUMNS)})
            values %s
            on conflict (sample_id, bin_ml) do update set
                berry_count = excluded.berry_count, analyzed_at = excluded.analyzed_at
            """,
            [tuple(r[c] for c in _HISTOGRAM_COLUMNS) for r in rows],
        )
    conn.commit()
    return len(rows)


def counts(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute("select count(*) from lab_samples")
        n_samples = cur.fetchone()[0]
        cur.execute("select count(*) from lab_results")
        n_results = cur.fetchone()[0]
        cur.execute("select count(*) from berry_volume_histogram")
        n_hist = cur.fetchone()[0]
    return {"lab_samples": n_samples, "lab_results": n_results, "berry_volume_histogram": n_hist}
