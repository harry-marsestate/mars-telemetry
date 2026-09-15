"""Direct Postgres writes for the labour_actuals backfill. Same
connection/upsert convention as open_meteo/db.py, innovint/db.py, and
irrigation_records/db.py.

Idempotency key is (source_file, source_row_id) rather than a business key
-- see the schema migration's comment (20260914120000_labour_actuals.sql)
for why: labour line items have no natural unique combination of fields.
"""

from __future__ import annotations

import os

import psycopg2
import psycopg2.extras

_COLUMNS = [
    "vintage", "period_month", "invoice_number", "invoice_type", "job_category",
    "task", "task_code", "role", "role_code", "hours", "rate_per_hour", "amount_usd",
    "entry_kind", "expense_vendor", "expense_memo", "expense_account", "expense_date",
    "source_system", "source_file", "source_row_id",
]


def get_connection():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def upsert_labour_actuals(conn, rows: list[dict]) -> int:
    if not rows:
        return 0
    set_clause = ",\n                ".join(f"{c} = excluded.{c}" for c in _COLUMNS if c not in ("source_file", "source_row_id"))
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            f"""
            insert into labour_actuals ({", ".join(_COLUMNS)})
            values %s
            on conflict (source_file, source_row_id) do update set
                {set_clause}
            """,
            [tuple(r[c] for c in _COLUMNS) for r in rows],
        )
    conn.commit()
    return len(rows)


def count_existing_rows(conn, source_file: str) -> int:
    with conn.cursor() as cur:
        cur.execute("select count(*) from labour_actuals where source_file = %s", (source_file,))
        return cur.fetchone()[0]


def vintage_totals(conn, vintage: int) -> dict:
    with conn.cursor() as cur:
        cur.execute(
            """
            select entry_kind, count(*), coalesce(sum(hours),0), coalesce(sum(amount_usd),0)
            from labour_actuals where vintage = %s group by entry_kind
            """,
            (vintage,),
        )
        return {row[0]: {"rows": row[1], "hours": float(row[2]), "amount": float(row[3])} for row in cur.fetchall()}
