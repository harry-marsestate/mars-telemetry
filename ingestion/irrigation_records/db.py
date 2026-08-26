"""Direct Postgres writes for the irrigation-records backfill. Same
connection/upsert convention as open_meteo/db.py and innovint/db.py.

Unlike open_meteo's estate-level real data (block_id always null, since
ERA5's grid can't distinguish blocks), irrigation's real data genuinely
has block resolution -- one sensor_id per block, block_id populated on
every row.
"""

from __future__ import annotations

import os
from datetime import date

import psycopg2
import psycopg2.extras

SOURCE_SYSTEM = "farm_irrigation_log"
SENSOR_ID_BY_BLOCK = {"B1": "IR-01", "B2": "IR-02", "B3": "IR-03"}

# Real dates in these files carry no time-of-day -- midnight Pacific is
# the genuine-semantics choice (matching every other real ingestion in
# this project), not mock's arbitrary marker time. -07:00 (PDT) is safe
# for the same reason it was for open_meteo: these events fall in
# Apr-Oct, which never crosses a DST boundary.
_PDT_OFFSET = "-07:00"


def get_connection():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def rows_to_sensor_readings(rows: list[dict], vintage: int) -> list[dict]:
    out = []
    for r in rows:
        d: date = r["date"]
        out.append(
            {
                "metric_key": "irrigation_volume",
                "sensor_id": SENSOR_ID_BY_BLOCK[r["block_id"]],
                "block_id": r["block_id"],
                "recorded_at": f"{d.isoformat()}T00:00:00{_PDT_OFFSET}",
                "value": round(r["gallons"], 2),
                "vintage": vintage,
            }
        )
    return out


def upsert_sensor_readings(conn, rows: list[dict]) -> int:
    if not rows:
        return 0
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            """
            insert into sensor_readings
                (metric_key, sensor_id, block_id, tank_id, recorded_at,
                 value, source_system, vintage)
            values %s
            on conflict (metric_key, sensor_id, recorded_at) do update set
                value = excluded.value,
                vintage = excluded.vintage
            """,
            [
                (
                    r["metric_key"],
                    r["sensor_id"],
                    r["block_id"],
                    None,
                    r["recorded_at"],
                    r["value"],
                    SOURCE_SYSTEM,
                    r["vintage"],
                )
                for r in rows
            ],
        )
    conn.commit()
    return len(rows)


def count_existing_real_rows(conn, vintage: int, block_id: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            select count(*) from sensor_readings
            where vintage = %s and metric_key = 'irrigation_volume'
              and block_id = %s and source_system = %s
            """,
            (vintage, block_id, SOURCE_SYSTEM),
        )
        return cur.fetchone()[0]
