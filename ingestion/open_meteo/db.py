"""Direct Postgres writes for the Open-Meteo climate backfill.

Same connection convention as innovint/db.py (DATABASE_URL, psycopg2,
execute_values). Phase 1 only -- insert real rows alongside the existing
mock data under a new source_system, never touching or deleting the mock
rows. That's a deliberately separate, later step (Phase 3), reviewed on
its own.
"""

from __future__ import annotations

import os

import psycopg2
import psycopg2.extras

SOURCE_SYSTEM = "open_meteo_era5"
SENSOR_ID = "OM-ERA5"


def get_connection():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def upsert_sensor_readings(conn, rows: list[dict]) -> int:
    """rows: dicts with metric_key, recorded_at, value, vintage.
    block_id is always None here -- every metric across both backfill
    rounds (air_temp, soil_moisture/soil_temp, and now humidity/
    precipitation/solar) is stored estate-level. air_temp/humidity/
    precipitation/solar already were (matches the existing WS-01
    convention); soil is a deliberate scope change from the mock's
    per-block SP-01/02/03 rows, since ERA5-Land's ~11km grid cannot
    distinguish our three blocks -- see the schema migration's reasoning.
    tank_id is always None (none of these metrics are fermentation data).

    ON CONFLICT target matches the table's real unique constraint
    (metric_key, sensor_id, recorded_at) -- reusing SENSOR_ID/SOURCE_SYSTEM
    for every row in this backfill makes this upsert naturally idempotent
    on rerun, the same property the InnoVint upserts rely on.
    """
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
                    SENSOR_ID,
                    None,
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


def count_existing_real_rows(conn, vintage: int, metric_key: str) -> int:
    """Phase 1 sanity check only -- lets backfill_phase1.py report how
    many rows already exist under our source_system before/after a run,
    so a rerun's row count makes sense at a glance rather than requiring
    a separate query.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            select count(*) from sensor_readings
            where vintage = %s and metric_key = %s and source_system = %s
            """,
            (vintage, metric_key, SOURCE_SYSTEM),
        )
        return cur.fetchone()[0]
