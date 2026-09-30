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

# Labels by the Open-Meteo model each metric is requested from -- the same
# pinning as supabase/functions/ingest-climate-2026/window.ts
# CLIMATE_SOURCES. Until 2026-09-30 every row here was labelled
# open_meteo_era5 / OM-ERA5, but the atmospheric variables came from
# best_match, i.e. ECMWF IFS (docs/SECURITY.md, "Climate rows were labelled
# ERA5 but came from ECMWF IFS"). Callers must fetch with the matching
# models= value (WEATHER_MODEL / SOIL_MODEL).
WEATHER_MODEL = "ecmwf_ifs"
SOIL_MODEL = "era5_land"
SOIL_METRICS = {"soil_moisture", "soil_temp"}
LABELS = {
    WEATHER_MODEL: ("open_meteo_ecmwf_ifs", "OM-IFS"),
    SOIL_MODEL: ("open_meteo_era5_land", "OM-ERA5-LAND"),
}


def labels_for(metric_key: str) -> tuple[str, str]:
    """(source_system, sensor_id) for a metric's pinned model."""
    return LABELS[SOIL_MODEL if metric_key in SOIL_METRICS else WEATHER_MODEL]


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
    (metric_key, sensor_id, recorded_at) -- one fixed (source_system,
    sensor_id) per metric (labels_for) makes this upsert naturally idempotent
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
                    labels_for(r["metric_key"])[1],
                    None,
                    None,
                    r["recorded_at"],
                    r["value"],
                    labels_for(r["metric_key"])[0],
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
