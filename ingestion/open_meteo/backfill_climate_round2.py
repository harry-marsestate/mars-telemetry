"""Real-climate-data backfill, round 2, Phase 1: insert real Open-Meteo
rows for precipitation/humidity/solar alongside the existing mock data.
Does NOT delete anything.

Kept as a separate script from backfill_phase1.py rather than extending
it -- that file's docstring explicitly scoped itself to air_temp and
soil_moisture/soil_temp only, and named humidity/wind/solar/uv/
precipitation as needing their own validation pass before ingestion.
This script is that pass, for the three of those five approved for
backfill (precipitation, humidity, solar). Wind and UV are explicitly
out of scope: UV is a hard, unfixable gap (Open-Meteo's uv_index returns
all-null for this historical range); wind has no usable real-world
reference near this site for 2022-2025 (three sources checked directly
and ruled out -- see docs/SECURITY.md). Both stay mock indefinitely.

Calibration note: unlike GDD/DTR, none of these three metrics get a
vintage_climate_calibration-style scalar. Precipitation's only real
reference point (Howell Mountain, April 2023, Napa Valley Grapegrowers
report) is a single month of a single vintage -- nowhere near enough to
derive a multi-year anchored/borrowed methodology the way GDD's two
full-season anchor years were. Humidity and solar have no numeric
reference at all. All three are ingested raw and uncorrected, same
treatment as VPD/ET0/soil_moisture/soil_temp.

Units: relative_humidity_2m (%) and shortwave_radiation (W/m^2) already
match this project's existing conventions with no conversion needed
(confirmed directly against current mock ranges). precipitation_unit is
requested explicitly as inches (Open-Meteo defaults to mm) to match the
mock's existing convention.

Run: poetry run python -m open_meteo.backfill_climate_round2
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import client, db
from .backfill_phase1 import _rows_from_series

VINTAGES = [2022, 2023, 2024, 2025]


def run() -> None:
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    conn = db.get_connection()

    try:
        for vintage in VINTAGES:
            print(f"=== {vintage} ===")

            data = client.fetch_hourly(
                run_stamp,
                vintage,
                ["relative_humidity_2m", "shortwave_radiation", "precipitation"],
                precipitation_unit="inch",
            )

            humidity_rows, humidity_nulls = _rows_from_series(
                data, "relative_humidity_2m", "humidity", vintage
            )
            solar_rows, solar_nulls = _rows_from_series(
                data, "shortwave_radiation", "solar", vintage
            )
            precip_rows, precip_nulls = _rows_from_series(
                data, "precipitation", "precipitation", vintage
            )

            written_humidity = db.upsert_sensor_readings(conn, humidity_rows)
            written_solar = db.upsert_sensor_readings(conn, solar_rows)
            written_precip = db.upsert_sensor_readings(conn, precip_rows)

            print(
                f"  humidity: {written_humidity} rows written ({humidity_nulls} null skipped)"
            )
            print(
                f"  solar: {written_solar} rows written ({solar_nulls} null skipped)"
            )
            print(
                f"  precipitation: {written_precip} rows written ({precip_nulls} null skipped)"
            )

            for mk in ("humidity", "solar", "precipitation"):
                total = db.count_existing_real_rows(conn, vintage, mk)
                print(f"  total real {mk} rows now in sensor_readings for {vintage}: {total}")
    finally:
        conn.close()


if __name__ == "__main__":
    run()
