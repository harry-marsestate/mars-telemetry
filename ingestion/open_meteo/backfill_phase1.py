"""Real-climate-data backfill, Phase 1: insert real Open-Meteo rows
alongside the existing mock data. Does NOT delete anything.

Scope, matching the approved design: air_temp and soil_moisture/soil_temp
only (the two metrics actually validated during reconnaissance) -- not
humidity/wind/solar/uv/precipitation, which need their own validation
pass before ingestion. Not 2026 -- stays on the existing mock/live
pipeline until the season closes and a real same-year report exists.

air_temp is stored raw (elevation-downscaled to our confirmed 670m site
elevation, no further correction) -- the Grapegrowers-calibration scalar
lives only in vintage_climate_calibration and is applied by the
daily_derived view to gdd_day/dtr_f, not to the underlying hourly
readings this script writes.

Depth-band note, worth surfacing before this runs: the mock soil panels'
subtitle says "Probes at 18 in" -- ERA5-Land's four fixed depth bands
(0-7/7-28/28-100/100-255cm) don't include anything at 18in (~46cm), and
this backfill uses 0_to_7cm specifically because that's the band actually
validated during reconnaissance (confirmed non-null at our coordinates).
Using a deeper, unvalidated band to chase the old "18 in" framing would
reintroduce exactly the kind of unvalidated-metric risk the scope was
narrowed to avoid. The frontend subtitle needs updating to reflect the
real depth (surface, 0-7cm) rather than keeping a now-inaccurate "18 in"
claim -- flagged here, not fixed here; that's a frontend change, out of
scope for this ingestion script.

Run: poetry run python -m open_meteo.backfill_phase1
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import client, db

VINTAGES = [2022, 2023, 2024, 2025]


# Open-Meteo returns local time (America/Los_Angeles, per &timezone=)
# without a UTC offset suffix -- sensor_readings is timestamptz, so this
# needs an explicit zone, not a naive parse Postgres would silently read
# as UTC. Fixed at -07:00 (PDT) because this backfill's date range (Apr 1
# - Oct 31) never crosses a DST boundary -- PDT runs mid-March to early
# November in California. Would need real DST logic if the range ever
# grew to include March or November.
_PDT_OFFSET = "-07:00"


def _rows_from_series(
    data: dict, variable: str, metric_key: str, vintage: int, *, scale: float = 1
) -> tuple[list[dict], int]:
    """scale=100 for soil_moisture_0_to_7cm only: Open-Meteo/ERA5-Land
    reports soil moisture as volumetric water content, a 0-1 fraction
    (confirmed directly: raw values landed 0.137-0.435). Every other
    consumer of this metric in this project -- the mock data, the
    soil_below_refill threshold (15), the "% VWC" display unit -- expects
    a 0-100 percentage. Applying the conversion at read time here (not as
    a one-off corrective UPDATE) means a rerun of this script never
    reintroduces the mismatch. temperature_2m and soil_temperature_0_to_7cm
    are already Fahrenheit (via &temperature_unit=fahrenheit) and need no
    scaling -- scale defaults to 1 (no-op) for those.
    """
    rows = []
    skipped_null = 0
    for iso_time, value in client.hourly_series(data, variable):
        if value is None:
            skipped_null += 1
            continue
        rows.append(
            {
                "metric_key": metric_key,
                "recorded_at": iso_time + _PDT_OFFSET,
                "value": value * scale,
                "vintage": vintage,
            }
        )
    return rows, skipped_null


def run() -> None:
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    conn = db.get_connection()

    try:
        for vintage in VINTAGES:
            print(f"=== {vintage} ===")

            temp_data = client.fetch_hourly(run_stamp, vintage, ["temperature_2m"])
            temp_rows, temp_nulls = _rows_from_series(
                temp_data, "temperature_2m", "air_temp", vintage
            )
            written = db.upsert_sensor_readings(conn, temp_rows)
            print(
                f"  air_temp: elevation={temp_data['elevation']}, "
                f"{written} rows written ({temp_nulls} null skipped)"
            )

            soil_data = client.fetch_hourly(
                run_stamp,
                vintage,
                ["soil_moisture_0_to_7cm", "soil_temperature_0_to_7cm"],
                models="era5_land",
            )
            moist_rows, moist_nulls = _rows_from_series(
                soil_data, "soil_moisture_0_to_7cm", "soil_moisture", vintage, scale=100
            )
            temp_soil_rows, temp_soil_nulls = _rows_from_series(
                soil_data, "soil_temperature_0_to_7cm", "soil_temp", vintage
            )
            written_moist = db.upsert_sensor_readings(conn, moist_rows)
            written_temp_soil = db.upsert_sensor_readings(conn, temp_soil_rows)
            print(
                f"  soil_moisture: {written_moist} rows written ({moist_nulls} null skipped)"
            )
            print(
                f"  soil_temp: {written_temp_soil} rows written ({temp_soil_nulls} null skipped)"
            )

            for mk in ("air_temp", "soil_moisture", "soil_temp"):
                total = db.count_existing_real_rows(conn, vintage, mk)
                print(f"  total real {mk} rows now in sensor_readings for {vintage}: {total}")
    finally:
        conn.close()


if __name__ == "__main__":
    run()
