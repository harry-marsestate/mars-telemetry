"""Open-Meteo Historical Weather API client for the real-climate-data
backfill (2022-2025).

Every raw response is landed to disk before parsing -- same durability
principle as innovint/raw_landing.py: if the calibration methodology
needs revisiting later, the exact API responses that produced a given
run's data can be replayed without re-hitting Open-Meteo.

Coordinates and elevation are fixed constants, not per-call parameters:
this project pulls one site, confirmed directly by the estate
(38.603091360858635, -122.45867651725105, ~670m/2200ft) -- deliberately
not the earlier approximate coordinates used during validation, which
landed on a materially different, lower-elevation grid cell (see
docs/SECURITY.md's climate-data-source notes for why that mattered).
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

LATITUDE = 38.603091360858635
LONGITUDE = -122.45867651725105
ELEVATION_M = 670

ARCHIVE_URL = "https://archive-api.open-meteo.com/v1/archive"

RAW_DIR = Path(__file__).parent / "_raw"


def _land_raw(run_stamp: str, key: str, payload: bytes) -> None:
    dest = RAW_DIR / run_stamp
    dest.mkdir(parents=True, exist_ok=True)
    (dest / f"{key}.json").write_bytes(payload)


def fetch_hourly(
    run_stamp: str,
    vintage: int,
    hourly_vars: list[str],
    *,
    models: str | None = None,
    precipitation_unit: str | None = None,
) -> dict:
    """One growing-season pull (1 Apr - 31 Oct), elevation-downscaled to
    our confirmed site elevation. `models=era5_land` is required for
    non-null soil_moisture_*/soil_temperature_* coverage at this location
    -- confirmed directly (the default blended archive endpoint does not
    reliably return ERA5-Land soil variables here). `models` is REQUIRED
    for every call since 2026-09-30: the default best_match served ECMWF
    IFS for the atmospheric variables here, and which model it serves is
    Open-Meteo's to change, so every request pins db.WEATHER_MODEL
    ("ecmwf_ifs") or db.SOIL_MODEL ("era5_land") -- see db.LABELS and
    docs/SECURITY.md, "Climate rows were labelled ERA5 but came from
    ECMWF IFS".

    `precipitation_unit="inch"` matches the app's existing convention
    (mock precipitation is stored in inches) -- Open-Meteo defaults to mm
    otherwise. relative_humidity_2m (%) and shortwave_radiation (W/m^2)
    need no unit override -- their defaults already match this project's
    conventions (confirmed directly against the existing mock ranges).
    """
    params = {
        "latitude": LATITUDE,
        "longitude": LONGITUDE,
        "elevation": ELEVATION_M,
        "start_date": f"{vintage}-04-01",
        "end_date": f"{vintage}-10-31",
        "hourly": ",".join(hourly_vars),
        "temperature_unit": "fahrenheit",
        "timezone": "America/Los_Angeles",
    }
    if not models:
        raise ValueError("fetch_hourly: pass models= (ecmwf_ifs or era5_land); best_match is not allowed")
    params["models"] = models
    if precipitation_unit:
        params["precipitation_unit"] = precipitation_unit

    resp = httpx.get(ARCHIVE_URL, params=params, timeout=60.0)
    resp.raise_for_status()
    key = f"{vintage}_{'_'.join(hourly_vars)}"
    _land_raw(run_stamp, key, resp.content)
    data = resp.json()

    reported_elevation = data.get("elevation")
    if reported_elevation is None or abs(reported_elevation - ELEVATION_M) > 1:
        raise ValueError(
            f"Open-Meteo returned elevation={reported_elevation} for vintage "
            f"{vintage}, expected {ELEVATION_M} (the &elevation= param should "
            f"force this exactly) -- refusing to ingest silently-mismatched data."
        )
    return data


def hourly_series(data: dict, variable: str) -> list[tuple[str, float | None]]:
    h = data["hourly"]
    return list(zip(h["time"], h[variable]))
