"""Durable local copies of every InnoVint API response this ingestion pulls,
written before any parsing/upsert happens (called from InnoVintClient._get,
so every fetch lands automatically -- no asset code needs to remember to
call this). If a bug in the transform/upsert logic is found later, the
exact responses that produced a given run's data can be replayed from these
files without re-hitting InnoVint or needing a live token.
"""

from __future__ import annotations

from pathlib import Path

RAW_DIR = Path(__file__).parent / "_raw"


def land_raw(run_stamp: str, category: str, key: str, payload: bytes) -> None:
    dest = RAW_DIR / run_stamp / category
    dest.mkdir(parents=True, exist_ok=True)
    (dest / f"{key}.json").write_bytes(payload)
