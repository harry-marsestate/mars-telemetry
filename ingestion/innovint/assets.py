"""Dagster assets for real InnoVint data: lot_analyses and vessels.

Both assets: fetch + validate against contracts.py (extra="forbid" -- any
InnoVint shape drift fails the run loudly rather than landing corrupted
data), with every raw response landed to disk automatically as a side
effect of InnoVintClient._get before a single row is transformed, then
upsert into Postgres via db.py.
"""

import os
from datetime import datetime, timezone

from dagster import AssetExecutionContext, MaterializeResult, asset

from . import capacity, db
from .client import InnoVintClient

WINERY_ID = os.environ.get("INNOVINT_WINERY_ID", "wnry_2PW0KJ93L726WKKG54OQE1RY")


def _resolve_block_id(
    client: InnoVintClient,
    innovint_block_map: dict[str, str],
    lot_id: str,
    cache: dict[str, str | None],
) -> str | None:
    """Resolve a local block_id for an InnoVint lot, or None.

    Only resolves lots with exactly one blockComponents entry at
    (effectively) 100% -- confirmed against all 47 real lots before this
    was written: just 16/47 are single-component; the rest are 2-4-way
    blends (17 two-block, 8 three-block, 1 four-block) or have zero
    components (5 lots). Everything else stays null, same as any
    InnoVint block with no blocks.innovint_block_id mapping (e.g. B1, or
    InnoVint's "06"/"Lower Block"/"xxV1" that were never matched to a
    local block -- see docs/SECURITY.md). Both are expected, not errors.
    """
    if lot_id in cache:
        return cache[lot_id]
    components = client.fetch_block_components(lot_id)
    resolved: str | None = None
    if len(components.results) == 1:
        comp = components.results[0].data
        if abs(comp.percentage - 1.0) < 1e-6:
            resolved = innovint_block_map.get(comp.block.id)
    cache[lot_id] = resolved
    return resolved


@asset
def analyses_sync(context: AssetExecutionContext) -> MaterializeResult:
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    now = datetime.now(timezone.utc)
    client = InnoVintClient(os.environ["INNOVINT_TOKEN"], WINERY_ID, run_stamp)
    conn = db.get_connection()
    block_cache: dict[str, str | None] = {}

    try:
        innovint_block_map = db.load_innovint_block_map(conn)
        lot_ids = client.list_lot_ids()
        context.log.info(f"{len(lot_ids)} lots found")

        rows: list[dict] = []
        skipped_deleted_or_skipped = 0
        skipped_null_value = 0

        for lot_id in lot_ids:
            for a in client.fetch_analyses(lot_id):
                # deleted/skipped records aren't real observations -- never
                # seen in the 1,411 real records pulled during the
                # inventory (all deleted=false, skipped=false), so this is
                # an inference about InnoVint's semantics, not a confirmed
                # behavior. Counted and logged rather than silently
                # dropped, so a spike here is visible.
                if a.deleted or a.skipped:
                    skipped_deleted_or_skipped += 1
                    continue
                # lot_analyses.value is NOT NULL per the approved schema;
                # the contract allows value=None defensively (never
                # observed in real data). Filter + count rather than let
                # one null-valued record abort the whole batch upsert.
                if a.value is None:
                    skipped_null_value += 1
                    continue
                block_id = _resolve_block_id(client, innovint_block_map, a.lot_id, block_cache)
                rows.append(
                    {
                        "source_system": "innovint",
                        "source_id": a.id,
                        "lot_id": a.lot_id,
                        "block_id": block_id,
                        "analysis_type": a.analysis_type.slug,
                        "value": a.value,
                        "unit": a.unit.unit,
                        "recorded_at": a.recorded_at,
                        "ingested_at": now,
                    }
                )

        written = db.upsert_lot_analyses(conn, rows)
        resolved = sum(1 for r in rows if r["block_id"] is not None)
        context.log.info(
            f"upserted {written} analyses rows ({resolved} with block_id); "
            f"skipped {skipped_deleted_or_skipped} deleted/skipped, "
            f"{skipped_null_value} null-value"
        )
        return MaterializeResult(
            metadata={
                "lots_processed": len(lot_ids),
                "rows_upserted": written,
                "rows_with_block_id": resolved,
                "rows_skipped_deleted_or_skipped": skipped_deleted_or_skipped,
                "rows_skipped_null_value": skipped_null_value,
                "run_stamp": run_stamp,
            }
        )
    finally:
        conn.close()
        client.close()


@asset
def vessels_sync(context: AssetExecutionContext) -> MaterializeResult:
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    now = datetime.now(timezone.utc)
    client = InnoVintClient(os.environ["INNOVINT_TOKEN"], WINERY_ID, run_stamp)
    conn = db.get_connection()
    block_cache: dict[str, str | None] = {}

    try:
        innovint_block_map = db.load_innovint_block_map(conn)
        vessels = list(client.fetch_vessels())
        context.log.info(f"{len(vessels)} vessels found")

        capacities = [
            v.capacity.value
            for v in vessels
            if v.capacity is not None and v.capacity.value is not None
        ]
        threshold = capacity.outlier_threshold(capacities)

        rows: list[dict] = []
        suspect_count = 0
        resolved_count = 0

        for v in vessels:
            cap_val = v.capacity.value if v.capacity is not None else None
            suspect = capacity.compute_capacity_suspect(cap_val, threshold)
            if suspect:
                suspect_count += 1

            block_id = None
            if v.lot_id is not None:
                block_id = _resolve_block_id(client, innovint_block_map, v.lot_id, block_cache)
                if block_id is not None:
                    resolved_count += 1

            rows.append(
                {
                    "vessel_id": v.id,
                    "source_system": "innovint",
                    # InnoVint's vessel_type is uppercase (TANK/BARREL/
                    # KEG/STEEL_DRUM); the vessels table's check
                    # constraint is lowercase, per the approved migration.
                    "vessel_type": v.vessel_type.lower(),
                    "code": v.code,
                    "capacity_gal": cap_val,
                    "capacity_suspect": suspect,
                    "current_lot_id": v.lot_id,
                    "block_id": block_id,
                    "archived": v.archived,
                    "updated_at": now,
                }
            )

        written = db.upsert_vessels(conn, rows)
        context.log.info(
            f"upserted {written} vessel rows ({suspect_count} capacity_suspect, "
            f"{resolved_count} with block_id)"
        )
        return MaterializeResult(
            metadata={
                "vessels_processed": len(vessels),
                "rows_upserted": written,
                "rows_capacity_suspect": suspect_count,
                "rows_with_block_id": resolved_count,
                "outlier_threshold_gal": threshold,
                "run_stamp": run_stamp,
            }
        )
    finally:
        conn.close()
        client.close()
