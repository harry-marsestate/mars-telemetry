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
from .weights import to_short_tons

WINERY_ID = os.environ.get("INNOVINT_WINERY_ID", "wnry_2PW0KJ93L726WKKG54OQE1RY")

# Floor of the growerReceipts sweep. 2022 is the earliest vintage with any
# receipt (verified by sweeping 2015-2027: zero rows before 2022).
HARVEST_RECEIPTS_FIRST_VINTAGE = 2022


def _resolve_block_id(
    client: InnoVintClient,
    innovint_block_map: dict[str, list[tuple]],
    lot_id: str,
    cache: dict[str, str | None],
) -> str | None:
    """Resolve a local block_id for an InnoVint lot, or None.

    Only resolves lots with exactly one blockComponents entry at
    (effectively) 100% -- confirmed against all 47 real lots before this
    was written: just 16/47 are single-component; the rest are 2-4-way
    blends (17 two-block, 8 three-block, 1 four-block) or have zero
    components (5 lots). Everything else stays null, same as any
    InnoVint block with no block_innovint_map row covering that component's
    vintage (e.g. "06"/"Lower Block", never matched to a local block).
    Both are expected, not errors.

    Vintage-aware since the mapping became time-scoped: the component's own
    `vintage` field selects which mapping window applies, so a lot from a
    post-replant vintage cannot resolve through a pre-replant block object.
    """
    if lot_id in cache:
        return cache[lot_id]
    components = client.fetch_block_components(lot_id)
    resolved: str | None = None
    if len(components.results) == 1:
        comp = components.results[0].data
        if abs(comp.percentage - 1.0) < 1e-6:
            resolved = db.resolve_block_id(
                innovint_block_map, comp.block.id, comp.vintage
            )
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
        lots = client.list_lots()
        context.log.info(f"{len(lots)} lots found")

        rows: list[dict] = []
        skipped_deleted_or_skipped = 0
        skipped_null_value = 0

        for lot in lots:
            for a in client.fetch_analyses(lot.id):
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
                        "lot_name": lot.name,
                        "lot_code": lot.code,
                        "block_id": block_id,
                        "analysis_type": a.analysis_type.slug,
                        "value": a.value,
                        "unit": a.unit.unit,
                        "recorded_at": a.recorded_at,
                        "ingested_at": now,
                    }
                )

        fetched_count = len(rows)
        written = db.upsert_lot_analyses(conn, rows)
        deduped = fetched_count - written
        resolved = sum(1 for r in rows if r["block_id"] is not None)
        context.log.info(
            f"upserted {written} analyses rows ({resolved} with block_id); "
            f"skipped {skipped_deleted_or_skipped} deleted/skipped, "
            f"{skipped_null_value} null-value, {deduped} duplicate source_id "
            f"(known InnoVint pagination-boundary overlap, see db.py); "
            f"{len(client.dangling_lot_refs)} dangling lot references"
        )
        return MaterializeResult(
            metadata={
                "lots_processed": len(lots),
                "rows_deduped": deduped,
                "rows_upserted": written,
                "rows_with_block_id": resolved,
                "rows_skipped_deleted_or_skipped": skipped_deleted_or_skipped,
                "rows_skipped_null_value": skipped_null_value,
                "dangling_lot_refs": sorted(client.dangling_lot_refs),
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
        # Keyed by lot.id, not just consulted for name/code: a vessel's
        # current_lot_id missing from this dict is exactly how a dangling
        # reference (e.g. TD-07/TD-08, see client.py) surfaces here too --
        # no special-case handling needed, .get() naturally returns None.
        lots_by_id = {lot.id: lot for lot in client.list_lots()}
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
            vol_val = v.volume.value if v.volume is not None else None
            suspect = capacity.compute_capacity_suspect(cap_val, threshold)
            if suspect:
                suspect_count += 1

            block_id = None
            if v.lot_id is not None:
                block_id = _resolve_block_id(client, innovint_block_map, v.lot_id, block_cache)
                if block_id is not None:
                    resolved_count += 1

            current_lot = lots_by_id.get(v.lot_id) if v.lot_id is not None else None

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
                    "volume_gal": vol_val,
                    "capacity_suspect": suspect,
                    "current_lot_id": v.lot_id,
                    "current_lot_name": current_lot.name if current_lot else None,
                    "current_lot_code": current_lot.code if current_lot else None,
                    "block_id": block_id,
                    "archived": v.archived,
                    "updated_at": now,
                }
            )

        fetched_count = len(rows)
        written = db.upsert_vessels(conn, rows)
        deduped = fetched_count - written
        context.log.info(
            f"upserted {written} vessel rows ({suspect_count} capacity_suspect, "
            f"{resolved_count} with block_id, {deduped} duplicate vessel_id); "
            f"{len(client.dangling_lot_refs)} dangling lot references "
            f"(vessel current_lot_id pointing at a lot that doesn't exist)"
        )
        return MaterializeResult(
            metadata={
                "vessels_processed": len(vessels),
                "rows_upserted": written,
                "rows_deduped": deduped,
                "rows_capacity_suspect": suspect_count,
                "rows_with_block_id": resolved_count,
                "outlier_threshold_gal": threshold,
                "dangling_lot_refs": sorted(client.dangling_lot_refs),
                "run_stamp": run_stamp,
            }
        )
    finally:
        conn.close()
        client.close()


@asset
def harvest_receipts_sync(context: AssetExecutionContext) -> MaterializeResult:
    """Fruit intake receipts (growerReceipts) -> harvest_receipts.

    On the ongoing daily asset rather than a standalone backfill script, for
    the same reason lot_analyses/vessels are: harvest receipts are a recurring
    operational event, one per lot every season, indefinitely. Standalone
    scripts (open_meteo, irrigation) were for historical datasets with a fixed
    end and no future writes.

    Sweeps every vintage from 2022 through current_year+1 each run, not just
    recent ones: ~6-8 GETs, trivially inside the ~100-call budget noted in
    client.py, and it both catches late corrections to historical vintages and
    keeps the reconcile-delete correct for every vintage rather than a recent
    window. current_year+1 costs one wasted call and avoids a year-boundary miss.
    """
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    now = datetime.now(timezone.utc)
    client = InnoVintClient(os.environ["INNOVINT_TOKEN"], WINERY_ID, run_stamp)
    conn = db.get_connection()

    try:
        block_map = db.load_innovint_block_map(conn)
        lots_by_id = {lot.id: lot for lot in client.list_lots()}

        vintages = list(range(HARVEST_RECEIPTS_FIRST_VINTAGE, now.year + 2))
        rows: list[dict] = []
        unmapped = 0

        # Every fetch completes BEFORE any write. A failure raises here, with
        # nothing upserted and nothing deleted -- an empty or partial payload
        # must never reach the reconcile step.
        for vintage in vintages:
            for r in client.fetch_grower_receipts(vintage):
                block_id = db.resolve_block_id(block_map, r.block_id, r.vintage)
                if block_id is None:
                    unmapped += 1
                lot = lots_by_id.get(r.lot_id)
                rows.append(
                    {
                        "innovint_receipt_id": r.id,
                        "innovint_action_id": r.action_id,
                        "innovint_lot_id": r.lot_id,
                        "innovint_block_id": r.block_id,
                        "block_id": block_id,
                        "vintage": r.vintage,
                        "weight_value": r.total_weight.value,
                        "weight_unit": r.total_weight.unit,
                        # Raises UnrecognizedWeightUnit rather than coercing --
                        # a volume unit here is a source data error.
                        "weight_tons": to_short_tons(
                            r.total_weight.value, r.total_weight.unit
                        ),
                        "receipt_date": r.receipt_date,
                        "weigh_tag_number": r.weigh_tag_number,
                        # Carries the raw id; swapped for a display name after
                        # every receipt is collected, so the catalogue lookup is
                        # one batched call per run rather than one per row.
                        "varietal_id": r.varietal_id,
                        "lot_code": lot.code if lot else None,
                        "lot_name": lot.name if lot else None,
                        "grower_id": r.grower_id,
                        "vineyard_id": r.vineyard_id,
                        "appellation_id": r.appellation_id,
                        "source_system": "innovint",
                        "synced_at": now,
                    }
                )

        # A varietal id that doesn't resolve leaves varietal_name NULL rather
        # than failing the run: the name is display-only (the panel's Variety
        # column falls back to an em dash), and varietal_id itself is never the
        # join key for anything. Contrast with an unrecognized weight unit,
        # which does fail loudly -- that one corrupts a real measurement.
        varietal_names = client.fetch_varietal_names({r["varietal_id"] for r in rows})
        unnamed = 0
        for row in rows:
            name = varietal_names.get(row.pop("varietal_id"))
            if name is None:
                unnamed += 1
            row["varietal_name"] = name

        upserted, deleted = db.upsert_harvest_receipts(conn, rows, vintages)
        context.log.info(
            f"{upserted} receipts upserted, {deleted} stale deleted, "
            f"{unmapped} unmapped to a local block, {unnamed} without a varietal name"
        )
        return MaterializeResult(
            metadata={
                "receipts": upserted,
                "stale_deleted": deleted,
                "unmapped_block": unmapped,
                "unnamed_varietal": unnamed,
                "vintages_swept": f"{vintages[0]}-{vintages[-1]}",
                "run_stamp": run_stamp,
            }
        )
    finally:
        client.close()
        conn.close()
