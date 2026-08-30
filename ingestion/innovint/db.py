"""Direct Postgres writes for the InnoVint ingestion assets.

Connects via DATABASE_URL -- the same connection string used throughout
this project for every RLS-bypassing operation this session (every
migration, every adversarial RLS verification). This is a direct-SQL
equivalent of the "service role" trust tier described in
docs/SECURITY.md: full read/write, RLS bypass, backend-only, never
exposed anywhere customer/operator-facing.

Worth flagging explicitly: this is not literally the PostgREST-JWT
SUPABASE_SERVICE_ROLE_KEY. There's no existing supabase-py dependency in
this project (ingestion/pyproject.toml has httpx + psycopg2, not
supabase-py), and a scheduled batch job upserting thousands of rows is
far better served by direct, batched SQL (INSERT ... ON CONFLICT via
execute_values) than by many individual PostgREST calls. Same privilege
tier, different transport -- surfacing the substitution rather than
making it silently.
"""

from __future__ import annotations

import os

import psycopg2
import psycopg2.extras


def get_connection():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def _dedupe_by_key(rows: list[dict], key_fields: tuple[str, ...]) -> list[dict]:
    """Postgres rejects a single INSERT...ON CONFLICT DO UPDATE batch that
    contains the same conflict key twice (CardinalityViolation). Confirmed
    against live data that this happens for InnoVint analyses on lots
    large enough to span multiple /analyses pages (found via a
    CardinalityViolation on lot_ZEQX2N9JG4WR83O718D54KRP and
    lot_2VQ0D3NK7LQJE5ZMZ6WROJ81, both >100 analyses) -- offset-pagination
    returning the same row across adjacent page boundaries, with
    byte-identical content both times, not divergent data. Dedupe here
    defensively regardless of root cause: any batched ON CONFLICT upsert
    needs this, independent of why a source API might hand back the same
    key twice.
    """
    deduped: dict[tuple, dict] = {}
    for row in rows:
        deduped[tuple(row[f] for f in key_fields)] = row
    return list(deduped.values())


def load_innovint_block_map(conn) -> dict[str, list[tuple]]:
    """InnoVint block id -> [(valid_from, valid_to, local block_id), ...].

    Reads block_innovint_map, NOT the superseded blocks.innovint_block_id
    column. Time-scoped because a local block can map to different InnoVint
    block objects across vintages: B1 is xxV1 for vintages <=2023 (the
    pre-replant Zinfandel parcel) and has no mapping for 2024+ until InnoVint
    gains a post-replant block object.

    Loaded once per run: 3 rows today, hand-edited, changes ~never.

    BEHAVIOR CHANGE, deliberate: B1 was previously absent from this map
    entirely, so lots resolving to xxV1 landed block_id NULL. With the B1
    mapping present, 8 single-component lots (the 2022/2023 Zinfandel and
    lees lots) now resolve to 'B1' in lot_analyses and vessels. That data was
    always Block 1's; it is newly visible, not newly correct.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            select innovint_block_id, valid_from_vintage, valid_to_vintage, block_id
            from block_innovint_map
            """
        )
        out: dict[str, list[tuple]] = {}
        for iv_block, v_from, v_to, block_id in cur.fetchall():
            out.setdefault(iv_block, []).append((v_from, v_to, block_id))
        return out


class AmbiguousBlockMapping(RuntimeError):
    pass


def resolve_block_id(
    block_map: dict[str, list[tuple]], innovint_block_id: str, vintage: int
) -> str | None:
    """Local block_id for an InnoVint block in a given vintage, or None.

    Raises rather than picking a winner when two windows overlap. The partial
    unique indexes on block_innovint_map prevent the likely case (two open
    windows); this catches overlapping CLOSED windows, which they cannot. A
    silent wrong answer here would attribute another block's history to a
    local block with no error -- the exact failure docs/SECURITY.md warns of.
    """
    hits = [
        block_id
        for v_from, v_to, block_id in block_map.get(innovint_block_id, [])
        if (v_from is None or vintage >= v_from) and (v_to is None or vintage <= v_to)
    ]
    if len(hits) > 1:
        raise AmbiguousBlockMapping(
            f"{innovint_block_id} maps to {sorted(hits)} for vintage {vintage}; "
            f"fix the overlapping windows in block_innovint_map"
        )
    return hits[0] if hits else None


def upsert_lot_analyses(conn, rows: list[dict]) -> int:
    if not rows:
        return 0
    rows = _dedupe_by_key(rows, ("source_system", "source_id"))
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            """
            insert into lot_analyses
                (source_system, source_id, lot_id, lot_name, lot_code, block_id,
                 analysis_type, value, unit, recorded_at, ingested_at)
            values %s
            on conflict (source_system, source_id) do update set
                lot_id = excluded.lot_id,
                lot_name = excluded.lot_name,
                lot_code = excluded.lot_code,
                block_id = excluded.block_id,
                analysis_type = excluded.analysis_type,
                value = excluded.value,
                unit = excluded.unit,
                recorded_at = excluded.recorded_at,
                ingested_at = excluded.ingested_at
            """,
            [
                (
                    r["source_system"],
                    r["source_id"],
                    r["lot_id"],
                    r["lot_name"],
                    r["lot_code"],
                    r["block_id"],
                    r["analysis_type"],
                    r["value"],
                    r["unit"],
                    r["recorded_at"],
                    r["ingested_at"],
                )
                for r in rows
            ],
        )
    conn.commit()
    return len(rows)


def upsert_vessels(conn, rows: list[dict]) -> int:
    if not rows:
        return 0
    rows = _dedupe_by_key(rows, ("vessel_id",))
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            """
            insert into vessels
                (vessel_id, source_system, vessel_type, code, capacity_gal,
                 volume_gal, capacity_suspect, current_lot_id, current_lot_name,
                 current_lot_code, block_id, archived, updated_at)
            values %s
            on conflict (vessel_id) do update set
                vessel_type = excluded.vessel_type,
                code = excluded.code,
                capacity_gal = excluded.capacity_gal,
                volume_gal = excluded.volume_gal,
                capacity_suspect = excluded.capacity_suspect,
                current_lot_id = excluded.current_lot_id,
                current_lot_name = excluded.current_lot_name,
                current_lot_code = excluded.current_lot_code,
                block_id = excluded.block_id,
                archived = excluded.archived,
                updated_at = excluded.updated_at
            """,
            [
                (
                    r["vessel_id"],
                    r["source_system"],
                    r["vessel_type"],
                    r["code"],
                    r["capacity_gal"],
                    r["volume_gal"],
                    r["capacity_suspect"],
                    r["current_lot_id"],
                    r["current_lot_name"],
                    r["current_lot_code"],
                    r["block_id"],
                    r["archived"],
                    r["updated_at"],
                )
                for r in rows
            ],
        )
    conn.commit()
    return len(rows)


def upsert_harvest_receipts(conn, rows: list[dict], vintages: list[int]) -> tuple[int, int]:
    """Upsert receipts, then delete stale rows for the vintages just fetched.

    Deliberately NOT pure-upsert, unlike upsert_lot_analyses/upsert_vessels
    above. Those sources expose a deleted/archived flag, so a removed record
    arrives as data. /growerReceipts exposes neither a `deleted` field nor a
    `state` filter -- a deleted receipt simply vanishes from the response, and
    reconciling the full per-vintage payload is the only way to notice.

    Scoping is the entire safety of this, per the Track 2 irrigation scoping
    mistake in docs/SECURITY.md: the delete is bounded to source_system
    'innovint' AND the specific vintages fetched this run. `vintages` is passed
    explicitly by the caller rather than derived from `rows`, so a vintage that
    legitimately returned zero receipts is still reconciled -- while a failed
    fetch raises before reaching here and deletes nothing.
    """
    if not vintages:
        return (0, 0)
    rows = _dedupe_by_key(rows, ("innovint_receipt_id",))
    with conn.cursor() as cur:
        if rows:
            psycopg2.extras.execute_values(
                cur,
                """
                insert into harvest_receipts
                    (innovint_receipt_id, innovint_action_id, innovint_lot_id,
                     innovint_block_id, block_id, vintage, weight_value,
                     weight_unit, weight_tons, receipt_date, weigh_tag_number,
                     varietal_name, lot_code, lot_name, grower_id, vineyard_id,
                     appellation_id, source_system, synced_at)
                values %s
                on conflict (innovint_receipt_id) do update set
                    innovint_action_id = excluded.innovint_action_id,
                    innovint_lot_id    = excluded.innovint_lot_id,
                    innovint_block_id  = excluded.innovint_block_id,
                    block_id           = excluded.block_id,
                    vintage            = excluded.vintage,
                    weight_value       = excluded.weight_value,
                    weight_unit        = excluded.weight_unit,
                    weight_tons        = excluded.weight_tons,
                    receipt_date       = excluded.receipt_date,
                    weigh_tag_number   = excluded.weigh_tag_number,
                    varietal_name      = excluded.varietal_name,
                    lot_code           = excluded.lot_code,
                    lot_name           = excluded.lot_name,
                    grower_id          = excluded.grower_id,
                    vineyard_id        = excluded.vineyard_id,
                    appellation_id     = excluded.appellation_id,
                    synced_at          = excluded.synced_at
                """,
                [
                    (
                        r["innovint_receipt_id"], r["innovint_action_id"],
                        r["innovint_lot_id"], r["innovint_block_id"], r["block_id"],
                        r["vintage"], r["weight_value"], r["weight_unit"],
                        r["weight_tons"], r["receipt_date"], r["weigh_tag_number"],
                        r["varietal_name"], r["lot_code"], r["lot_name"],
                        r["grower_id"], r["vineyard_id"], r["appellation_id"],
                        r["source_system"], r["synced_at"],
                    )
                    for r in rows
                ],
            )
        cur.execute(
            """
            delete from harvest_receipts
            where source_system = 'innovint'
              and vintage = any(%s)
              and not (innovint_receipt_id = any(%s))
            """,
            (vintages, [r["innovint_receipt_id"] for r in rows]),
        )
        deleted = cur.rowcount
    conn.commit()
    return (len(rows), deleted)
