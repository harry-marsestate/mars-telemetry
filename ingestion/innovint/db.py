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


def load_innovint_block_map(conn) -> dict[str, str]:
    """InnoVint block id -> local block_id, resolved subset only.

    Loaded once per asset run rather than queried per lot: this mapping
    is small (2 rows today -- B2, B3) and changes rarely, by hand, per
    the blocks.innovint_block_id migration and docs/SECURITY.md. B1 is
    expected to be absent from this dict -- that's the documented,
    correct state (no confident InnoVint block match exists), not an
    error to handle specially.
    """
    with conn.cursor() as cur:
        cur.execute(
            "select innovint_block_id, block_id from blocks where innovint_block_id is not null"
        )
        return dict(cur.fetchall())


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
                 capacity_suspect, current_lot_id, current_lot_name, current_lot_code,
                 block_id, archived, updated_at)
            values %s
            on conflict (vessel_id) do update set
                vessel_type = excluded.vessel_type,
                code = excluded.code,
                capacity_gal = excluded.capacity_gal,
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
