#!/usr/bin/env python3
"""Compare every live RLS policy in `public` against what the migrations intend.

    ~/Library/Caches/pypoetry/virtualenvs/ingestion-*/bin/python scripts/check_policy_drift.py

For each (table, policy) the migrations touch, the LAST statement in migration
order wins (create -> intended definition, drop -> intended absent). The live
state is snapshotted first; then, inside ONE transaction that is always rolled
back, every intended policy is re-created from its migration text so Postgres
itself normalizes the expression. The comparison is therefore
Postgres-normalized text vs Postgres-normalized text -- no hand-written
expression parsing.

Reports:
  MATCH           live == intended
  DRIFT           live differs from the last migration's definition
  MISSING         intended by migrations, absent live
  SHOULD-BE-GONE  dropped by a later migration, present live
  LIVE-ONLY       live, but no migration ever defines it (dbt macro, dashboard, ...)
Tables that no longer exist live are listed as skipped. Exit 1 on any DRIFT,
MISSING or SHOULD-BE-GONE.
"""
import pathlib
import re
import sys

import psycopg2

ROOT = pathlib.Path(__file__).resolve().parent.parent
MIGRATIONS = sorted((ROOT / "supabase" / "migrations").glob("*.sql"))


def database_url():
    for line in (ROOT / ".env").read_text().splitlines():
        if line.startswith("DATABASE_URL="):
            return line.split("=", 1)[1].strip().strip("'\"")
    sys.exit("DATABASE_URL not found in .env")


def strip_comments(sql):
    return re.sub(r"--[^\n]*", "", sql)


STMT = re.compile(r"\b(create|drop)\s+policy\s+(if\s+exists\s+)?(\"?[\w]+\"?)\s+on\s+([\w.\"]+)([^;]*);", re.I | re.S)


def intended_policies():
    intended = {}  # (table, policy) -> (action, statement, migration)
    for path in MIGRATIONS:
        for m in STMT.finditer(strip_comments(path.read_text())):
            action, _, name, table = m.group(1).lower(), m.group(2), m.group(3).strip('"'), m.group(4).strip('"')
            table = table.split(".")[-1]
            intended[(table, name)] = (action, m.group(0), path.name)
    return intended


SNAPSHOT = """
select tablename, policyname, permissive, roles::text, cmd, coalesce(qual, ''), coalesce(with_check, '')
from pg_policies where schemaname = 'public'
"""


def main():
    intended = intended_policies()
    conn = psycopg2.connect(database_url())
    conn.autocommit = False
    cur = conn.cursor()
    cur.execute(SNAPSHOT)
    live = {(r[0], r[1]): r[2:] for r in cur.fetchall()}
    cur.execute("select tablename from pg_tables where schemaname = 'public'")
    tables = {r[0] for r in cur.fetchall()}
    conn.rollback()

    normalized = {}
    try:
        for (table, name), (action, stmt, _) in intended.items():
            if action != "create" or table not in tables:
                continue
            cur.execute("savepoint p")
            cur.execute(f'drop policy if exists "{name}" on public."{table}"')
            cur.execute(stmt)
            cur.execute(SNAPSHOT + " and tablename = %s and policyname = %s", (table, name))
            row = cur.fetchone()
            normalized[(table, name)] = row[2:] if row else None
            cur.execute("rollback to savepoint p")
    finally:
        conn.rollback()
        conn.close()

    problems = 0
    lines = []
    for key in sorted(set(intended) | set(live)):
        table, name = key
        if key in intended and table not in tables:
            lines.append(f"skipped         {table}.{name}  (table no longer exists; last touched in {intended[key][2]})")
            continue
        if key not in intended:
            lines.append(f"LIVE-ONLY       {table}.{name}  live: {live[key][2]} USING ({live[key][3] or '-'})")
            continue
        action, _, migration = intended[key]
        if action == "drop":
            if key in live:
                problems += 1
                lines.append(f"SHOULD-BE-GONE  {table}.{name}  dropped in {migration}, still live: USING ({live[key][3]})")
            continue
        if key not in live:
            problems += 1
            lines.append(f"MISSING         {table}.{name}  defined in {migration}, absent live")
            continue
        want, got = normalized[key], live[key]
        if want == got:
            lines.append(f"MATCH           {table}.{name}  ({migration})")
        else:
            problems += 1
            lines.append(f"DRIFT           {table}.{name}  intended by {migration}")
            for label, a, b in zip(["permissive", "roles", "cmd", "USING", "WITH CHECK"], want, got):
                if a != b:
                    lines.append(f"                  {label}: intended {a or '-'}  |  live {b or '-'}")
    print("\n".join(lines))
    print(f"\n{len(live)} live policies, {len(intended)} migration-defined (table, policy) pairs, {problems} problem(s).")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
