#!/usr/bin/env python3
"""
Query a test run's SQLite database for analysis.

Usage:
    python3 query.py results.db summary
    python3 query.py results.db convergence
    python3 query.py results.db assertions
    python3 query.py results.db timeline r1
    python3 query.py results.db sql "SELECT ..."
"""

import sqlite3
import sys
from pathlib import Path


def summary(conn):
    """Print run summary."""
    row = conn.execute("SELECT * FROM run LIMIT 1").fetchone()
    if not row:
        print("No run data found")
        return
    cols = [d[0] for d in conn.execute("SELECT * FROM run LIMIT 1").description]
    for col, val in zip(cols, row):
        print(f"  {col}: {val}")

    # Assertion summary
    results = conn.execute(
        "SELECT passed, COUNT(*) FROM assertions GROUP BY passed"
    ).fetchall()
    for passed, count in results:
        label = "PASS" if passed else "FAIL"
        print(f"  {label}: {count}")


def convergence(conn):
    """Show convergence: how peers_hot evolves over time for relays."""
    print("timestamp\tnode\tpeers_hot")
    rows = conn.execute("""
        SELECT ts, node_id, value FROM observations
        WHERE metric = 'peers_hot' AND node_role = 'relay'
        ORDER BY ts, node_id
    """).fetchall()
    for ts, node, val in rows:
        print(f"{ts}\t{node}\t{int(val)}")


def assertions(conn):
    """Show all assertions."""
    rows = conn.execute(
        "SELECT name, CASE passed WHEN 1 THEN 'PASS' ELSE 'FAIL' END, expected, actual "
        "FROM assertions ORDER BY id"
    ).fetchall()
    for name, result, expected, actual in rows:
        print(f"  {result}: {name} (expected={expected}, actual={actual})")


def timeline(conn, node_id: str):
    """Show metric timeline for a specific node."""
    rows = conn.execute("""
        SELECT ts, phase, metric, value FROM observations
        WHERE node_id LIKE ?
        ORDER BY ts
    """, (f"%{node_id}%",)).fetchall()
    if not rows:
        print(f"No observations for node matching '{node_id}'")
        return
    print("timestamp\tphase\tmetric\tvalue")
    for ts, phase, metric, val in rows:
        print(f"{ts}\t{phase}\t{metric}\t{val}")


def sql_query(conn, query: str):
    """Run arbitrary SQL."""
    rows = conn.execute(query).fetchall()
    if not rows:
        print("(no results)")
        return
    # Print column headers
    cols = [d[0] for d in conn.execute(query).description]
    print("\t".join(cols))
    for row in rows:
        print("\t".join(str(v) for v in row))


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1

    db_path = sys.argv[1]
    command = sys.argv[2]
    extra = sys.argv[3] if len(sys.argv) > 3 else None

    conn = sqlite3.connect(db_path)

    commands = {
        "summary": lambda: summary(conn),
        "convergence": lambda: convergence(conn),
        "assertions": lambda: assertions(conn),
        "timeline": lambda: timeline(conn, extra or "r1"),
        "sql": lambda: sql_query(conn, extra or "SELECT 1"),
    }

    if command in commands:
        commands[command]()
    else:
        print(f"Unknown command: {command}")
        print(f"Available: {', '.join(commands.keys())}")
        return 1

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
