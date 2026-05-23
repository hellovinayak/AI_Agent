"""Async SQLite database layer using aiosqlite.

Provides connection management, schema initialisation, and CRUD helpers used
throughout the application.  No ORM — all queries are plain SQL executed via
parameterised statements for safety and transparency.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import aiosqlite

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Module-level connection reference ────────────────────────────────────────
_db: aiosqlite.Connection | None = None

# ── Schema DDL ───────────────────────────────────────────────────────────────

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    rule_id TEXT,
    event_type TEXT,
    user_name TEXT,
    ip_address TEXT,
    location TEXT,
    device TEXT,
    severity TEXT,
    raw_message TEXT,
    confidence_score REAL,
    adjusted_severity TEXT,
    fp_reason TEXT,
    status TEXT DEFAULT 'open',
    ai_analysis TEXT,
    incident_id TEXT,
    analyst_verdict TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT,
    severity TEXT,
    status TEXT DEFAULT 'open',
    created_at TEXT,
    updated_at TEXT,
    affected_user TEXT,
    affected_ip TEXT,
    alert_ids TEXT,
    timeline TEXT,
    ai_narrative TEXT,
    mitre_tactics TEXT,
    recommended_actions TEXT,
    business_impact TEXT,
    response_actions TEXT
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    user_name TEXT,
    ip_address TEXT,
    location TEXT,
    device TEXT,
    event_type TEXT,
    severity TEXT,
    raw_message TEXT,
    simulation_type TEXT
);

CREATE TABLE IF NOT EXISTS response_actions (
    id TEXT PRIMARY KEY,
    action_type TEXT,
    target TEXT,
    executed_at TEXT,
    executed_by TEXT,
    status TEXT,
    incident_id TEXT,
    alert_id TEXT,
    verification_method TEXT,
    audit_trail_id TEXT,
    rollback_available INTEGER,
    rollback_window_seconds INTEGER
);

CREATE TABLE IF NOT EXISTS user_baselines (
    user_id TEXT PRIMARY KEY,
    normal_hour_sin_mean REAL,
    normal_hour_cos_mean REAL,
    known_ip_subnets TEXT,
    known_devices TEXT,
    avg_daily_events REAL,
    avg_fail_rate REAL,
    last_updated TEXT
);
"""


# ── Connection helpers ───────────────────────────────────────────────────────

async def get_db() -> aiosqlite.Connection:
    """Return the shared database connection, creating it if needed."""
    global _db
    if _db is None:
        _db = await aiosqlite.connect(settings.db_path)
        _db.row_factory = aiosqlite.Row
        await _db.execute("PRAGMA journal_mode=WAL;")
        await _db.execute("PRAGMA foreign_keys=ON;")
    return _db


async def init_db() -> None:
    """Create all tables if they do not exist yet."""
    db = await get_db()
    await db.executescript(_SCHEMA_SQL)
    await db.commit()
    logger.info("Database initialised at %s", settings.db_path)


async def close_db() -> None:
    """Close the shared connection gracefully."""
    global _db
    if _db is not None:
        await _db.close()
        _db = None
        logger.info("Database connection closed.")


# ── Generic CRUD helpers ─────────────────────────────────────────────────────

async def insert_row(table: str, data: dict[str, Any]) -> None:
    """Insert a single row into *table* using the key/value pairs in *data*."""
    db = await get_db()
    columns = ", ".join(data.keys())
    placeholders = ", ".join(["?"] * len(data))
    sql = f"INSERT OR REPLACE INTO {table} ({columns}) VALUES ({placeholders})"
    await db.execute(sql, list(data.values()))
    await db.commit()


async def fetch_one(table: str, row_id: str, id_col: str = "id") -> dict[str, Any] | None:
    """Fetch a single row by its primary key."""
    db = await get_db()
    cursor = await db.execute(f"SELECT * FROM {table} WHERE {id_col} = ?", [row_id])
    row = await cursor.fetchone()
    if row is None:
        return None
    return dict(row)


async def fetch_many(
    table: str,
    *,
    page: int = 1,
    page_size: int = 20,
    filters: dict[str, Any] | None = None,
    order_by: str = "created_at DESC",
) -> tuple[list[dict[str, Any]], int]:
    """Paginated fetch with optional equality filters.

    Returns ``(rows, total_count)``.
    """
    db = await get_db()
    where_clauses: list[str] = []
    params: list[Any] = []

    if filters:
        for col, val in filters.items():
            if val is not None and val != "":
                where_clauses.append(f"{col} = ?")
                params.append(val)

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # Total count
    count_cursor = await db.execute(f"SELECT COUNT(*) FROM {table}{where_sql}", params)
    total = (await count_cursor.fetchone())[0]

    # Paginated data
    offset = (page - 1) * page_size
    data_cursor = await db.execute(
        f"SELECT * FROM {table}{where_sql} ORDER BY {order_by} LIMIT ? OFFSET ?",
        params + [page_size, offset],
    )
    rows = [dict(r) for r in await data_cursor.fetchall()]
    return rows, total


async def update_row(table: str, row_id: str, data: dict[str, Any], id_col: str = "id") -> None:
    """Update columns for a single row identified by *row_id*."""
    db = await get_db()
    set_clause = ", ".join(f"{k} = ?" for k in data)
    values = list(data.values()) + [row_id]
    await db.execute(f"UPDATE {table} SET {set_clause} WHERE {id_col} = ?", values)
    await db.commit()


async def delete_all(table: str) -> int:
    """Delete all rows from *table*. Returns the number of deleted rows."""
    db = await get_db()
    cursor = await db.execute(f"DELETE FROM {table}")
    await db.commit()
    return cursor.rowcount  # type: ignore[return-value]


async def execute_sql(sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
    """Run arbitrary read SQL and return rows as dicts."""
    db = await get_db()
    cursor = await db.execute(sql, params or [])
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]
