"""SQLite persistence engine for monitoring telemetry snapshots and audit alerts."""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from pathlib import Path
from typing import Any

from pqsysguard.monitor.models import SystemSnapshot
from pqsysguard.utils.logger import get_logger

logger = get_logger("monitor.storage")

SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS metric_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    uptime_seconds REAL NOT NULL,
    cpu_percent REAL NOT NULL,
    load_1m REAL NOT NULL,
    load_5m REAL NOT NULL,
    load_15m REAL NOT NULL,
    memory_percent REAL NOT NULL,
    swap_percent REAL NOT NULL,
    max_disk_percent REAL NOT NULL,
    max_inode_percent REAL NOT NULL,
    net_bytes_sent INTEGER NOT NULL,
    net_bytes_recv INTEGER NOT NULL,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    subsystem TEXT NOT NULL,
    metric TEXT NOT NULL,
    current_value TEXT NOT NULL,
    threshold_value TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON metric_snapshots(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON audit_alerts(timestamp);
"""


def init_db(db_path: Path | str) -> None:
    """Initialize SQLite tables and indexes."""
    target_path = Path(db_path)
    if target_path.parent != Path("."):
        target_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(target_path))
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


def save_snapshot(snapshot: SystemSnapshot, db_path: Path | str) -> int:
    """Save a telemetry snapshot and its alerts into SQLite database."""
    init_db(db_path)
    summary = snapshot.to_summary_dict()
    raw_json = snapshot.model_dump_json()

    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO metric_snapshots (
                timestamp, uptime_seconds, cpu_percent, load_1m, load_5m, load_15m,
                memory_percent, swap_percent, max_disk_percent, max_inode_percent,
                net_bytes_sent, net_bytes_recv, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                summary["timestamp"],
                summary["uptime_seconds"],
                summary["cpu_percent"],
                summary["load_1m"],
                summary["load_5m"],
                summary["load_15m"],
                summary["memory_percent"],
                summary["swap_percent"],
                summary["max_disk_percent"],
                summary["max_inode_percent"],
                summary["net_bytes_sent"],
                summary["net_bytes_recv"],
                raw_json,
            ),
        )
        snapshot_id = cursor.lastrowid or 0

        # Save any alerts triggered
        for alert in snapshot.alerts:
            cursor.execute(
                """
                INSERT INTO audit_alerts (
                    timestamp, subsystem, metric, current_value, threshold_value, severity, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.timestamp.isoformat(),
                    alert.subsystem,
                    alert.metric,
                    str(alert.current_value),
                    str(alert.threshold_value),
                    alert.severity.value,
                    alert.message,
                ),
            )

        conn.commit()
        return snapshot_id
    finally:
        conn.close()


def get_history(db_path: Path | str, limit: int = 100) -> list[dict[str, Any]]:
    """Retrieve recent snapshot summaries from database in descending order."""
    init_db(db_path)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, uptime_seconds, cpu_percent, load_1m, load_5m, load_15m,
                   memory_percent, swap_percent, max_disk_percent, max_inode_percent,
                   net_bytes_sent, net_bytes_recv
            FROM metric_snapshots
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def export_history(db_path: Path | str, export_format: str = "json", limit: int = 100) -> str:
    """Export snapshot history to JSON or CSV string."""
    records = get_history(db_path, limit=limit)
    if not records:
        if export_format.lower() == "csv":
            return ""
        return "[]"

    if export_format.lower() == "csv":
        output = io.StringIO()
        fieldnames = list(records[0].keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
        return output.getvalue()

    return json.dumps(records, indent=2)
