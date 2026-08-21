#!/usr/bin/env python3

import sqlite3
from pathlib import Path
from datetime import datetime


DB_PATH = Path(__file__).parent / "collector.db"


def get_conn() -> sqlite3.Connection:
    """Return a connection to the collector database."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create tables if they do not exist."""
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,   -- ISO-8601 UTC
            artifact_path   TEXT    NOT NULL,
            access_type     TEXT    NOT NULL,   -- read, write, create, delete, moved
            pid             INTEGER,
            process_name    TEXT,
            ppid            INTEGER,
            parent_process_name TEXT,
            user_id         INTEGER,
            username        TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_events_artifact
            ON events(artifact_path);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_user
            ON events(user_id);

        CREATE TABLE IF NOT EXISTS baseline (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_path       TEXT    NOT NULL,
            user_id             INTEGER NOT NULL,
            process_name        TEXT    NOT NULL,
            access_count        INTEGER NOT NULL DEFAULT 0,
            first_seen          TEXT    NOT NULL,
            last_seen           TEXT    NOT NULL,
            normal_hours        TEXT,           -- JSON array, e.g. "[9,10,11,14,15]"
            avg_access_interval REAL,           -- seconds between accesses
            created_at          TEXT    NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_baseline_key
            ON baseline(artifact_path, user_id, process_name);
        """
    )
    conn.commit()
    conn.close()


def insert_event(
    artifact_path: str,
    access_type: str,
    pid: int | None = None,
    process_name: str | None = None,
    ppid: int | None = None,
    parent_process_name: str | None = None,
    user_id: int | None = None,
    username: str | None = None,
) -> int:
    """Insert a filesystem access event. Returns the new row id."""
    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO events
            (timestamp, artifact_path, access_type,
             pid, process_name, ppid, parent_process_name,
             user_id, username)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(),
            artifact_path,
            access_type,
            pid,
            process_name,
            ppid,
            parent_process_name,
            user_id,
            username,
        ),
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def upsert_baseline(
    artifact_path: str,
    user_id: int,
    process_name: str,
    access_count: int,
    first_seen: str,
    last_seen: str,
    normal_hours: str,
    avg_access_interval: float | None,
) -> None:
    """Insert or update a baseline profile for a (artifact, user, process) triple."""
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO baseline
            (artifact_path, user_id, process_name,
             access_count, first_seen, last_seen,
             normal_hours, avg_access_interval, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(artifact_path, user_id, process_name)
        DO UPDATE SET
            access_count        = excluded.access_count,
            first_seen          = excluded.first_seen,
            last_seen           = excluded.last_seen,
            normal_hours        = excluded.normal_hours,
            avg_access_interval = excluded.avg_access_interval,
            created_at          = excluded.created_at
        """,
        (
            artifact_path,
            user_id,
            process_name,
            access_count,
            first_seen,
            last_seen,
            normal_hours,
            avg_access_interval,
            datetime.utcnow().isoformat(),
        ),
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")
