#!/usr/bin/env python3

import os
import sqlite3
from pathlib import Path
from datetime import datetime


DB_PATH = Path(os.path.dirname(os.path.abspath(__file__))) / "collector.db"


def get_conn() -> sqlite3.Connection:
    """Return a connection to the collector database."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create tables if they do not exist, and add new columns if missing."""
    conn = get_conn()
    
    # Check if events table exists
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
    )
    table_exists = cursor.fetchone() is not None
    
    if not table_exists:
        # Create fresh table with all columns
        conn.executescript(
            """
            CREATE TABLE events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                artifact_path   TEXT    NOT NULL,
                access_type     TEXT    NOT NULL,
                pid             INTEGER,
                process_name    TEXT,
                ppid            INTEGER,
                parent_process_name TEXT,
                user_id         INTEGER,
                username        TEXT,
                time_delta      REAL,
                session_id      TEXT,
                files_in_session INTEGER
            );

            CREATE INDEX idx_events_artifact
                ON events(artifact_path);
            CREATE INDEX idx_events_timestamp
                ON events(timestamp);
            CREATE INDEX idx_events_user
                ON events(user_id);
            CREATE INDEX idx_events_session
                ON events(session_id);
            """
        )
        print("✓ Created events table with all columns")
    else:
        # Table exists — add missing columns
        _migrate_db(conn)
    
    # Create baseline table if not exists
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS baseline (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_path       TEXT    NOT NULL,
            user_id             INTEGER NOT NULL,
            process_name        TEXT    NOT NULL,
            access_count        INTEGER NOT NULL DEFAULT 0,
            first_seen          TEXT    NOT NULL,
            last_seen           TEXT    NOT NULL,
            normal_hours        TEXT,
            avg_access_interval REAL,
            created_at          TEXT    NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_baseline_key
            ON baseline(artifact_path, user_id, process_name);
        """
    )
    
    conn.commit()
    conn.close()


def _migrate_db(conn) -> None:
    """Add new columns to existing tables if they don't exist."""
    # Get existing columns in events table
    cursor = conn.execute("PRAGMA table_info(events)")
    existing_columns = {row["name"] for row in cursor.fetchall()}
    
    # Add timing columns if missing
    migrations = [
        ("time_delta", "REAL"),
        ("session_id", "TEXT"),
        ("files_in_session", "INTEGER"),
    ]
    
    for col_name, col_type in migrations:
        if col_name not in existing_columns:
            try:
                conn.execute(f"ALTER TABLE events ADD COLUMN {col_name} {col_type}")
                print(f"  ✓ Added column: {col_name}")
            except Exception as e:
                # Column might already exist or other error
                pass


def insert_event(
    artifact_path: str,
    access_type: str,
    pid: int | None = None,
    process_name: str | None = None,
    ppid: int | None = None,
    parent_process_name: str | None = None,
    user_id: int | None = None,
    username: str | None = None,
    time_delta: float | None = None,
    session_id: str | None = None,
    files_in_session: int | None = None,
) -> int:
    """Insert a filesystem access event. Returns the new row id."""
    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO events
            (timestamp, artifact_path, access_type,
             pid, process_name, ppid, parent_process_name,
             user_id, username, time_delta, session_id, files_in_session)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            time_delta,
            session_id,
            files_in_session,
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
