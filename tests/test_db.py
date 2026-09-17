#!/usr/bin/env python3
"""Unit tests for the SQLite schema, migrations, and insert/fetch helpers.

Each test runs against a throwaway database so the real collector.db is
never touched.
"""

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import db


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_path = db.DB_PATH
        db.DB_PATH = Path(self._tmp.name) / "test.db"

    def tearDown(self):
        db.DB_PATH = self._old_path
        self._tmp.cleanup()

    def test_init_creates_expected_schema(self):
        db.init_db()
        conn = db.get_conn()
        tables = {
            r["name"]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        self.assertIn("events", tables)
        self.assertIn("baseline", tables)
        conn.close()

    def test_init_is_idempotent(self):
        db.init_db()
        db.init_db()  # must not raise
        conn = db.get_conn()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
        conn.close()

    def test_insert_and_get_event_roundtrip(self):
        db.init_db()
        row_id = db.insert_event(
            artifact_path="/home/debian/.aws/credentials",
            access_type="read",
            pid=4242,
            process_name="cat",
            ppid=1,
            parent_process_name="bash",
            user_id=1000,
            username="debian",
            time_delta=0.25,
            session_id="normal_1234",
            files_in_session=2,
        )
        row = db.get_event(row_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["artifact_path"], "/home/debian/.aws/credentials")
        self.assertEqual(row["process_name"], "cat")
        self.assertEqual(row["files_in_session"], 2)
        self.assertAlmostEqual(row["time_delta"], 0.25)

    def test_missing_event_returns_none(self):
        db.init_db()
        self.assertIsNone(db.get_event(999999))

    def test_upsert_baseline_updates_in_place(self):
        db.init_db()
        kwargs = dict(
            artifact_path="/home/debian/.ssh",
            user_id=1000,
            process_name="cat",
            first_seen="2026-08-10T00:00:00+00:00",
            last_seen="2026-08-10T01:00:00+00:00",
            normal_hours="[10]",
            avg_access_interval=5.0,
        )
        db.upsert_baseline(access_count=1, **kwargs)
        db.upsert_baseline(access_count=7, **kwargs)

        conn = db.get_conn()
        rows = conn.execute(
            "SELECT * FROM baseline WHERE artifact_path = ?", ("/home/debian/.ssh",)
        ).fetchall()
        conn.close()
        self.assertEqual(len(rows), 1, "upsert must not create duplicate profiles")
        self.assertEqual(rows[0]["access_count"], 7)

    def test_migration_adds_timing_columns_to_legacy_table(self):
        # Simulate a database created before timing features existed.
        conn = sqlite3.connect(str(db.DB_PATH))
        conn.execute(
            """
            CREATE TABLE events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                access_type   TEXT NOT NULL,
                pid           INTEGER,
                process_name  TEXT,
                ppid          INTEGER,
                parent_process_name TEXT,
                user_id       INTEGER,
                username      TEXT
            )
            """
        )
        conn.commit()
        conn.close()

        db.init_db()

        conn = db.get_conn()
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(events)")}
        conn.close()
        self.assertTrue({"time_delta", "session_id", "files_in_session"} <= columns)


if __name__ == "__main__":
    unittest.main()
