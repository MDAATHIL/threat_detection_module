#!/usr/bin/env python3
"""Unit tests for the collector's session tracking and path matching.

`files_in_session` must count DISTINCT files: a single shell redirect emits
several inotify events on one file and must not look like a credential sweep.
"""

import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import collector
from collector import ArtifactHandler, _map_event_type
from watchdog.events import FileModifiedEvent, FileCreatedEvent, FileDeletedEvent


class TestArtifactMatching(unittest.TestCase):
    def setUp(self):
        self.handler = ArtifactHandler(
            {"/home/debian/.aws", "/home/debian/.ssh"},
            resolver=None, fallback=None, detector=None,
        )

    def test_exact_directory_match(self):
        self.assertEqual(
            self.handler._matches_artifact("/home/debian/.aws"), "/home/debian/.aws"
        )

    def test_nested_file_match(self):
        self.assertEqual(
            self.handler._matches_artifact("/home/debian/.aws/credentials"),
            "/home/debian/.aws",
        )

    def test_unrelated_path_does_not_match(self):
        self.assertIsNone(self.handler._matches_artifact("/home/debian/.bashrc"))
        # Prefix-but-not-child must not match.
        self.assertIsNone(self.handler._matches_artifact("/home/debian/.awsx/file"))


class TestSessionTracking(unittest.TestCase):
    def setUp(self):
        self.handler = ArtifactHandler(
            {"/home/debian/.azure"}, resolver=None, fallback=None, detector=None,
        )

    def test_first_event_has_no_delta(self):
        delta, session_id, files = self.handler._update_session("/a")
        self.assertIsNone(delta)
        self.assertTrue(session_id)
        self.assertEqual(files, 1)

    def test_repeated_events_on_one_file_count_as_one(self):
        # This is the false-positive guard: `echo x >> file` emits a cluster
        # of events, all on the same file.
        for _ in range(6):
            _, _, files = self.handler._update_session("/a")
        self.assertEqual(files, 1)

    def test_distinct_files_accumulate(self):
        for i in range(30):
            _, _, files = self.handler._update_session(f"/file_{i}")
        self.assertEqual(files, 30)

    def test_session_resets_after_timeout(self):
        self.handler._update_session("/a")
        self.handler._update_session("/b")
        # Pretend the gap exceeded SESSION_TIMEOUT.
        self.handler._last_event_time = time.time() - (self.handler.SESSION_TIMEOUT + 5)

        delta, session_id, files = self.handler._update_session("/c")
        self.assertGreater(delta, self.handler.SESSION_TIMEOUT)
        self.assertEqual(files, 1, "a new session starts with one distinct file")

    def test_new_session_gets_a_new_id(self):
        _, first_id, _ = self.handler._update_session("/a")
        self.handler._last_event_time = time.time() - (self.handler.SESSION_TIMEOUT + 5)
        _, second_id, _ = self.handler._update_session("/b")
        self.assertNotEqual(first_id, second_id)


class TestScoringFailureHandling(unittest.TestCase):
    """A broken model must not crash the collector — nor fail silently."""

    class _ExplodingDetector:
        def score_event(self, row):
            raise RuntimeError("model exploded")

    def test_scoring_exception_is_caught_and_counted(self):
        handler = ArtifactHandler(
            {"/home/debian/.azure"}, resolver=None, fallback=None,
            detector=self._ExplodingDetector(),
        )
        original = collector.get_event
        collector.get_event = lambda event_id: {"id": event_id}
        try:
            handler._score_event(1)
            handler._score_event(2)
        finally:
            collector.get_event = original
        self.assertEqual(handler._score_errors, 2)

    def test_no_errors_when_scoring_succeeds(self):
        class FineDetector:
            def score_event(self, row):
                return {"risk_level": "normal", "score": 0.9}

        handler = ArtifactHandler(
            {"/home/debian/.azure"}, resolver=None, fallback=None,
            detector=FineDetector(),
        )
        original = collector.get_event
        collector.get_event = lambda event_id: {"id": event_id}
        try:
            handler._score_event(1)
        finally:
            collector.get_event = original
        self.assertEqual(handler._score_errors, 0)


class TestStoredEventPath(unittest.TestCase):
    """The DB must record the accessed file, not the watched directory.

    The seeded dataset stores full file paths and the chain rules match on
    file names (`id_rsa`, `authorized_keys`). Storing the artifact directory
    instead made every live event look like it touched `.azure`, so DB-based
    chain scanning could never fire on live traffic.
    """

    class _NoProcessResolver:
        def scan_for_file(self, path):
            return None

    def _capture_insert(self, event):
        captured = {}
        handler = ArtifactHandler(
            {"/home/debian/.azure"}, resolver=self._NoProcessResolver(),
            fallback=None, detector=None,
        )
        original_insert = collector.insert_event
        original_get = collector.get_event
        # A scored row is fetched back by id; skip that for this test.
        collector.insert_event = lambda **kw: captured.update(kw) or 1
        collector.get_event = lambda event_id: None
        try:
            handler.on_any_event(event)
        finally:
            collector.insert_event = original_insert
            collector.get_event = original_get
        return captured

    def test_accessed_file_is_stored(self):
        captured = self._capture_insert(
            FileCreatedEvent("/home/debian/.azure/id_rsa")
        )
        self.assertEqual(captured.get("artifact_path"), "/home/debian/.azure/id_rsa")

    def test_stored_path_preserves_the_file_name_for_chain_rules(self):
        captured = self._capture_insert(
            FileModifiedEvent("/home/debian/.azure/authorized_keys")
        )
        self.assertTrue(
            captured["artifact_path"].endswith("/authorized_keys"),
            "the file name must survive into the DB or chain rules cannot match",
        )


class TestEventTypeMapping(unittest.TestCase):
    def test_watchdog_events_map_to_access_types(self):
        self.assertEqual(_map_event_type(FileCreatedEvent("/x")), "create")
        self.assertEqual(_map_event_type(FileModifiedEvent("/x")), "write")
        self.assertEqual(_map_event_type(FileDeletedEvent("/x")), "delete")


if __name__ == "__main__":
    unittest.main()
