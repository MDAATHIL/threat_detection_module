#!/usr/bin/env python3
"""End-to-end tests for the detection pipeline.

Builds a seeded dataset in a throwaway database, trains the Bayesian
Network, and asserts the two properties the system promises:

  1. Ordinary single-file access is NOT flagged (low false positives).
  2. A sweep across many distinct files IS flagged (true positives).

It also guards the calibrated thresholds: if the score mapping or the
generator drifts, the clean normal/attack gap must still hold.
"""

import random
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ml"))

import db
import anomaly_detector as ad
import generate_test_events as gen

FLAGGED = {"unusual", "suspicious", "anomaly"}
HOME = Path.home()


def _row(**overrides) -> dict:
    """A live-style event row (dicts stand in for sqlite3.Row)."""
    row = {
        "id": 10_000_000,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "artifact_path": str(HOME / ".azure" / "config"),
        "access_type": "write",
        "process_name": "bash",
        "username": "debian",
        "time_delta": 0.2,
        "files_in_session": 1,
    }
    row.update(overrides)
    return row


class TestPipeline(unittest.TestCase):
    """Trained-model tests. One training run is shared across the class."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls._old_db = db.DB_PATH
        cls._old_model = ad.AnomalyDetector.MODEL_PATH
        db.DB_PATH = Path(cls._tmp.name) / "pipeline.db"
        ad.AnomalyDetector.MODEL_PATH = Path(cls._tmp.name) / "model.json"

        db.init_db()
        random.seed(7)
        gen.generate_events(num_per_artifact=40, include_attacks=True)

        conn = db.get_conn()
        cls.rows = conn.execute("SELECT * FROM events ORDER BY timestamp").fetchall()
        conn.close()

        cls.detector = ad.AnomalyDetector()
        cls.detector.train()
        cls.results = cls.detector.score_all_events()

    @classmethod
    def tearDownClass(cls):
        db.DB_PATH = cls._old_db
        ad.AnomalyDetector.MODEL_PATH = cls._old_model
        cls._tmp.cleanup()

    def _ids_with_prefix(self, prefix: str) -> set[int]:
        conn = db.get_conn()
        ids = {
            r["id"] for r in conn.execute("SELECT id, session_id FROM events")
            if str(r["session_id"] or "").startswith(prefix)
        }
        conn.close()
        return ids

    def _burst_ids(self) -> set[int]:
        return self._ids_with_prefix("attack_burst_")

    def _chain_ids(self) -> set[int]:
        return self._ids_with_prefix("attack_chain_")

    def test_dataset_is_labeled(self):
        self.assertEqual(len(self._burst_ids()), 180)
        self.assertEqual(len(self._chain_ids()), 80)
        scored = {r["event_id"] for r in self.results}
        self.assertEqual(len(scored - self._burst_ids() - self._chain_ids()), 200)

    def test_no_normal_event_is_flagged(self):
        attacks = self._burst_ids() | self._chain_ids()
        false_positives = [
            r for r in self.results
            if r["event_id"] not in attacks and r["risk_level"] in FLAGGED
        ]
        self.assertEqual(
            false_positives, [],
            f"{len(false_positives)} normal events were flagged",
        )

    def test_every_burst_attack_event_is_flagged(self):
        missed = [
            r for r in self.results
            if r["event_id"] in self._burst_ids() and r["risk_level"] not in FLAGGED
        ]
        self.assertEqual(missed, [], f"{len(missed)} burst attack events were missed")

    def test_clean_gap_between_normal_and_burst(self):
        burst = self._burst_ids()
        chain = self._chain_ids()
        normal_scores = [r["risk_score"] for r in self.results
                         if r["event_id"] not in burst and r["event_id"] not in chain]
        burst_scores = [r["risk_score"] for r in self.results
                        if r["event_id"] in burst]
        self.assertLess(
            max(normal_scores), min(burst_scores),
            "normal/burst risk distributions overlap — recalibrate thresholds",
        )

    def test_bn_is_blind_to_some_chains(self):
        # Chain attacks mimic normal shape on purpose. The per-event model is
        # not expected to catch them all — that is the sequence layer's job.
        chain = self._chain_ids()
        flagged = [r for r in self.results
                   if r["event_id"] in chain and r["risk_level"] in FLAGGED]
        self.assertLess(
            len(flagged), len(chain),
            "the BN caught every chain event — the blind spot no longer exists",
        )

    def test_sequence_layer_catches_every_chain_session(self):
        import sequences

        sessions = sequences.sessions_from_db()
        chain_sessions = [s for s in sessions if s.startswith("attack_chain")]
        self.assertEqual(len(chain_sessions), 20)
        caught = [s for s in chain_sessions if sequences.detect_chains(sessions[s])]
        self.assertEqual(len(caught), len(chain_sessions))

    def test_sequence_layer_does_not_fire_on_normal_sessions(self):
        import sequences

        sessions = sequences.sessions_from_db()
        normal_sessions = [s for s in sessions if s.startswith("normal_")]
        false_positives = [s for s in normal_sessions
                           if sequences.detect_chains(sessions[s])]
        self.assertEqual(false_positives, [],
                         f"sequence rules fired on {len(false_positives)} normal sessions")

    def test_benign_single_file_append_is_normal(self):
        # `echo test >> ~/.azure/config`: a cluster of events on ONE file.
        result = self.detector.score_event(_row(files_in_session=1, time_delta=0.2))
        self.assertEqual(result["risk_level"], "normal")

    def test_benign_repeat_access_stays_normal(self):
        result = self.detector.score_event(
            _row(access_type="read", files_in_session=3, time_delta=0.4)
        )
        self.assertEqual(result["risk_level"], "normal")

    def test_distinct_file_sweep_is_flagged(self):
        # A credential sweep touches many distinct files in one session.
        result = self.detector.score_event(
            _row(process_name="touch", access_type="create",
                 files_in_session=30, time_delta=0.05)
        )
        self.assertIn(result["risk_level"], FLAGGED)
        self.assertGreaterEqual(result["risk_score"], ad.RISK_SUSPICIOUS)

    def test_score_reports_the_driving_factor(self):
        result = self.detector.score_event(
            _row(process_name="touch", access_type="create",
                 files_in_session=30, time_delta=0.05)
        )
        self.assertEqual(result["worst_factor"], "session_size")
        self.assertIn("session_size", result["explanation"])

    def test_factor_probabilities_are_valid(self):
        result = self.detector.score_event(_row())
        for f in result["factors"]:
            self.assertGreaterEqual(f["probability"], 0.0)
            self.assertLessEqual(f["probability"], 1.0)

    def test_model_roundtrip_preserves_scores(self):
        reloaded = ad.AnomalyDetector()
        self.assertTrue(reloaded.load_model())
        sample = [_row(), _row(process_name="touch", files_in_session=30)]
        for row in sample:
            self.assertAlmostEqual(
                self.detector.score_event(row)["risk_score"],
                reloaded.score_event(row)["risk_score"],
                places=6,
            )


class TestUntrainedModel(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_db = db.DB_PATH
        self._old_model = ad.AnomalyDetector.MODEL_PATH
        db.DB_PATH = Path(self._tmp.name) / "empty.db"
        ad.AnomalyDetector.MODEL_PATH = Path(self._tmp.name) / "absent.json"
        db.init_db()

    def tearDown(self):
        db.DB_PATH = self._old_db
        ad.AnomalyDetector.MODEL_PATH = self._old_model
        self._tmp.cleanup()

    def test_load_model_returns_false_when_absent(self):
        self.assertFalse(ad.AnomalyDetector().load_model())

    def test_scoring_without_a_model_does_not_crash(self):
        result = ad.AnomalyDetector().score_event(_row())
        self.assertEqual(result["risk_level"], "unknown")

    def test_training_on_empty_data_builds_uniform_model(self):
        detector = ad.AnomalyDetector()
        summary = detector.train()
        self.assertEqual(summary["events_trained"], 0)
        self.assertIsNotNone(detector.model)
        self.assertIn(
            detector.score_event(_row())["risk_level"],
            FLAGGED | {"normal"},
        )


if __name__ == "__main__":
    unittest.main()
