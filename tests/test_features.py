#!/usr/bin/env python3
"""Unit tests for feature extraction and bucketing.

These are the pieces every score depends on: if a bucket boundary moves,
the calibration in anomaly_detector.py is no longer valid.
"""

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ml"))

import anomaly_detector as ad


class TestTimeDeltaBuckets(unittest.TestCase):
    def test_none_is_treated_as_normal(self):
        # The collector reports None for the first event of a session.
        self.assertEqual(ad._bucketize_time_delta(None), "normal")

    def test_boundaries(self):
        cases = [
            (0.0, "instant"),
            (0.099, "instant"),
            (0.1, "rapid"),
            (0.999, "rapid"),
            (1.0, "normal"),
            (59.9, "normal"),
            (60.0, "slow"),
            (599.0, "slow"),
            (600.0, "idle"),
            (10_000.0, "idle"),
        ]
        for delta, expected in cases:
            with self.subTest(delta=delta):
                self.assertEqual(ad._bucketize_time_delta(delta), expected)

    def test_covers_all_named_states(self):
        self.assertEqual(set(ad.TIME_DELTA_NAMES), set(ad.TIME_DELTA_BUCKETS))


class TestSessionSizeBuckets(unittest.TestCase):
    def test_none_and_zero_are_single(self):
        self.assertEqual(ad._bucketize_session_size(None), "single")
        self.assertEqual(ad._bucketize_session_size(0), "single")
        self.assertEqual(ad._bucketize_session_size(1), "single")

    def test_boundaries(self):
        cases = [
            (2, "small"), (5, "small"),
            (6, "medium"), (20, "medium"),
            (21, "large"), (50, "large"),
            (51, "burst"), (1000, "burst"),
        ]
        for count, expected in cases:
            with self.subTest(count=count):
                self.assertEqual(ad._bucketize_session_size(count), expected)

    def test_normal_vs_attack_never_share_a_bucket(self):
        # The whole detection story rests on this: a normal session is at
        # most 5 distinct files, an attack sweep is at least 20.
        self.assertNotEqual(
            ad._bucketize_session_size(5), ad._bucketize_session_size(20)
        )


class TestHourAndDayBuckets(unittest.TestCase):
    def test_hour_buckets(self):
        for hour, expected in [(0, "night"), (5, "night"), (6, "early"),
                               (9, "morning"), (12, "midday"),
                               (14, "afternoon"), (23, "evening")]:
            dt = datetime(2026, 8, 10, hour, tzinfo=timezone.utc)
            with self.subTest(hour=hour):
                self.assertEqual(ad._bucketize_hour(dt), expected)

    def test_day_buckets(self):
        monday = datetime(2026, 8, 10, 12, tzinfo=timezone.utc)
        saturday = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
        self.assertEqual(ad._bucketize_day(monday), "weekday")
        self.assertEqual(ad._bucketize_day(saturday), "weekend")


class TestArtifactCategorization(unittest.TestCase):
    def test_known_artifacts(self):
        cases = [
            ("/home/debian/.azure/config", "azure"),
            ("/home/debian/.aws/credentials", "aws"),
            ("/home/debian/.ssh/id_rsa", "ssh"),
            ("/home/debian/.kube/config", "kube"),
            ("/home/debian/.steampipe/config", "steampipe"),
            ("/etc/shadow", "shadow"),
        ]
        for path, expected in cases:
            with self.subTest(path=path):
                self.assertEqual(ad._categorize_artifact(path), expected)


class TestExtractEventFeatures(unittest.TestCase):
    def _row(self, **overrides):
        row = {
            "id": 1,
            "timestamp": "2026-08-10T10:30:00+00:00",
            "artifact_path": "/home/debian/.aws/credentials",
            "access_type": "read",
            "process_name": "cat",
            "username": "debian",
            "time_delta": 2.0,
            "files_in_session": 1,
        }
        row.update(overrides)
        return row

    def test_known_values_pass_through(self):
        feats = ad.extract_event_features(self._row())
        self.assertEqual(feats["artifact"], "aws")
        self.assertEqual(feats["process"], "cat")
        self.assertEqual(feats["user"], "debian")
        self.assertEqual(feats["access_type"], "read")
        self.assertEqual(feats["hour_bucket"], "morning")
        self.assertEqual(feats["day_bucket"], "weekday")
        self.assertEqual(feats["time_delta"], "normal")
        self.assertEqual(feats["session_size"], "single")

    def test_unknown_values_collapse_to_other(self):
        feats = ad.extract_event_features(
            self._row(process_name="evil_tool", username="mallory")
        )
        self.assertEqual(feats["process"], "other")
        self.assertEqual(feats["user"], "other")

    def test_bad_timestamp_does_not_raise(self):
        feats = ad.extract_event_features(self._row(timestamp="not-a-date"))
        self.assertIn(feats["hour_bucket"], ad.BUCKET_NAMES)
        self.assertIn(feats["day_bucket"], ad.DAY_BUCKET_NAMES)

    def test_missing_optional_columns(self):
        row = self._row()
        del row["time_delta"]
        del row["files_in_session"]
        feats = ad.extract_event_features(row)
        self.assertEqual(feats["time_delta"], "normal")
        self.assertEqual(feats["session_size"], "single")

    def test_every_feature_has_a_known_state(self):
        feats = ad.extract_event_features(self._row())
        for node, value in feats.items():
            states = ad.NODE_STATES.get(node)
            if states is None:  # artifact is dynamic
                continue
            self.assertIn(value, states, f"{node}={value} not in {states}")


class TestCpdHelpers(unittest.TestCase):
    def test_root_cpd_is_a_distribution(self):
        cpd = ad._build_cpd_from_counts(
            variable="artifact", parent=None,
            counts={"aws": 8, "ssh": 2},
            variable_states=["aws", "ssh"],
            parent_states=None,
        )
        self.assertAlmostEqual(float(sum(cpd.values.flatten())), 1.0, places=6)

    def test_conditional_columns_are_distributions(self):
        cpd = ad._build_cpd_from_counts(
            variable="process", parent="artifact",
            counts={"aws": {"cat": 5, "bash": 5}},
            variable_states=ad.KNOWN_PROCESSES + ["other"],
            parent_states=["aws", "ssh"],
        )
        self.assertAlmostEqual(float(cpd.values.sum(axis=0)[0]), 1.0, places=6)
        # Laplace smoothing keeps an unobserved parent state valid.
        self.assertAlmostEqual(float(cpd.values.sum(axis=0)[1]), 1.0, places=6)

    def test_multi_parent_cpd_is_a_distribution(self):
        cpd = ad._build_cpd_multi_parent(
            variable="session_size",
            parents=["process", "time_delta"],
            counts={("cat", "rapid"): {"single": 3, "small": 1}},
            variable_states=ad.SESSION_SIZE_NAMES,
            parent_states_map={
                "process": ["cat", "bash"],
                "time_delta": ["rapid", "normal"],
            },
        )
        self.assertAlmostEqual(float(cpd.values.sum(axis=0).min()), 1.0, places=6)
        self.assertAlmostEqual(float(cpd.values.sum(axis=0).max()), 1.0, places=6)


if __name__ == "__main__":
    unittest.main()
