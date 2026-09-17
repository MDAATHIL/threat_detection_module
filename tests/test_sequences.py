#!/usr/bin/env python3
"""Unit tests for the order-aware sequence (chain) rules."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import sequences
from sequences import EventView, detect_chains


def ev(event_id: int, path: str, access: str = "read", process: str = "cat",
       artifact: str = "ssh", t: float = 0.0) -> EventView:
    return EventView(id=event_id, path=path, access_type=access,
                     process=process, artifact=artifact, t=t)


class TestSshKeyInjection(unittest.TestCase):
    KEY = "/home/debian/.ssh/id_rsa"
    AUTH = "/home/debian/.ssh/authorized_keys"

    def test_fires_on_key_then_authorized_keys_write(self):
        events = [ev(1, self.KEY, "read", t=0.0),
                  ev(2, self.AUTH, "write", "bash", t=5.0)]
        matches = sequences.rule_ssh_key_injection(events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule, "ssh_key_injection")
        self.assertEqual(matches[0].event_ids, [1, 2])

    def test_quiet_when_authorized_keys_is_only_read(self):
        events = [ev(1, self.KEY, "read", t=0.0),
                  ev(2, self.AUTH, "read", t=1.0)]
        self.assertEqual(sequences.rule_ssh_key_injection(events), [])

    def test_quiet_when_order_is_reversed(self):
        events = [ev(1, self.AUTH, "write", "bash", t=0.0),
                  ev(2, self.KEY, "read", t=1.0)]
        self.assertEqual(sequences.rule_ssh_key_injection(events), [])

    def test_quiet_when_key_never_touched(self):
        events = [ev(1, self.AUTH, "write", "bash", t=0.0)]
        self.assertEqual(sequences.rule_ssh_key_injection(events), [])

    def test_quiet_outside_the_window(self):
        events = [ev(1, self.KEY, "read", t=0.0),
                  ev(2, self.AUTH, "write", "bash",
                     t=sequences.CHAIN_WINDOW_SECONDS + 1)]
        self.assertEqual(sequences.rule_ssh_key_injection(events), [])

    def test_pem_files_count_as_private_keys(self):
        events = [ev(1, "/home/debian/.ssh/server.pem", "read", t=0.0),
                  ev(2, self.AUTH, "create", "bash", t=2.0)]
        self.assertEqual(len(sequences.rule_ssh_key_injection(events)), 1)


class TestBulkCredentialDelete(unittest.TestCase):
    def test_fires_at_threshold(self):
        events = [ev(i, f"/home/debian/.aws/f{i}", "delete", t=float(i))
                  for i in range(sequences.BULK_DELETE_FILES)]
        matches = sequences.rule_bulk_credential_delete(events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule, "bulk_credential_delete")

    def test_quiet_below_threshold(self):
        events = [ev(i, f"/home/debian/.aws/f{i}", "delete", t=float(i))
                  for i in range(sequences.BULK_DELETE_FILES - 1)]
        self.assertEqual(sequences.rule_bulk_credential_delete(events), [])

    def test_repeated_deletes_of_one_file_do_not_count(self):
        events = [ev(i, "/home/debian/.aws/credentials", "delete", t=float(i))
                  for i in range(6)]
        self.assertEqual(sequences.rule_bulk_credential_delete(events), [])


class TestCrossArtifactSweep(unittest.TestCase):
    def test_fires_when_three_stores_are_touched(self):
        events = [ev(1, "/home/debian/.aws/credentials", artifact="aws"),
                  ev(2, "/home/debian/.azure/accessTokens.json", artifact="azure"),
                  ev(3, "/home/debian/.kube/config", artifact="kube")]
        matches = sequences.rule_cross_artifact_sweep(events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule, "cross_artifact_sweep")

    def test_quiet_for_two_stores(self):
        events = [ev(1, "/home/debian/.aws/credentials", artifact="aws"),
                  ev(2, "/home/debian/.azure/accessTokens.json", artifact="azure")]
        self.assertEqual(sequences.rule_cross_artifact_sweep(events), [])


class TestRapidMultiFileSweep(unittest.TestCase):
    def test_fires_when_files_are_touched_quickly(self):
        events = [ev(i, f"/home/debian/.aws/f{i}", t=i * 0.5)
                  for i in range(sequences.RAPID_SWEEP_FILES)]
        matches = sequences.rule_rapid_multi_file_sweep(events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule, "rapid_multi_file_sweep")

    def test_quiet_when_the_same_file_repeats(self):
        events = [ev(i, "/home/debian/.aws/credentials", t=i * 0.5)
                  for i in range(10)]
        self.assertEqual(sequences.rule_rapid_multi_file_sweep(events), [])

    def test_quiet_when_spread_out_over_time(self):
        events = [ev(i, f"/home/debian/.aws/f{i}", t=i * 30.0)
                  for i in range(sequences.RAPID_SWEEP_FILES)]
        self.assertEqual(sequences.rule_rapid_multi_file_sweep(events), [])


class TestDetectChains(unittest.TestCase):
    def test_benign_session_is_quiet(self):
        events = [ev(1, "/home/debian/.aws/config", "read", "bash", "aws", 0.0),
                  ev(2, "/home/debian/.aws/config", "write", "bash", "aws", 0.2),
                  ev(3, "/home/debian/.aws/credentials", "read", "cat", "aws", 0.3)]
        self.assertEqual(detect_chains(events), [])

    def test_empty_session_is_quiet(self):
        self.assertEqual(detect_chains([]), [])

    def test_all_rules_are_callable(self):
        for rule in sequences.RULES:
            self.assertEqual(rule([]), [])


class TestEventView(unittest.TestCase):
    def test_name_is_the_basename(self):
        self.assertEqual(ev(1, "/home/debian/.ssh/id_rsa").name, "id_rsa")

    def test_missing_timestamps_do_not_hide_a_chain(self):
        # No usable clock: fall back to event order rather than silence.
        events = [ev(1, "/home/debian/.ssh/id_rsa", t=None),
                  ev(2, "/home/debian/.ssh/authorized_keys", "write", t=None)]
        self.assertEqual(len(sequences.rule_ssh_key_injection(events)), 1)


if __name__ == "__main__":
    unittest.main()
