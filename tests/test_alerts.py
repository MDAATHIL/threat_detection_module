#!/usr/bin/env python3
"""Unit tests for the alert sinks (config resolution and fan-out)."""

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import alerts


class TestAlertConfig(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.policy = Path(self._tmp.name) / "policy.yaml"
        self._env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        self._tmp.cleanup()

    def _write(self, text: str) -> Path:
        self.policy.write_text(text)
        return self.policy

    def test_defaults_are_off(self):
        cfg = alerts.load_alert_config(self._write("monitoring: []\n"))
        self.assertFalse(cfg["syslog"]["enabled"])
        self.assertFalse(cfg["webhook"]["enabled"])

    def test_policy_file_enables_sinks(self):
        path = self._write(
            "alerting:\n"
            "  syslog:\n"
            "    enabled: true\n"
            "    facility: LOCAL1\n"
            "  webhook:\n"
            "    enabled: true\n"
            "    url: http://example.invalid/hook\n"
        )
        cfg = alerts.load_alert_config(path)
        self.assertTrue(cfg["syslog"]["enabled"])
        self.assertEqual(cfg["syslog"]["facility"], "LOCAL1")
        self.assertEqual(cfg["webhook"]["url"], "http://example.invalid/hook")

    def test_env_overrides_policy_file(self):
        path = self._write("alerting:\n  webhook:\n    enabled: false\n")
        os.environ["TDT_WEBHOOK_URL"] = "http://env.invalid/hook"
        cfg = alerts.load_alert_config(path)
        self.assertTrue(cfg["webhook"]["enabled"])
        self.assertEqual(cfg["webhook"]["url"], "http://env.invalid/hook")

    def test_syslog_env_flag(self):
        path = self._write("monitoring: []\n")
        os.environ["TDT_SYSLOG_ENABLED"] = "1"
        self.assertTrue(alerts.load_alert_config(path)["syslog"]["enabled"])
        os.environ["TDT_SYSLOG_ENABLED"] = "0"
        self.assertFalse(alerts.load_alert_config(path)["syslog"]["enabled"])

    def test_missing_policy_file_is_not_fatal(self):
        cfg = alerts.load_alert_config(Path(self._tmp.name) / "does-not-exist.yaml")
        self.assertFalse(cfg["webhook"]["enabled"])

    def test_real_policy_v2_is_valid_yaml(self):
        cfg = alerts.load_alert_config(ROOT / "policy_v2.yaml")
        self.assertIn("syslog", cfg)


class _Receiver(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):  # noqa: N802 (stdlib naming)
        length = int(self.headers.get("Content-Length", 0))
        _Receiver.received.append((self.path, json.loads(self.rfile.read(length))))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):  # keep test output clean
        pass


class TestEmit(unittest.TestCase):
    def test_no_enabled_sinks_is_a_noop(self):
        config = {"syslog": {"enabled": False}, "webhook": {"enabled": False}}
        self.assertEqual(alerts.emit({"type": "risk"}, config), {})

    def test_webhook_receives_the_alert(self):
        _Receiver.received = []
        server = HTTPServer(("127.0.0.1", 0), _Receiver)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)

        port = server.server_address[1]
        config = {
            "syslog": {"enabled": False},
            "webhook": {"enabled": True,
                        "url": f"http://127.0.0.1:{port}/hook",
                        "timeout": 5},
        }
        alert = {"type": "risk", "risk_level": "suspicious", "risk_score": 84.5}

        outcomes = alerts.emit(alert, config)

        self.assertEqual(outcomes, {"webhook": "ok"})
        self.assertEqual(len(_Receiver.received), 1)
        path, body = _Receiver.received[0]
        self.assertEqual(path, "/hook")
        self.assertEqual(body, alert)

    def test_failing_webhook_is_reported_not_raised(self):
        # Port 1 is reserved and nothing listens there.
        config = {
            "syslog": {"enabled": False},
            "webhook": {"enabled": True, "url": "http://127.0.0.1:1/hook",
                        "timeout": 1},
        }
        outcomes = alerts.emit({"type": "risk"}, config)
        self.assertIn("webhook", outcomes)
        self.assertNotEqual(outcomes["webhook"], "ok")

    def test_enabled_webhook_without_url_is_reported(self):
        config = {"syslog": {"enabled": False},
                  "webhook": {"enabled": True, "url": ""}}
        outcomes = alerts.emit({"type": "risk"}, config)
        self.assertNotEqual(outcomes.get("webhook"), "ok")


if __name__ == "__main__":
    unittest.main()
