#!/usr/bin/env python3
"""Alert sinks — where a flag goes once it fires.

The collector always logs to stdout. This module adds two optional sinks so
alerts can leave the box:

  syslog   local logging daemon (SOC pipelines, journald)
  webhook  HTTP POST of the alert as JSON (Slack-style relay, ticketing)

Configure in `policy_v2.yaml`:

    alerting:
      syslog:
        enabled: true
        facility: LOCAL0
      webhook:
        enabled: true
        url: "https://example.internal/hooks/tdt"
        timeout: 5

Environment variables override the file, which is handy for containers:

    TDT_SYSLOG_ENABLED=1
    TDT_WEBHOOK_URL=https://example.internal/hooks/tdt

Every sink is best-effort: a failing sink logs a warning and never raises,
because alerting must not be able to take the collector down.

Usage:
    from alerts import emit
    emit({"type": "risk", "risk_level": "suspicious", "risk_score": 84.5, ...})
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
from copy import deepcopy
from logging.handlers import SysLogHandler
from pathlib import Path
from urllib import request as _request
from urllib.error import URLError

import yaml

log = logging.getLogger("alerts")

POLICY_PATH = Path(__file__).resolve().parent / "policy_v2.yaml"

DEFAULT_CONFIG: dict = {
    "syslog": {"enabled": False, "facility": "LOCAL0"},
    "webhook": {"enabled": False, "url": "", "timeout": 5.0},
}

_TRUTHY = {"1", "true", "yes", "on"}

_syslog_handler: SysLogHandler | None = None
_config_cache: dict | None = None


def _as_bool(value) -> bool:
    return str(value).strip().lower() in _TRUTHY


def load_alert_config(policy_path: Path | str | None = None,
                      *, refresh: bool = False) -> dict:
    """Merge default sinks, the policy file, and environment overrides.

    Results are cached so the hot path (one call per alert) does not re-read
    the policy file. Pass `refresh=True` to re-read.
    """
    global _config_cache
    if policy_path is None and _config_cache is not None and not refresh:
        return _config_cache

    config = deepcopy(DEFAULT_CONFIG)

    path = Path(policy_path) if policy_path else POLICY_PATH
    try:
        policy = yaml.safe_load(path.read_text()) or {}
        section = policy.get("alerting") or {}
        for name in ("syslog", "webhook"):
            if isinstance(section.get(name), dict):
                config[name].update(
                    {k: v for k, v in section[name].items() if v is not None}
                )
    except (OSError, yaml.YAMLError) as e:
        log.debug("No usable alerting config in %s: %s", path, e)

    if "TDT_SYSLOG_ENABLED" in os.environ:
        config["syslog"]["enabled"] = _as_bool(os.environ["TDT_SYSLOG_ENABLED"])
    if os.environ.get("TDT_WEBHOOK_URL"):
        config["webhook"]["enabled"] = True
        config["webhook"]["url"] = os.environ["TDT_WEBHOOK_URL"]

    if policy_path is None:
        _config_cache = config
    return config


def _get_syslog_handler(facility: str) -> SysLogHandler:
    """Create (and cache) a syslog handler for the local daemon."""
    global _syslog_handler
    if _syslog_handler is not None:
        return _syslog_handler

    facility_value = getattr(SysLogHandler, f"LOG_{facility.upper()}",
                             SysLogHandler.LOG_LOCAL0)
    # /dev/log on Linux, /var/run/syslog on macOS; fall back to UDP 514.
    for address in ("/dev/log", "/var/run/syslog"):
        if os.path.exists(address):
            _syslog_handler = SysLogHandler(address=address, facility=facility_value)
            break
    else:
        _syslog_handler = SysLogHandler(
            address=("localhost", 514), facility=facility_value,
            socktype=socket.SOCK_DGRAM,
        )
    _syslog_handler.setFormatter(logging.Formatter("tdt[%(process)d]: %(message)s"))
    return _syslog_handler


def _send_syslog(alert: dict, config: dict) -> None:
    handler = _get_syslog_handler(config.get("facility", "LOCAL0"))
    record = logging.LogRecord(
        name="tdt", level=logging.WARNING, pathname=__file__, lineno=0,
        msg=json.dumps(alert, sort_keys=True), args=(), exc_info=None,
    )
    handler.emit(record)


def _send_webhook(alert: dict, config: dict) -> None:
    url = config.get("url") or ""
    if not url:
        raise ValueError("webhook sink enabled but no url configured")
    body = json.dumps(alert).encode()
    req = _request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "tdt-collector/1.0"},
    )
    with _request.urlopen(req, timeout=float(config.get("timeout", 5.0))) as resp:
        if resp.status >= 400:
            raise URLError(f"webhook returned HTTP {resp.status}")


_SINKS = {"syslog": _send_syslog, "webhook": _send_webhook}


def emit(alert: dict, config: dict | None = None) -> dict[str, str]:
    """Send an alert to every enabled sink.

    Returns {sink_name: "ok" | error message} so callers (and tests) can see
    what happened. Never raises.
    """
    config = config if config is not None else load_alert_config()
    outcomes: dict[str, str] = {}

    for name, sender in _SINKS.items():
        sink_config = config.get(name) or {}
        if not sink_config.get("enabled"):
            continue
        try:
            sender(alert, sink_config)
            outcomes[name] = "ok"
        except Exception as e:  # best-effort: alerting must never break detection
            outcomes[name] = str(e)
            log.warning("Alert sink '%s' failed: %s", name, e)

    return outcomes


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg = load_alert_config()
    print(json.dumps(cfg, indent=2))
    enabled = [n for n in _SINKS if cfg.get(n, {}).get("enabled")]
    if not enabled:
        print("\nNo sinks enabled — set them in policy_v2.yaml or via env vars.")
        sys.exit(0)
    outcome = emit({"type": "test", "message": "alert sink self-test"}, cfg)
    print("\nSelf-test result:", outcome)
