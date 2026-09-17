#!/usr/bin/env python3

"""
Context Collector — monitors sensitive artifacts via inotify (watchdog)
and logs filesystem access events with available context to SQLite.

Process resolution strategy:
  1. If auditd is available: use audit rules + ausearch (zero race condition)
  2. Fallback: scan /proc/*/fd/ (may miss short-lived processes)

Setup for auditd:
  sudo apt install auditd audispd-plugins
  sudo systemctl start auditd
  sudo usermod -aG auditd $(whoami)  # or run collector as root
"""

import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    DirCreatedEvent,
    DirDeletedEvent,
    DirModifiedEvent,
    DirMovedEvent,
)

# ml/ is not a package — load anomaly detector directly from its directory
sys.path.insert(0, str(Path(__file__).parent / "ml"))
from anomaly_detector import AnomalyDetector, _categorize_artifact
from sequences import EventView, detect_chains

import alerts
from db import init_db, insert_event, get_event
from proc_scanner import ProcScanner
from auditd_integration import AuditdResolver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("collector")

POLICY_PATH = Path(__file__).parent / "policy_v2.yaml"


def load_policy() -> list[dict[str, Any]]:
    """Load monitoring targets from policy.yaml.
    Paths containing ~ are expanded to the current user's home directory.
    """
    with open(POLICY_PATH) as f:
        policy = yaml.safe_load(f)
    targets = policy.get("monitoring", [])
    # Expand ~ to the actual home directory
    for t in targets:
        if "path" in t:
            t["path"] = str(Path(t["path"]).expanduser())
    return targets


def _map_event_type(event) -> str:
    """Map watchdog event to a human-readable access type."""
    if isinstance(event, (FileCreatedEvent, DirCreatedEvent)):
        return "create"
    if isinstance(event, (FileDeletedEvent, DirDeletedEvent)):
        return "delete"
    if isinstance(event, (FileMovedEvent, DirMovedEvent)):
        return "moved"
    if isinstance(event, (FileModifiedEvent, DirModifiedEvent)):
        return "write"
    return "read"


class ArtifactHandler(FileSystemEventHandler):
    """Receives inotify events, resolves process context, and logs to SQLite.
    
    Tracks timing patterns to detect burst/frequency-based attacks.
    Scores each event against the anomaly model in real time.
    """

    # Session threshold: events within this many seconds are grouped
    SESSION_TIMEOUT = 5.0  # seconds
    BURST_THRESHOLD = 0.5  # seconds - events faster than this = burst
    
    def __init__(self, watched_paths: set[str], resolver=None, fallback=None,
                 detector: AnomalyDetector | None = None):
        super().__init__()
        self.watched_paths = watched_paths
        self.resolver = resolver  # AuditdResolver or ProcScanner
        self.fallback = fallback  # ProcScanner as fallback when auditd returns nothing
        self.use_auditd = isinstance(resolver, AuditdResolver)
        self.detector = detector  # optional real-time scorer
        self._score_errors = 0    # consecutive scoring failures (for logging)
        # Session tracking for burst detection
        self._last_event_time: float = 0.0
        self._session_id: str | None = None
        self._session_files: set[str] = set()
        self._session_start_time: float = 0.0
        # Ordered events in the current session, for sequence (chain) analysis
        self._session_events: list[EventView] = []
        self._chained_rules: set[str] = set()

    def _matches_artifact(self, path: str) -> str | None:
        """Check if an event path falls under a monitored artifact.
        Returns the artifact path if matched, else None."""
        # Check exact match first
        if path in self.watched_paths:
            return path
        # Check if path is inside a monitored directory
        for watched in self.watched_paths:
            if path.startswith(watched + "/") or path.startswith(watched + os.sep):
                return watched
        return None

    def _score_event(self, event_id: int) -> None:
        """Score a freshly-inserted event against the anomaly model and
        log an inline risk alert if it's anything other than normal."""
        try:
            row = get_event(event_id)
            if row is None:
                return
            result = self.detector.score_event(row)
            level = result["risk_level"]
            if level == "normal":
                log.info(
                    "  risk: NORMAL (score=%.4f)",
                    result["score"],
                )
            else:
                log.warning(
                    "  RISK ALERT: %s (risk=%.1f/100) — %s",
                    level.upper(),
                    result["risk_score"],
                    result["explanation"],
                )
                alerts.emit({
                    "type": "risk",
                    "risk_level": level,
                    "risk_score": round(result["risk_score"], 2),
                    "event_id": event_id,
                    "explanation": result["explanation"],
                    "features": result.get("features", {}),
                })
        except Exception as e:
            # Scoring must never crash the collector, but it must not fail
            # silently either: a broken model would otherwise switch detection
            # off with nothing in the log to show for it.
            self._score_errors += 1
            if self._score_errors <= 3 or self._score_errors % 100 == 0:
                log.warning(
                    "Real-time scoring failed for event #%d "
                    "(%d failure(s) so far): %s",
                    event_id, self._score_errors, e,
                )
            else:
                log.debug("Real-time scoring failed for event #%d: %s", event_id, e)

    def _update_session(self, path: str) -> tuple[float | None, str, int]:
        """Track the current access session for burst detection.

        A session is a run of events separated by less than SESSION_TIMEOUT.
        `files_in_session` counts DISTINCT files touched — that is the
        credential-sweep signal. Repeated events on one file must not inflate
        it, since a single normal shell redirect emits several inotify events.

        Returns:
            (time_delta, session_id, files_in_session)
        """
        now = time.time()
        time_delta = None

        if self._last_event_time > 0:
            time_delta = now - self._last_event_time

            # Start new session if too much time has passed
            if time_delta > self.SESSION_TIMEOUT:
                self._session_id = str(uuid.uuid4())[:8]
                self._session_files = set()
                self._session_events = []
                self._chained_rules = set()
                self._session_start_time = now
        else:
            # First event ever
            self._session_id = str(uuid.uuid4())[:8]
            self._session_files = set()
            self._session_events = []
            self._chained_rules = set()
            self._session_start_time = now

        self._session_files.add(path)
        self._last_event_time = now
        return time_delta, self._session_id, len(self._session_files)

    def on_any_event(self, event):
        """Called for every inotify event."""
        if event.is_directory:
            # We track directory events separately
            src = getattr(event, "src_path", "")
            dest = getattr(event, "dest_path", src)
        else:
            src = getattr(event, "src_path", "")
            dest = getattr(event, "dest_path", src)

        # Check source path
        artifact = self._matches_artifact(src)
        if artifact is None:
            artifact = self._matches_artifact(dest)
        if artifact is None:
            return

        access_type = _map_event_type(event)

        # Resolve process context — try auditd first, fall back to /proc
        ctx = None
        if self.use_auditd:
            ctx = self.resolver.find_process_for_file(src)
            if ctx is None and self.fallback is not None:
                log.debug("auditd returned no process for %s, falling back to /proc", src)
                ctx = self.fallback.scan_for_file(src)
        else:
            ctx = self.resolver.scan_for_file(src)

        # Track timing for burst detection
        time_delta, session_id, files_in_session = self._update_session(src)

        # Store the accessed FILE, not the watched directory. The dataset uses
        # full file paths, the artifact category is derived from the path, and
        # the chain rules match on file names (id_rsa, authorized_keys) — so
        # storing the directory made live events unusable for sequence analysis.
        row_id = insert_event(
            artifact_path=src or artifact,
            access_type=access_type,
            pid=ctx.pid if ctx else None,
            process_name=ctx.comm if ctx else None,
            ppid=ctx.ppid if ctx else None,
            parent_process_name=ctx.parent_comm if ctx else None,
            user_id=ctx.uid if ctx else None,
            username=ctx.username if ctx else None,
            time_delta=time_delta,
            session_id=session_id,
            files_in_session=files_in_session,
        )

        proc_info = f"pid={ctx.pid} comm={ctx.comm} user={ctx.username}" if ctx else "no process found"
        burst_info = f"delta={time_delta:.3f}s" if time_delta else "first_event"
        log.info(
            "Event #%d: %s on %s (artifact=%s, %s, session=%s, %s)",
            row_id,
            access_type,
            src if src != dest else f"{src} -> {dest}",
            artifact,
            proc_info,
            session_id,
            burst_info,
        )

        # Real-time anomaly scoring
        if self.detector is not None:
            self._score_event(row_id)

        # Order-aware sequence analysis (complements the per-event score)
        self._check_chains(row_id, src, access_type, ctx, artifact)

    def _check_chains(self, row_id: int, path: str, access_type: str,
                      ctx, artifact: str) -> None:
        """Run chain rules over the session so far and alert on new matches.

        A chain is reported once, at the event that completes it, so a long
        session does not emit the same alert repeatedly.
        """
        self._session_events.append(EventView(
            id=row_id,
            path=path,
            access_type=access_type,
            process=(ctx.comm if ctx else "unknown").lower(),
            artifact=artifact,
            t=time.time(),
        ))

        try:
            matches = detect_chains(self._session_events)
        except Exception as e:
            # Sequence analysis must not be able to crash the collector.
            log.warning("Chain detection failed for event #%d: %s", row_id, e)
            return

        for match in matches:
            if not match.event_ids or match.event_ids[-1] != row_id:
                continue  # this chain did not complete on the current event
            if match.rule in self._chained_rules:
                continue  # already reported for this session
            self._chained_rules.add(match.rule)

            log.warning(
                "  CHAIN ALERT: %s [%s] — %s (events=%s)",
                match.rule.upper(), match.severity.upper(),
                match.description, match.event_ids,
            )
            alerts.emit({
                "type": "chain",
                "rule": match.rule,
                "severity": match.severity,
                "description": match.description,
                "detail": match.detail,
                "session_id": self._session_id,
                "event_ids": match.event_ids,
            })


def build_watch_list(targets: list[dict]) -> list[tuple[Path, bool]]:
    """Build (path, recursive) pairs from policy targets.
    Validates each path exists on disk. Paths with ~ are expanded automatically."""
    watch_list = []
    for t in targets:
        path = Path(t["path"]).expanduser()
        recursive = t.get("recursive", False)
        if not path.exists():
            log.warning("Skipping non-existent path: %s", path)
            continue
        watch_list.append((path, recursive))
        log.info("Watching: %s (recursive=%s)", path, recursive)
    return watch_list


def start_collector():
    """Initialize DB, load policy, and start inotify observer."""
    init_db()

    targets = load_policy()
    if not targets:
        log.error("No monitoring targets in policy.yaml — nothing to watch")
        sys.exit(1)

    watch_list = build_watch_list(targets)
    if not watch_list:
        log.error("No valid paths to watch")
        sys.exit(1)

    # Build set of watched paths for matching events
    watched_paths = {str(p.resolve()) for p, _ in watch_list}

    # Process resolution: auditd first, /proc as fallback
    proc_scanner = ProcScanner()
    auditd = AuditdResolver()
    if auditd.is_available():
        # Add audit rules for all monitored paths
        paths_to_watch = [str(p) for p, _ in watch_list]
        if auditd.add_watches(paths_to_watch):
            log.info("Using auditd + /proc fallback for process resolution")
            log.info("Audit rules installed for %d path(s)", len(paths_to_watch))
            resolver = auditd
            fallback = proc_scanner
        else:
            log.warning("auditd rules failed (need root) — using /proc scanning")
            log.info("For zero-gap detection: sudo python collector.py")
            resolver = proc_scanner
            fallback = None
    else:
        log.info("auditd not available — using /proc scanning (race condition possible)")
        log.info("For zero-gap detection: sudo apt install auditd && sudo systemctl start auditd")
        resolver = proc_scanner
        fallback = None

    # Real-time anomaly scorer (loads trained model if present)
    detector = AnomalyDetector()
    if detector.load_model():
        log.info("Real-time scoring enabled (model: ml/anomaly_model.json)")
    else:
        log.warning("No trained model found — real-time scoring disabled "
                    "(run: python ml/anomaly_detector.py train)")
        detector = None

    # Which alert sinks are configured (stdout is always on)
    alert_config = alerts.load_alert_config()
    enabled_sinks = [name for name in ("syslog", "webhook")
                     if alert_config.get(name, {}).get("enabled")]
    if enabled_sinks:
        log.info("Alert sinks enabled: %s", ", ".join(enabled_sinks))
    else:
        log.info("Alert sinks: stdout only (configure `alerting:` in "
                 "policy_v2.yaml for syslog/webhook)")

    handler = ArtifactHandler(watched_paths, resolver=resolver, fallback=fallback,
                              detector=detector)
    observer = Observer()

    for path, recursive in watch_list:
        observer.schedule(handler, str(path), recursive=recursive)

    observer.start()
    log.info("Collector started — monitoring %d artifact(s)", len(watch_list))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down collector...")
        observer.stop()
    observer.join()

    # Clean up audit rules on exit
    if isinstance(resolver, AuditdResolver):
        log.info("Removing audit rules...")
        resolver.remove_watches()

    log.info("Collector stopped.")


if __name__ == "__main__":
    start_collector()
