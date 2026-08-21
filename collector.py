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

from db import init_db, insert_event
from proc_scanner import ProcScanner
from auditd_integration import AuditdResolver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("collector")

POLICY_PATH = Path(__file__).parent / "policy.yaml"


def load_policy() -> list[dict[str, Any]]:
    """Load monitoring targets from policy.yaml."""
    with open(POLICY_PATH) as f:
        policy = yaml.safe_load(f)
    return policy.get("monitoring", [])


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
    """Receives inotify events, resolves process context, and logs to SQLite."""

    def __init__(self, watched_paths: set[str], resolver=None, fallback=None):
        super().__init__()
        self.watched_paths = watched_paths
        self.resolver = resolver  # AuditdResolver or ProcScanner
        self.fallback = fallback  # ProcScanner as fallback when auditd returns nothing
        self.use_auditd = isinstance(resolver, AuditdResolver)

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

        row_id = insert_event(
            artifact_path=artifact,
            access_type=access_type,
            pid=ctx.pid if ctx else None,
            process_name=ctx.comm if ctx else None,
            ppid=ctx.ppid if ctx else None,
            parent_process_name=ctx.parent_comm if ctx else None,
            user_id=ctx.uid if ctx else None,
            username=ctx.username if ctx else None,
        )

        proc_info = f"pid={ctx.pid} comm={ctx.comm} user={ctx.username}" if ctx else "no process found"
        log.info(
            "Event #%d: %s on %s (artifact=%s, %s)",
            row_id,
            access_type,
            src if src != dest else f"{src} -> {dest}",
            artifact,
            proc_info,
        )


def build_watch_list(targets: list[dict]) -> list[tuple[Path, bool]]:
    """Build (path, recursive) pairs from policy targets.
    Validates each path exists on disk."""
    watch_list = []
    for t in targets:
        path = Path(t["path"])
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
        log.info("Using auditd + /proc fallback for process resolution")
        # Add audit rules for all monitored paths
        paths_to_watch = [str(p) for p, _ in watch_list]
        if auditd.add_watches(paths_to_watch):
            log.info("Audit rules installed for %d path(s)", len(paths_to_watch))
        else:
            log.warning("Some audit rules failed — /proc fallback will be used for those paths")
        resolver = auditd
        fallback = proc_scanner
    else:
        log.info("auditd not available — using /proc scanning (race condition possible)")
        log.info("For zero-gap detection: sudo apt install auditd && sudo systemctl start auditd")
        resolver = proc_scanner
        fallback = None

    handler = ArtifactHandler(watched_paths, resolver=resolver, fallback=fallback)
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
