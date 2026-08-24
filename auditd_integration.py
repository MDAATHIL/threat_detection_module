#!/usr/bin/env python3

"""
Auditd Integration — reliable process resolution via the Linux audit framework.

Instead of the race-prone /proc scanning, this module:
  1. Adds audit rules (auditctl) to watch sensitive files
  2. Reads audit events (ausearch) to get PID, process, user context
  3. Parses audit log output to extract full process information

Requires:
  - auditd installed and running: sudo apt install auditd audispd-plugins
  - Root/sudo access for auditctl commands

Usage:
    from auditd_integration import AuditdResolver

    resolver = AuditdResolver()
    if resolver.is_available():
        resolver.add_watches(["/home/kali/.aws"])
        ctx = resolver.find_process_for_file("/home/kali/.aws/credentials")
    else:
        # Fall back to /proc scanning
        ...
"""

import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

log = logging.getLogger("auditd")

AUDIT_RULE_PREFIX = "artifact_watch"
AUDIT_RULE_KEY = "artifact_watch_all"  # Shared key for all collector instances


def _find_auditctl() -> str | None:
    """Find the auditctl binary, checking both PATH and /usr/sbin."""
    path = shutil.which("auditctl")
    if path:
        return path
    # Check /usr/sbin (common for audit tools)
    sbin_path = "/usr/sbin/auditctl"
    if os.path.isfile(sbin_path) and os.access(sbin_path, os.X_OK):
        return sbin_path
    return None


def _find_ausearch() -> str | None:
    """Find the ausearch binary, checking both PATH and /usr/sbin."""
    path = shutil.which("ausearch")
    if path:
        return path
    sbin_path = "/usr/sbin/ausearch"
    if os.path.isfile(sbin_path) and os.access(sbin_path, os.X_OK):
        return sbin_path
    return None


@dataclass
class AuditProcessContext:
    """Process information from an audit event."""
    pid: int
    comm: str
    ppid: int | None
    parent_comm: str | None  # parent process name (not always available from audit)
    uid: int
    username: str
    syscall: str | None
    exe: str | None
    timestamp: str | None


class AuditdResolver:
    """Manages audit rules and reads audit events for process resolution."""

    def __init__(self):
        self._rule_key = AUDIT_RULE_KEY
        self._auditctl = _find_auditctl()
        self._ausearch = _find_ausearch()

    def _run_audit(self, cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
        """Run an audit command with sudo."""
        return subprocess.run(
            ["sudo"] + cmd,
            capture_output=kwargs.pop("capture_output", True),
            text=kwargs.pop("text", True),
            timeout=kwargs.pop("timeout", 10),
            **kwargs,
        )

    def is_available(self) -> bool:
        """Check if auditd is installed and the audit daemon is running."""
        if self._auditctl is None:
            log.info("auditctl not found — auditd not installed")
            return False
        # Check if auditctl exists
        try:
            result = self._run_audit([self._auditctl, "-s"], timeout=5)
            if result.returncode == 0 and "enabled" in result.stdout.lower():
                return True
            # auditctl exists but needs root — still consider available
            output = result.stdout + result.stderr
            if "root" in output.lower() or "permission denied" in output.lower():
                log.info("auditd is installed but requires root. Run collector with sudo.")
                # We consider it available since it works when run as root
                return True
        except FileNotFoundError:
            log.info("auditctl not found — auditd not installed")
            return False
        except subprocess.TimeoutExpired:
            log.warning("auditctl timed out")
            return False
        return False

    def add_watches(self, paths: list[str]) -> bool:
        """Add audit watch rules for the given paths.

        Uses -w (watch) which recursively watches directories.
        The -k flag adds a key we can search for later.
        -p rwxa = watch read, write, execute, attribute changes.

        Returns True if rules were added successfully.
        """
        if not self.is_available():
            return False

        success = True
        for path in paths:
            # Remove any existing rules for this path first
            self._remove_watch_for_path(path)

            cmd = [self._auditctl, "-w", path, "-p", "rwxa", "-k", self._rule_key]
            try:
                result = self._run_audit(cmd)
                if result.returncode == 0:
                    log.info("Audit rule added: %s", path)
                else:
                    log.error("Failed to add audit rule for %s: %s", path, result.stderr.strip())
                    success = False
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                log.error("auditctl error for %s: %s", path, e)
                success = False

        return success

    def _remove_watch_for_path(self, path: str) -> None:
        """Remove the audit watch rule for a specific path."""
        if not self.is_available():
            return
        try:
            result = self._run_audit([self._auditctl, "-l"], timeout=5)
            for line in result.stdout.splitlines():
                if self._rule_key in line and path in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        watched_path = parts[1]
                        self._run_audit(
                            [self._auditctl, "-W", watched_path, "-p", "rwxa", "-k", self._rule_key],
                            timeout=5,
                        )
                        log.info("Audit rule removed: %s", watched_path)
        except Exception as e:
            log.warning("Error removing audit rule for %s: %s", path, e)

    def remove_watches(self) -> None:
        """Remove all artifact watch rules added by this process."""
        if not self.is_available():
            return

        # Delete all rules with our key
        try:
            result = self._run_audit([self._auditctl, "-l"], timeout=5)
            for line in result.stdout.splitlines():
                if self._rule_key in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        path = parts[1]
                        self._run_audit(
                            [self._auditctl, "-W", path, "-p", "rwxa", "-k", self._rule_key],
                            timeout=5,
                        )
                        log.info("Audit rule removed: %s", path)
        except Exception as e:
            log.warning("Error removing audit rules: %s", e)

    def find_process_for_file(self, target_path: str, max_age_seconds: int = 5) -> AuditProcessContext | None:
        """Find which process accessed a file by querying audit logs.

        Searches for recent audit events matching our watch key and the
        target file path. Returns the most recent match.

        Args:
            target_path: Absolute path to the file
            max_age_seconds: Only look at events from the last N seconds
        """
        if not self.is_available():
            return None

        # Audit events may not be in the log yet when inotify fires.
        # Retry with increasing delays to let auditd flush to disk.
        for attempt in range(5):
            ctx = self._query_audit(target_path)
            if ctx is not None:
                return ctx
            if attempt < 4:
                time.sleep(0.5)
        log.debug("No audit event found for %s after 5 attempts", target_path)
        return None

    def _query_audit(self, target_path: str) -> AuditProcessContext | None:
        """Single ausearch query for the target path."""
        # Use --start today to avoid -ts recent missing very new events
        try:
            result = self._run_audit(
                [
                    self._ausearch, "-k", self._rule_key,
                    "-ts", "today",
                    "-i",
                ],
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            log.warning("ausearch error: %s", e)
            return None

        if result.returncode != 0 or not result.stdout.strip():
            log.debug("ausearch returned no output (rc=%d)", result.returncode)
            return None
        return self._parse_audit_events(result.stdout, target_path)

    def find_process_for_event(self, event_time: str, target_path: str) -> AuditProcessContext | None:
        """Find process for a specific event by timestamp.

        More precise than find_process_for_file — searches around the
        exact timestamp of the inotify event.
        """
        if not self.is_available():
            return None

        try:
            result = self._run_audit(
                [
                    self._ausearch, "-k", self._rule_key,
                    "-ts", event_time,
                    "-te", event_time,
                    "-i",
                ],
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            log.warning("ausearch error: %s", e)
            return None

        if result.returncode != 0 or not result.stdout.strip():
            return None

        return self._parse_audit_events(result.stdout, target_path)

    def _parse_audit_events(self, raw_output: str, target_path: str) -> AuditProcessContext | None:
        """Parse ausearch output and extract process context for the target file.

        Uses a state-machine approach: builds event blocks from audit records.
        Each audit event consists of multiple record types:
            type=SYSCALL → contains PID, UID, comm, exe, syscall
            type=CWD     → current working directory
            type=PATH    → accessed file paths
            type=PROCTITLE → full command line
        Events are separated by '----' lines.
        """
        lines = raw_output.splitlines()
        log.debug("parse_audit_events: raw line count=%d", len(lines))

        # Parse all audit events by splitting on '----' separators
        # and grouping records within each event block
        events = []
        current_records = []

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped == "----":
                # End of an event block — process it
                if current_records:
                    parsed = self._parse_event_block(current_records)
                    if parsed:
                        events.append(parsed)
                    current_records = []
            else:
                current_records.append(stripped)

        # Don't forget the last block (no trailing ----)
        if current_records:
            parsed = self._parse_event_block(current_records)
            if parsed:
                events.append(parsed)

        log.debug("Parsed %d events from ausearch, target='%s'", len(events), target_path)

        # Find the event that matches our target path
        for event in reversed(events):  # Most recent first
            sc = event.get("syscall", {})
            # Skip auditd's own rule-installation events
            if sc.get("comm") in ("auditctl", "audispd", "auditd"):
                log.debug("Skipping auditd's own event (comm=%s)", sc.get("comm"))
                continue
            # Skip events with no PID (shouldn't happen but be safe)
            if not sc.get("pid"):
                log.debug("Skipping event with no PID")
                continue
            event_paths = event.get("paths", [])
            matched = any(
                target_path == p or target_path in p or p in target_path
                for p in event_paths
            )
            if matched:
                username = self._uid_to_name(sc.get("uid"))
                log.info("Resolved process: pid=%s comm=%s user=%s", sc.get("pid"), sc.get("comm"), username)
                return AuditProcessContext(
                    pid=sc["pid"],
                    comm=sc["comm"],
                    ppid=None,
                    parent_comm=None,
                    uid=sc["uid"],
                    username=username,
                    syscall=sc.get("syscall"),
                    exe=sc.get("exe"),
                    timestamp=sc.get("timestamp"),
                )
            else:
                log.debug("Event paths %s don't match target '%s' (comm=%s)", event_paths, target_path, sc.get('comm'))

        return None

    def _parse_event_block(self, records: list[str]) -> dict | None:
        """Parse a single audit event block (records between ---- separators).

        Returns dict with 'syscall' info and 'paths' list, or None if invalid.
        """
        syscall_info = None
        paths = []
        proctitle = None
        cwd = None

        for record in records:
            if record.startswith("type=SYSCALL"):
                pid = self._extract_field(record, "pid")
                uid = self._extract_field(record, "uid")
                comm = self._extract_quoted(record, "comm")
                exe = self._extract_quoted(record, "exe")
                syscall = self._extract_field(record, "syscall")
                timestamp = self._extract_timestamp(record)

                syscall_info = {
                    "pid": int(pid) if pid else None,
                    "uid": self._parse_uid(uid),
                    "comm": comm or "unknown",
                    "exe": exe,
                    "syscall": syscall,
                    "timestamp": timestamp,
                }

            elif record.startswith("type=CWD"):
                cwd = self._extract_quoted(record, "cwd")

            elif record.startswith("type=PATH"):
                name = self._extract_quoted(record, "name")
                if name:
                    # Audit PATH names can be relative ("config") or absolute
                    # ("/home/debian/.azure/config"). Combine with CWD if relative.
                    if not name.startswith("/") and cwd:
                        name = cwd.rstrip("/") + "/" + name
                    paths.append(name)

            elif record.startswith("type=PROCTITLE"):
                proctitle = self._extract_quoted(record, "proctitle")

        if not syscall_info or not paths:
            log.debug("Skipping event block: syscall=%s paths=%s", bool(syscall_info), paths)
            return None

        # PROCTITLE gives the full command line — prefer it over comm
        if proctitle:
            syscall_info["exe"] = proctitle

        return {"syscall": syscall_info, "paths": paths}

    def _extract_field(self, line: str, field: str) -> str | None:
        """Extract a numeric field from an audit log line.

        Matches patterns like: pid=1234, uid=1000, syscall=openat
        """
        match = re.search(rf'\b{field}=(\S+)', line)
        return match.group(1) if match else None

    def _extract_quoted(self, line: str, field: str) -> str | None:
        """Extract a field value from an audit log line.

        Handles both quoted and unquoted formats:
          comm="curl"  OR  comm=curl
          name="/home/kali/.aws/config"  OR  name=/home/kali/.aws/config
        """
        # Try quoted first
        match = re.search(rf'{field}="([^"]*)"', line)
        if match:
            return match.group(1)
        # Try unquoted - value is everything up to the next space or end of line
        match = re.search(rf'\b{field}=(\S+)', line)
        return match.group(1) if match else None

    def _extract_timestamp(self, line: str) -> str | None:
        """Extract timestamp from audit message header.

        Handles both formats:
          Without -i: msg=audit(1234567890.123:456)
          With -i:    msg=audit(21/08/26 22:07:21.674:290)
        """
        # Try numeric timestamp format (without -i)
        match = re.search(r'msg=audit\((\d+\.\d+):\d+\)', line)
        if match:
            return match.group(1)
        # Try human-readable format (with -i)
        match = re.search(r'msg=audit\(([^)]+)\)', line)
        if match:
            return match.group(1)
        return None

    def _parse_uid(self, uid_str: str | None) -> int:
        """Parse UID from ausearch -i output.

        With -i flag, ausearch outputs usernames instead of numeric UIDs
        (e.g. 'root' instead of '0'). Handle both cases.
        """
        if not uid_str:
            return 0
        try:
            return int(uid_str)
        except ValueError:
            # It's a username string like 'root' — resolve to numeric UID
            try:
                import pwd
                return pwd.getpwnam(uid_str).pw_uid
            except (KeyError, ImportError):
                return 0

    def _uid_to_name(self, uid: int | None) -> str | None:
        """Resolve UID to username."""
        if uid is None:
            return None
        try:
            import pwd
            return pwd.getpwuid(uid).pw_name
        except (KeyError, ValueError):
            return None


# --- Quick self-test ---
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.DEBUG)

    resolver = AuditdResolver()

    if not resolver.is_available():
        print("auditd is NOT available.")
        print("Install with: sudo apt install auditd audispd-plugins")
        print("Then start:   sudo systemctl start auditd")
        sys.exit(1)

    print("auditd is available!")
    print()

    if len(sys.argv) > 1:
        path = sys.argv[1]
        print(f"Adding audit watch: {path}")
        resolver.add_watches([path])
        print()
        print("Now access the file in another terminal, then press Enter to search...")
        input()

        ctx = resolver.find_process_for_file(path)
        if ctx:
            print(f"  PID:      {ctx.pid}")
            print(f"  Comm:     {ctx.comm}")
            print(f"  UID:      {ctx.uid}")
            print(f"  Username: {ctx.username}")
            print(f"  Syscall:  {ctx.syscall}")
            print(f"  Exe:      {ctx.exe}")
        else:
            print("  No audit event found for this file.")

        print("\nCleaning up rules...")
        resolver.remove_watches()
    else:
        print("Usage: python auditd_integration.py <file_path>")
