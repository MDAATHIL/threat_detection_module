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
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

log = logging.getLogger("auditd")

AUDIT_RULE_PREFIX = "artifact_watch"


@dataclass
class AuditProcessContext:
    """Process information from an audit event."""
    pid: int
    comm: str
    ppid: int | None
    uid: int
    username: str
    syscall: str | None
    exe: str | None
    timestamp: str | None


class AuditdResolver:
    """Manages audit rules and reads audit events for process resolution."""

    def __init__(self):
        self._rule_key = f"{AUDIT_RULE_PREFIX}_{os.getpid()}"

    def is_available(self) -> bool:
        """Check if auditd is installed and the audit daemon is running."""
        # Check if auditctl exists
        try:
            result = subprocess.run(
                ["auditctl", "-s"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and "enabled" in result.stdout.lower():
                return True
            # auditctl exists but auditd might not be running
            if "Permission denied" in result.stderr:
                log.warning("auditctl requires root/sudo. Run as root or configure sudoers.")
                return False
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

            cmd = ["auditctl", "-w", path, "-p", "rwxa", "-k", self._rule_key]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10,
                )
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
            result = subprocess.run(
                ["auditctl", "-l"], capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if self._rule_key in line and path in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        watched_path = parts[1]
                        subprocess.run(
                            ["auditctl", "-W", watched_path, "-p", "rwxa", "-k", self._rule_key],
                            capture_output=True, timeout=5,
                        )
                        log.info("Audit rule removed: %s", watched_path)
        except Exception as e:
            log.warning("Error removing audit rule for %s: %s", path, e)

    def remove_watches(self) -> None:
        """Remove all artifact watch rules added by this process."""
        if not self.is_available():
            return

        cmd = ["auditctl", "-d", "-w", "/", "-p", "rwxa", "-k", self._rule_key]
        # Simpler: delete all rules with our key
        try:
            # List current rules and delete ours
            result = subprocess.run(
                ["auditctl", "-l"], capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if self._rule_key in line:
                    # Parse the rule to delete it
                    # Rules look like: -w /path -p rwxa -k key
                    parts = line.split()
                    if len(parts) >= 2:
                        path = parts[1]
                        subprocess.run(
                            ["auditctl", "-W", path, "-p", "rwxa", "-k", self._rule_key],
                            capture_output=True, timeout=5,
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
            result = subprocess.run(
                [
                    "ausearch", "-k", self._rule_key,
                    "-ts", "today",
                    "-i",
                ],
                capture_output=True, text=True, timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            log.warning("ausearch error: %s", e)
            return None

        if result.returncode != 0 or not result.stdout.strip():
            log.debug("ausearch returned no output (rc=%d, stderr=%s)", result.returncode, result.stderr.strip())
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
            result = subprocess.run(
                [
                    "ausearch", "-k", self._rule_key,
                    "-ts", event_time,
                    "-te", event_time,
                    "-i",
                ],
                capture_output=True, text=True, timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            log.warning("ausearch error: %s", e)
            return None

        if result.returncode != 0 or not result.stdout.strip():
            return None

        return self._parse_audit_events(result.stdout, target_path)

    def _parse_audit_events(self, raw_output: str, target_path: str) -> AuditProcessContext | None:
        """Parse ausearch output and extract process context for the target file.

        Audit event format (with -i flag):
            type=SYSCALL msg=audit(1234567890.123:456): arch=x86_64 syscall=openat
                success=yes exit=3 a0=ffffff9c ... pid=1234 uid=1000 ...
                comm=\"curl\" exe=\"/usr/bin/curl\"
            type=CWD msg=audit(...): cwd=\"/home/kali\"
            type=PATH msg=audit(...): item=0 name=\"/home/kali/.aws/config\" ...
            type=PROCTITLE msg=audit(...): proctitle=\"curl https://...\"
        """
        lines = raw_output.splitlines()
        log.debug("parse_audit_events: raw line count=%d", len(lines))
        for i, raw_line in enumerate(lines[:5]):
            log.debug("  raw[%d]: %s", i, raw_line[:200])

        current_event = {}
        events = []
        num_syscall = 0
        num_path = 0
        num_other = 0

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Parse SYSCALL line — contains PID, UID, comm, exe
            if "type=SYSCALL" in line:
                num_syscall += 1
                # Start a new event block
                if current_event and current_event.get("paths"):
                    events.append(current_event)
                current_event = {"syscall": {}, "paths": []}

                # Extract fields
                pid = self._extract_field(line, "pid")
                uid = self._extract_field(line, "uid")
                comm = self._extract_quoted(line, "comm")
                exe = self._extract_quoted(line, "exe")
                syscall = self._extract_field(line, "syscall")
                timestamp = self._extract_timestamp(line)

                if pid:
                    current_event["syscall"] = {
                        "pid": int(pid),
                        "uid": self._parse_uid(uid),
                        "comm": comm or "unknown",
                        "exe": exe,
                        "syscall": syscall,
                        "timestamp": timestamp,
                    }

            # Parse PATH line — contains accessed file
            elif "type=PATH" in line:
                num_path += 1
                name = self._extract_quoted(line, "name")
                if name:
                    current_event.setdefault("paths", []).append(name)

            # Parse PROCTITLE — contains full command line
            elif "type=PROCTITLE" in line:
                proctitle = self._extract_quoted(line, "proctitle")
                if proctitle and current_event.get("syscall"):
                    current_event["syscall"]["exe"] = proctitle

        # Don't forget the last event
        if current_event and current_event.get("paths"):
            events.append(current_event)

        log.debug("ausearch lines: total=%d SYSCALL=%d PATH=%d other=%d", len(raw_output.splitlines()), num_syscall, num_path, num_other)

        # Find the event that matches our target path
        log.debug("Parsed %d events from ausearch, target='%s'", len(events), target_path)
        for event in reversed(events):  # Most recent first
            sc = event.get("syscall", {})
            # Skip auditd's own rule-installation events
            if sc.get("comm") in ("auditctl", "audispd", "auditd"):
                continue
            event_paths = event.get("paths", [])
            matched = any(
                target_path == p or target_path in p or p in target_path
                for p in event_paths
            )
            if matched:
                # Resolve username from UID
                username = self._uid_to_name(sc.get("uid"))

                return AuditProcessContext(
                    pid=sc["pid"],
                    comm=sc["comm"],
                    ppid=None,  # Audit doesn't directly provide PPID
                    uid=sc["uid"],
                    username=username,
                    syscall=sc.get("syscall"),
                    exe=sc.get("exe"),
                    timestamp=sc.get("timestamp"),
                )
            else:
                log.debug("Event paths %s don't match target '%s' (comm=%s)", event_paths, target_path, sc.get('comm'))

        return None

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
        match = re.search(rf'{field}=(\S+)', line)
        return match.group(1) if match else None

    def _extract_timestamp(self, line: str) -> str | None:
        """Extract timestamp from audit message header.

        Matches: msg=audit(1234567890.123:456)
        """
        match = re.search(r'msg=audit\((\d+\.\d+):\d+\)', line)
        return match.group(1) if match else None

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
