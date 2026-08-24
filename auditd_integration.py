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
    parent_comm: str | None
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
        # Diagnostic: dump raw ausearch output on first miss to help debug
        if not hasattr(self, '_debug_shown'):
            self._debug_shown = True
            self._query_audit_debug(target_path)
        log.info("No audit event found for %s after 5 attempts (key=%s)", target_path, self._rule_key)
        return None

    def _query_audit(self, target_path: str) -> AuditProcessContext | None:
        """Single ausearch query for the target path."""
        # Use -ts recent (last 10 min) to avoid midnight boundary issues
        # with -ts today. The inotify event fires within seconds of access
        # so 10 minutes is more than enough.
        try:
            result = subprocess.run(
                [
                    "ausearch", "-k", self._rule_key,
                    "-ts", "recent",
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

    def _query_audit_debug(self, target_path: str) -> None:
        """Diagnostic: dump raw ausearch output at INFO level."""
        try:
            result = subprocess.run(
                ["ausearch", "-k", self._rule_key, "-ts", "recent", "-i"],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip():
                lines = result.stdout.strip().splitlines()
                log.info("[auditd-debug] ausearch returned %d lines for key=%s", len(lines), self._rule_key)
                for line in lines[:20]:
                    log.info("[auditd-debug] %s", line[:250])
            else:
                log.info("[auditd-debug] ausearch returned empty output (rc=%d stderr=%s)", result.returncode, result.stderr.strip()[:200])
        except Exception as e:
            log.info("[auditd-debug] ausearch exception: %s", e)

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

        NOTE: ausearch -i may output records in any order (PATH before SYSCALL
        is common). We use a two-pass approach: first collect all records by
        event ID, then find the matching event.
        """
        lines = raw_output.splitlines()
        log.debug("parse_audit_events: raw line count=%d", len(lines))
        for i, raw_line in enumerate(lines[:5]):
            log.debug("  raw[%d]: %s", i, raw_line[:200])

        # --- Pass 1: collect records grouped by event ID ---
        # Event ID is the numeric part in msg=audit(EPOCH:ID)
        events: dict[str, dict] = {}  # event_id -> {syscall, paths, cwd}

        for line in lines:
            line = line.strip()
            if not line:
                continue

            event_id = self._extract_event_id(line)
            if event_id is None:
                continue

            event = events.setdefault(event_id, {"syscall": None, "paths": [], "cwd": None})

            if "type=SYSCALL" in line:
                pid = self._extract_field(line, "pid")
                uid = self._extract_field(line, "uid")
                comm = self._extract_quoted(line, "comm")
                exe = self._extract_quoted(line, "exe")
                syscall = self._extract_field(line, "syscall")
                timestamp = self._extract_timestamp(line)
                if pid:
                    event["syscall"] = {
                        "pid": int(pid),
                        "uid": self._parse_uid(uid),
                        "comm": comm or "unknown",
                        "exe": exe,
                        "syscall": syscall,
                        "timestamp": timestamp,
                    }

            elif "type=PATH" in line:
                name = self._extract_quoted(line, "name")
                if name:
                    event["paths"].append(name)

            elif "type=CWD" in line:
                cwd = self._extract_quoted(line, "cwd")
                if cwd:
                    event["cwd"] = cwd

            elif "type=PROCTITLE" in line:
                proctitle = self._extract_quoted(line, "proctitle")
                if proctitle and event.get("syscall"):
                    event["syscall"]["exe"] = proctitle

        log.debug("ausearch lines: total=%d events=%d", len(lines), len(events))

        # --- Pass 2: find the event matching our target path ---
        event_list = list(events.values())
        log.info("[auditd-debug] Parsed %d events from ausearch, target='%s'", len(event_list), target_path)
        for event in reversed(event_list):  # Most recent first
            sc = event.get("syscall")
            if sc is None:
                continue
            # Skip auditd's own rule-installation events
            if sc.get("comm") in ("auditctl", "audispd", "auditd"):
                continue

            event_paths = event.get("paths", [])
            cwd = event.get("cwd")

            # Resolve relative paths against CWD so we can match them
            resolved_paths = []
            for p in event_paths:
                if os.path.isabs(p):
                    resolved_paths.append(p)
                elif cwd:
                    resolved_paths.append(os.path.normpath(os.path.join(cwd, p)))
                else:
                    resolved_paths.append(p)  # keep as-is if no CWD

            matched = any(
                target_path == p or target_path in p or p in target_path
                for p in resolved_paths
            )
            log.info("[auditd-debug] Event pid=%s comm=%s cwd=%s paths=%s resolved=%s matched=%s",
                     sc.get('pid'), sc.get('comm'), cwd, event_paths, resolved_paths, matched)
            if matched:
                # Resolve username from UID
                username = self._uid_to_name(sc.get("uid"))

                ctx = AuditProcessContext(
                    pid=sc["pid"],
                    comm=sc["comm"],
                    ppid=None,  # Audit doesn't directly provide PPID
                    parent_comm=None,
                    uid=sc["uid"],
                    username=username,
                    syscall=sc.get("syscall"),
                    exe=sc.get("exe"),
                    timestamp=sc.get("timestamp"),
                )
                # Enrich with PPID from /proc since auditd doesn't provide it
                self._enrich_from_proc(ctx)
                return ctx
            else:
                log.debug("Event paths %s don't match target '%s' (comm=%s)", resolved_paths, target_path, sc.get('comm'))

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

    def _extract_event_id(self, line: str) -> str | None:
        """Extract event ID from audit message header.

        Matches: msg=audit(1234567890.123:456) → returns '456'
        This ID groups all records belonging to the same audit event.
        """
        match = re.search(r'msg=audit\([\d.]+:(\d+)\)', line)
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

    def _enrich_from_proc(self, ctx: AuditProcessContext) -> None:
        """Read /proc/[pid]/status to fill in PPID and parent_comm.

        Auditd provides pid, uid, comm, exe, syscall — but not the parent
        PID or parent process name. Since we already know the PID from the
        audit event, we can read /proc/[pid]/status to get PPID, then
        /proc/[ppid]/comm for the parent's short name.
        """
        proc_status = Path(f"/proc/{ctx.pid}/status")
        try:
            for line in proc_status.read_text().splitlines():
                if line.startswith("PPid:"):
                    ctx.ppid = int(line.split()[1])
                    # Read parent's comm from /proc/[ppid]/comm
                    parent_comm_path = Path(f"/proc/{ctx.ppid}/comm")
                    if parent_comm_path.exists():
                        ctx.parent_comm = parent_comm_path.read_text().strip()
                    break
        except (OSError, ValueError, IndexError) as e:
            log.debug("Could not enrich pid %d from /proc: %s", ctx.pid, e)

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
            print(f"  PPID:     {ctx.ppid}")
            print(f"  Parent:   {ctx.parent_comm}")
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
