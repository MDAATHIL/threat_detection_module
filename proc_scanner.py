#!/usr/bin/env python3

"""
Process Scanner — resolves which process has a file open by scanning /proc.

When inotify fires, the triggering process is unknown. This module scans
/proc/*/fd/ symlinks to find which PIDs currently have the target file open,
then reads process metadata (name, parent, user) from /proc.

Usage:
    scanner = ProcScanner()
    context = scanner.scan_for_file("~/.aws/credentials")
    # Returns: {"pid": 1234, "comm": "curl", "ppid": 1000, "parent_comm": "bash",
    #           "uid": 1000, "username": "debian"}
    # Returns None if no process found (file was opened/closed too fast).
"""

import os
import pwd
import re
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ProcessContext:
    """Process information resolved from /proc."""
    pid: int
    comm: str
    ppid: int | None
    parent_comm: str | None
    uid: int | None
    username: str | None


class ProcScanner:
    """Scans /proc to find which process has a given file open."""

    def scan_for_file(self, target_path: str) -> ProcessContext | None:
        """Find the first process that has `target_path` open via /proc/*/fd/.

        Args:
            target_path: Absolute path to the file (e.g. ~/.aws/credentials)

        Returns:
            ProcessContext if found, None otherwise.
        """
        proc_root = Path("/proc")

        for pid_dir in proc_root.iterdir():
            if not pid_dir.name.isdigit():
                continue

            pid = int(pid_dir.name)
            fd_dir = pid_dir / "fd"

            if not fd_dir.exists() or not fd_dir.is_dir():
                continue

            # Skip our own process
            if pid == os.getpid():
                continue

            # Check each file descriptor symlink
            try:
                for fd_entry in fd_dir.iterdir():
                    try:
                        link = os.readlink(fd_entry)
                        # Symlinks look like:
                        #   /home/user/.aws/credentials
                        #   /home/user/.aws/credentials (deleted)
                        #   socket:[12345]
                        if link == target_path or link.startswith(target_path + " ("):
                            return self._read_process_info(pid_dir, pid)
                    except (OSError, PermissionError):
                        # fd may vanish between readdir and readlink
                        continue
            except (OSError, PermissionError):
                continue

        return None

    def scan_for_paths(self, target_paths: set[str]) -> dict[str, ProcessContext]:
        """Scan once for multiple target files. Returns {path: context} for matches.

        More efficient than calling scan_for_file() per path since it
        only iterates /proc once.
        """
        proc_root = Path("/proc")
        result: dict[str, ProcessContext] = {}

        for pid_dir in proc_root.iterdir():
            if not pid_dir.name.isdigit():
                continue

            pid = int(pid_dir.name)
            if pid == os.getpid():
                continue

            fd_dir = pid_dir / "fd"
            if not fd_dir.exists() or not fd_dir.is_dir():
                continue

            # Cache process info (read lazily)
            proc_info = None

            try:
                for fd_entry in fd_dir.iterdir():
                    try:
                        link = os.readlink(fd_entry)
                        if link == target_path or link.startswith(target_path + " ("):
                            if proc_info is None:
                                proc_info = self._read_process_info(pid_dir, pid)
                            result[target_path] = proc_info
                            break  # Found match for this pid, move on
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue

            # Early exit if all paths found
            if len(result) == len(target_paths):
                break

        return result

    def _read_process_info(self, pid_dir: Path, pid: int) -> ProcessContext:
        """Read process metadata from /proc/[pid]/."""
        comm = self._safe_read(pid_dir / "comm", "unknown").strip()
        ppid, parent_comm = self._read_parent(pid_dir)
        uid, username = self._read_user(pid_dir)

        return ProcessContext(
            pid=pid,
            comm=comm,
            ppid=ppid,
            parent_comm=parent_comm,
            uid=uid,
            username=username,
        )

    def _read_parent(self, pid_dir: Path) -> tuple[int | None, str | None]:
        """Parse PPid from /proc/[pid]/status and read parent's comm."""
        ppid = None
        parent_comm = None

        try:
            status = (pid_dir / "status").read_text()
            for line in status.splitlines():
                if line.startswith("PPid:"):
                    ppid = int(line.split()[1])
                    parent_dir = Path(f"/proc/{ppid}")
                    if parent_dir.exists():
                        parent_comm = self._safe_read(parent_dir / "comm", None)
                    break
        except (OSError, ValueError):
            pass

        return ppid, parent_comm

    def _read_user(self, pid_dir: Path) -> tuple[int | None, str | None]:
        """Get UID from /proc/[pid]/status and resolve username."""
        try:
            status = (pid_dir / "status").read_text()
            for line in status.splitlines():
                if line.startswith("Uid:"):
                    # First field is real UID
                    uid = int(line.split()[1])
                    try:
                        username = pwd.getpwuid(uid).pw_name
                    except KeyError:
                        username = None
                    return uid, username
        except (OSError, ValueError):
            pass
        return None, None

    def _safe_read(self, path: Path, default=None) -> str | None:
        """Read a file, returning default on any error."""
        try:
            return path.read_text()
        except (OSError, PermissionError):
            return default


# --- Quick self-test ---
if __name__ == "__main__":
    import sys
    scanner = ProcScanner()

    if len(sys.argv) < 2:
        print("Usage: python proc_scanner.py <file_path>")
        print("Example: python proc_scanner.py ~/.aws/credentials")
        sys.exit(1)

    target = sys.argv[1]
    print(f"Scanning /proc for processes with '{target}' open...\n")

    ctx = scanner.scan_for_file(target)
    if ctx:
        print(f"  PID:       {ctx.pid}")
        print(f"  Comm:      {ctx.comm}")
        print(f"  PPID:      {ctx.ppid}")
        print(f"  Parent:    {ctx.parent_comm}")
        print(f"  UID:       {ctx.uid}")
        print(f"  Username:  {ctx.username}")
    else:
        print("  No process found (file may not be open, or access was too fast).")
