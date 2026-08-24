#!/usr/bin/env python3
"""Diagnostic: test auditd event capture end-to-end."""

import subprocess
import time
import sys
import os
from auditd_integration import AuditdResolver
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("auditd_debug")

def main():
    resolver = AuditdResolver()
    
    print(f"Running as: uid={os.getuid()} euid={os.geteuid()}")
    print(f"Rule key: {resolver._rule_key}")
    
    if not resolver.is_available():
        print("FATAL: auditd not available. Run with sudo.")
        sys.exit(1)
    
    print("auditd is available!\n")
    
    # Add watch on a test dir
    test_dir = "/home/kali/.ssh"
    print(f"Adding watch on {test_dir}...")
    resolver.add_watches([test_dir])
    
    # Wait for rules to settle
    time.sleep(1)
    
    # Verify rules
    result = subprocess.run(["auditctl", "-l"], capture_output=True, text=True, timeout=5)
    print(f"\nCurrent audit rules with our key:")
    for line in result.stdout.splitlines():
        if resolver._rule_key in line:
            print(f"  {line}")
    
    # Now trigger a file access in a subprocess
    print(f"\nTriggering file access on {test_dir}/known_hosts...")
    subprocess.run(["bash", "-c", f"cat {test_dir}/known_hosts > /dev/null"])
    
    # Wait for audit to flush
    print("Waiting 2s for audit log flush...")
    time.sleep(2)
    
    # Query ausearch directly
    print(f"\n--- Direct ausearch query ---")
    result = subprocess.run(
        ["ausearch", "-k", resolver._rule_key, "-ts", "today", "-i"],
        capture_output=True, text=True, timeout=10,
    )
    print(f"Return code: {result.returncode}")
    print(f"Stdout lines: {len(result.stdout.splitlines())}")
    if result.stderr.strip():
        print(f"Stderr: {result.stderr.strip()[:300]}")
    
    if result.stdout.strip():
        lines = result.stdout.strip().splitlines()
        print(f"\nFirst 30 lines of ausearch output:")
        for i, line in enumerate(lines[:30]):
            print(f"  [{i}] {line[:250]}")
    else:
        print("No stdout from ausearch!")
    
    # Now test the resolver
    print(f"\n--- Testing find_process_for_file ---")
    ctx = resolver.find_process_for_file(f"{test_dir}/known_hosts")
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
        print("  No process found!")
    
    print("\nCleaning up...")
    resolver.remove_watches()
    print("Done.")

if __name__ == "__main__":
    main()
