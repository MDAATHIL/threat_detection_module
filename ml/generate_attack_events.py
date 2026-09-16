#!/usr/bin/env python3
"""Generate synthetic attack events for anomaly detector evaluation.

Attack scenarios:
1. Credential theft — rapid reads of ssh/azure/aws/kube/steampipe files
2. Data exfiltration — curl/wget accessing sensitive artifacts with tiny deltas
3. Privilege escalation — root user scanning all credential stores
4. Automated scanning — python3 script iterating over credential files
"""

import random
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import datetime, timedelta
from db import get_conn, init_db

# --- Attack Templates ---

SENSITIVE_ARTIFACTS = [
    "/home/debian/.ssh/id_rsa",
    "/home/debian/.ssh/authorized_keys",
    "/home/debian/.aws/credentials",
    "/home/debian/.aws/config",
    "/home/debian/.azure/accessTokens.json",
    "/home/debian/.azure/azureProfile.json",
    "/home/debian/.azure/config",
    "/home/debian/.kube/config",
    "/home/debian/.steampipe/credentials",
    "/home/debian/.steampipe/config",
]

NON_SENSITIVE_ARTIFACTS = [
    "/home/debian/.bash_history",
    "/home/kali/Music/demo.txt",
]

ATTACK_USERS = ["root", "kali", "other"]
ATTACK_PROCESSES = ["curl", "wget", "python3", "cat", "bash", "ssh", "scp"]
ATTACK_ACCESS = ["read", "write", "create", "delete"]

def generate_attack_events():
    """Generate a list of attack event dicts."""
    events = []
    base_time = datetime(2026, 8, 20, 2, 0, 0)  # 2 AM — suspicious hour

    # --- Scenario 1: Rapid credential theft (session 1) ---
    # Attacker reads all SSH + cloud creds in < 1 second
    sid = "attack_credential_theft_001"
    t = base_time
    artifacts = [
        "/home/debian/.ssh/id_rsa",
        "/home/debian/.ssh/authorized_keys",
        "/home/debian/.aws/credentials",
        "/home/debian/.azure/accessTokens.json",
        "/home/debian/.kube/config",
        "/home/debian/.steampipe/credentials",
    ]
    for i, art in enumerate(artifacts):
        delta = random.uniform(0.02, 0.08)  # 20-80ms — batch automation
        events.append({
            "timestamp": t.isoformat(),
            "artifact_path": art,
            "access_type": "read",
            "pid": 31337 + i,
            "process_name": "curl",
            "ppid": 31336,
            "parent_process_name": "python3",
            "user_id": 0,
            "username": "root",
            "time_delta": delta,
            "session_id": sid,
            "files_in_session": len(artifacts),
        })
        t += timedelta(seconds=delta)

    # --- Scenario 2: Exfiltration via wget (session 2) ---
    sid = "attack_exfil_wget_002"
    t = base_time + timedelta(minutes=5)
    exfil_artifacts = [
        "/home/debian/.ssh/id_rsa",
        "/home/debian/.aws/credentials",
        "/home/debian/.azure/accessTokens.json",
        "/home/debian/.azure/azureProfile.json",
        "/home/debian/.kube/config",
        "/home/debian/.steampipe/credentials",
        "/home/debian/.steampipe/config",
        "/home/debian/.aws/config",
    ]
    for i, art in enumerate(exfil_artifacts):
        delta = random.uniform(0.03, 0.09)
        events.append({
            "timestamp": t.isoformat(),
            "artifact_path": art,
            "access_type": "read",
            "pid": 42000 + i,
            "process_name": "wget",
            "ppid": 41999,
            "parent_process_name": "bash",
            "user_id": 0,
            "username": "root",
            "time_delta": delta,
            "session_id": sid,
            "files_in_session": len(exfil_artifacts),
        })
        t += timedelta(seconds=delta)

    # --- Scenario 3: Recon scan at 3 AM (session 3) ---
    sid = "attack_recon_003"
    t = base_time + timedelta(hours=1)
    recon_artifacts = SENSITIVE_ARTIFACTS + [
        "/home/debian/.bash_history",
        "/etc/shadow",
        "/etc/passwd",
    ]
    for i, art in enumerate(recon_artifacts):
        delta = random.uniform(0.05, 0.15)
        events.append({
            "timestamp": t.isoformat(),
            "artifact_path": art,
            "access_type": "read",
            "pid": 55000 + i,
            "process_name": "cat",
            "ppid": 54999,
            "parent_process_name": "bash",
            "user_id": 1000,
            "username": "kali",
            "time_delta": delta,
            "session_id": sid,
            "files_in_session": len(recon_artifacts),
        })
        t += timedelta(seconds=delta)

    # --- Scenario 4: Automated python3 scraper (session 4) ---
    sid = "attack_python_scraper_004"
    t = base_time + timedelta(hours=2)
    scraper_artifacts = [
        "/home/debian/.ssh/id_rsa",
        "/home/debian/.ssh/authorized_keys",
        "/home/debian/.aws/credentials",
        "/home/debian/.aws/config",
        "/home/debian/.azure/accessTokens.json",
        "/home/debian/.azure/azureProfile.json",
        "/home/debian/.kube/config",
        "/home/debian/.steampipe/credentials",
    ]
    for i, art in enumerate(scraper_artifacts):
        delta = random.uniform(0.01, 0.05)  # very fast — script
        events.append({
            "timestamp": t.isoformat(),
            "artifact_path": art,
            "access_type": "read",
            "pid": 66000 + i,
            "process_name": "python3",
            "ppid": 65999,
            "parent_process_name": "bash",
            "user_id": 1000,
            "username": "kali",
            "time_delta": delta,
            "session_id": sid,
            "files_in_session": len(scraper_artifacts),
        })
        t += timedelta(seconds=delta)

    # --- Scenario 5: Deletion attack (session 5) ---
    sid = "attack_deletion_005"
    t = base_time + timedelta(hours=3)
    del_artifacts = [
        "/home/debian/.ssh/id_rsa",
        "/home/debian/.ssh/authorized_keys",
        "/home/debian/.aws/credentials",
        "/home/debian/.azure/accessTokens.json",
    ]
    for i, art in enumerate(del_artifacts):
        delta = random.uniform(0.1, 0.5)
        events.append({
            "timestamp": t.isoformat(),
            "artifact_path": art,
            "access_type": "delete",
            "pid": 77000 + i,
            "process_name": "rm",
            "ppid": 76999,
            "parent_process_name": "bash",
            "user_id": 0,
            "username": "root",
            "time_delta": delta,
            "session_id": sid,
            "files_in_session": len(del_artifacts),
        })
        t += timedelta(seconds=delta)

    # --- Scenario 6: SSH-based lateral movement (session 6) ---
    sid = "attack_ssh_lateral_006"
    t = base_time + timedelta(hours=4)
    ssh_artifacts = [
        "/home/debian/.ssh/id_rsa",
        "/home/debian/.ssh/authorized_keys",
        "/home/debian/.ssh/known_hosts",
        "/home/debian/.aws/credentials",
        "/home/debian/.kube/config",
    ]
    for i, art in enumerate(ssh_artifacts):
        delta = random.uniform(0.5, 2.0)
        events.append({
            "timestamp": t.isoformat(),
            "artifact_path": art,
            "access_type": "read",
            "pid": 88000 + i,
            "process_name": "ssh",
            "ppid": 87999,
            "parent_process_name": "bash",
            "user_id": 0,
            "username": "root",
            "time_delta": delta,
            "session_id": sid,
            "files_in_session": len(ssh_artifacts),
        })
        t += timedelta(seconds=delta)

    # --- Scenario 7: Night-time credential dump (session 7) ---
    sid = "attack_night_dump_007"
    t = datetime(2026, 8, 21, 3, 30, 0)  # 3:30 AM
    dump_artifacts = SENSITIVE_ARTIFACTS[:]
    for i, art in enumerate(dump_artifacts):
        delta = random.uniform(0.04, 0.12)
        events.append({
            "timestamp": t.isoformat(),
            "artifact_path": art,
            "access_type": "read",
            "pid": 99000 + i,
            "process_name": "python3",
            "ppid": 98999,
            "parent_process_name": "bash",
            "user_id": 0,
            "username": "root",
            "time_delta": delta,
            "session_id": sid,
            "files_in_session": len(dump_artifacts),
        })
        t += timedelta(seconds=delta)

    # --- Scenario 8: Write-back / implant (session 8) ---
    sid = "attack_implant_008"
    t = base_time + timedelta(hours=5)
    implant_events = [
        ("/home/debian/.ssh/authorized_keys", "write", "root"),
        ("/home/debian/.ssh/authorized_keys", "write", "root"),
        ("/home/debian/.aws/config", "write", "root"),
        ("/home/debian/.azure/config", "write", "kali"),
    ]
    for i, (art, acc, user) in enumerate(implant_events):
        delta = random.uniform(0.2, 1.0)
        events.append({
            "timestamp": t.isoformat(),
            "artifact_path": art,
            "access_type": acc,
            "pid": 110000 + i,
            "process_name": "bash",
            "ppid": 109999,
            "parent_process_name": "python3",
            "user_id": 0,
            "username": user,
            "time_delta": delta,
            "session_id": sid,
            "files_in_session": len(implant_events),
        })
        t += timedelta(seconds=delta)

    # --- Scenario 9: SCP-based exfiltration (session 9) ---
    sid = "attack_scp_exfil_009"
    t = base_time + timedelta(hours=6)
    scp_artifacts = [
        "/home/debian/.ssh/id_rsa",
        "/home/debian/.aws/credentials",
        "/home/debian/.azure/accessTokens.json",
        "/home/debian/.kube/config",
        "/home/debian/.steampipe/credentials",
    ]
    for i, art in enumerate(scp_artifacts):
        delta = random.uniform(0.8, 3.0)
        events.append({
            "timestamp": t.isoformat(),
            "artifact_path": art,
            "access_type": "read",
            "pid": 120000 + i,
            "process_name": "scp",
            "ppid": 119999,
            "parent_process_name": "bash",
            "user_id": 1000,
            "username": "kali",
            "time_delta": delta,
            "session_id": sid,
            "files_in_session": len(scp_artifacts),
        })
        t += timedelta(seconds=delta)

    # --- Scenario 10: Mass grep for secrets (session 10) ---
    sid = "attack_grep_secrets_010"
    t = base_time + timedelta(hours=7)
    grep_artifacts = [
        "/home/debian/.ssh/id_rsa",
        "/home/debian/.aws/credentials",
        "/home/debian/.azure/accessTokens.json",
        "/home/debian/.kube/config",
        "/home/debian/.steampipe/credentials",
        "/home/debian/.bash_history",
        "/etc/passwd",
        "/etc/shadow",
    ]
    for i, art in enumerate(grep_artifacts):
        delta = random.uniform(0.06, 0.2)
        events.append({
            "timestamp": t.isoformat(),
            "artifact_path": art,
            "access_type": "read",
            "pid": 130000 + i,
            "process_name": "grep",
            "ppid": 129999,
            "parent_process_name": "bash",
            "user_id": 0,
            "username": "root",
            "time_delta": delta,
            "session_id": sid,
            "files_in_session": len(grep_artifacts),
        })
        t += timedelta(seconds=delta)

    return events


def insert_events(events):
    """Insert events into the database."""
    conn = get_conn()
    inserted = 0
    for ev in events:
        conn.execute(
            """INSERT INTO events
               (timestamp, artifact_path, access_type, pid, process_name,
                ppid, parent_process_name, user_id, username,
                time_delta, session_id, files_in_session)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ev["timestamp"], ev["artifact_path"], ev["access_type"],
                ev["pid"], ev["process_name"], ev["ppid"],
                ev["parent_process_name"], ev["user_id"], ev["username"],
                ev["time_delta"], ev["session_id"], ev["files_in_session"],
            ),
        )
        inserted += 1
    conn.commit()
    conn.close()
    return inserted


def main():
    init_db()

    # Check if attack events already exist
    conn = get_conn()
    count = conn.execute(
        "SELECT COUNT(*) FROM events WHERE session_id LIKE 'attack_%'"
    ).fetchone()[0]
    conn.close()

    if count > 0:
        print(f"Found {count} existing attack events.")
        resp = input("Delete and regenerate? [y/N] ").strip().lower()
        if resp == "y":
            conn = get_conn()
            conn.execute("DELETE FROM events WHERE session_id LIKE 'attack_%'")
            conn.commit()
            conn.close()
            print("Deleted existing attack events.")
        else:
            print("Keeping existing events. Exiting.")
            return

    events = generate_attack_events()
    inserted = insert_events(events)

    # Summary
    sessions = set(e["session_id"] for e in events)
    print(f"\nInserted {inserted} attack events across {len(sessions)} sessions:")
    for sid in sorted(sessions):
        count = sum(1 for e in events if e["session_id"] == sid)
        print(f"  {sid}: {count} events")

    # Verify
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    attacks = conn.execute(
        "SELECT COUNT(*) FROM events WHERE session_id LIKE 'attack_%'"
    ).fetchone()[0]
    normals = conn.execute(
        "SELECT COUNT(*) FROM events WHERE session_id NOT LIKE 'attack_%'"
    ).fetchone()[0]
    conn.close()
    print(f"\nTotal events in DB: {total} ({normals} normal + {attacks} attack)")


if __name__ == "__main__":
    main()
