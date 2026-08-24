#!/usr/bin/env python3
"""
Generate realistic test events across all 5 artifact categories.
Inserts directly into SQLite — does NOT touch any real files.
"""

import random
from datetime import datetime, timedelta
from db import get_conn, init_db

# Realistic event templates per artifact category
EVENT_TEMPLATES = {
    "azure": {
        "processes": {
            "bash": 0.40,      # shell scripts
            "cat": 0.15,       # reading config
            "python3": 0.10,   # azure CLI wrapper
            "curl": 0.10,      # API calls
            "nano": 0.05,      # editing config
            "tail": 0.05,      # monitoring logs
            "grep": 0.05,      # searching config
            "head": 0.05,      # peeking at config
            "other": 0.05,
        },
        "users": {"debian": 0.85, "root": 0.15},
        "access_types": {"read": 0.45, "write": 0.30, "create": 0.15, "delete": 0.05, "moved": 0.05},
        "hours": {"night": 0.10, "early": 0.05, "morning": 0.25, "midday": 0.20, "afternoon": 0.25, "evening": 0.15},
    },
    "aws": {
        "processes": {
            "bash": 0.25,
            "cat": 0.20,
            "python3": 0.15,   # boto3
            "curl": 0.15,      # aws cli
            "grep": 0.10,
            "less": 0.05,
            "other": 0.10,
        },
        "users": {"debian": 0.80, "root": 0.20},
        "access_types": {"read": 0.60, "write": 0.20, "create": 0.10, "delete": 0.05, "moved": 0.05},
        "hours": {"night": 0.05, "early": 0.10, "morning": 0.30, "midday": 0.15, "afternoon": 0.25, "evening": 0.15},
    },
    "ssh": {
        "processes": {
            "bash": 0.30,
            "ssh": 0.25,
            "cat": 0.15,
            "scp": 0.10,
            "rsync": 0.05,
            "less": 0.05,
            "grep": 0.05,
            "other": 0.05,
        },
        "users": {"debian": 0.90, "root": 0.10},
        "access_types": {"read": 0.55, "write": 0.25, "create": 0.10, "delete": 0.05, "moved": 0.05},
        "hours": {"night": 0.15, "early": 0.05, "morning": 0.25, "midday": 0.20, "afternoon": 0.20, "evening": 0.15},
    },
    "kube": {
        "processes": {
            "bash": 0.35,
            "python3": 0.15,   # kubernetes client
            "curl": 0.15,      # API calls
            "cat": 0.15,
            "grep": 0.10,
            "other": 0.10,
        },
        "users": {"debian": 0.75, "root": 0.25},
        "access_types": {"read": 0.50, "write": 0.25, "create": 0.15, "delete": 0.05, "moved": 0.05},
        "hours": {"night": 0.10, "early": 0.10, "morning": 0.30, "midday": 0.15, "afternoon": 0.20, "evening": 0.15},
    },
    "steampipe": {
        "processes": {
            "bash": 0.40,
            "python3": 0.20,
            "cat": 0.15,
            "grep": 0.10,
            "curl": 0.10,
            "other": 0.05,
        },
        "users": {"debian": 0.85, "root": 0.15},
        "access_types": {"read": 0.55, "write": 0.20, "create": 0.15, "delete": 0.05, "moved": 0.05},
        "hours": {"night": 0.10, "early": 0.05, "morning": 0.30, "midday": 0.20, "afternoon": 0.20, "evening": 0.15},
    },
}

# Bucket → hour range for timestamp generation
HOUR_RANGES = {
    "night": (0, 5),
    "early": (6, 8),
    "morning": (9, 11),
    "midday": (12, 13),
    "afternoon": (14, 17),
    "evening": (18, 23),
}

# Paths within each artifact category
ARTIFACT_PATHS = {
    "azure": ["/home/debian/.azure/config", "/home/debian/.azure/accessTokens.json", "/home/debian/.azure/azureProfile.json"],
    "aws":   ["/home/debian/.aws/config", "/home/debian/.aws/credentials", "/home/debian/.aws/cli cache"],
    "ssh":   ["/home/debian/.ssh/known_hosts", "/home/debian/.ssh/id_rsa", "/home/debian/.ssh/authorized_keys"],
    "kube":  ["/home/debian/.kube/config"],
    "steampipe": ["/home/debian/.steampipe/config", "/home/debian/.steampipe/credentials"],
}


def weighted_choice(choices: dict) -> str:
    """Pick from a dict of {value: probability}."""
    items = list(choices.keys())
    weights = list(choices.values())
    return random.choices(items, weights=weights, k=1)[0]


def generate_timestamp(date_str: str, hour_bucket: str) -> str:
    """Generate a timestamp within the given hour bucket on the given date."""
    h_start, h_end = HOUR_RANGES[hour_bucket]
    hour = random.randint(h_start, h_end)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    microsecond = random.randint(0, 999999)
    dt = datetime.strptime(date_str, "%Y-%m-%d")
    dt = dt.replace(hour=hour, minute=minute, second=second, microsecond=microsecond)
    return dt.isoformat()


def generate_events(num_per_artifact: int = 40):
    """Generate test events across all artifacts."""
    conn = get_conn()

    # Generate events over a 14-day window
    base_date = datetime(2026, 8, 10)

    total = 0
    for artifact, template in EVENT_TEMPLATES.items():
        for _ in range(num_per_artifact):
            # Pick features from distributions
            process = weighted_choice(template["processes"])
            user = weighted_choice(template["users"])
            access_type = weighted_choice(template["access_types"])
            hour_bucket = weighted_choice(template["hours"])

            # Random date within the 14-day window
            day_offset = random.randint(0, 13)
            date = (base_date + timedelta(days=day_offset)).strftime("%Y-%m-%d")

            # Pick a path within this artifact category
            path = random.choice(ARTIFACT_PATHS[artifact])

            timestamp = generate_timestamp(date, hour_bucket)

            conn.execute(
                """INSERT INTO events
                   (timestamp, artifact_path, access_type,
                    pid, process_name, ppid, parent_process_name,
                    user_id, username)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    timestamp,
                    path,
                    access_type,
                    random.randint(1000, 65000),  # synthetic PID
                    process,
                    random.randint(1, 9999),      # synthetic PPID
                    "bash" if random.random() > 0.3 else "systemd",
                    1000 if user == "debian" else 0,
                    user,
                ),
            )
            total += 1

    conn.commit()
    conn.close()
    print(f"Generated {total} test events across {len(EVENT_TEMPLATES)} artifact categories")
    print(f"Artifacts: {', '.join(EVENT_TEMPLATES.keys())}")
    print(f"Events per artifact: ~{num_per_artifact}")


if __name__ == "__main__":
    init_db()
    generate_events()
