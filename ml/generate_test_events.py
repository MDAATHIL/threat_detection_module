#!/usr/bin/env python3
"""
Generate realistic test events across all 5 artifact categories.
Inserts directly into SQLite — does NOT touch any real files.
"""

import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure we import db.py from the project root, not ml/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
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

# Paths within each artifact category (dynamically resolved from current user's home)
_HOME = str(Path.home())
ARTIFACT_PATHS = {
    "azure": [
        f"{_HOME}/.azure/config",
        f"{_HOME}/.azure/accessTokens.json",
        f"{_HOME}/.azure/azureProfile.json",
    ],
    "aws": [
        f"{_HOME}/.aws/config",
        f"{_HOME}/.aws/credentials",
        f"{_HOME}/.aws/cli cache",
    ],
    "ssh": [
        f"{_HOME}/.ssh/known_hosts",
        f"{_HOME}/.ssh/id_rsa",
        f"{_HOME}/.ssh/authorized_keys",
    ],
    "kube": [f"{_HOME}/.kube/config"],
    "steampipe": [
        f"{_HOME}/.steampipe/config",
        f"{_HOME}/.steampipe/credentials",
    ],
}

# Access types a normal user realistically performs on each path: secrets are
# read, configs are edited, caches are churned. Writing `authorized_keys` is
# deliberately NOT in this list — installing a key is worth a human looking at,
# and leaving it out is what keeps the `ssh_key_injection` chain rule quiet on
# normal traffic.
NORMAL_PATH_ACCESS = {
    f"{_HOME}/.azure/config": ["read", "write", "create"],
    f"{_HOME}/.azure/accessTokens.json": ["read"],
    f"{_HOME}/.azure/azureProfile.json": ["read", "write"],
    f"{_HOME}/.aws/config": ["read", "write", "create"],
    f"{_HOME}/.aws/credentials": ["read"],
    f"{_HOME}/.aws/cli cache": ["read", "write", "delete"],
    f"{_HOME}/.ssh/known_hosts": ["read", "write", "delete"],
    f"{_HOME}/.ssh/id_rsa": ["read"],
    f"{_HOME}/.ssh/authorized_keys": ["read"],
    f"{_HOME}/.kube/config": ["read", "write"],
    f"{_HOME}/.steampipe/config": ["read", "write"],
    f"{_HOME}/.steampipe/credentials": ["read"],
}


# Multi-step attack chains. These are deliberately *low and slow*: a couple of
# files, human-scale gaps, no burst — every event is statistically ordinary, so
# the per-event Bayesian model is blind to them by construction. They exist to
# exercise the sequence layer (sequences.py), which reasons about order.
CHAIN_ATTACKS = [
    {
        "name": "ssh_key_injection",
        "repeats": 10,
        "gap_seconds": (2.0, 5.0),
        "steps": [
            (f"{_HOME}/.ssh/id_rsa", "read", "cat", "debian"),
            (f"{_HOME}/.ssh/id_rsa", "read", "cat", "debian"),
            (f"{_HOME}/.ssh/authorized_keys", "write", "bash", "debian"),
            (f"{_HOME}/.ssh/authorized_keys", "write", "bash", "debian"),
        ],
    },
    {
        "name": "credential_sweep",
        "repeats": 10,
        "gap_seconds": (1.5, 6.0),
        "steps": [
            (f"{_HOME}/.aws/credentials", "read", "cat", "debian"),
            (f"{_HOME}/.azure/accessTokens.json", "read", "cat", "debian"),
            (f"{_HOME}/.kube/config", "read", "cat", "debian"),
            (f"{_HOME}/.steampipe/credentials", "read", "grep", "debian"),
        ],
    },
]


def weighted_choice(choices: dict) -> str:
    """Pick from a dict of {value: probability}."""
    items = list(choices.keys())
    weights = list(choices.values())
    return random.choices(items, weights=weights, k=1)[0]


# --- Realistic event-stream modelling --------------------------------------
# The collector is driven by inotify, which fires MULTIPLE events per logical
# file access (open -> "read", modify -> "write", plus directory events). A
# single `echo x >> ~/.azure/config` therefore produces a short *cluster* of
# events with sub-second gaps. Normal training data must reproduce that
# stream shape, otherwise every ordinary access looks like a timing anomaly.
#
# The attack signature is NOT "fast events" on its own — it is fast events
# spread over MANY DISTINCT FILES. That is what `files_in_session` captures.
WITHIN_CLUSTER_RAPID = 0.70     # share of intra-cluster gaps in 0.1-1.0s
CLUSTER_SIZE_WEIGHTS = [(1, 0.20), (2, 0.30), (3, 0.30), (4, 0.20)]
FILES_PER_SESSION_WEIGHTS = [(1, 0.45), (2, 0.25), (3, 0.15), (4, 0.10), (5, 0.05)]


def _weighted_pick(pairs: list[tuple]) -> int:
    """Pick an int from a list of (value, weight) pairs."""
    values = [p[0] for p in pairs]
    weights = [p[1] for p in pairs]
    return random.choices(values, weights=weights, k=1)[0]


def generate_timestamp(date_str: str, hour_bucket: str) -> str:
    """Generate a timestamp within the given hour bucket on the given date."""
    h_start, h_end = HOUR_RANGES[hour_bucket]
    hour = random.randint(h_start, h_end)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    microsecond = random.randint(0, 999999)
    dt = datetime.strptime(date_str, "%Y-%m-%d")
    dt = dt.replace(hour=hour, minute=minute, second=second, microsecond=microsecond,
                    tzinfo=timezone.utc)
    return dt.isoformat()


def generate_events(num_per_artifact: int = 80, include_attacks: bool = True):
    """Generate test events across all artifacts.
    
    Args:
        num_per_artifact: Number of normal events per artifact
        include_attacks: If True, also generates synthetic attack patterns
    """
    conn = get_conn()

    # Generate events over a 14-day window
    base_date = datetime(2026, 8, 10)

    total = 0
    for artifact, template in EVENT_TEMPLATES.items():
        total += _generate_normal_session_events(
            conn, artifact, template, num_per_artifact, base_date
        )

    # Generate synthetic attack patterns for testing burst detection
    if include_attacks:
        attack_templates = [
            {
                "name": "credential_harvester",
                "process": "python3",
                "user": "debian",
                "artifact": "aws",
                "num_events": 60,
            },
            {
                "name": "azure_token_stealer",
                "process": "curl",
                "user": "root",
                "artifact": "azure",
                "num_events": 60,
            },
            {
                "name": "ssh_key_extractor",
                "process": "cat",
                "user": "debian",
                "artifact": "ssh",
                "num_events": 60,
            },
        ]

        for attack in attack_templates:
            artifact = attack["artifact"]
            for i in range(attack["num_events"]):
                # Attack timing: very fast access (instant/rapid buckets)
                time_delta = random.uniform(0.01, 0.5)  # 10ms to 500ms
                files_in_session = random.randint(20, 100)  # burst: many files
                
                timestamp = (
                    datetime(2026, 8, 20, 3, 0, 0, tzinfo=timezone.utc)
                    + timedelta(seconds=i * time_delta)
                ).isoformat()
                path = random.choice(ARTIFACT_PATHS[artifact])
                
                conn.execute(
                    """INSERT INTO events
                       (timestamp, artifact_path, access_type,
                        pid, process_name, ppid, parent_process_name,
                        user_id, username, time_delta, session_id, files_in_session)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        timestamp,
                        path,
                        "read",
                        random.randint(1000, 65000),
                        attack["process"],
                        random.randint(1, 9999),
                        "python3",
                        1000 if attack["user"] == "debian" else 0,
                        attack["user"],
                        time_delta,
                        f"attack_burst_{attack['name']}",
                        files_in_session,
                    ),
                )
                total += 1

        # Multi-step chains: low and slow, so no individual event looks
        # unusual. Only order-aware rules (sequences.py) can see these.
        for chain in CHAIN_ATTACKS:
            for repeat in range(chain["repeats"]):
                session_id = f"attack_chain_{chain['name']}_{repeat}"
                clock = (datetime(2026, 8, 20, 3, 30, tzinfo=timezone.utc)
                         + timedelta(seconds=repeat * 600))
                distinct = 0
                seen: set[str] = set()
                gap = None
                for path, access_type, process, user in chain["steps"]:
                    if path not in seen:
                        seen.add(path)
                        distinct += 1
                    conn.execute(
                        """INSERT INTO events
                           (timestamp, artifact_path, access_type,
                            pid, process_name, ppid, parent_process_name,
                            user_id, username, time_delta, session_id, files_in_session)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            clock.isoformat(),
                            path,
                            access_type,
                            random.randint(1000, 65000),
                            process,
                            random.randint(1, 9999),
                            "bash",
                            1000 if user == "debian" else 0,
                            user,
                            gap,
                            session_id,
                            distinct,
                        ),
                    )
                    total += 1
                    gap = random.uniform(*chain["gap_seconds"])
                    clock += timedelta(seconds=gap)

    conn.commit()
    conn.close()
    print(f"Generated {total} test events across {len(EVENT_TEMPLATES)} artifact categories")
    print(f"Artifacts: {', '.join(EVENT_TEMPLATES.keys())}")
    print(f"Events per artifact: ~{num_per_artifact}")
    if include_attacks:
        print("Included synthetic attacks: burst patterns (".rstrip()
              + ", ".join(a["name"] for a in attack_templates) + ")"
              + " and low-and-slow chains ("
              + ", ".join(c["name"] for c in CHAIN_ATTACKS) + ")")


def _pick_access_type(template: dict, path: str) -> str:
    """Pick an access type that is realistic for this specific file.

    Falls back to the artifact-wide distribution for unknown paths.
    """
    allowed = NORMAL_PATH_ACCESS.get(path)
    if not allowed:
        return weighted_choice(template["access_types"])
    choices = {k: v for k, v in template["access_types"].items() if k in allowed}
    return weighted_choice(choices) if choices else "read"


def _generate_normal_session_events(conn, artifact, template, target, base_date):
    """Emit exactly `target` normal events that mimic the collector's stream.

    Events arrive in per-access clusters (same file, sub-second gaps) grouped
    into sessions that touch only a handful of distinct files. Keeping the
    session small is what separates a normal user from a credential sweep.
    """
    emitted = 0
    user_id_by_name = {"debian": 1000, "root": 0}

    while emitted < target:
        session_id = f"normal_{random.randint(1000, 9999)}"
        hour_bucket = weighted_choice(template["hours"])
        day_offset = random.randint(0, 13)
        date = (base_date + timedelta(days=day_offset)).strftime("%Y-%m-%d")

        # Session clock advances with each gap so timestamps stay ordered.
        session_clock = datetime.fromisoformat(generate_timestamp(date, hour_bucket))
        n_files = _weighted_pick(FILES_PER_SESSION_WEIGHTS)
        paths = [random.choice(ARTIFACT_PATHS[artifact]) for _ in range(n_files)]

        first_event = True
        distinct_in_session = 0
        for path in paths:
            distinct_in_session += 1
            for j in range(_weighted_pick(CLUSTER_SIZE_WEIGHTS)):
                if emitted >= target:
                    break

                if first_event:
                    time_delta = None  # collector reports None for first_event
                    first_event = False
                elif j > 0:
                    # Within one file access: the collector's sub-second cluster.
                    if random.random() < WITHIN_CLUSTER_RAPID:
                        time_delta = random.uniform(0.1, 1.0)
                    else:
                        time_delta = random.uniform(0.01, 0.1)
                else:
                    # Between accesses: human-scale pause.
                    time_delta = (random.uniform(1.0, 60.0)
                                  if random.random() < 0.85
                                  else random.uniform(60.0, 300.0))

                if time_delta is not None:
                    session_clock += timedelta(seconds=time_delta)

                process = weighted_choice(template["processes"])
                user = weighted_choice(template["users"])
                access_type = _pick_access_type(template, path)

                conn.execute(
                    """INSERT INTO events
                       (timestamp, artifact_path, access_type,
                        pid, process_name, ppid, parent_process_name,
                        user_id, username, time_delta, session_id, files_in_session)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        session_clock.isoformat(),
                        path,
                        access_type,
                        random.randint(1000, 65000),  # synthetic PID
                        process,
                        random.randint(1, 9999),      # synthetic PPID
                        "bash" if random.random() > 0.3 else "systemd",
                        user_id_by_name.get(user, 1000),
                        user,
                        time_delta,
                        session_id,
                        distinct_in_session,
                    ),
                )
                emitted += 1

    return emitted


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate labeled synthetic events")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed (default 42 — same seed = same dataset)")
    args = parser.parse_args()

    random.seed(args.seed)
    print(f"Random seed: {args.seed}")
    init_db()
    generate_events()
