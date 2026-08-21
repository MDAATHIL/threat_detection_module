#!/usr/bin/env python3

"""
Baseline Engine — reads events from SQLite and computes normal behavior
profiles for each (artifact, user, process) triple.

Profiles include:
  - access_count:  total observed accesses
  - first_seen / last_seen: time range of observations
  - normal_hours:  JSON array of hours when access typically occurs
  - avg_access_interval: average seconds between consecutive accesses

Run standalone to compute baseline:
    python baseline.py

Run with --reset to clear existing baseline and recompute:
    python baseline.py --reset
"""

import json
import sys
from datetime import datetime
from collections import defaultdict

from db import get_conn, init_db, upsert_baseline


def compute_baseline(reset: bool = False) -> dict:
    """Compute baseline profiles from all events in the database.

    Returns a dict summary:
        {
          "triples": <number of (artifact, user, process) profiles>,
          "total_events": <number of events processed>,
          "artifacts": [<list of artifact paths>]
        }
    """
    conn = get_conn()

    if reset:
        conn.execute("DELETE FROM baseline")
        conn.commit()
        print("Baseline table cleared.")

    # Fetch all events ordered by artifact, user, process, timestamp
    rows = conn.execute(
        """
        SELECT artifact_path, user_id, process_name, timestamp
        FROM events
        ORDER BY artifact_path, user_id, process_name, timestamp
        """
    ).fetchall()
    conn.close()

    if not rows:
        print("No events found — nothing to baseline.")
        return {"triples": 0, "total_events": 0, "artifacts": []}

    # Group events by (artifact_path, user_id, process_name)
    groups: dict[tuple, list[str]] = defaultdict(list)
    for row in rows:
        key = (row["artifact_path"], row["user_id"], row["process_name"])
        groups[key].append(row["timestamp"])

    artifacts_seen = set()
    profiles_built = 0

    for (artifact, user_id, process), timestamps in groups.items():
        artifacts_seen.add(artifact)
        timestamps.sort()

        # --- access_count ---
        access_count = len(timestamps)

        # --- first_seen / last_seen ---
        first_seen = timestamps[0]
        last_seen = timestamps[-1]

        # --- normal_hours ---
        # Count accesses per hour of day (0-23)
        hour_counts: dict[int, int] = defaultdict(int)
        for ts in timestamps:
            try:
                dt = datetime.fromisoformat(ts)
                hour_counts[dt.hour] += 1
            except (ValueError, TypeError):
                continue

        # Keep hours that account for at least 10% of accesses, or at least 1 access
        if hour_counts:
            threshold = max(1, int(access_count * 0.1))
            normal_hours = sorted(
                h for h, c in hour_counts.items() if c >= threshold
            )
        else:
            normal_hours = []

        # --- avg_access_interval ---
        if access_count >= 2:
            intervals = []
            for i in range(1, len(timestamps)):
                try:
                    t_prev = datetime.fromisoformat(timestamps[i - 1])
                    t_curr = datetime.fromisoformat(timestamps[i])
                    delta = (t_curr - t_prev).total_seconds()
                    intervals.append(delta)
                except (ValueError, TypeError):
                    continue
            avg_interval = sum(intervals) / len(intervals) if intervals else None
        else:
            avg_interval = None

        # Upsert into baseline
        upsert_baseline(
            artifact_path=artifact,
            user_id=user_id if user_id is not None else 0,
            process_name=process if process else "unknown",
            access_count=access_count,
            first_seen=first_seen,
            last_seen=last_seen,
            normal_hours=json.dumps(normal_hours),
            avg_access_interval=avg_interval,
        )
        profiles_built += 1

    summary = {
        "triples": profiles_built,
        "total_events": len(rows),
        "artifacts": sorted(artifacts_seen),
    }

    print(f"Baseline computed:")
    print(f"  Profiles built:   {summary['triples']}")
    print(f"  Events processed: {summary['total_events']}")
    print(f"  Artifacts:        {', '.join(summary['artifacts'])}")

    return summary


def show_baseline():
    """Print the current baseline table contents."""
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT artifact_path, user_id, process_name,
               access_count, first_seen, last_seen,
               normal_hours, avg_access_interval
        FROM baseline
        ORDER BY artifact_path, user_id, process_name
        """
    ).fetchall()
    conn.close()

    if not rows:
        print("Baseline is empty — run baseline.py to compute it.")
        return

    print(f"\n{'='*80}")
    print(f"{'Artifact':<45} {'User':>6} {'Process':<15} {'Count':>6} {'Avg Interval':>13}")
    print(f"{'='*80}")
    for r in rows:
        interval = f"{r['avg_access_interval']:.1f}s" if r["avg_access_interval"] else "N/A"
        print(
            f"{r['artifact_path']:<45} "
            f"{r['user_id']:>6} "
            f"{r['process_name']:<15} "
            f"{r['access_count']:>6} "
            f"{interval:>13}"
        )
    print(f"{'='*80}\n")


if __name__ == "__main__":
    init_db()

    reset = "--reset" in sys.argv
    show = "--show" in sys.argv

    if show:
        show_baseline()
    else:
        compute_baseline(reset=reset)
        show_baseline()
