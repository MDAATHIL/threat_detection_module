#!/usr/bin/env python3
"""Sequence (chain) analysis for multi-step attacks.

`ml/anomaly_detector.py` scores events one at a time. That answers "is this
event unusual?" but not "do these events, in this order, mean something?".
A careful intruder can keep every individual event statistically normal —
read a private key slowly, then edit `authorized_keys` a few seconds later —
and never trip a per-event model.

This module adds a small, deliberate rule layer over *ordered* events within
a session. Every rule reports the exact event ids that fired it, so a chain
alert is as auditable as a probability.

Rules (all confined to one session and a bounded time window):

  ssh_key_injection       private key accessed, then authorized_keys written
                          — persistence by installing an attacker's key
  bulk_credential_delete  three or more distinct credential files deleted
                          — destructive cleanup / ransomware precursor
  cross_artifact_sweep    three or more credential stores touched in one
                          session — harvesting across `.aws`, `.azure`, ...
  rapid_multi_file_sweep  five or more distinct files touched within seconds
                          — a fast harvest that a file-count-only model misses

Usage:
    python sequences.py                     # scan the DB, report all chains
    python sequences.py --session <id>      # restrict to one session
    python sequences.py --evaluate          # recall on chains, FP on normal
    python sequences.py --json chains.json  # machine-readable report
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from posixpath import basename

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ml"))

from db import get_conn, init_db  # noqa: E402
from anomaly_detector import _categorize_artifact  # noqa: E402

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Two events belong to the same chain if they are no more than this far apart.
CHAIN_WINDOW_SECONDS = 300.0

# "Rapid sweep" = this many distinct files touched inside this many seconds.
RAPID_SWEEP_FILES = 5
RAPID_SWEEP_SECONDS = 3.0

# "Bulk delete" = this many distinct credential files deleted in one session.
BULK_DELETE_FILES = 3

# "Cross-artifact sweep" = this many distinct credential stores in one session.
CROSS_ARTIFACT_COUNT = 3

PRIVATE_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity"}
PRIVATE_KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
AUTHORIZED_KEYS_NAME = "authorized_keys"

WRITE_TYPES = {"write", "create", "moved"}
READ_TYPES = {"read"}


@dataclass(frozen=True)
class EventView:
    """The slice of an event the sequence rules care about."""

    id: int
    path: str
    access_type: str
    process: str
    artifact: str
    t: float | None = None  # epoch seconds, when known

    @property
    def name(self) -> str:
        return basename(self.path)


@dataclass
class ChainMatch:
    """A rule that fired, with the events that fired it."""

    rule: str
    severity: str  # "high" | "medium"
    description: str
    event_ids: list[int] = field(default_factory=list)
    detail: str = ""
    session_id: str | None = None

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "description": self.description,
            "event_ids": self.event_ids,
            "detail": self.detail,
            "session_id": self.session_id,
        }


def event_view_from_row(row) -> EventView:
    """Build an EventView from a SQLite event row."""
    path = row["artifact_path"] or ""
    return EventView(
        id=int(row["id"]),
        path=path,
        access_type=(row["access_type"] or "").lower(),
        process=(row["process_name"] or "unknown").lower(),
        artifact=_categorize_artifact(path),
        t=_parse_ts(row["timestamp"]),
    )


def _parse_ts(value) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Predicates
# ---------------------------------------------------------------------------

def _is_private_key(path: str) -> bool:
    name = basename(path).lower()
    return name in PRIVATE_KEY_NAMES or name.endswith(PRIVATE_KEY_SUFFIXES)


def _is_authorized_keys(path: str) -> bool:
    return basename(path).lower() == AUTHORIZED_KEYS_NAME


def _within(a: EventView, b: EventView, window: float = CHAIN_WINDOW_SECONDS) -> bool:
    """True when b follows a inside `window`.

    When either event has no usable timestamp we fall back to event order
    rather than dropping the pair — missing time must not hide a chain.
    """
    if a.t is None or b.t is None:
        return True
    return 0.0 <= (b.t - a.t) <= window


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def rule_ssh_key_injection(events: list[EventView]) -> list[ChainMatch]:
    """A private key is touched, then authorized_keys is written."""
    for i, key_event in enumerate(events):
        if not _is_private_key(key_event.path):
            continue
        for mutation in events[i + 1:]:
            if (_is_authorized_keys(mutation.path)
                    and mutation.access_type in WRITE_TYPES
                    and _within(key_event, mutation)):
                return [ChainMatch(
                    rule="ssh_key_injection",
                    severity="high",
                    description="private key access followed by authorized_keys write",
                    event_ids=[key_event.id, mutation.id],
                    detail=(f"{key_event.name} touched by {key_event.process}, then "
                            f"{mutation.name} {mutation.access_type} by {mutation.process}"),
                )]
    return []


def rule_bulk_credential_delete(events: list[EventView]) -> list[ChainMatch]:
    """Several distinct credential files deleted in one session."""
    deleted = [e for e in events if e.access_type == "delete"]
    distinct = []
    for e in deleted:
        if e.path not in distinct:
            distinct.append(e.path)
    if len(distinct) < BULK_DELETE_FILES:
        return []
    ids = [e.id for e in deleted if e.path in distinct]
    return [ChainMatch(
        rule="bulk_credential_delete",
        severity="high",
        description=f"{len(distinct)} distinct credential files deleted in one session",
        event_ids=ids,
        detail="; ".join(sorted(set(basename(p) for p in distinct))),
    )]


def rule_cross_artifact_sweep(events: list[EventView]) -> list[ChainMatch]:
    """One session touching several different credential stores."""
    artifacts: list[str] = []
    for e in events:
        if e.artifact and e.artifact not in artifacts:
            artifacts.append(e.artifact)
    if len(artifacts) < CROSS_ARTIFACT_COUNT:
        return []
    ids = []
    seen = set()
    for e in events:
        if e.artifact not in seen:
            seen.add(e.artifact)
            ids.append(e.id)
    return [ChainMatch(
        rule="cross_artifact_sweep",
        severity="high",
        description=f"session touched {len(artifacts)} credential stores",
        event_ids=ids,
        detail=", ".join(artifacts),
    )]


def rule_rapid_multi_file_sweep(events: list[EventView]) -> list[ChainMatch]:
    """Many distinct files touched inside a few seconds."""
    timed = [e for e in events if e.t is not None]
    for start in range(len(timed)):
        window = [timed[start]]
        seen = {timed[start].path}
        for e in timed[start + 1:]:
            if e.t - timed[start].t > RAPID_SWEEP_SECONDS:
                break
            window.append(e)
            seen.add(e.path)
        if len(seen) >= RAPID_SWEEP_FILES:
            return [ChainMatch(
                rule="rapid_multi_file_sweep",
                severity="medium",
                description=(f"{len(seen)} distinct files touched within "
                             f"{RAPID_SWEEP_SECONDS:.0f}s"),
                event_ids=[e.id for e in window],
                detail=", ".join(sorted(basename(p) for p in seen)),
            )]
    return []


RULES = (
    rule_ssh_key_injection,
    rule_bulk_credential_delete,
    rule_cross_artifact_sweep,
    rule_rapid_multi_file_sweep,
)


def detect_chains(events: list[EventView]) -> list[ChainMatch]:
    """Run every rule over one session's ordered events."""
    matches: list[ChainMatch] = []
    for rule in RULES:
        matches.extend(rule(events))
    return matches


# ---------------------------------------------------------------------------
# Database scanning
# ---------------------------------------------------------------------------

def sessions_from_db(session_id: str | None = None) -> dict[str, list[EventView]]:
    """Group DB events into ordered sessions."""
    conn = get_conn()
    if session_id:
        rows = conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp, id",
            (session_id,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM events ORDER BY timestamp, id").fetchall()
    conn.close()

    sessions: dict[str, list[EventView]] = {}
    for row in rows:
        sid = row["session_id"] or f"event_{row['id']}"
        sessions.setdefault(sid, []).append(event_view_from_row(row))
    return sessions


def scan_sessions(session_id: str | None = None) -> list[ChainMatch]:
    """Detect chains across every stored session."""
    matches: list[ChainMatch] = []
    for sid, events in sessions_from_db(session_id).items():
        for match in detect_chains(events):
            match.session_id = sid
            matches.append(match)
    return matches


def _is_chain_session(sid: str) -> bool:
    return sid.startswith("attack_chain")


def _is_burst_session(sid: str) -> bool:
    return sid.startswith("attack") and not _is_chain_session(sid)


def evaluate() -> dict:
    """Measure the sequence layer against the labeled dataset.

    Recall is over chain sessions (the attacks this layer exists to catch).
    False positives are normal sessions that raised any chain rule.
    """
    sessions = sessions_from_db()
    chain_total = chain_hit = 0
    burst_total = burst_hit = 0
    normal_total = normal_fp = 0
    by_rule: dict[str, int] = {}

    for sid, events in sessions.items():
        matches = detect_chains(events)
        for m in matches:
            by_rule[m.rule] = by_rule.get(m.rule, 0) + 1
        if _is_chain_session(sid):
            chain_total += 1
            chain_hit += 1 if matches else 0
        elif _is_burst_session(sid):
            burst_total += 1
            burst_hit += 1 if matches else 0
        else:
            normal_total += 1
            normal_fp += 1 if matches else 0

    return {
        "chain_sessions": chain_total,
        "chain_detected": chain_hit,
        "burst_sessions": burst_total,
        "burst_detected": burst_hit,
        "normal_sessions": normal_total,
        "false_positives": normal_fp,
        "by_rule": by_rule,
    }


def _print_matches(matches: list[ChainMatch]) -> None:
    colors = {"high": "\033[91m", "medium": "\033[93m"}
    reset = "\033[0m"
    for m in sorted(matches, key=lambda x: (x.severity != "high", x.rule)):
        color = colors.get(m.severity, "")
        print(f"  {color}[{m.severity.upper():6}]{reset} {m.rule} "
              f"(session={m.session_id})")
        print(f"           {m.description}")
        print(f"           events={m.event_ids}")
        if m.detail:
            print(f"           {m.detail}")


def main() -> None:
    init_db()
    argv = sys.argv[1:]

    if "--evaluate" in argv:
        result = evaluate()
        print(f"\n{'='*70}")
        print("Sequence layer — chain detection vs labeled sessions")
        print(f"{'='*70}")
        print(f"  Chain sessions:  {result['chain_detected']}/{result['chain_sessions']} detected")
        print(f"  Burst sessions:  {result['burst_detected']}/{result['burst_sessions']} "
              f"(statistical layer's job)")
        print(f"  Normal sessions: {result['false_positives']}/{result['normal_sessions']} "
              f"false positives")
        if result["by_rule"]:
            print("  Fired by rule:")
            for rule, count in sorted(result["by_rule"].items()):
                print(f"    {rule}: {count}")
        print(f"{'='*70}\n")
        return

    session_id = None
    if "--session" in argv:
        idx = argv.index("--session")
        if idx + 1 >= len(argv):
            print("Usage: python sequences.py --session <id>")
            sys.exit(1)
        session_id = argv[idx + 1]

    matches = scan_sessions(session_id)

    if "--json" in argv:
        idx = argv.index("--json")
        out = argv[idx + 1] if len(argv) > idx + 1 and not argv[idx + 1].startswith("--") else "chains.json"
        Path(out).write_text(json.dumps(
            {"total": len(matches), "chains": [m.as_dict() for m in matches]}, indent=2
        ))
        print(f"Wrote {out} ({len(matches)} chain(s))")

    if not matches:
        print("No attack chains detected.")
        return

    print(f"\n{'='*70}")
    print(f"Detected {len(matches)} attack chain(s)")
    print(f"{'='*70}")
    _print_matches(matches)
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
