#!/usr/bin/env python3

"""
Anomaly Detector — Bayesian Network-based scoring for filesystem access events.

Uses pgmpy to build a Discrete Bayesian Network over event features
(artifact, process, user, access_type, hour, day_of_week) and scores
new events against learned normal behavior.

Network structure:
    artifact ──┬── process
               ├── user
               ├── access_type
               └── hour ── day_of_week

Scoring:
    P(event) = P(artifact) × P(process|artifact) × P(user|artifact)
               × P(access_type|artifact) × P(hour|process,user)
               × P(day_of_week|hour)

Low P(event) → anomaly.  Each conditional probability is reported for
explainability.

Usage:
    python anomaly_detector.py train              # learn from historical events
    python anomaly_detector.py score <event_id>   # score a single event
    python anomaly_detector.py score-all           # score all events
    python anomaly_detector.py explain <event_id>  # detailed explanation
    python anomaly_detector.py status              # show model info
"""

import json
import logging
import math
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from db import get_conn, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("anomaly_detector")

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

# Discrete states for each feature
KNOWN_PROCESSES = [
    "bash", "cat", "head", "tail", "nano", "python3",
    "curl", "wget", "ssh", "grep", "less",
]

KNOWN_USERS = ["root", "debian"]

KNOWN_ACCESS_TYPES = ["read", "write", "create", "delete", "moved"]

# Hour buckets: 6 ranges covering 24h
HOUR_BUCKETS = {
    "night":    list(range(0, 6)),      # 00-05
    "early":    list(range(6, 9)),      # 06-08
    "morning":  list(range(9, 12)),     # 09-11
    "midday":   list(range(12, 14)),    # 12-13
    "afternoon":list(range(14, 18)),    # 14-17
    "evening":  list(range(18, 24)),    # 18-23
}
BUCKET_NAMES = list(HOUR_BUCKETS.keys())
HOUR_TO_BUCKET = {}
for _bname, _hours in HOUR_BUCKETS.items():
    for _h in _hours:
        HOUR_TO_BUCKET[_h] = _bname

# Day-of-week buckets: weekday vs weekend
DAY_BUCKETS = {
    "weekday": [0, 1, 2, 3, 4],   # Mon-Fri
    "weekend": [5, 6],             # Sat-Sun
}
DAY_BUCKET_NAMES = list(DAY_BUCKETS.keys())
DAY_TO_BUCKET = {}
for _bname, _days in DAY_BUCKETS.items():
    for _d in _days:
        DAY_TO_BUCKET[_d] = _bname


def _bucketize_hour(dt: datetime) -> str:
    """Convert hour of day to a named bucket."""
    return HOUR_TO_BUCKET.get(dt.hour, "morning")


def _bucketize_day(dt: datetime) -> str:
    """Convert day of week to weekday/weekend."""
    return DAY_TO_BUCKET.get(dt.weekday(), "weekday")


def extract_event_features(event_row) -> dict:
    """Extract discrete features from a database event row.

    Returns dict with keys matching BN node names:
        artifact, process, user, access_type, hour_bucket, day_bucket
    """
    # Parse timestamp
    ts_str = event_row["timestamp"]
    try:
        dt = datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        dt = datetime.utcnow()

    # Artifact — extract category (last meaningful directory name)
    artifact_path = event_row["artifact_path"] or "unknown"
    artifact = _categorize_artifact(artifact_path)

    # Process
    process = (event_row["process_name"] or "unknown").lower().strip()
    if process not in KNOWN_PROCESSES:
        process = "other"

    # User
    username = (event_row["username"] or "unknown").lower().strip()
    if username not in KNOWN_USERS:
        username = "other"

    # Access type
    access_type = (event_row["access_type"] or "read").lower().strip()
    if access_type not in KNOWN_ACCESS_TYPES:
        access_type = "read"

    return {
        "artifact": artifact,
        "process": process,
        "user": username,
        "access_type": access_type,
        "hour_bucket": _bucketize_hour(dt),
        "day_bucket": _bucketize_day(dt),
    }


def _categorize_artifact(path: str) -> str:
    """Map a full filesystem path to a short artifact category name.

    Examples:
        /home/debian/.azure/config     → azure
        /home/debian/.ssh/id_rsa       → ssh
        /home/debian/.aws/credentials  → aws
        /home/debian/.kube/config      → kube
        /etc/shadow                    → etc
    """
    path_lower = path.lower()
    for keyword in ["azure", "aws", "ssh", "kube", "steampipe", "gnupg",
                     "docker", "npm", "pip", "bash_history", "shadow",
                     "passwd", "sudoers"]:
        if keyword in path_lower:
            return keyword
    # Fallback: use last two path components
    parts = Path(path).parts
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return parts[-1] if parts else "unknown"


# ---------------------------------------------------------------------------
# BN node cardinalities (must match state lists above + "other" for some)
# ---------------------------------------------------------------------------

NODE_STATES = {
    "artifact":    None,   # dynamic — built from data
    "process":     KNOWN_PROCESSES + ["other"],
    "user":        KNOWN_USERS + ["other"],
    "access_type": KNOWN_ACCESS_TYPES,
    "hour_bucket": BUCKET_NAMES,
    "day_bucket":  DAY_BUCKET_NAMES,
}

# BN edges — the causal structure
BN_EDGES = [
    ("artifact", "process"),
    ("artifact", "user"),
    ("artifact", "access_type"),
    ("user",     "hour_bucket"),
    ("hour_bucket", "day_bucket"),
]


# ---------------------------------------------------------------------------
# CPD construction helpers
# ---------------------------------------------------------------------------

def _build_cpd_from_counts(
    variable: str,
    parent: str | None,
    counts: dict,
    variable_states: list[str],
    parent_states: list[str] | None,
    alpha: float = 1.0,
):
    """Build a TabularCPD from observed counts with Laplace smoothing.

    Args:
        variable: node name
        parent: parent node name (None for root nodes)
        counts: dict mapping parent_value → {var_value: count}
                For root nodes: {var_value: count}
        variable_states: ordered list of variable's discrete states
        parent_states: ordered list of parent's discrete states (None for root)
        alpha: Laplace smoothing pseudo-count

    Returns:
        TabularCPD instance
    """
    from pgmpy.factors.discrete import TabularCPD

    var_card = len(variable_states)

    if parent is None:
        # Root node: P(variable)
        total = sum(counts.get(s, 0) for s in variable_states) + alpha * var_card
        values = [[(counts.get(s, 0) + alpha) / total] for s in variable_states]
    else:
        # Conditional: P(variable | parent)
        par_card = len(parent_states)
        values = []
        for pv in parent_states:
            parent_counts = counts.get(pv, {})
            total = sum(parent_counts.get(s, 0) for s in variable_states) + alpha * var_card
            col = [(parent_counts.get(s, 0) + alpha) / total for s in variable_states]
            values.append(col)
        # Transpose: pgmpy expects [var_states × parent_combinations]
        # Each column = one parent state combination
        values = list(zip(*values))

    if parent is not None:
        cpd = TabularCPD(
            variable=variable,
            variable_card=var_card,
            values=values,
            evidence=[parent],
            evidence_card=[len(parent_states)],
            state_names={variable: variable_states, parent: parent_states},
        )
    else:
        cpd = TabularCPD(
            variable=variable,
            variable_card=var_card,
            values=values,
            state_names={variable: variable_states},
        )
    return cpd


def _build_cpd_multi_parent(
    variable: str,
    parents: list[str],
    counts: dict,
    variable_states: list[str],
    parent_states_map: dict[str, list[str]],
    alpha: float = 1.0,
):
    """Build a CPD for a node with multiple parents.

    counts maps (parent1_val, parent2_val, ...) → {var_value: count}
    """
    from pgmpy.factors.discrete import TabularCPD

    var_card = len(variable_states)
    parent_cards = [len(parent_states_map[p]) for p in parents]

    # Generate all parent combinations in lexicographic order
    from itertools import product
    parent_combos = list(product(*[parent_states_map[p] for p in parents]))

    columns = []
    for combo in parent_combos:
        parent_counts = counts.get(combo, {})
        total = sum(parent_counts.get(s, 0) for s in variable_states) + alpha * var_card
        col = [(parent_counts.get(s, 0) + alpha) / total for s in variable_states]
        columns.append(col)

    # Transpose to [var_states × num_combinations]
    values = list(zip(*columns))

    state_names = {variable: variable_states}
    for p in parents:
        state_names[p] = parent_states_map[p]

    cpd = TabularCPD(
        variable=variable,
        variable_card=var_card,
        values=values,
        evidence=parents,
        evidence_card=parent_cards,
        state_names=state_names,
    )
    return cpd


# ---------------------------------------------------------------------------
# AnomalyDetector class
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """Bayesian Network anomaly detector for filesystem access events."""

    MODEL_PATH = Path(__file__).parent / "anomaly_model.json"

    def __init__(self):
        self.model = None          # pgmpy DiscreteBayesianNetwork
        self.variable_states = {}  # node → list of states
        self._counts = {}          # learned counts for CPD construction
        self._trained = False

    def train(self, min_events: int = 5) -> dict:
        """Learn CPDs from all historical events in the database.

        Returns summary dict with training stats.
        """
        from pgmpy.models import DiscreteBayesianNetwork

        conn = get_conn()
        rows = conn.execute(
            "SELECT artifact_path, process_name, username, access_type, timestamp "
            "FROM events ORDER BY timestamp"
        ).fetchall()
        conn.close()

        if len(rows) < min_events:
            log.warning("Only %d events found (need >= %d). Using uniform priors.", len(rows), min_events)
            return self._build_uniform_model()

        log.info("Training on %d events...", len(rows))

        # Extract features for all events
        features_list = [extract_event_features(row) for row in rows]

        # Discover artifact categories dynamically
        artifacts = sorted(set(f["artifact"] for f in features_list))
        self.variable_states["artifact"] = artifacts
        # Ensure other nodes have states set
        for node, states in NODE_STATES.items():
            if states is not None:
                self.variable_states[node] = states

        # Build the BN structure
        self.model = DiscreteBayesianNetwork(ebunch=BN_EDGES)

        # --- Count occurrences for CPD construction ---
        # Root: P(artifact)
        artifact_counts = defaultdict(int)
        for f in features_list:
            artifact_counts[f["artifact"]] += 1

        # P(process | artifact)
        process_given_artifact = defaultdict(lambda: defaultdict(int))
        for f in features_list:
            process_given_artifact[f["artifact"]][f["process"]] += 1

        # P(user | artifact)
        user_given_artifact = defaultdict(lambda: defaultdict(int))
        for f in features_list:
            user_given_artifact[f["artifact"]][f["user"]] += 1

        # P(access_type | artifact)
        access_given_artifact = defaultdict(lambda: defaultdict(int))
        for f in features_list:
            access_given_artifact[f["artifact"]][f["access_type"]] += 1

        # P(hour_bucket | user)
        hour_given_user = defaultdict(lambda: defaultdict(int))
        for f in features_list:
            hour_given_user[f["user"]][f["hour_bucket"]] += 1

        # P(day_bucket | hour_bucket)
        day_given_hour = defaultdict(lambda: defaultdict(int))
        for f in features_list:
            day_given_hour[f["hour_bucket"]][f["day_bucket"]] += 1

        # --- Build CPDs ---
        log.info("Building CPDs with Laplace smoothing (alpha=1.0)...")

        states = self.variable_states

        cpd_artifact = _build_cpd_from_counts(
            variable="artifact", parent=None,
            counts=dict(artifact_counts),
            variable_states=states["artifact"],
            parent_states=None,
        )

        cpd_process = _build_cpd_from_counts(
            variable="process", parent="artifact",
            counts=dict(process_given_artifact),
            variable_states=states["process"],
            parent_states=states["artifact"],
        )

        cpd_user = _build_cpd_from_counts(
            variable="user", parent="artifact",
            counts=dict(user_given_artifact),
            variable_states=states["user"],
            parent_states=states["artifact"],
        )

        cpd_access = _build_cpd_from_counts(
            variable="access_type", parent="artifact",
            counts=dict(access_given_artifact),
            variable_states=states["access_type"],
            parent_states=states["artifact"],
        )

        cpd_hour = _build_cpd_from_counts(
            variable="hour_bucket", parent="user",
            counts=dict(hour_given_user),
            variable_states=states["hour_bucket"],
            parent_states=states["user"],
        )

        cpd_day = _build_cpd_from_counts(
            variable="day_bucket", parent="hour_bucket",
            counts=dict(day_given_hour),
            variable_states=states["day_bucket"],
            parent_states=states["hour_bucket"],
        )

        # Add CPDs to model
        self.model.add_cpds(cpd_artifact, cpd_process, cpd_user,
                            cpd_access, cpd_hour, cpd_day)

        # Validate model
        assert self.model.check_model(), "Model validation failed!"

        self._trained = True

        # Save model state
        self._save_model()

        summary = {
            "events_trained": len(rows),
            "artifacts": artifacts,
            "nodes": list(self.model.nodes()),
            "edges": [list(e) for e in self.model.edges()],
        }
        log.info("Model trained: %d events → %d nodes, %d edges",
                 len(rows), len(self.model.nodes()), len(self.model.edges()))
        return summary

    def _build_uniform_model(self) -> dict:
        """Build model with uniform priors (no data or too little data)."""
        from pgmpy.models import DiscreteBayesianNetwork

        # Use a minimal artifact set
        self.variable_states["artifact"] = ["azure", "ssh", "aws", "kube", "other"]
        for node, states in NODE_STATES.items():
            if states is not None:
                self.variable_states[node] = states

        self.model = DiscreteBayesianNetwork(ebunch=BN_EDGES)
        states = self.variable_states

        # Uniform CPDs
        from pgmpy.factors.discrete import TabularCPD

        n_art = len(states["artifact"])
        cpd_artifact = TabularCPD(
            variable="artifact", variable_card=n_art,
            values=[[1.0 / n_art]] * n_art,
            state_names={"artifact": states["artifact"]},
        )

        n_proc = len(states["process"])
        # P(process | artifact) — uniform for each artifact
        cpd_process = TabularCPD(
            variable="process", variable_card=n_proc,
            values=[[1.0 / n_proc]] * n_proc,
            evidence=["artifact"], evidence_card=[n_art],
            state_names={"process": states["process"], "artifact": states["artifact"]},
        )

        n_user = len(states["user"])
        cpd_user = TabularCPD(
            variable="user", variable_card=n_user,
            values=[[1.0 / n_user]] * n_user,
            evidence=["artifact"], evidence_card=[n_art],
            state_names={"user": states["user"], "artifact": states["artifact"]},
        )

        n_acc = len(states["access_type"])
        cpd_access = TabularCPD(
            variable="access_type", variable_card=n_acc,
            values=[[1.0 / n_acc]] * n_acc,
            evidence=["artifact"], evidence_card=[n_art],
            state_names={"access_type": states["access_type"], "artifact": states["artifact"]},
        )

        n_hour = len(states["hour_bucket"])
        cpd_hour = TabularCPD(
            variable="hour_bucket", variable_card=n_hour,
            values=[[1.0 / n_hour]] * n_hour,
            evidence=["user"], evidence_card=[n_user],
            state_names={
                "hour_bucket": states["hour_bucket"],
                "user": states["user"],
            },
        )

        n_day = len(states["day_bucket"])
        cpd_day = TabularCPD(
            variable="day_bucket", variable_card=n_day,
            values=[[1.0 / n_day]] * n_day,
            evidence=["hour_bucket"], evidence_card=[n_hour],
            state_names={"day_bucket": states["day_bucket"], "hour_bucket": states["hour_bucket"]},
        )

        self.model.add_cpds(cpd_artifact, cpd_process, cpd_user,
                            cpd_access, cpd_hour, cpd_day)
        assert self.model.check_model(), "Uniform model validation failed!"
        self._trained = True
        self._save_model()

        return {
            "events_trained": 0,
            "artifacts": states["artifact"],
            "nodes": list(self.model.nodes()),
            "edges": [list(e) for e in self.model.edges()],
            "mode": "uniform_priors",
        }

    # -------------------------------------------------------------------
    # Scoring
    # -------------------------------------------------------------------

    def score_event(self, event_row) -> dict:
        """Score a single event against the learned model.

        Returns:
            {
                "event_id": int,
                "score": float (0-1, higher = more normal),
                "log_score": float (log probability),
                "risk_level": "normal" | "unusual" | "suspicious" | "anomaly",
                "risk_score": float (0-100, higher = more risky),
                "factors": [ { "variable": str, "parent": str|None,
                               "probability": float, "normal": bool } ],
                "explanation": str (human-readable),
            }
        """
        if not self._trained or self.model is None:
            return {"event_id": None, "score": 0.5, "risk_level": "unknown",
                    "risk_score": 50.0, "explanation": "Model not trained"}

        features = extract_event_features(event_row)
        event_id = event_row["id"]

        # Compute P(event) from CPDs
        log_score = 0.0
        factors = []

        # P(artifact)
        cpd = self.model.get_cpds("artifact")
        p = self._lookup_cpd(cpd, "artifact", features["artifact"], {})
        log_score += math.log(max(p, 1e-15))
        factors.append({"variable": "artifact", "parent": None,
                        "probability": p, "normal": p > 0.05})

        # P(process | artifact)
        cpd = self.model.get_cpds("process")
        p = self._lookup_cpd(cpd, "process", features["process"],
                             {"artifact": features["artifact"]})
        log_score += math.log(max(p, 1e-15))
        factors.append({"variable": "process", "parent": "artifact",
                        "probability": p, "normal": p > 0.05})

        # P(user | artifact)
        cpd = self.model.get_cpds("user")
        p = self._lookup_cpd(cpd, "user", features["user"],
                             {"artifact": features["artifact"]})
        log_score += math.log(max(p, 1e-15))
        factors.append({"variable": "user", "parent": "artifact",
                        "probability": p, "normal": p > 0.05})

        # P(access_type | artifact)
        cpd = self.model.get_cpds("access_type")
        p = self._lookup_cpd(cpd, "access_type", features["access_type"],
                             {"artifact": features["artifact"]})
        log_score += math.log(max(p, 1e-15))
        factors.append({"variable": "access_type", "parent": "artifact",
                        "probability": p, "normal": p > 0.05})

        # P(hour_bucket | user)
        cpd = self.model.get_cpds("hour_bucket")
        p = self._lookup_cpd(cpd, "hour_bucket", features["hour_bucket"],
                             {"user": features["user"]})
        log_score += math.log(max(p, 1e-15))
        factors.append({"variable": "hour_bucket", "parent": "user",
                        "probability": p, "normal": p > 0.05})

        # P(day_bucket | hour_bucket)
        cpd = self.model.get_cpds("day_bucket")
        p = self._lookup_cpd(cpd, "day_bucket", features["day_bucket"],
                             {"hour_bucket": features["hour_bucket"]})
        log_score += math.log(max(p, 1e-15))
        factors.append({"variable": "day_bucket", "parent": "hour_bucket",
                        "probability": p, "normal": p > 0.05})

        # --- Normalized scoring using log-probability ratio ---
        # Each factor contributes log(p_i). Best case = log(1.0) = 0.
        # Worst case per factor = log(min_p) where min_p is the floor.
        n_factors = len(factors)
        min_p = 1e-3  # floor probability for worst case
        best_log_score = 0.0                # all factors = 1.0
        worst_log_score = n_factors * math.log(min_p)  # all factors = min_p

        # Gap from best (0 = perfect match, large = very anomalous)
        gap = best_log_score - log_score   # always >= 0
        max_gap = best_log_score - worst_log_score

        # Normalize to 0-1: 0 = perfectly normal, 1 = maximally anomalous
        normalized = gap / max_gap if max_gap > 0 else 0.0
        normalized = max(0.0, min(1.0, normalized))

        # Score = how normal (0-1), risk = how anomalous (0-100)
        score = 1.0 - normalized
        risk_score = normalized * 100.0

        # Risk level classification
        if risk_score >= 80:
            risk_level = "anomaly"
        elif risk_score >= 50:
            risk_level = "suspicious"
        elif risk_score >= 20:
            risk_level = "unusual"
        else:
            risk_level = "normal"

        # Build explanation
        worst_factors = sorted(factors, key=lambda f: f["probability"])[:3]
        explanation_parts = []
        for f in worst_factors:
            if f["parent"]:
                explanation_parts.append(
                    f"P({f['variable']}={features[f['variable']]} | {f['parent']}) = {f['probability']:.4f}"
                )
            else:
                explanation_parts.append(
                    f"P({f['variable']}={features[f['variable']]}) = {f['probability']:.4f}"
                )
        explanation = "; ".join(explanation_parts)

        return {
            "event_id": event_id,
            "features": features,
            "score": score,
            "log_score": log_score,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "factors": factors,
            "explanation": explanation,
        }

    def _lookup_cpd(self, cpd, variable: str, var_value: str,
                    evidence: dict[str, str]) -> float:
        """Look up a probability from a CPD given variable value and evidence.

        Handles 1D (scalar root), 2D (single-parent), and nD (multi-parent) CPDs.
        pgmpy internally stores multi-parent CPDs as nD arrays where each
        dimension corresponds to one parent in evidence order.
        """
        var_states = cpd.state_names[variable]
        var_idx = var_states.index(var_value) if var_value in var_states else 0

        evidence_vars = cpd.get_evidence() or []
        vals = cpd.values

        if not evidence_vars or vals.ndim == 1:
            # Root node or scalar
            if vals.ndim == 1:
                return float(vals[0]) if len(vals) == 1 else float(vals[var_idx])
            return float(vals[var_idx][0])

        # Build multi-dimensional index for nD arrays
        # pgmpy orders dimensions as [var, evidence_var_0, evidence_var_1, ...]
        indices = [var_idx]
        for ev_var in evidence_vars:
            ev_states = cpd.state_names[ev_var]
            ev_val = evidence.get(ev_var, ev_states[0])
            ev_idx = ev_states.index(ev_val) if ev_val in ev_states else 0
            indices.append(ev_idx)

        return float(vals[tuple(indices)])

    # -------------------------------------------------------------------
    # Batch scoring
    # -------------------------------------------------------------------

    def score_all_events(self, limit: int = 0) -> list[dict]:
        """Score all events in the database. Returns list of score dicts."""
        conn = get_conn()
        query = "SELECT * FROM events ORDER BY timestamp"
        if limit > 0:
            query += f" LIMIT {limit}"
        rows = conn.execute(query).fetchall()
        conn.close()

        results = []
        for row in rows:
            result = self.score_event(row)
            results.append(result)
        return results

    # -------------------------------------------------------------------
    # Model persistence
    # -------------------------------------------------------------------

    def _save_model(self):
        """Save full model state (structure, CPDs, states) to JSON."""
        from pgmpy.models import DiscreteBayesianNetwork

        # Serialize CPDs
        cpds_data = []
        for cpd in self.model.get_cpds():
            evidence = cpd.get_evidence()
            # evidence_card: cardinality of each parent (skip first element which is self)
            all_card = list(cpd.cardinality)
            evidence_card = all_card[1:] if len(all_card) > 1 else []
            cpds_data.append({
                "variable": cpd.variable,
                "variable_card": int(cpd.variable_card),
                "values": cpd.values.tolist(),
                "evidence": evidence,
                "evidence_card": [int(c) for c in evidence_card],
                "state_names": cpd.state_names,
            })

        data = {
            "variable_states": self.variable_states,
            "edges": [list(e) for e in self.model.edges()],
            "cpds": cpds_data,
            "trained": self._trained,
        }
        self.MODEL_PATH.write_text(json.dumps(data, indent=2))
        log.info("Model saved to %s", self.MODEL_PATH)

    def load_model(self) -> bool:
        """Load full model from JSON. Returns True if successful."""
        from pgmpy.models import DiscreteBayesianNetwork
        from pgmpy.factors.discrete import TabularCPD

        if not self.MODEL_PATH.exists():
            return False
        try:
            data = json.loads(self.MODEL_PATH.read_text())
            self.variable_states = data["variable_states"]
            self._trained = data.get("trained", False)

            if "cpds" in data and "edges" in data:
                # Reconstruct full model
                self.model = DiscreteBayesianNetwork(ebunch=data["edges"])
                for cpd_data in data["cpds"]:
                    values = np.array(cpd_data["values"])
                    # pgmpy stores multi-parent CPDs as nD arrays internally,
                    # but the constructor expects 2D [var_card x product(evidence_card)].
                    # Also handle edge case where single-state root node gets
                    # saved as a flat 1D list like [1.0].
                    if values.ndim == 1:
                        values = values.reshape(-1, 1)
                    elif values.ndim > 2:
                        values = values.reshape(values.shape[0], -1)
                    cpd = TabularCPD(
                        variable=cpd_data["variable"],
                        variable_card=cpd_data["variable_card"],
                        values=values.tolist(),
                        evidence=cpd_data.get("evidence", []),
                        evidence_card=cpd_data.get("evidence_card", []),
                        state_names=cpd_data["state_names"],
                    )
                    self.model.add_cpds(cpd)
                log.info("Model loaded from %s (%d nodes, %d CPDs)",
                         self.MODEL_PATH, len(self.model.nodes()), len(data["cpds"]))
            else:
                log.info("Model metadata loaded (no CPDs — run 'train' to rebuild)")

            return True
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            log.warning("Failed to load model: %s", e)
            return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_score(result: dict, verbose: bool = False):
    """Pretty-print a scoring result."""
    if "error" in result:
        print(f"  Event #{result.get('event_id', '?')}: ERROR — {result['error']}")
        return

    risk_colors = {
        "normal": "\033[92m",     # green
        "unusual": "\033[93m",    # yellow
        "suspicious": "\033[91m", # red
        "anomaly": "\033[95m",    # magenta
    }
    reset = "\033[0m"
    color = risk_colors.get(result["risk_level"], "")

    features = result.get("features", {})
    print(
        f"  Event #{result['event_id']}: "
        f"{color}{result['risk_level'].upper():>10}{reset} "
        f"(risk={result['risk_score']:.1f}, score={result['score']:.6f}) "
        f"artifact={features.get('artifact', '?')} "
        f"process={features.get('process', '?')} "
        f"user={features.get('user', '?')} "
        f"hour={features.get('hour_bucket', '?')}"
    )

    if verbose:
        print(f"    Explanation: {result['explanation']}")
        print(f"    Factor breakdown:")
        for f in result.get("factors", []):
            marker = "✓" if f["normal"] else "✗"
            print(f"      {marker} P({f['variable']} | {f['parent'] or 'root'}) = {f['probability']:.6f}")


def main():
    init_db()
    detector = AnomalyDetector()
    detector.load_model()

    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "train":
        summary = detector.train()
        print(f"\nTraining complete:")
        print(f"  Events:       {summary['events_trained']}")
        print(f"  Artifacts:    {', '.join(summary['artifacts'])}")
        print(f"  BN nodes:     {len(summary['nodes'])}")
        print(f"  BN edges:     {len(summary['edges'])}")
        if summary.get("mode") == "uniform_priors":
            print(f"  Mode:         Uniform priors (insufficient data)")

    elif cmd == "score":
        if len(sys.argv) < 3:
            print("Usage: python anomaly_detector.py score <event_id>")
            sys.exit(1)
        event_id = int(sys.argv[2])
        conn = get_conn()
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        conn.close()
        if row is None:
            print(f"Event #{event_id} not found.")
            sys.exit(1)
        result = detector.score_event(row)
        _print_score(result, verbose=True)

    elif cmd == "score-all":
        results = detector.score_all_events()
        if not results:
            print("No events to score.")
            sys.exit(0)

        # Summary stats
        levels = defaultdict(int)
        for r in results:
            levels[r["risk_level"]] += 1

        print(f"\n{'='*70}")
        print(f"Scoring {len(results)} events")
        print(f"{'='*70}")
        for level in ["normal", "unusual", "suspicious", "anomaly"]:
            count = levels.get(level, 0)
            pct = (count / len(results)) * 100 if results else 0
            print(f"  {level.upper():>12}: {count:4d} ({pct:5.1f}%)")
        print(f"{'='*70}\n")

        # Show non-normal events
        anomalies = [r for r in results if r["risk_level"] != "normal"]
        if anomalies:
            print(f"Flagged events ({len(anomalies)}):")
            for r in sorted(anomalies, key=lambda x: -x["risk_score"]):
                _print_score(r, verbose=True)
                print()
        else:
            print("No anomalies detected — all events are normal.")

    elif cmd == "explain":
        if len(sys.argv) < 3:
            print("Usage: python anomaly_detector.py explain <event_id>")
            sys.exit(1)
        event_id = int(sys.argv[2])
        conn = get_conn()
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        conn.close()
        if row is None:
            print(f"Event #{event_id} not found.")
            sys.exit(1)
        result = detector.score_event(row)
        print(f"\n{'='*70}")
        print(f"Event #{result['event_id']} — Detailed Explanation")
        print(f"{'='*70}")
        print(f"Risk Level:  {result['risk_level'].upper()}")
        print(f"Risk Score:  {result['risk_score']:.1f}/100")
        print(f"Probability: {result['score']:.8f}")
        print(f"\nFeatures:")
        for k, v in result.get("features", {}).items():
            print(f"  {k:20s} = {v}")
        print(f"\nConditional Probabilities:")
        for f in result.get("factors", []):
            marker = "✓ NORMAL" if f["normal"] else "✗ UNUSUAL"
            if f["parent"]:
                print(f"  P({f['variable']}={result['features'][f['variable']]} | {f['parent']}) "
                      f"= {f['probability']:.6f}  [{marker}]")
            else:
                print(f"  P({f['variable']}={result['features'][f['variable']]}) "
                      f"= {f['probability']:.6f}  [{marker}]")
        print(f"\nInterpretation:")
        print(f"  {result['explanation']}")
        print(f"{'='*70}")

    elif cmd == "status":
        if detector._trained and detector.model:
            print(f"Model: trained")
            print(f"  Nodes: {list(detector.model.nodes())}")
            print(f"  Edges: {list(detector.model.edges())}")
            print(f"  Artifact states: {detector.variable_states.get('artifact', [])}")
            conn = get_conn()
            count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            conn.close()
            print(f"  Events in DB: {count}")
        else:
            print("Model: not trained (run 'python anomaly_detector.py train')")

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
