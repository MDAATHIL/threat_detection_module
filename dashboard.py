#!/usr/bin/env python3
"""
Interactive web dashboard for the behavior-based threat detection system.

This is a *thin* control surface: every button calls the same functions the CLIs
call (`baseline.compute_baseline`, `anomaly_detector.train/evaluate/...`,
`sequences.scan_sessions`, `alerts.emit`, `generate_test_events.generate_dataset`)
and reads the same SQLite database the collector writes to. Nothing is mocked
and no detection logic is reimplemented here.

Run it:

    python dashboard.py                 # http://127.0.0.1:8765
    python dashboard.py --port 9000     # different port
    python dashboard.py --open          # also open a browser
    python dashboard.py --host 0.0.0.0  # expose on the network (see warning)

Uses only the standard library for the web layer — no new dependencies.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import io
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ml"))

import db  # noqa: E402
import alerts  # noqa: E402
import baseline as baseline_mod  # noqa: E402
import sequences  # noqa: E402
import anomaly_detector as ad  # noqa: E402
import generate_test_events as gen  # noqa: E402
from db import get_conn, init_db  # noqa: E402

log = logging.getLogger("dashboard")

FLAGGED_LEVELS = {"unusual", "suspicious", "anomaly"}
ALL_LEVELS = ["normal", "unusual", "suspicious", "anomaly"]
COLLECTOR_LOG = ROOT / "collector.log"
ALERTS_REPORT = ROOT / "alerts.json"
CHAINS_REPORT = ROOT / "chains.json"
UI_FILE = ROOT / "dashboard.html"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_JOB_LINES = 4000

OP_LOCK = threading.RLock()
_SCORE_LOCK = threading.RLock()
_JOBS_LOCK = threading.RLock()
_JOBS: dict[str, "Job"] = {}
_JOBS_ORDER: list[str] = []
_SCORE_CACHE: dict = {"loaded": False}
_COLLECTOR: dict = {"proc": None, "logfh": None}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

class HttpError(Exception):
    """An HTTP error with a status code and a message for the client."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def row_to_dict(row) -> dict:
    return {k: row[k] for k in row.keys()}


def _json_default(obj):
    if isinstance(obj, (datetime,)):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    return str(obj)


def event_count() -> int:
    conn = get_conn()
    try:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        conn.close()


def baseline_count() -> int:
    conn = get_conn()
    try:
        return conn.execute("SELECT COUNT(*) FROM baseline").fetchone()[0]
    finally:
        conn.close()


def session_label(session_id: str | None) -> str:
    """Map a session id to its dataset label (mirrors the evaluation logic)."""
    sid = str(session_id or "")
    if sid.startswith("attack_chain"):
        return "chain"
    if sid.startswith("attack"):
        return "burst"
    if sid.startswith("normal"):
        return "normal"
    return "live"


def _parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Score cache — scoring 660 events takes ~2.5s, so score once per dataset/model
# ---------------------------------------------------------------------------

def _score_key():
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT COUNT(*), COALESCE(MAX(id), 0) FROM events"
        ).fetchone()
    finally:
        conn.close()
    model = ad.AnomalyDetector.MODEL_PATH
    mtime = model.stat().st_mtime if model.exists() else 0
    return (int(row[0]), int(row[1]), float(mtime))


def invalidate_scores() -> None:
    with _SCORE_LOCK:
        _SCORE_CACHE.clear()
        _SCORE_CACHE["loaded"] = False


def get_scores(force: bool = False) -> dict:
    """Score every event once and cache it until the data or the model changes.

    The lock is held across the (re)computation so that two requests arriving
    together cannot both run a full scoring pass.
    """
    key = _score_key()
    with _SCORE_LOCK:
        if not force and _SCORE_CACHE.get("loaded") and _SCORE_CACHE.get("key") == key:
            return _SCORE_CACHE

        detector = ad.AnomalyDetector()
        trained = detector.load_model()
        results = detector.score_all_events() if trained else []

        _SCORE_CACHE.clear()
        _SCORE_CACHE.update({
            "loaded": True,
            "key": key,
            "trained": trained,
            "results": results,
            "by_id": {r["event_id"]: r for r in results if r.get("event_id") is not None},
            "scored_at": datetime.now(timezone.utc).isoformat(),
        })
        return _SCORE_CACHE


# ---------------------------------------------------------------------------
# Job runner — long operations stream their stdout/stderr back to the browser
# ---------------------------------------------------------------------------

class Job:
    def __init__(self, name: str, kind: str = "action"):
        self.id = f"job_{int(time.time() * 1000)}_{os.getpid()}_{id(self) % 10000}"
        self.name = name
        self.kind = kind
        self.status = "running"
        self.output: list[str] = []
        self.result = None
        self.error: str | None = None
        self.started = time.time()
        self.finished: float | None = None

    def log(self, line: str) -> None:
        with _JOBS_LOCK:
            self.output.append(line)
            if len(self.output) > MAX_JOB_LINES:
                del self.output[: len(self.output) - MAX_JOB_LINES]

    def as_dict(self, include_output: bool = True) -> dict:
        data = {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "status": self.status,
            "error": self.error,
            "started": self.started,
            "finished": self.finished,
            "duration": (self.finished or time.time()) - self.started,
            "line_count": len(self.output),
        }
        if include_output:
            data["output"] = list(self.output)
        if self.result is not None:
            data["result"] = self.result
        return data


class _JobWriter(io.TextIOBase):
    """Redirects print() output line-by-line into a Job's log."""

    def __init__(self, job: Job):
        self.job = job
        self._buf = ""

    def write(self, s: str) -> int:
        if not isinstance(s, str):
            s = str(s)
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self.job.log(line.rstrip("\r"))
        return len(s)

    def flush(self) -> None:
        if self._buf:
            self.job.log(self._buf.rstrip("\r"))
            self._buf = ""


def start_job(name: str, fn, *args, kind: str = "action", **kwargs) -> Job:
    job = Job(name, kind=kind)

    def _run():
        writer = _JobWriter(job)
        try:
            with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
                job.result = fn(*args, **kwargs)
            writer.flush()
            job.status = "done"
        except Exception as e:  # surfaced to the UI, never swallowed
            writer.flush()
            job.error = f"{type(e).__name__}: {e}"
            job.log(f"[error] {job.error}")
            job.log(traceback.format_exc())
            job.status = "error"
        finally:
            job.finished = time.time()

    with _JOBS_LOCK:
        _JOBS[job.id] = job
        _JOBS_ORDER.append(job.id)
        # Keep the registry bounded — drop the oldest finished jobs.
        while len(_JOBS_ORDER) > 40:
            oldest = _JOBS_ORDER.pop(0)
            if _JOBS.get(oldest) and _JOBS[oldest].status == "running":
                _JOBS_ORDER.append(oldest)
                break
            _JOBS.pop(oldest, None)

    threading.Thread(target=_run, daemon=True, name=f"job:{name}").start()
    return job


def get_job(job_id: str) -> dict | None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        return job.as_dict() if job else None


def list_jobs() -> list[dict]:
    with _JOBS_LOCK:
        return [j.as_dict(include_output=False) for j in _JOBS.values()][::-1]


# ---------------------------------------------------------------------------
# Operations — each one is the CLI's own logic, callable directly
# ---------------------------------------------------------------------------

def op_clear_db() -> dict:
    with OP_LOCK:
        conn = get_conn()
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM baseline")
        conn.commit()
        conn.close()
        print("Cleared events and baseline tables.")
    invalidate_scores()
    return {"events": event_count(), "baseline_profiles": baseline_count()}


def op_generate(seed: int = 42, clear: bool = True) -> dict:
    with OP_LOCK:
        if clear:
            op_clear_db()
        total = gen.generate_dataset(seed=int(seed))
    invalidate_scores()
    print(f"Dataset ready: {event_count()} events.")
    return {"generated": total, "seed": int(seed), "events": event_count()}


def op_baseline(reset: bool = True) -> dict:
    with OP_LOCK:
        summary = baseline_mod.compute_baseline(reset=reset)
    return summary


def op_train() -> dict:
    with OP_LOCK:
        detector = ad.AnomalyDetector()
        summary = detector.train()
    invalidate_scores()
    print(f"Model trained on {summary.get('events_trained', 0)} normal events.")
    return summary


def op_score_all(report: bool = True) -> dict:
    with OP_LOCK:
        detector = ad.AnomalyDetector()
        if not detector.load_model():
            raise RuntimeError(
                "No trained model — run 'Train model' first "
                "(CLI: python ml/anomaly_detector.py train)"
            )
        results = detector.score_all_events()
        levels = ad.summarize_levels(results)
        print(f"Scored {len(results)} events: {levels}")
        out = {"scored": len(results), "levels": levels}
        if report:
            rep = ad.write_alerts_report(results, ALERTS_REPORT)
            print(f"Report written: {ALERTS_REPORT.name} "
                  f"({len(rep['alerts'])} alerts)")
            out["report_alerts"] = len(rep["alerts"])
    invalidate_scores()
    return out


def op_evaluate() -> dict:
    with OP_LOCK:
        summary = ad.evaluate()
    if summary.get("events"):
        print(f"BN vs burst attacks — precision={summary['precision']:.3f} "
              f"recall={summary['recall']:.3f} f1={summary['f1']:.3f} "
              f"accuracy={summary['accuracy']:.3f}")
        print(f"Chain events the BN missed: {summary['chain_flagged']}/"
              f"{summary['chain_total']} (the sequence layer's job)")
    seq = sequences.evaluate()
    print(f"Sequence layer — chains {seq['chain_detected']}/{seq['chain_sessions']}, "
          f"normal false positives {seq['false_positives']}/{seq['normal_sessions']}")
    return {"statistical": summary, "sequence": seq}


def collect_chains() -> dict:
    """Chain rules over every stored session (read-only)."""
    sessions = sequences.sessions_from_db()
    matches = []
    for sid, events in sessions.items():
        for match in sequences.detect_chains(events):
            match.session_id = sid
            matches.append(match.as_dict())
    matches.sort(key=lambda m: (m["severity"] != "high", m["rule"]))
    return {
        "total": len(matches),
        "chains": matches,
        "evaluation": sequences.evaluate(),
        "tunables": {
            "chain_window_seconds": sequences.CHAIN_WINDOW_SECONDS,
            "rapid_sweep_files": sequences.RAPID_SWEEP_FILES,
            "rapid_sweep_seconds": sequences.RAPID_SWEEP_SECONDS,
            "bulk_delete_files": sequences.BULK_DELETE_FILES,
            "cross_artifact_count": sequences.CROSS_ARTIFACT_COUNT,
        },
        "rules": [
            {"name": fn.__name__.replace("rule_", ""),
             "doc": (fn.__doc__ or "").strip().splitlines()[0] if fn.__doc__ else ""}
            for fn in sequences.RULES
        ],
    }


def op_scan_chains(write_report: bool = True) -> dict:
    with OP_LOCK:
        payload = collect_chains()
        if write_report:
            CHAINS_REPORT.write_text(json.dumps(
                {"total": payload["total"], "chains": payload["chains"]}, indent=2))
            print(f"Wrote {CHAINS_REPORT.name} ({payload['total']} chain(s))")
        print(f"Chain scan: {payload['total']} match(es)")
        for m in payload["chains"][:12]:
            print(f"  [{m['severity'].upper()}] {m['rule']} "
                  f"session={m['session_id']} events={m['event_ids']}")
    return {"total": payload["total"]}


def op_alerts_test() -> dict:
    config = alerts.load_alert_config(refresh=True)
    print(json.dumps(config, indent=2))
    enabled = [n for n in ("syslog", "webhook") if config.get(n, {}).get("enabled")]
    if not enabled:
        print("No remote sinks enabled — configure `alerting:` in policy_v2.yaml "
              "or the TDT_* environment variables.")
        return {"enabled": [], "outcome": {}, "note": "stdout only"}
    outcome = alerts.emit({"type": "test", "message": "dashboard self-test"}, config)
    print(f"Self-test result: {outcome}")
    return {"enabled": enabled, "outcome": outcome}


def op_pipeline(seed: int = 42) -> dict:
    print("=" * 68)
    print("Full rebuild — generate -> baseline -> train -> score -> evaluate")
    print("=" * 68)
    results = {}
    for step, fn in (
        ("generate", lambda: op_generate(seed=seed, clear=True)),
        ("baseline", lambda: op_baseline(reset=True)),
        ("train", op_train),
        ("score", lambda: op_score_all(report=True)),
        ("evaluate", op_evaluate),
        ("chains", lambda: op_scan_chains(write_report=True)),
    ):
        print(f"\n--- {step} ---")
        results[step] = fn()
    print("\nFull rebuild complete.")
    return results


def op_demo(fast: bool = True, with_metrics: bool = False) -> dict:
    """Run the project's own live demo (demo.sh --self [--fast] [--with-metrics])."""
    args = ["bash", str(ROOT / "demo.sh"), "--self"]
    if fast:
        args.append("--fast")
    if with_metrics:
        args.append("--with-metrics")
    print("Running: " + " ".join(args))
    proc = subprocess.Popen(
        args, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line.rstrip("\n"))
    code = proc.wait()
    if code != 0:
        raise RuntimeError(f"demo.sh exited with code {code}")
    return {"exit_code": code}


# ---------------------------------------------------------------------------
# Collector supervision (long-running process, separate from the job runner)
# ---------------------------------------------------------------------------

def _proc_cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\0", b" ").decode(errors="replace").strip()


def find_collector_pids() -> list[int]:
    """Any process whose command line runs collector.py (mirrors demo.sh's pgrep)."""
    pids: list[int] = []
    me = os.getpid()
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return pids
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == me:
            continue
        cmd = _proc_cmdline(pid)
        if "collector.py" in cmd and "dashboard" not in cmd:
            pids.append(pid)
    return pids


def _read_collector_log() -> str:
    if not COLLECTOR_LOG.exists():
        return ""
    try:
        return COLLECTOR_LOG.read_text(errors="replace")
    except OSError:
        return ""


def collector_status() -> dict:
    proc = _COLLECTOR.get("proc")
    managed_running = proc is not None and proc.poll() is None
    pids = find_collector_pids()
    return {
        "running": bool(pids) or managed_running,
        "managed": bool(managed_running),
        "managed_pid": proc.pid if managed_running else None,
        "pids": pids,
        "exit_code": (proc.returncode if (proc is not None and not managed_running) else None),
        "log": str(COLLECTOR_LOG),
        "log_size": COLLECTOR_LOG.stat().st_size if COLLECTOR_LOG.exists() else 0,
    }


def start_collector() -> dict:
    existing = find_collector_pids()
    if existing:
        raise HttpError(409, f"A collector is already running (pid {existing}). "
                             "Stop it first.")

    COLLECTOR_LOG.parent.mkdir(parents=True, exist_ok=True)
    logfh = open(COLLECTOR_LOG, "w")  # noqa: SIM115 - kept open for the child's lifetime
    proc = subprocess.Popen(
        [sys.executable, "-u", str(ROOT / "collector.py")],
        cwd=str(ROOT), stdout=logfh, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, start_new_session=True,
    )
    _COLLECTOR["proc"] = proc
    _COLLECTOR["logfh"] = logfh

    deadline = time.time() + 15
    ready = False
    while time.time() < deadline:
        if proc.poll() is not None:
            # Nothing to supervise — release the handle and clear the state so a
            # retry (after fixing the policy, say) starts cleanly.
            _COLLECTOR["proc"] = None
            _COLLECTOR["logfh"] = None
            with contextlib.suppress(OSError):
                logfh.close()
            raise HttpError(
                500,
                f"Collector exited immediately (code {proc.returncode}). "
                "See the collector log — usually a missing policy path.",
            )
        if "Collector started" in _read_collector_log():
            ready = True
            break
        time.sleep(0.3)

    status = collector_status()
    status["ready"] = ready
    return status


def stop_collector() -> dict:
    proc = _COLLECTOR.get("proc")
    targets: list[int] = []
    if proc is not None and proc.poll() is None:
        targets.append(proc.pid)
    for pid in find_collector_pids():
        if pid not in targets:
            targets.append(pid)

    if not targets:
        return {"stopped": [], "message": "No collector running."}

    for pid in targets:
        _signal_process(pid, signal.SIGINT)

    # Bounded graceful shutdown: SIGINT lets the collector remove its audit rules.
    for _ in range(24):
        if not find_collector_pids() and (proc is None or proc.poll() is not None):
            break
        time.sleep(0.5)

    remaining = find_collector_pids()
    for pid in remaining:
        _signal_process(pid, signal.SIGTERM, force_kill=True)
    time.sleep(0.5)

    if proc is not None:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logfh = _COLLECTOR.get("logfh")
        if logfh is not None:
            try:
                logfh.close()
            except OSError:
                pass
        _COLLECTOR["proc"] = None
        _COLLECTOR["logfh"] = None

    return {"stopped": targets, "remaining": find_collector_pids()}


def _signal_process(pid: int, sig: int, force_kill: bool = False) -> None:
    """Signal `pid`, using its process group only when it leads its own.

    A collector we started uses start_new_session=True (pgid == pid), which
    lets us reach the whole process group. Signalling an arbitrary group could
    hit the dashboard's own session, so external processes get a plain kill.
    """
    try:
        pgid = os.getpgid(pid)
    except OSError:
        return
    try:
        if pgid == pid:
            os.killpg(pgid, sig)
        else:
            os.kill(pid, sig)
    except OSError:
        if force_kill:
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGKILL)


def collector_log(tail: int = 400) -> dict:
    text = _read_collector_log()
    lines = text.splitlines()
    return {
        "status": collector_status(),
        "lines": lines[-tail:],
        "total_lines": len(lines),
    }


# ---------------------------------------------------------------------------
# Policy / model / alerts read views
# ---------------------------------------------------------------------------

def policy_info() -> dict:
    targets = []
    error = None
    try:
        from collector import load_policy
        raw = load_policy()
    except Exception as e:  # a broken policy file must not break the dashboard
        raw, error = [], f"{type(e).__name__}: {e}"

    for t in raw or []:
        path = Path(str(t.get("path", "")))
        targets.append({
            "path": str(path),
            "type": t.get("type"),
            "recursive": bool(t.get("recursive")),
            "category": t.get("category"),
            "exists": path.exists(),
        })

    file_path = ROOT / "policy_v2.yaml"
    alerting = {}
    try:
        import yaml
        doc = yaml.safe_load(file_path.read_text()) or {}
        alerting = doc.get("alerting") or {}
    except Exception:
        pass

    return {
        "path": str(file_path),
        "targets": targets,
        "missing": [t["path"] for t in targets if not t["exists"]],
        "alerting": alerting,
        "error": error,
    }


def model_info() -> dict:
    path = ad.AnomalyDetector.MODEL_PATH
    detector = ad.AnomalyDetector()
    trained = detector.load_model()
    info = {
        "path": str(path),
        "exists": path.exists(),
        "trained": bool(trained),
        "size": path.stat().st_size if path.exists() else 0,
        "mtime": (datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
                  if path.exists() else None),
        "nodes": list(detector.model.nodes()) if detector.model else [],
        "edges": [list(e) for e in detector.model.edges()] if detector.model else [],
        "states": detector.variable_states,
        "thresholds": {
            "unusual": ad.RISK_UNUSUAL,
            "suspicious": ad.RISK_SUSPICIOUS,
            "anomaly": ad.RISK_ANOMALY,
        },
        "weights": ad.FACTOR_WEIGHTS,
        "surprise": {"floor": ad.SURPRISE_FLOOR, "ceil": ad.SURPRISE_CEIL},
    }
    return info


def reports_info() -> dict:
    out = {}
    for name, path in (("alerts", ALERTS_REPORT), ("chains", CHAINS_REPORT)):
        if not path.exists():
            out[name] = {"path": str(path), "present": False}
            continue
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            out[name] = {"path": str(path), "present": True, "error": str(e)}
            continue
        data["path"] = str(path)
        data["present"] = True
        data["mtime"] = datetime.fromtimestamp(
            path.stat().st_mtime, timezone.utc).isoformat()
        out[name] = data
    return out


# ---------------------------------------------------------------------------
# Event / statistics queries
# ---------------------------------------------------------------------------

def build_stats() -> dict:
    cache = get_scores()
    by_id = cache["by_id"]

    conn = get_conn()
    rows = conn.execute(
        "SELECT id, timestamp, artifact_path, access_type, process_name, "
        "username, session_id, time_delta, files_in_session FROM events ORDER BY id"
    ).fetchall()
    conn.close()

    histogram = {f"{i}-{i + 10}": {"normal": 0, "burst": 0, "chain": 0, "live": 0}
                 for i in range(0, 100, 10)}
    artifact_counts: dict[str, dict] = {}
    process_counts: Counter = Counter()
    access_counts: Counter = Counter()
    hour_counts = [0] * 24
    day_counts: Counter = Counter()
    label_counts: Counter = Counter()
    session_ids: set = set()
    risk_levels = {lvl: 0 for lvl in ALL_LEVELS}
    flagged_rows = []

    for row in rows:
        rid = row["id"]
        score = by_id.get(rid)
        level = score["risk_level"] if score else "unscored"
        label = session_label(row["session_id"])
        label_counts[label] += 1
        if row["session_id"]:
            session_ids.add(row["session_id"])

        artifact = ad._categorize_artifact(row["artifact_path"] or "")
        bucket = artifact_counts.setdefault(artifact, {"artifact": artifact, "total": 0, "flagged": 0})
        bucket["total"] += 1

        process_counts[(row["process_name"] or "unknown").lower()] += 1
        access_counts[row["access_type"] or "unknown"] += 1

        dt = _parse_ts(row["timestamp"])
        if dt:
            hour_counts[dt.hour] += 1
            day_counts[dt.date().isoformat()] += 1

        if score:
            lvl = score["risk_level"]
            if lvl in risk_levels:
                risk_levels[lvl] += 1
            idx = min(9, int(score["risk_score"] // 10))
            histogram[f"{idx * 10}-{idx * 10 + 10}"][label] += 1
            if lvl in FLAGGED_LEVELS:
                bucket["flagged"] += 1
                flagged_rows.append((score, row))

    flagged_rows.sort(key=lambda pair: -pair[0]["risk_score"])
    top_flagged = [
        {
            "event_id": score["event_id"],
            "risk_score": round(score["risk_score"], 2),
            "risk_level": score["risk_level"],
            "artifact": score.get("features", {}).get("artifact"),
            "process": score.get("features", {}).get("process"),
            "session_id": row["session_id"],
            "label": session_label(row["session_id"]),
            "timestamp": row["timestamp"],
            "explanation": score.get("explanation", ""),
        }
        for score, row in flagged_rows[:15]
    ]

    risk_values = [r["risk_score"] for r in cache["results"]]
    return {
        "total_events": len(rows),
        "sessions": len(session_ids),
        "labels": dict(label_counts),
        "risk_levels": risk_levels,
        "score_status": {
            "trained": cache["trained"],
            "scored": len(cache["results"]),
            "scored_at": cache.get("scored_at"),
            "min": round(min(risk_values), 2) if risk_values else None,
            "max": round(max(risk_values), 2) if risk_values else None,
        },
        "histogram": [{"range": k, **v} for k, v in histogram.items()],
        "by_artifact": sorted(artifact_counts.values(), key=lambda b: -b["total"]),
        "by_process": [{"process": p, "count": c} for p, c in process_counts.most_common(12)],
        "by_access_type": [{"access_type": a, "count": c} for a, c in access_counts.most_common()],
        "by_hour": [{"hour": h, "count": c} for h, c in enumerate(hour_counts)],
        "timeline": [{"date": d, "count": c} for d, c in sorted(day_counts.items())],
        "top_flagged": top_flagged,
    }


def _event_where(session: str, artifact: str, access_type: str,
                 q: str) -> tuple[list[str], list]:
    """SQL WHERE fragments for the event explorer's filters."""
    where: list[str] = []
    params: list = []
    if session:
        where.append("session_id LIKE ?")
        params.append(f"%{session}%")
    if artifact:
        where.append("LOWER(artifact_path) LIKE ?")
        params.append(f"%{artifact.lower()}%")
    if access_type:
        where.append("access_type = ?")
        params.append(access_type)
    if q:
        like = f"%{q}%"
        where.append("(artifact_path LIKE ? OR process_name LIKE ? OR username LIKE ?)")
        params += [like, like, like]
    return where, params


def _scored_event(row, by_id: dict) -> dict:
    """An event row joined with its cached score and its dataset label."""
    item = row_to_dict(row)
    score = by_id.get(item["id"])
    item["artifact"] = ad._categorize_artifact(item.get("artifact_path") or "")
    item["risk_level"] = score["risk_level"] if score else None
    item["risk_score"] = round(score["risk_score"], 2) if score else None
    item["label"] = session_label(item["session_id"])
    return item


def select_events(session: str = "", artifact: str = "", access_type: str = "",
                  risk_level: str = "", q: str = "", order: str = "newest",
                  limit: int = 0, offset: int = 0) -> tuple[list[dict], int]:
    """Filtered, scored events newest (or oldest) first.

    Single source of truth for the events view *and* the events export, so a
    downloaded file can never disagree with the table on screen. `limit=0`
    returns everything left after `offset`.
    """
    where, params = _event_where(session, artifact, access_type, q)
    sql = "SELECT * FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id " + ("ASC" if order == "oldest" else "DESC")

    conn = get_conn()
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    by_id = get_scores()["by_id"]
    items = []
    for row in rows:
        item = _scored_event(row, by_id)
        if risk_level and (item["risk_level"] or "unscored") != risk_level:
            continue
        items.append(item)

    total = len(items)
    if offset:
        items = items[offset:]
    if limit:
        items = items[:limit]
    return items, total


def query_events(limit: int, offset: int, session: str, artifact: str,
                 access_type: str, risk_level: str, q: str, order: str) -> dict:
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    items, total = select_events(session=session, artifact=artifact,
                                 access_type=access_type, risk_level=risk_level,
                                 q=q, order=order, limit=limit, offset=offset)
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": items,
        "risk_levels": ALL_LEVELS + ["unscored"],
    }


# ---------------------------------------------------------------------------
# Exports — the data behind the tables, honoring the view's active filters
# ---------------------------------------------------------------------------

MAX_EXPORT_ROWS = 100_000

_EVENT_COLUMNS = ["id", "timestamp", "session_id", "label", "risk_level",
                  "risk_score", "artifact", "artifact_path", "access_type",
                  "process_name", "pid", "ppid", "parent_process_name",
                  "user_id", "username", "time_delta", "files_in_session"]
_BASELINE_COLUMNS = ["id", "artifact_path", "user_id", "process_name",
                     "access_count", "first_seen", "last_seen", "normal_hours",
                     "avg_access_interval", "created_at"]
_CHAIN_COLUMNS = ["rule", "severity", "session_id", "event_ids", "description", "detail"]
_ALERT_COLUMNS = ["event_id", "risk_level", "risk_score", "artifact", "process",
                  "session_size", "time_delta", "explanation"]


def _csv_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value)
    return str(value)


def _to_csv(columns: list[str], rows: list[dict]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_csv_value(row.get(c)) for c in columns])
    return buf.getvalue().encode("utf-8")


def _to_json(dataset: str, rows: list[dict], total: int, filters: dict) -> bytes:
    return json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": dataset,
        "filters": filters,
        "total": total,
        "rows": rows,
    }, indent=2, default=_json_default).encode("utf-8")


def _alert_rows() -> list[dict]:
    """Rows behind the Alerts view: the report if present, else live scores."""
    def shape(features: dict, **rest) -> dict:
        return {
            "artifact": (features or {}).get("artifact"),
            "process": (features or {}).get("process"),
            "session_size": (features or {}).get("session_size"),
            "time_delta": (features or {}).get("time_delta"),
            **rest,
        }

    if ALERTS_REPORT.exists():
        try:
            report = json.loads(ALERTS_REPORT.read_text())
            return [shape(a.get("features") or {},
                          event_id=a.get("event_id"),
                          risk_level=a.get("risk_level"),
                          risk_score=a.get("risk_score"),
                          explanation=a.get("explanation"))
                    for a in report.get("alerts", [])]
        except (OSError, json.JSONDecodeError) as e:
            log.warning("Could not read %s for export: %s", ALERTS_REPORT, e)

    return [shape(r.get("features") or {},
                  event_id=r["event_id"],
                  risk_level=r["risk_level"],
                  risk_score=round(r["risk_score"], 2),
                  explanation=r.get("explanation"))
            for r in sorted(get_scores()["results"], key=lambda x: -x["risk_score"])
            if r["risk_level"] in FLAGGED_LEVELS]


def _baseline_rows() -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM baseline ORDER BY artifact_path, user_id, process_name"
    ).fetchall()
    conn.close()
    out = []
    for row in rows:
        item = row_to_dict(row)
        try:
            item["normal_hours"] = json.loads(item.get("normal_hours") or "[]")
        except (json.JSONDecodeError, TypeError):
            pass
        out.append(item)
    return out


def export_dataset(dataset: str, fmt: str, **filters) -> dict:
    """Serialize one dashboard table for download.

    Returns ``{"body": bytes, "content_type": str, "filename": str}``. Reuses
    the same filters, scoring cache and chain scan the views render, so an
    export never disagrees with what is on screen.
    """
    if fmt not in ("csv", "json"):
        raise ValueError(f"unsupported format {fmt!r} (use csv or json)")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if dataset == "events":
        rows, total = select_events(
            session=filters.get("session", ""), artifact=filters.get("artifact", ""),
            access_type=filters.get("access_type", ""),
            risk_level=filters.get("risk_level", ""), q=filters.get("q", ""),
            order=filters.get("order", "newest"), limit=MAX_EXPORT_ROWS,
        )
        columns = _EVENT_COLUMNS
        applied = {k: filters.get(k, "") for k in
                   ("session", "artifact", "access_type", "risk_level", "q", "order")}
    elif dataset == "baseline":
        rows, total, columns, applied = _baseline_rows(), None, _BASELINE_COLUMNS, {}
        total = len(rows)
    elif dataset == "chains":
        rows = collect_chains()["chains"]
        total, columns, applied = len(rows), _CHAIN_COLUMNS, {}
    elif dataset == "alerts":
        rows = _alert_rows()
        total, columns, applied = len(rows), _ALERT_COLUMNS, {}
    else:
        raise ValueError(
            f"unknown dataset {dataset!r} (events, baseline, chains, alerts)")

    body = (_to_csv(columns, rows) if fmt == "csv"
            else _to_json(dataset, rows, total, applied))
    content_type = ("text/csv; charset=utf-8" if fmt == "csv"
                    else "application/json; charset=utf-8")
    return {"body": body, "content_type": content_type,
            "filename": f"tdt_{dataset}_{stamp}.{fmt}"}


def event_detail(event_id: int) -> dict:
    conn = get_conn()
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    conn.close()
    if row is None:
        raise HttpError(404, f"Event #{event_id} not found.")

    detector = ad.AnomalyDetector()
    if not detector.load_model():
        raise HttpError(409, "No trained model — train it first to explain events.")

    result = detector.score_event(row)
    return {
        "event": row_to_dict(row),
        "label": session_label(row["session_id"]),
        "score": result,
    }


def baseline_view() -> dict:
    profiles = _baseline_rows()  # shared with the baseline CSV export

    by_artifact: Counter = Counter(p["artifact_path"] for p in profiles)
    by_user: Counter = Counter(str(p["user_id"]) for p in profiles)
    by_process: Counter = Counter(p["process_name"] for p in profiles)
    intervals = [p["avg_access_interval"] for p in profiles
                 if p.get("avg_access_interval") is not None]

    return {
        "profiles": profiles,
        "total": len(profiles),
        "total_events": sum(p["access_count"] for p in profiles),
        "artifacts": [{"artifact": a, "profiles": c} for a, c in by_artifact.most_common()],
        "users": [{"user": u, "profiles": c} for u, c in by_user.most_common()],
        "processes": [{"process": p, "profiles": c} for p, c in by_process.most_common()],
        "avg_interval": round(sum(intervals) / len(intervals), 2) if intervals else None,
    }


# ---------------------------------------------------------------------------
# Upload import
# ---------------------------------------------------------------------------

def _pick(raw: dict, *names):
    for name in names:
        if name in raw and raw[name] not in (None, ""):
            return raw[name]
    return None


def _as_int(value, field: str):
    if value in (None, ""):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        raise ValueError(f"invalid {field}: {value!r}")


def _as_float(value, field: str):
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        raise ValueError(f"invalid {field}: {value!r}")


def _normalize_uploaded_event(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("record is not an object")

    timestamp = _pick(raw, "timestamp", "time", "ts", "datetime")
    path = _pick(raw, "artifact_path", "path", "file", "filepath")
    access = _pick(raw, "access_type", "access", "operation", "event_type") or "read"

    if not path:
        raise ValueError("missing artifact_path")
    if not timestamp:
        raise ValueError("missing timestamp")
    try:
        datetime.fromisoformat(str(timestamp))
    except (ValueError, TypeError):
        raise ValueError(f"invalid timestamp {timestamp!r} (expected ISO-8601)")

    def text(*names):
        v = _pick(raw, *names)
        return str(v) if v is not None else None

    return dict(
        artifact_path=str(path),
        access_type=str(access).lower(),
        pid=_as_int(_pick(raw, "pid"), "pid"),
        process_name=text("process_name", "process", "comm"),
        ppid=_as_int(_pick(raw, "ppid"), "ppid"),
        parent_process_name=text("parent_process_name", "parent", "parent_comm"),
        user_id=_as_int(_pick(raw, "user_id", "uid"), "user_id"),
        username=text("username", "user"),
        time_delta=_as_float(_pick(raw, "time_delta", "delta"), "time_delta"),
        session_id=text("session_id", "session"),
        files_in_session=_as_int(
            _pick(raw, "files_in_session", "session_size", "files"), "files_in_session"),
        timestamp=str(timestamp),
    )


def import_events(text: str, filename: str = "") -> dict:
    stripped = text.lstrip()
    source = "json" if (filename.lower().endswith(".json") or stripped[:1] in "[{") else "csv"

    if source == "json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise HttpError(400, f"Invalid JSON: {e}")
        if isinstance(data, dict):
            data = data.get("events") or data.get("rows") or data.get("data")
        if not isinstance(data, list):
            raise HttpError(400, 'JSON must be a list of events or {"events": [...]}')
        records = list(enumerate(data, start=1))
    else:
        try:
            records = list(enumerate(csv.DictReader(io.StringIO(text)), start=1))
        except csv.Error as e:
            raise HttpError(400, f"Invalid CSV: {e}")
        if records and not records[0][1]:
            raise HttpError(400, "CSV has no header row")

    imported = 0
    errors: list[str] = []
    sessions: set = set()

    for index, raw in records:
        try:
            event = _normalize_uploaded_event(raw)
            db.insert_event(**event)
            imported += 1
            if event.get("session_id"):
                sessions.add(event["session_id"])
        except Exception as e:
            if len(errors) < 25:
                errors.append(f"record {index}: {e}")

    if imported:
        invalidate_scores()

    return {
        "source": source,
        "imported": imported,
        "skipped": len(records) - imported,
        "errors": errors,
        "sessions": sorted(sessions)[:50],
        "events_total": event_count(),
    }


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

def overview() -> dict:
    conn = get_conn()
    row = conn.execute(
        "SELECT COUNT(*) AS events, COUNT(DISTINCT session_id) AS sessions, "
        "MIN(timestamp) AS first_event, MAX(timestamp) AS last_event FROM events"
    ).fetchone()
    conn.close()

    cache = get_scores()
    labels = Counter(session_label(r["session_id"])
                     for r in _session_rows())
    risk_levels = ad.summarize_levels(cache["results"]) if cache["trained"] else {}

    deps = {}
    for name in ("yaml", "watchdog", "pgmpy", "numpy"):
        try:
            __import__(name)
            deps[name] = True
        except ImportError:
            deps[name] = False

    import shutil
    policy = policy_info()
    alert_report = reports_info()["alerts"] or {}
    return {
        "project_root": str(ROOT),
        "python": sys.version.split()[0],
        "db": {
            "path": str(db.DB_PATH),
            "exists": db.DB_PATH.exists(),
            "size": db.DB_PATH.stat().st_size if db.DB_PATH.exists() else 0,
            "events": row["events"],
            "sessions": row["sessions"],
            "baseline_profiles": baseline_count(),
            "first_event": row["first_event"],
            "last_event": row["last_event"],
        },
        "labels": dict(labels),
        "model": model_info(),
        "risk_levels": risk_levels,
        "scoring": {
            "trained": cache["trained"],
            "scored": len(cache["results"]),
            "scored_at": cache.get("scored_at"),
        },
        "collector": collector_status(),
        "policy": {"targets": policy["targets"], "missing": policy["missing"],
                   "alerting": policy["alerting"]},
        "alerts": {
            "config": alerts.load_alert_config(),
            "report": {k: v for k, v in alert_report.items()
                       if k in ("present", "path", "total_events", "summary", "mtime")},
            "alert_count": len(alert_report.get("alerts", [])),
        },
        "tools": {"auditctl": bool(shutil.which("auditctl")),
                  "ausearch": bool(shutil.which("ausearch"))},
        "deps": deps,
        "counts": {"events": event_count(), "baseline": baseline_count()},
    }


def _session_rows():
    conn = get_conn()
    rows = conn.execute("SELECT session_id FROM events").fetchall()
    conn.close()
    return rows


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def handle_get(route: str, query: dict) -> tuple[int, dict | None, str]:
    """Returns (status, json_payload_or_None, content_type)."""
    if route in ("/", "/index.html", "/dashboard"):
        if not UI_FILE.exists():
            raise HttpError(500, f"UI file missing: {UI_FILE}")
        return 200, None, "html"

    if route == "/api/health":
        return 200, {"ok": True, "time": datetime.now(timezone.utc).isoformat()}, "json"

    if route == "/api/overview":
        return 200, overview(), "json"

    if route == "/api/stats":
        return 200, build_stats(), "json"

    if route == "/api/export":
        try:
            payload = export_dataset(
                (query.get("dataset") or "events").lower(),
                (query.get("format") or "csv").lower(),
                session=query.get("session", ""),
                artifact=query.get("artifact", ""),
                access_type=query.get("access_type", ""),
                risk_level=query.get("risk_level", ""),
                q=query.get("q", ""),
                order=query.get("order", "newest"),
            )
        except ValueError as e:
            raise HttpError(400, str(e))
        return 200, payload, "download"

    if route == "/api/events":
        return 200, query_events(
            limit=int(query.get("limit", 50) or 50),
            offset=int(query.get("offset", 0) or 0),
            session=query.get("session", ""),
            artifact=query.get("artifact", ""),
            access_type=query.get("access_type", ""),
            risk_level=query.get("risk_level", ""),
            q=query.get("q", ""),
            order=query.get("order", "newest"),
        ), "json"

    if route == "/api/event":
        if "id" not in query:
            raise HttpError(400, "Missing ?id=<event id>")
        return 200, event_detail(int(query["id"])), "json"

    if route == "/api/baseline":
        return 200, baseline_view(), "json"

    if route == "/api/model":
        return 200, model_info(), "json"

    if route == "/api/chains":
        return 200, collect_chains(), "json"

    if route == "/api/alerts":
        config = alerts.load_alert_config()
        reports = reports_info()
        return 200, {"config": config, "report": reports["alerts"],
                     "enabled": [n for n in ("syslog", "webhook")
                                 if config.get(n, {}).get("enabled")]}, "json"

    if route == "/api/reports":
        return 200, reports_info(), "json"

    if route == "/api/policy":
        return 200, policy_info(), "json"

    if route == "/api/jobs":
        return 200, {"jobs": list_jobs()}, "json"

    if route == "/api/job":
        if "id" not in query:
            raise HttpError(400, "Missing ?id=<job id>")
        job = get_job(query["id"])
        if job is None:
            raise HttpError(404, "Unknown job id")
        return 200, job, "json"

    if route == "/api/collector":
        return 200, collector_status(), "json"

    if route == "/api/collector/log":
        return 200, collector_log(tail=int(query.get("tail", 400) or 400)), "json"

    raise HttpError(404, f"Unknown route: {route}")


def handle_post(route: str, query: dict, body: dict, headers,
                raw_body: str = "") -> tuple[int, dict]:
    if route == "/api/generate":
        seed = int(body.get("seed", 42) or 42)
        job = start_job(f"Generate dataset (seed {seed})", op_generate,
                        seed=seed, clear=bool(body.get("clear", True)))
        return 202, {"job": job.as_dict(include_output=False)}

    if route == "/api/pipeline":
        seed = int(body.get("seed", 42) or 42)
        job = start_job(f"Full rebuild (seed {seed})", op_pipeline, seed=seed)
        return 202, {"job": job.as_dict(include_output=False)}

    if route == "/api/baseline/compute":
        reset = bool(body.get("reset", True))
        job = start_job("Compute baseline" + (" (reset)" if reset else ""),
                        op_baseline, reset=reset)
        return 202, {"job": job.as_dict(include_output=False)}

    if route == "/api/model/train":
        job = start_job("Train Bayesian Network", op_train)
        return 202, {"job": job.as_dict(include_output=False)}

    if route == "/api/score-all":
        report = bool(body.get("report", True))
        job = start_job("Score all events" + (" + report" if report else ""),
                        op_score_all, report=report)
        return 202, {"job": job.as_dict(include_output=False)}

    if route == "/api/evaluate":
        job = start_job("Evaluate detection layers", op_evaluate)
        return 202, {"job": job.as_dict(include_output=False)}

    if route == "/api/chains/scan":
        job = start_job("Scan sessions for chains", op_scan_chains,
                        write_report=bool(body.get("report", True)))
        return 202, {"job": job.as_dict(include_output=False)}

    if route == "/api/alerts/test":
        job = start_job("Alert sink self-test", op_alerts_test)
        return 202, {"job": job.as_dict(include_output=False)}

    if route == "/api/db/clear":
        invalidate_scores()
        result = op_clear_db()
        return 200, result

    if route == "/api/upload":
        filename = headers.get("X-Filename", "")
        # The UI posts the file contents as the raw body; the same text is kept
        # for application/json posts, so both paths import identically.
        text = raw_body or body.get("__raw__", "")
        if not text.strip():
            raise HttpError(400, "Empty upload body.")
        result = import_events(text, filename)
        if str(query.get("analyze", "")).lower() in ("1", "true", "yes"):
            job = start_job(
                "Analyze uploaded events (baseline + score)",
                op_pipeline_analyze,
            )
            result["job"] = job.as_dict(include_output=False)
        return 200, result

    if route == "/api/collector/start":
        return 200, start_collector()

    if route == "/api/collector/stop":
        return 200, stop_collector()

    if route == "/api/demo":
        job = start_job(
            "Live demo (benign / chain / sweep)",
            op_demo,
            fast=bool(body.get("fast", True)),
            with_metrics=bool(body.get("with_metrics", False)),
            kind="demo",
        )
        return 202, {"job": job.as_dict(include_output=False)}

    raise HttpError(404, f"Unknown route: {route}")


def op_pipeline_analyze() -> dict:
    """Baseline + score the current dataset (used after an upload)."""
    results = {"baseline": op_baseline(reset=True), "score": op_score_all(report=True)}
    results["evaluate"] = op_evaluate()
    return results


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "TDT-Dashboard/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quieter default logging
        if self.server.verbose:  # type: ignore[attr-defined]
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):  # noqa: N802
        self._handle("GET")

    def do_POST(self):  # noqa: N802
        self._handle("POST")

    def _handle(self, method: str) -> None:
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"
        query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}

        try:
            if method == "GET":
                status, payload, kind = handle_get(route, query)
                if kind == "html":
                    self._send_bytes(200, UI_FILE.read_bytes(), "text/html; charset=utf-8")
                elif kind == "download":
                    self._send_bytes(status, payload["body"], payload["content_type"],
                                     payload.get("filename"))
                else:
                    self._send_json(status, payload)
            else:
                body, raw_body = self._read_body()
                status, result = handle_post(route, query, body, self.headers, raw_body)
                self._send_json(status, result)
        except HttpError as e:
            self._send_json(e.status, {"error": e.message})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:  # never take the dashboard down
            traceback.print_exc()
            self._send_json(500, {
                "error": f"{type(e).__name__}: {e}",
                "traceback": traceback.format_exc().splitlines()[-6:],
            })

    def _read_body(self) -> tuple[dict, str]:
        """Read the request body as (parsed_dict, raw_text)."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_UPLOAD_BYTES:
            raise HttpError(413, f"Body too large (limit {MAX_UPLOAD_BYTES} bytes).")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}, ""

        text = raw.decode("utf-8", errors="replace")
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as e:
                raise HttpError(400, f"Invalid JSON body: {e}")
            # A JSON array is a valid upload payload but not a parameter map;
            # keep it out of the dict so route handlers cannot trip over it.
            return (parsed if isinstance(parsed, dict) else {}), text
        # Anything else is treated as an uploaded file body.
        return {"__raw__": text}, text

    def _send_json(self, status: int, payload) -> None:
        body = json.dumps(payload, default=_json_default).encode()
        self._send_bytes(status, body, "application/json")

    def _send_bytes(self, status: int, body: bytes, content_type: str,
                    filename: str | None = None) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if filename:
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def serve(host: str, port: int, verbose: bool, open_browser: bool) -> None:
    # Line-buffer stdout so the URL appears immediately even when output is
    # redirected to a file or a pipe.
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(line_buffering=True)

    init_db()
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    server.daemon_threads = True
    server.verbose = verbose  # type: ignore[attr-defined]

    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '') else host}:{port}/"
    print("=" * 68)
    print("  Behavior-Based Threat Detection — dashboard")
    print("=" * 68)
    print(f"  Database:  {db.DB_PATH}  ({event_count()} events, "
          f"{baseline_count()} baseline profiles)")
    print(f"  Model:     {'trained' if model_info()['trained'] else 'NOT trained'}"
          f"  ({ad.AnomalyDetector.MODEL_PATH})")
    print(f"  UI:        {UI_FILE}")
    print(f"  Serving:   {url}")
    if host == "0.0.0.0":
        print("  WARNING:   bound to all interfaces — the API can run the "
              "collector and rewrite the database.")
    print("  Ctrl+C to stop.")
    print("=" * 68)
    sys.stdout.flush()

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        server.shutdown()
        server.server_close()
        # A collector started from the dashboard is left running on purpose:
        # killing it here would also kill one started outside the dashboard.
        # Stop it from the UI, or Ctrl+C in its own terminal.
        still_running = find_collector_pids()
        if still_running:
            print(f"NOTE: collector still running (pid {still_running}) — it keeps "
                  "monitoring until you stop it (dashboard UI or Ctrl+C in its terminal).")
        print("Dashboard stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Interactive web dashboard for the threat detection project")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default 127.0.0.1; 0.0.0.0 exposes it)")
    parser.add_argument("--port", type=int, default=8765, help="Port (default 8765)")
    parser.add_argument("--open", action="store_true", dest="open_browser",
                        help="Open the dashboard in a browser")
    parser.add_argument("--verbose", action="store_true", help="Log every request")
    args = parser.parse_args()

    try:
        serve(args.host, args.port, args.verbose, args.open_browser)
    except OSError as e:
        print(f"Failed to bind {args.host}:{args.port} — {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
