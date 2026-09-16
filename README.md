# Behavior-Based Threat Detection for Compromised Linux Servers

A context-aware filesystem monitoring system that detects credential theft on
Linux servers. Instead of treating every access to sensitive files as malicious,
it learns what *normal* access looks like — who, when, how fast — and flags
deviations with **explainable risk scores**.

Monitored artifact categories: `~/.azure`, `~/.aws`, `~/.ssh`, `~/.kube`, `~/.steampipe`

```
Filesystem Access Event
        │
collector.py  (watchdog/inotify, real-time scoring)
        │
auditd_integration.py   ← primary: kernel-level audit (zero race condition)
proc_scanner.py         ← fallback: /proc scan (race-prone)
        │
  SQLite (events)  ──►  inline RISK ALERT in collector log
        │
baseline.py  (profiles per artifact × user × process)
        │
ml/anomaly_detector.py  (Bayesian Network scoring)
        │
  alerts.json / console report
```

## How It Works

1. **Collect** — `collector.py` watches the paths in `policy_v2.yaml` via
   inotify. Each event is enriched with process context (PID, process name,
   parent, user) using auditd rules (kernel-level, no race) with a `/proc`
   scanner as fallback, then written to SQLite with timing metadata
   (`time_delta`, `session_id`, `files_in_session`).
2. **Baseline** — `baseline.py` groups events by `(artifact, user, process)`
   and computes access counts, active hours, and average intervals.
3. **Score** — `ml/anomaly_detector.py` trains a discrete Bayesian Network on
   *normal* sessions only, then computes `P(event)` for every new event.
   Low probability → high risk. Every factor is reported for explainability.
4. **Alert** — flagged events surface three ways: inline `RISK ALERT` log
   lines in the collector, a batch console report, and a machine-readable
   `alerts.json`.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt        # watchdog, pyyaml, pgmpy

# For zero-race process resolution (optional but recommended):
sudo apt install auditd audispd-plugins
sudo systemctl start auditd
```

Without auditd the collector automatically falls back to `/proc` scanning
(short-lived processes like `cat file` may be missed).

## Usage

```bash
source venv/bin/activate

# One-command rebuild: reset DB, regenerate seeded data, baseline, train,
# evaluate, generate alerts.json, and run a live smoke test (all verified)
./run_all.sh                    # add --skip-live to skip the smoke test
```

# Health check
python db.py

# Generate a labeled demo dataset (400 normal + 180 attack events)
python ml/generate_test_events.py

# Baseline
python baseline.py --reset            # compute + display
python baseline.py --show             # view anytime

# Anomaly detection
python ml/anomaly_detector.py train          # train on normal_* sessions only
python ml/anomaly_detector.py score-all      # batch score + flagged events
python ml/anomaly_detector.py score-all --report   # also writes alerts.json
python ml/anomaly_detector.py evaluate       # precision/recall/F1/confusion matrix
python ml/anomaly_detector.py explain <id>   # per-event probability breakdown
python ml/anomaly_detector.py status         # model info

# Live monitoring with real-time scoring
python collector.py                     # Ctrl+C to stop (removes audit rules)
```

### Optional: kernel-level process resolution

```bash
sudo ./setup_auditd.sh    # installs auditd + sudoers rule for the collector
```

Without auditd the collector uses `/proc` scanning, which can miss
short-lived processes (e.g. `touch`, `rm`). With it, every event resolves to
exact pid/process/user with zero race condition — recommended for the live
demo.

Trigger a test event while the collector runs:

```bash
echo test >> ~/.azure/config
```

## The Model

A pgmpy `DiscreteBayesianNetwork` — 8 nodes, 8 edges:

```
artifact ──┬── process ──┬── time_delta ── session_size
           ├── user ── hour_bucket ── day_bucket
           └── access_type
```

| Node | States |
|---|---|
| `artifact` | azure, aws, ssh, kube, steampipe (learned from data) |
| `process` | bash, cat, head, tail, nano, python3, curl, wget, ssh, grep, less, other |
| `user` | root, debian, other |
| `access_type` | read, write, create, delete, moved |
| `hour_bucket` | night, early, morning, midday, afternoon, evening |
| `day_bucket` | weekday, weekend |
| `time_delta` | instant (<0.1s), rapid (0.1–1s), normal (1–60s), slow (1–10min), idle (>10min) |
| `session_size` | single (1), small (2–5), medium (6–20), large (21–50), burst (51+) |

Key properties:

- **Trained on normal only** — events with `session_id LIKE 'attack_%'` are
  excluded from training and held out for evaluation.
- **Laplace smoothing** (α=1.0) handles unseen feature combinations.
- **Timing gets 2× weight** — burst patterns (rapid deltas, large sessions)
  are the highest-signal attack indicator, so `time_delta` and `session_size`
  factors are double-weighted in the risk score.
- **Persisted** to `ml/anomaly_model.json`; the collector auto-loads it at
  startup for real-time scoring.

## Risk Thresholds

Risk scores are 0–100 (higher = more anomalous). Thresholds were **calibrated
on the labeled dataset**, not guessed:

| Distribution | Measured range (seed 42) |
|---|---|
| Normal events | risk ≤ **20.6** |
| Attack events | **26.5** – 29.4 |

There is a clean gap between the classes — the thresholds sit inside it:

| Risk score | Classification |
|---|---|
| ≥ 45 | ANOMALY |
| ≥ 27 | SUSPICIOUS ← attacks land here |
| ≥ 23 | UNUSUAL |
| < 23 | NORMAL |

## Evaluation Results

Evaluated with `python ml/anomaly_detector.py evaluate` against the labeled
580-event dataset (400 normal, 180 attack — 3 attack patterns: credential
harvester on `.aws`, Azure token stealer as root, SSH key extractor):

```
Confusion matrix            Precision: 1.000
                 Attack  Normal    Recall:    1.000
Actual Attack     180       0      F1 score:  1.000
Actual Normal       0     400      Accuracy:  1.000
```

Every attack event was flagged and no normal event was. Flag escalation with
the seed-42 dataset: 120 SUSPICIOUS / 60 UNUSUAL.

> **Why 1.000 — read this before quoting the number.** The evaluation is a
> *pipeline integration test*, not a field benchmark. The synthetic normal and
> attack classes are non-overlapping by construction (attacks use 0.01–0.5s
> deltas and 20–100-file sessions; normals use 1–60s and 1–5 files), so perfect
> separation is expected. Real attackers can mimic normal timing (deltas of
> several seconds, small sessions) and would score near-normal — that mimicry
> gap is exactly what this evaluation cannot measure.

### Reproducibility

The generator is seeded: `python ml/generate_test_events.py --seed 42`
(defaults to 42). The same seed always produces the same 580 events, the same
baseline (112 profiles), and the same metrics above. Regenerating without the
same seed yields different draws — profile counts and the risk band shift
slightly, though detection performance is unaffected.

## Project Layout

```
policy_v2.yaml          Monitoring targets (5 credential categories)
artifact_scan.py        TUI browser for building the policy
collector.py            inotify collector + real-time scoring
auditd_integration.py   Kernel-level process resolver (primary)
proc_scanner.py         /proc process resolver (fallback)
db.py                   SQLite schema + helpers
baseline.py             Behavior profile engine
ml/anomaly_detector.py  Bayesian Network detector + CLI
ml/generate_test_events.py  Labeled synthetic data generator
ml/anomaly_model.json   Trained model (auto-generated)
alerts.json             Alert report (auto-generated, gitignored)
collector.db            SQLite database (auto-created)
```

## Design Principles

1. **Context over content** — reading `~/.azure/config` isn't malicious;
   who, when, and at what speed determines risk.
2. **Explainability** — every flag ships with per-factor conditional
   probabilities, not a black-box score.
3. **Low false-positive rate** — train on normal behavior only; measure
   against labeled data.
4. **Burst-awareness** — single accesses are low-signal; rapid multi-file
   access chains are high-signal and weighted accordingly.

## Known Limitations

- Perfect evaluation metrics reflect non-overlapping synthetic classes, not
  field performance; realistic attacks (slower deltas, small sessions) are
  the known blind spot, and no real-world validation has been done yet.
- No sequence analysis yet — events are scored individually, not as attack
  chains (e.g. `cat id_rsa` → append `authorized_keys`).
- Alert sinks are stdout + `alerts.json`; no syslog/email/webhook yet.
- Attack risk scores cluster narrowly (27.9–30.9), so ANOMALY (≥45) is
  rarely reached — the threshold awaits more diverse attack data.
