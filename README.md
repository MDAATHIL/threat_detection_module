# Behavior-Based Threat Detection for Compromised Linux Servers

A context-aware filesystem monitoring system that detects credential theft on
Linux servers. Instead of treating every access to sensitive files as malicious,
it learns what *normal* access looks like — who, when, how fast — and flags
deviations with **explainable risk scores**.

Monitored artifact categories: `~/.azure`, `~/.aws`, `~/.ssh`, `~/.kube`, `~/.steampipe`

> Presenting this? Start with **`DEMO_RUNBOOK.md`** — it has the exact commands
> to run, in the order that works, plus what to do when a live step fails.

```
Filesystem Access Event
        │
collector.py  (watchdog/inotify + real-time scoring)
        │
auditd_integration.py   ← primary: kernel-level audit (zero race condition)
proc_scanner.py         ← fallback: /proc scan (race-prone)
        │
  SQLite (events)
        │
        ├── ml/anomaly_detector.py   per-event Bayesian Network ─► RISK ALERT
        └── sequences.py             order-aware chain rules    ─► CHAIN ALERT
                                │
                          alerts.py  ─► stdout · alerts.json
                                     └► syslog · webhook
        │
baseline.py  (profiles per artifact × user × process)
```

Two detection layers, because they answer different questions: the Bayesian
Network asks *is this event unusual?*, `sequences.py` asks *do these events,
in this order, mean something?*

## How It Works

1. **Collect** — `collector.py` watches the paths in `policy_v2.yaml` via
   inotify. Each event is enriched with process context (PID, process name,
   parent, user) using auditd rules (kernel-level, no race) with a `/proc`
   scanner as fallback, then written to SQLite with timing metadata
   (`time_delta`, `session_id`, `files_in_session`).
2. **Baseline** — `baseline.py` groups events by `(artifact, user, process)`
   and computes access counts, active hours, and average intervals.
3. **Score** — `ml/anomaly_detector.py` trains a discrete Bayesian Network on
   *normal* sessions only, then scores each event by its **strongest weighted
   surprise**: `S = max_i w_i · −ln P(factor_i)`. A single highly improbable
   factor is the signal — an attack is a burst of rare values surrounded by
   ordinary ones, and summing every factor's probability would dilute it.
   Every factor is reported for explainability.
4. **Correlate** — `sequences.py` replays the *order* of events inside a
   session against deliberate chain rules (private key → `authorized_keys`,
   bulk credential deletion, cross-store sweep, rapid sweep). This catches
   low-and-slow attacks that leave every individual event looking ordinary,
   and raises a `CHAIN ALERT` naming the event ids that fired it.
5. **Alert** — flags surface as inline `RISK ALERT` / `CHAIN ALERT` log
   lines, a batch console report, `alerts.json`, and — when configured —
   syslog and a webhook.

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

# Unit tests (features, DB, collector, end-to-end detection)
python -m unittest discover -s tests -t .

# Health check
python db.py

# Generate a labeled demo dataset (400 normal + 180 burst + 80 chain events)
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

# Sequence (chain) analysis — order-aware, complements the per-event score
python sequences.py                     # scan stored sessions for chains
python sequences.py --evaluate          # recall on chains vs false positives
python sequences.py --json chains.json  # machine-readable chain report

# Alert sinks (off by default; see `alerting:` in policy_v2.yaml)
python alerts.py                        # show config, optionally self-test

# Live monitoring with real-time scoring
python collector.py                     # Ctrl+C to stop (removes audit rules)

# Live demo, in one command (see DEMO_RUNBOOK.md §4 for the manual path)
./demo.sh --self --with-metrics          # batch numbers, then benign/chain/sweep
./demo.sh                                # same, driving your own collector
./demo.sh --fast                         # rehearse the whole flow in ~40s

# Interactive web dashboard — every operation above, in a browser
python dashboard.py --open
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

## Web Dashboard

The dashboard is a thin control surface over the code above — every button
calls the same function the CLI calls and reads the same `collector.db`.
There is no mock data and no second copy of the detection logic.

```bash
python dashboard.py                 # http://127.0.0.1:8765
python dashboard.py --open          # also launch a browser
python dashboard.py --port 9000     # different port
```

It uses only the standard library for the web layer (no Flask/Django), so
nothing is added to `requirements.txt`.

What you get:

| View | What it does |
|---|---|
| **Overview** | Event / session / profile counts, risk histogram by dataset label, risk-classification donut, per-artifact and per-process breakdowns, collection timeline, top flagged events, system health |
| **Events** | Filter by session, artifact, access type, risk level or free text; paginate; click a row for the full per-factor probability breakdown (`score_event`) |
| **Detection** | Train the Bayesian Network (`train`), score everything and write `alerts.json` (`score-all --report`), evaluate both layers (`evaluate` + `sequences.evaluate`) with a confusion matrix |
| **Chains** | Run the order-aware rules over the stored sessions, show recall vs. false positives, the fired rules, the tunables, and every match with its event ids |
| **Baseline** | Recompute profiles (`baseline.py --reset`) and browse them per artifact / process / user |
| **Exports** | CSV/JSON downloads of the events table (honoring every active filter), plus baseline CSV, chain scan CSV/JSON and an alerts CSV |
| **Collector** | Start and stop `collector.py` (SIGINT first, so audit rules are removed), show the monitored paths and their existence, tail the live log, and run `demo.sh` |
| **Alerts** | Show the sink configuration (`alerts.py`), run a sink self-test, read `alerts.json`, and download the alert / chain reports |
| **Data** | Regenerate the seeded dataset, run the whole pipeline (generate → baseline → train → score → evaluate → chain scan), **import uploaded CSV/JSON events** into the same table and optionally analyze them, and clear the tables |

Long-running actions stream their stdout into an **Activity** drawer, so a
training run or the live demo shows its own log as it happens.

### API

The UI is a plain JSON client, so the same endpoints are usable from scripts:

```
GET  /api/overview /api/stats /api/events /api/event?id=N /api/baseline
     /api/model /api/chains /api/alerts /api/reports /api/policy
     /api/jobs /api/job?id=ID /api/collector /api/collector/log?tail=400
GET  /api/export?dataset=events|baseline|chains|alerts&format=csv|json
     [&session=..&artifact=..&access_type=..&risk_level=..&q=..&order=..]
POST /api/generate /api/pipeline /api/baseline/compute /api/model/train
     /api/score-all /api/evaluate /api/chains/scan /api/alerts/test
     /api/upload /api/db/clear /api/collector/start /api/collector/stop /api/demo
```

Action endpoints return `202 {"job": {...}}`; poll `GET /api/job?id=...` for
status, streamed output and the result.

`/api/export` streams a file attachment built from the *same* filters, scoring
cache and chain scan the views render, so an export cannot disagree with the
table on screen. Example: download every flagged AWS event as CSV.

```bash
curl -OJ 'http://127.0.0.1:8765/api/export?dataset=events&format=csv&artifact=aws&risk_level=suspicious'
```

> The dashboard binds to `127.0.0.1` by default. `--host 0.0.0.0` exposes an
> API that can start the collector and rewrite the database — only do that on a
> trusted network.

## The Model

A pgmpy `DiscreteBayesianNetwork` — 8 nodes, 7 edges:

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
- **Fixed account vocabulary** — the modelled users are `root` and `debian`;
  every other account collapses to `other`, exactly as an unknown process does.
  The state space never depends on the login running the detector, so the same
  seed trains the same model on any machine.
- **Laplace smoothing** (α=1.0) handles unseen feature combinations.
- **Sweep size gets 2× weight** — `session_size` counts *distinct files touched
  in the session*, which is the credential-sweep signature, so it is
  double-weighted. Raw `time_delta` keeps 1× because it is noisy: every
  ordinary file access emits a sub-second cluster of inotify events.
- **Sessions are counted honestly** — the collector increments
  `files_in_session` only when a *new* file appears, so `echo x >> file`
  (several events, one file) is a single-file session, not a burst.
- **Modelled on the real event stream** — training data reproduces the
  collector's per-access event clusters, so an ordinary access is not
  mistaken for an attack. `session_size` is conditioned on `time_delta` alone
  rather than on `(process, time_delta)`: with ~400 normal events the larger
  parent set over-parameterises the CPD and Laplace mass hides the signal.
- **Persisted** to `ml/anomaly_model.json`; the collector auto-loads it at
  startup for real-time scoring.

## Risk Thresholds

Risk scores are 0–100 (higher = more anomalous). Thresholds were **calibrated
on the labeled dataset**, not guessed:

| Distribution | Measured range (seed 42) |
|---|---|
| Normal events | risk **5.5** – **25.7** |
| Attack events | risk **70.4** – **84.5** |

There is a clean gap between the classes — the thresholds sit inside it:

| Risk score | Classification |
|---|---|
| ≥ 85 | ANOMALY |
| ≥ 45 | SUSPICIOUS ← attacks land here |
| ≥ 40 | UNUSUAL |
| < 40 | NORMAL |

The score is `100 · (S − 1) / (12 − 1)` clipped to 0–100, where `S` is the
weighted surprise above. Normal activity never exceeds `S = 3.83`; the
synthetic attacks start at `S = 8.74`.

## Sequence (Chain) Analysis

A per-event score cannot see order. An intruder can read a private key and
then quietly append their own key to `authorized_keys` — every event ordinary,
the intent visible only in the sequence. `sequences.py` adds a small,
deliberate rule layer over the ordered events of one session:

| Rule | Fires when | Severity |
|---|---|---|
| `ssh_key_injection` | a private key (`id_rsa`, `*.pem`, …) is touched, then `authorized_keys` is written | high |
| `bulk_credential_delete` | ≥ 3 distinct credential files deleted in one session | high |
| `cross_artifact_sweep` | ≥ 3 different credential stores touched in one session | high |
| `rapid_multi_file_sweep` | ≥ 5 distinct files touched within 3 seconds | medium |

Pairs must fall inside a 300-second window and belong to the same session.
Every alert names the rule, the severity, and the exact event ids, so a chain
is as auditable as a probability:

```
CHAIN ALERT: SSH_KEY_INJECTION [HIGH] — private key access followed by
  authorized_keys write (events=[13795, 13802])
```

The rule list is deliberately short and explicit: a rule you cannot explain
is not usable in a SOC.

## Evaluation Results

The dataset is labeled by session prefix — `normal_*`, `attack_burst_*`
(three per-event patterns) and `attack_chain_*` (two low-and-slow chains):

```
$ python ml/anomaly_detector.py evaluate
  Events: 660  (burst attacks: 180, chain attacks: 80, normal: 400)

  Statistical layer — per-event Bayesian Network vs burst attacks:
                 Attack     Normal
  Actual Attack     180         0        Precision: 1.000
  Actual Normal       0       400        Recall:    1.000
                                         F1: 1.000  Accuracy: 1.000

  Sequence layer — order-aware rules:
    Chain events flagged by the BN alone: 0/80   <- the per-event blind spot

$ python sequences.py --evaluate
  Chain sessions:  20/20 detected
  Normal sessions: 0/82 false positives
```

Two numbers carry the story. The per-event model separates burst attacks
cleanly **and is blind to all 80 chain events** — by construction, because
those chains mimic normal shape. The sequence layer catches **all 20 chain
sessions with zero false positives** on normal traffic. Neither layer is
sufficient alone, and reporting both is the point.

> **Why the BN's 1.000 — read this before quoting it.** The evaluation is a
> *pipeline integration test*, not a field benchmark. The synthetic classes
> are non-overlapping by construction: burst attacks sweep 20–100 **distinct
> files** per session while normal sessions touch at most 5, and distinct-file
> count is what the score keys on. The sequence layer is only as good as its
> rules — a chain shape the four rules do not describe is still missed. No
> real-world validation has been done.

### Reproducibility

The generator is seeded: `python ml/generate_test_events.py --seed 42`
(defaults to 42). The same seed always produces the same 660 events, the same
baseline (118 profiles), and the same metrics above. Regenerating without the
same seed yields different draws — profile counts and the risk band shift
slightly, though detection performance is unaffected.

## Project Layout

```
DEMO_RUNBOOK.md         Step-by-step presentation flow, commands, fallbacks
PRESENTATION.md         5-minute talk script + anticipated Q&A
dashboard.py            Web dashboard: stdlib HTTP server + JSON API (no new deps)
dashboard.html          Dashboard UI (single page, no external assets, no CDN)
demo.sh                 The live demo (benign/chain/sweep) as one command
policy_v2.yaml          Monitoring targets (5 credential categories)
artifact_scan.py        TUI browser for building the policy
collector.py            inotify collector + real-time scoring
auditd_integration.py   Kernel-level process resolver (primary)
proc_scanner.py         /proc process resolver (fallback)
db.py                   SQLite schema + helpers
baseline.py             Behavior profile engine
ml/anomaly_detector.py  Bayesian Network detector + CLI
ml/generate_test_events.py  Labeled synthetic data generator
sequences.py            Order-aware chain rules + CLI
ml/anomaly_model.json   Trained model (auto-generated)
alerts.py               Optional syslog / webhook alert sinks
tests/                  Unit + end-to-end tests (82, stdlib unittest, no new deps)
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

- Perfect statistical metrics reflect non-overlapping synthetic classes, not
  field performance, and no real-world validation has been done yet.
- Chain rules are heuristic and name/path based. An attacker who renames a
  private key, or splits a chain across sessions (pausing >5s per step),
  evades them; novel chain shapes are not covered at all.
- ANOMALY (≥85) is not reached by the synthetic burst attacks (they top out
  at 84.5) — the tier is headroom for harder, more blatant attack data.
- `session_id` groups events by a 5-second idle timeout, not by a real login
  session, so a patient attacker who pauses >5s per file resets both the
  distinct-file count and the chain buffer.
- Alert sinks are fire-and-forget: no retry, queueing, or delivery guarantee.
- Detection is per-session and per-event; there is no cross-session or
  long-horizon correlation.
