# Presentation Script — Behavior-Based Threat Detection for Linux Servers

A 5-minute demo flow with talking points, exact commands, and prep for the
questions you're most likely to get. Everything here is verified working —
rebuild the demo state any time with `./run_all.sh`.

---

## The night before

```bash
./run_all.sh --skip-live     # rebuild seeded dataset + retrain + verify metrics
```

Confirm the final block shows all four metrics at 1.000. That's your state.

## The morning of

```bash
./run_all.sh                 # full rebuild including live smoke test
```

If this passes, the live demo will work — it just ran the same code path.
Keep `/tmp/collector_test.log` around as your screenshot fallback.

> Optional shortcut for §4 below: `./demo.sh --self` fires the three live
> scenarios with the correct pacing and cleans up after itself, so you can
> narrate instead of typing. `--fast` rehearses it in ~40 seconds.

---

## Flow (5 minutes)

### 1. The problem (30s)

> "When servers get breached, attackers don't smash things — they quietly
> steal credentials: `~/.aws/credentials`, `~/.ssh/id_rsa`, Azure tokens.
> The files being read are legitimate; what's abnormal is *who* reads them,
> *when*, and *how fast*. So instead of alerting on every access, we learned
> what normal looks like and flag deviations."

One-line pitch: **context over content**.

### 2. Architecture (1 min)

Draw or show:

```
filesystem event → collector (inotify) → auditd resolves pid/user (kernel-level)
                 → SQLite ─┬─ Bayesian Network  ─► RISK ALERT  (per event)
                           │
                           └─ sequence rules   ─► CHAIN ALERT (per session)
```

Talking points:
- **auditd, not polling** — kernel-level audit trail, zero race condition,
  with a `/proc` fallback if auditd isn't available (graceful degradation).
- **Two layers, two questions** — the Bayesian Network asks *is this event
  unusual?*; `sequences.py` asks *do these events, in this order, mean
  something?* A per-event score structurally cannot see a chain.
- **Bayesian Network, 8 nodes** — artifact, process, user, access type, hour,
  weekday, time-delta, session size. `session_size` (distinct files touched)
  gets **2× weight** because a credential sweep is the strongest signal.
- **Explainable by design** — every score decomposes into per-factor
  probabilities, and every chain names the exact event ids that fired it.
  Not a black box.

### 3. Metrics (30s)

```bash
python ml/anomaly_detector.py evaluate
```

Show: confusion matrix TP=180 FN=0 FP=0 TN=400, all metrics 1.000.

```bash
python sequences.py --evaluate
```

Show: `Chain sessions: 20/20 detected`, `Normal sessions: 0/82 false positives`.

**Then immediately pre-empt the question (see Q&A #1) — and make the second
number the point:**

> "To be clear about what this 1.000 means — the synthetic burst classes are
> separable by construction: attacks sweep 20–100 distinct files per session,
> normals touch at most 5. This validates the pipeline end-to-end on a fixed
> seed. And the same run tells you where the per-event model *fails*: it flags
> **0 of the 80 low-and-slow chain events**. That's the honest blind spot, and
> it's exactly why there's a second layer — which catches all 20 chain
> sessions with no false positives on normal traffic."

Saying it first reads as rigor. Being asked first reads as a hole.

### 4. Live demo (2 minutes) — the centerpiece

Terminal 1:
```bash
python collector.py
```
Wait for: `Real-time scoring enabled` and `Collector started`.

Run the three scenarios **in this order** — the chain first, the sweep last.
Every event costs an `ausearch` call, so doing the heavy sweep last keeps the
handler from falling behind (and the demo from dropping events).

**(a) Normal access stays quiet**
```bash
echo test >> ~/.azure/config
```
→ **all four** events log `risk: NORMAL`. *"Low false positives matter as much
as catching attacks. That redirect is a cluster of inotify events on a single
file, and the model knows a one-file session is normal."*

**(b) The chain — the part a per-event model cannot see**
```bash
touch ~/.azure/id_rsa
sleep 3
echo attacker >> ~/.azure/authorized_keys
```
Terminal 1:
```
CHAIN ALERT: SSH_KEY_INJECTION [HIGH] — private key access followed by
  authorized_keys write (events=[13795, 13802])
```
Narrate: *"Two files, three seconds apart, nothing statistically unusual — the
Bayesian Network scores both events as normal. The chain is what matters:
private key touched, then `authorized_keys` written. That's the classic
backdoor, and the rule names the exact event ids that fired it."*

**(c) The credential sweep — the statistical layer**
```bash
for i in $(seq 1 30); do touch ~/.azure/.sneaky_$i; sleep 0.15; done
```
The sweep has to be broad, not just fast: the model escalates once the session
touches more than 5 distinct files. A 3-file burst is genuinely
indistinguishable from normal activity — and should stay quiet.
Terminal 1:
```
RISK ALERT: SUSPICIOUS (risk=84.5/100) — P(session_size=medium | time_delta) = 0.0058; ...
```
Narrate: *"It resolved the exact process and user from the kernel audit trail,
scored the event in real time, and flagged the session size — the number of
distinct credential files touched — as the anomaly driver. That's the
explainability."*

**If the demo gods are angry:** fall back to `cat /tmp/collector_test.log`
and narrate from the morning's verified run. Never debug live.

### 5. Explainability (1 min)

```bash
python ml/anomaly_detector.py explain <id>    # any event id flagged by run_all.sh
```

Show 2–3 factors: `✗ P(time_delta=rapid | process) = 0.0119` next to
`✓ P(user | artifact) = 0.77`. One sentence: *"A SOC analyst sees exactly
which condition fired, not just a score."*

### 6. Close (30s)

- **Done:** collector with kernel-level attribution, baseline engine,
  explainable Bayesian scoring, an order-aware sequence layer for multi-step
  chains, real-time RISK + CHAIN alerts, syslog/webhook sinks, JSON reports,
  an 81-test suite, and seeded reproducible evaluation.
- **Next (say it before they ask):** real-world validation against audit-log
  ground truth, cross-session correlation (chains that span more than one
  session survive an idle gap today), and widening the chain rule set.

---

## Anticipated Q&A

**Q1: "Your precision is 1.000 — isn't that suspicious?"**
> "Right — it means the synthetic burst classes are separable by construction,
> not that field performance is perfect. Attacks sweep 20–100 distinct files
> per session; normal sessions touch at most 5, and distinct-file count is
> exactly what the score keys on. The metric validates the pipeline on a fixed
> seed. The genuinely interesting number is right underneath it: the per-event
> model flags **0 of the 80 chain events**. An adversary who mimics normal
> shape defeats it by design. That's why there's a sequence layer, and it's
> why I report both numbers instead of the flattering one."

**Q2: "Why a Bayesian Network and not an ML classifier / autoencoder?"**
> "Explainability is a requirement, not a preference — a SOC needs to know
> *why* an alert fired. A BN gives per-factor conditional probabilities for
> free. It also trains on normal data only, which matches the problem: I have
> abundant normal behavior and no realistic labeled attacks in production."

**Q3: "Why SUSPICIOUS and never ANOMALY?"**
> "Thresholds are calibrated to measured score distributions, not guessed:
> normal events top out at 25.7, attacks start at 70.4 and reach 84.5, and the
> cutoffs sit inside that gap. ANOMALY (≥85) is deliberate headroom for
> harder, more blatant attack data. A flag level I can defend beats a dramatic
> label I can't."

**Q4: "What's the false-positive story in production?"**
> "The design targets it three ways: training on normal-only, per-factor
> thresholds with smoothing, and 2× weighting only on timing — but I haven't
> measured FP rate on real traffic, and I'd expect it to be the main
> tuning work in deployment."

**Q5: "Why does the process show as 'no process found' sometimes?"**
> "That's the `/proc` fallback — it polls after the fact, so very short-lived
> processes can be missed. With auditd installed (`sudo ./setup_auditd.sh`),
> resolution is kernel-level and race-free. The system degrades gracefully
> rather than failing."

**Q6: "How is this different from just watching file access with auditd?"**
> "auditd gives you events; it doesn't tell you what's abnormal. The added
> layers are the behavioral model (who/when/speed baselines), real-time risk
> scoring with explanation, session-level burst detection, and order-aware
> chain rules — the difference between logging and detecting."

**Q7: "Is the sequence layer just a pile of regex rules?"**
> "Yes — four explicit rules, and that's deliberate. A rule I can state is a
> rule a SOC can tune, argue with, and audit; each alert names the exact event
> ids that fired it. It also has a clear failure mode I can state honestly:
> rename the private key, or pause more than five seconds between steps and
> let the session split, and the rule won't fire. The per-event model has the
> complementary weakness — it can't see order at all. Together they cover
> more than either does alone, and I can say precisely where each one breaks."

---

## One-page cheat sheet

| Command | What it shows |
|---|---|
| `./demo.sh --self --with-metrics` | The whole live demo (benign → chain → sweep) as one command |
| `./run_all.sh` | Full rebuild + verification (8 stages, all green) |
| `python ml/anomaly_detector.py evaluate` | Confusion matrix + P/R/F1 + the BN's chain blind spot |
| `python sequences.py --evaluate` | Chain recall vs false positives |
| `python collector.py` | Live monitoring + real-time RISK and CHAIN alerts |
| `echo test >> ~/.azure/config` | Normal event → `risk: NORMAL` |
| `touch ~/.azure/id_rsa` then `echo x >> ~/.azure/authorized_keys` | Chain → `CHAIN ALERT: SSH_KEY_INJECTION` |
| `for i in $(seq 1 30); do touch ~/.azure/.sneaky_$i; sleep 0.15; done` | Sweep → `RISK ALERT: SUSPICIOUS` |
| `python ml/anomaly_detector.py explain <id>` | Per-factor probability breakdown |
| `cat alerts.json | head` | Machine-readable SOC-ready output |
