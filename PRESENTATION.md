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
                 → SQLite → baseline profiles → Bayesian Network → risk score
```

Talking points:
- **auditd, not polling** — kernel-level audit trail, zero race condition,
  with a `/proc` fallback if auditd isn't available (graceful degradation).
- **Bayesian Network, 8 nodes** — artifact, process, user, access type, hour,
  weekday, time-delta, session size. Timing features get **2× weight** because
  burst access is the strongest attack signal.
- **Explainable by design** — every score decomposes into per-factor
  probabilities. Not a black box.

### 3. Metrics (30s)

```bash
python ml/anomaly_detector.py evaluate
```

Show: confusion matrix TP=180 FN=0 FP=0 TN=400, all metrics 1.000.

**Then immediately pre-empt the question (see Q&A #1):**

> "To be clear about what this 1.000 means — the synthetic attack and normal
> classes are separable by construction. This validates the pipeline
> end-to-end on a fixed seed. The real-world blind spot is timing mimicry,
> which is documented as future work."

Saying it first reads as rigor. Being asked first reads as a hole.

### 4. Live demo (2 minutes) — the centerpiece

Terminal 1:
```bash
python collector.py
```
Wait for: `Real-time scoring enabled` and `Collector started`.

Terminal 2 — the attack (rapid credential sweep):
```bash
for i in 1 2 3; do touch ~/.azure/.sneaky_$i; sleep 0.2; rm -f ~/.azure/.sneaky_$i; done
```

Terminal 1 shows, within a second:
```
Event #N: create on /home/debian/.azure/.sneaky_1 (pid=6383 comm=touch user=debian ...)
  RISK ALERT: SUSPICIOUS (risk=30.7/100) — P(time_delta=rapid | process) = 0.0119; ...
```

Narrate: *"It resolved the exact process and user from the kernel audit trail,
scored the event in real time, and flagged the rapid timing as the anomaly
driver — that last part is the explainability."*

Then show a normal access:
```bash
echo test >> ~/.azure/config
```
→ logs `risk: NORMAL`. *"Low false positives matter as much as catching attacks."*

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
  explainable Bayesian scoring, real-time alerting, JSON reports,
  seeded reproducible evaluation.
- **Next (say it before they ask):** sequence analysis for multi-step attack
  chains (`cat id_rsa` → append `authorized_keys`), real-world validation
  against audit-log ground truth, alert sinks (syslog/webhook).

---

## Anticipated Q&A

**Q1: "Your precision is 1.000 — isn't that suspicious?"**
> "Right — it means the evaluation classes are separable by construction, not
> that field performance is perfect. The attack generator uses 10–500ms deltas
> and 20–100-file sessions; normal data uses 1–60s and 1–5 files. There's no
> overlap, so perfect separation is expected. The metric validates the
> pipeline on a fixed seed. A real attacker mimicking normal timing is the
> documented blind spot — that's the first thing I'd attack this system with,
> and it needs sequence analysis and real-world data to close."

**Q2: "Why a Bayesian Network and not an ML classifier / autoencoder?"**
> "Explainability is a requirement, not a preference — a SOC needs to know
> *why* an alert fired. A BN gives per-factor conditional probabilities for
> free. It also trains on normal data only, which matches the problem: I have
> abundant normal behavior and no realistic labeled attacks in production."

**Q3: "Why SUSPICIOUS and never ANOMALY?"**
> "Thresholds are calibrated to measured score distributions — normal events
> max out at 20.6, attacks start at 26.5, and the cutoffs sit in that gap.
> The ANOMALY tier (≥45) is a placeholder for harder, more subtle attack
> data. A flag level I can defend beats a dramatic label I can't."

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
> scoring with explanation, and session-level burst detection — the difference
> between logging and detecting."

---

## One-page cheat sheet

| Command | What it shows |
|---|---|
| `./run_all.sh` | Full rebuild + verification (6 stages, all green) |
| `python ml/anomaly_detector.py evaluate` | Confusion matrix + P/R/F1 |
| `python collector.py` | Live monitoring + real-time alerts |
| `echo test >> ~/.azure/config` | Normal event → `risk: NORMAL` |
| `touch ~/.azure/.sneaky_1` | Burst → `RISK ALERT: SUSPICIOUS` |
| `python ml/anomaly_detector.py explain <id>` | Per-factor probability breakdown |
| `cat alerts.json | head` | Machine-readable SOC-ready output |
