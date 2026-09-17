# Demo Runbook — Behavior-Based Threat Detection

Everything needed to *show* this project: what to do, what to type, what should
appear, and what to do when it doesn't. Verified against the current code.

Pairs with `PRESENTATION.md` (the talk) and `README.md` (the reference).
Run `./run_all.sh` and it ends with `ALL CHECKS PASSED (15 steps)` — that is
the state every command below assumes.

---

## 0. The one rule

> **Run every batch/statistical command BEFORE the live demo.**

The live demo writes real events into the same `collector.db`. `evaluate`
treats any session that isn't `attack_burst_*` / `attack_chain_*` as normal
traffic, so a live event sitting in the database after the demo will be counted
as a false positive and your 1.000 metrics will look worse — for no real reason.

**Batch first (stages 2–3), live second (stages 4–5).** If you slip up, run
`./run_all.sh --skip-live` afterwards to restore the pristine seeded state.

---

## 1. What you are actually demonstrating

Not "my tool." You are putting **three detectors on the same intrusion**:

| Detector | Greedy sweep | Careful, slow chain | Benign admin |
|---|---|---|---|
| Naive "watch credential files" | 180 noisy alerts | alert (no context) | alert (pure noise) |
| Per-event Bayesian Network | **catches** | **blind — 0 of 80** | silent |
| `+ sequences.py` (order-aware) | catches | **catches — 20/20** | silent |

That table is the talk. The second row's failure is a *designed result you
measured and report*, not a hole someone found. That is the maturity signal.

**Protagonist**: a server being quietly stripped of credentials.
**Complication**: every individual access is legitimate.
**Resolution**: context (the network) plus order (the rules), with the
blind spot of each layer stated out loud.

---

## 2. Pre-flight — the night before

```bash
cd ~/threat_detection_module
source venv/bin/activate

# Full rebuild + verification: tests, dataset, baseline, train, evaluate,
# sequence layer, live smoke test. Must end all-green.
./run_all.sh
```

Then keep the fallback artefact that run leaves behind:

```bash
cp /tmp/collector_test.log /tmp/demo_fallback.log
wc -l /tmp/demo_fallback.log      # should be a few hundred lines
```

If `run_all.sh` does not pass, **stop** — nothing below will work. Fix that
first (`./run_all.sh --skip-live` to bisect without the live stage).

Optional but strongly recommended — record a replay you can fall back to:

```bash
asciinema rec /tmp/demo.cast      # run the demo, Ctrl-D to stop
```

---

## 3. Setup — 5 minutes before

Two terminals, side by side. Large font (18pt+). No fancy prompt, no
notifications (close Slack/mail/updates). Dark background, high contrast.

Set up **both** terminals:

```bash
cd ~/threat_detection_module
source venv/bin/activate
mkdir -p ~/.azure
```

Confirm dependencies are importable in the venv you just activated:

```bash
python -c "import yaml, watchdog, pgmpy; print('deps OK')"
```

Keep the command card (§8) open on a second screen or printed. Know your
fallback: `cat /tmp/demo_fallback.log`.

**Terminal roles**
- **T1** = the collector (the detection engine — this is where the alerts appear)
- **T2** = the attacker + the batch reports

---

## 4. Run sheet

Total: ~6 minutes. Cut marks for shorter slots are in §5.

> **Shortcut — the whole live demo in one command:** `./demo.sh --self`
> runs Stage 4a–c for you with the right pacing, verifies the outcome, and
> removes its own scratch files (even if you hit Ctrl+C). Add `--with-metrics`
> to print Stage 3 first. Rehearse it with `--fast` in ~40 seconds.
>
> Everything below is still the manual path, and it stays the reference: if the
> script misbehaves on stage, fall back to typing the commands yourself. See
> §8 for the flags.
>
> ```bash
> ./demo.sh --self --with-metrics   # full run: numbers, then live demo
> ```

### Stage 1 — The problem (30s, no commands)

Say the pitch. One line: **context over content.**

> "When a server is breached, attackers don't smash things — they quietly
> steal credentials: `~/.aws/credentials`, `~/.ssh/id_rsa`, Azure tokens.
> The files being read are *legitimate*. What's abnormal is who reads them,
> when, and how fast. So instead of alerting on every access, we learned what
> normal looks like and flag deviations."

### Stage 2 — Start the collector (T1) + architecture (60s)

```bash
python collector.py
```

Takes ~6 seconds to boot (it installs audit rules). Narrate while it does —
these lines are your architecture slide:

```
Watching: /home/debian/.azure (recursive=True)          ← 5 credential stores
Audit rule added: /home/debian/.azure                   ← kernel-level, zero race
Using auditd + /proc fallback for process resolution    ← graceful degradation
Model loaded from ml/anomaly_model.json (8 nodes, 8 CPDs)
Real-time scoring enabled (model: ml/anomaly_model.json)
Alert sinks: stdout only (configure `alerting:` in policy_v2.yaml ...)
Collector started — monitoring 5 artifact(s)
```

Talking points while it scrolls:
- **auditd, not polling** — kernel audit trail, no race condition, `/proc`
  fallback if auditd is missing.
- **Two layers, two questions** — the network asks *is this event unusual?*;
  the rules ask *do these events, in this order, mean something?*
- **Explainable by design** — every alert decomposes into numbers you can see.

### Stage 3 — The numbers (T2, 60s) ← batch, before any live events

```bash
python ml/anomaly_detector.py evaluate
```

Expect:

```
Events: 660  (burst attacks: 180, chain attacks: 80, normal: 400)

Statistical layer — per-event Bayesian Network vs burst attacks:
                 Attack     Normal
Actual Attack     180         0        Precision: 1.000
Actual Normal       0       400        Recall:    1.000
                                       F1: 1.000  Accuracy: 1.000

Sequence layer — order-aware rules:
  Chain events flagged by the BN alone: 0/80   <- the per-event blind spot
```

Then:

```bash
python sequences.py --evaluate
```

Expect:

```
Chain sessions:  20/20 detected
Normal sessions: 0/82 false positives
```

**This is your strongest 60 seconds.** Read the `0/80` line out loud *first*,
before anyone can ask. Then:

> "The network separates the greedy attacks perfectly — and it is completely
> blind to all 80 chain events, because those are built to look normal. That's
> the honest blind spot, and it's exactly why there's a second layer. Which
> catches all 20 chain sessions, with zero false positives on normal traffic."

### Stage 4 — Live demo (T2, 2–3 min) — the centerpiece

Order matters. Chain **before** sweep: every event costs an `ausearch` call,
and burying the handler makes the kernel drop inotify events.

**(a) Normal access stays quiet**

```bash
echo test >> ~/.azure/config
```

T1 within a second (four events, all calm):

```
Event #N: read  on /home/debian/.azure/config (pid=..., comm=bash user=debian, session=...)
  risk: NORMAL (score=0.9446)
...
```

> "Low false positives matter as much as catching attacks. That redirect is a
> cluster of inotify events on a single file — and the model knows a one-file
> session is normal."

**(b) The chain — what a per-event model cannot see**

```bash
touch ~/.azure/id_rsa ; sleep 3 ; echo attacker >> ~/.azure/authorized_keys
```

T1 shows, within a second of the second command:

```
CHAIN ALERT: SSH_KEY_INJECTION [HIGH] — private key access followed by authorized_keys write (events=[13795, 13802])
```

> "Two files, three seconds apart. Neither event is statistically unusual —
> the network scores both as normal. The *sequence* is the attack: private key
> touched, then `authorized_keys` written. That's the classic backdoor, and the
> alert names the exact event ids that fired it."

**(c) The sweep — the statistical layer**

```bash
for i in $(seq 1 30); do touch ~/.azure/.sneaky_$i; sleep 0.15; done
```

T1 streams (first alert at the 6th distinct file, then a run of them):

```
RISK ALERT: SUSPICIOUS (risk=84.5/100) — P(session_size=medium | time_delta) = 0.0058; P(process=other | artifact) = 0.0543; ...
```

Let the alerts scroll while you narrate — that's the visual payoff. Each event
needs an `ausearch` call, so allow **~15 seconds** to drain.

> "It resolved the exact process and user from the kernel audit trail, scored
> the event in real time, and flagged the session size — the number of distinct
> credential files touched — as the driver. That last part is the
> explainability."

### Stage 5 — Explainability (T2, 45s)

```bash
EID=$(python -c "
from db import get_conn
c = get_conn()
print(c.execute(\"SELECT id FROM events WHERE session_id LIKE 'attack_burst_%' ORDER BY id LIMIT 1\").fetchone()[0])
c.close()
")
python ml/anomaly_detector.py explain $EID
```

Expect a feature list and a per-factor breakdown with one `✗` among several `✓`:

```
  P(artifact=aws) = 0.200000  [✓ NORMAL]
  P(process=python3 | artifact) = 0.108696  [✓ NORMAL]
  P(time_delta=rapid | process) = 0.450000  [✓ NORMAL]
  P(session_size=burst | time_delta) = 0.005814  [✗ UNUSUAL]
```

> "A SOC analyst sees exactly which condition fired, not just a score."

*(Tip: you can pre-run this minutes before and keep the id in a scratch file if
typing a heredoc on stage makes you nervous.)*

### Stage 6 — Close (30s)

Ctrl+C in T1 and let this scroll:

```
Shutting down collector...
Removing audit rules...
Audit rule removed: /home/debian/.azure
...
Collector stopped.
```

> "Cleanup is automatic — the audit rules it installed are removed on exit."

Then close on what's done and what's next:

- **Done:** kernel-level attribution, baseline profiles, explainable
  per-factor scoring, order-aware chain layer, real-time RISK + CHAIN alerts,
  syslog/webhook sinks, 81 tests, seeded reproducible evaluation.
- **Next:** real-world validation against audit-log ground truth, cross-session
  correlation (chains that survive a >5s idle gap), widening the rule set.

---

## 5. Timing variants

| Slot | Include | Cut |
|---|---|---|
| **15 min** | Everything, plus `python sequences.py` (full chain list) and `cat alerts.json \| head` | — |
| **10 min** | Stages 1–6, plus `cat alerts.json \| head` | shorter narration |
| **5 min** | Stage 1 (30s) → Stage 3 (60s) → Stage 4 live (2.5 min) → Stage 6 (30s) | Stage 2 detail, Stage 5 |
| **3 min** | Stage 3 numbers → Stage 4b chain → Stage 4c sweep | everything else |

If you only get one live moment, make it **Stage 4b** (the chain). It is the
one thing a per-event detector structurally cannot do.

---

## 6. Failure playbook

Never debug on stage. Each row is a recovery, not a fix.

| Symptom | Move |
|---|---|
| Collector won't start / crashes | `cat /tmp/demo_fallback.log` and narrate from the verified run |
| No `CHAIN ALERT` | The live events are already in the DB — run `python sequences.py` and show the chain pulled from storage. Same proof, different route |
| No `RISK ALERT` | Stage 3 already proved detection; show `cat alerts.json \| head` |
| Alerts arrive far too slowly | You ran the sweep before the chain. Ctrl+C, `./run_all.sh --skip-live`, restart the collector, use the original order |
| Metrics look worse than 1.000 | Live events are polluting the DB. That's expected *after* the demo — run `./run_all.sh --skip-live` to reset, and quote the Stage 3 screenshot |
| `demo.sh` reports no CHAIN ALERT | It prints the failing check and the log path. The chain is usually just still draining — `python sequences.py` shows it from the DB |
| `demo.sh` wedges or prints nothing | Ctrl+C. It cleans up after itself, kills only the collector it started, and is safe to re-run |
| Terminal font unreadable | Fix before you start; there is no recovering this mid-talk |
| Someone asks for an event id you don't have | `python sequences.py` prints event id lists for every chain |

**Golden rule:** if a live step fails twice, switch to the fallback log and keep
talking. The narrative does not depend on the demo gods.

---

## 7. After the talk — restore

```bash
# T1 already stopped with Ctrl+C. Clean up the scratch files:
rm -f ~/.azure/.sneaky_* ~/.azure/id_rsa ~/.azure/authorized_keys

# Restore the pristine seeded dataset + trained model:
./run_all.sh --skip-live
```

`--skip-live` takes ~30s and leaves you with 660 labeled events, 118 baseline
profiles, and metrics back at 1.000.

---

## 8. Command card

| Command | What it shows |
|---|---|
| `./demo.sh --self --with-metrics` | **The whole live demo in one command** — batch numbers, then benign → chain → sweep, with a pass/fail summary |
| `./demo.sh` | Same, but driving a collector you started yourself in T1 |
| `./demo.sh --fast` | Rehearsal: ~40 seconds, short waits, 12-file sweep |
| `./run_all.sh` | Full rebuild + verification (8 stages, 15 checks) |
| `./run_all.sh --skip-live` | Same, without the live collector stage |
| `python collector.py` | Live monitoring + real-time RISK/CHAIN alerts (Ctrl+C stops) |
| `python ml/anomaly_detector.py evaluate` | Metrics **and** the chain blind spot |
| `python ml/anomaly_detector.py explain <id>` | Per-factor probability breakdown |
| `python ml/anomaly_detector.py score-all --report` | Batch score + `alerts.json` |
| `python sequences.py` | All detected chains, with event ids |
| `python sequences.py --evaluate` | Chain recall vs false positives |
| `python sequences.py --json chains.json` | Machine-readable chain report |
| `python baseline.py --show` | Behaviour profiles (artifact × user × process) |
| `python alerts.py` | Alert-sink config / self-test |
| `echo test >> ~/.azure/config` | Normal access → `risk: NORMAL` |
| `touch ~/.azure/id_rsa; sleep 3; echo x >> ~/.azure/authorized_keys` | Chain → `CHAIN ALERT` |
| `for i in $(seq 1 30); do touch ~/.azure/.sneaky_$i; sleep 0.15; done` | Sweep → `RISK ALERT: SUSPICIOUS` |
| `cat alerts.json \| head` | Machine-readable SOC-ready output |

---

## 9. Answering the likely questions

Short answers here; the full script is in `PRESENTATION.md` §Q&A.

**"Precision 1.000 — isn't that suspicious?"**
> "It means the synthetic burst classes are separable by construction, not that
> field performance is perfect. The more interesting number is right under it:
> the per-event model flags *0 of the 80* chain events. An attacker who mimics
> normal shape defeats it by design. That's why there's a second layer, and why
> I report both numbers instead of the flattering one."

**"Why a Bayesian Network and not a classifier?"**
> "Explainability is a requirement, not a preference — a SOC needs to know *why*.
> A BN gives per-factor conditional probabilities for free, and it trains on
> normal data only, which matches the problem: abundant normal behaviour, no
> realistic labelled attacks in production."

**"Why is the alert only SUSPICIOUS, never ANOMALY?"**
> "Thresholds are calibrated on measured distributions, not guessed: normal
> tops out at 25.7, attacks start at 70.4 and reach 84.5. ANOMALY (≥85) is
> deliberate headroom. A flag level I can defend beats a dramatic label I can't."

**"Isn't the sequence layer just a pile of rules?"**
> "Yes — four explicit rules, deliberately. A rule I can state is a rule a SOC
> can tune and argue with, and every alert names the exact event ids that fired
> it. It also fails in a way I can state: rename the private key, or pause more
> than five seconds between steps and let the session split, and it won't fire.
> The network has the complementary weakness — it can't see order at all."

**"How is this different from Falco / Wazuh / plain auditd?"**
> "auditd gives you events; Falco gives you rules; Wazuh gives you a SIEM. None
> of them tell you what *normal* looks like for these files. The added value
> here is the behavioural baseline, per-factor explanation, and the fact that I
> measure and report where it fails."

---

## 10. Appendix — where each claim lives in the code

Have these files open in an editor tab; jump to them if someone asks "show me".

| Claim | Where |
|---|---|
| Distinct-file session counting | `collector.py` → `ArtifactHandler._update_session` |
| Real-time scoring + alert sinks | `collector.py` → `_score_event` |
| Real-time chain detection | `collector.py` → `_check_chains` |
| Risk score = strongest weighted surprise | `ml/anomaly_detector.py` → `AnomalyDetector.score_event` |
| `session_size` 2× weight, calibrated thresholds | `ml/anomaly_detector.py` → `FACTOR_WEIGHTS`, `SURPRISE_FLOOR/CEIL`, `RISK_*` |
| Burst-vs-chain split evaluation | `ml/anomaly_detector.py` → `evaluate` branch |
| The four chain rules | `sequences.py` → `RULES` |
| Chain recall / FP measurement | `sequences.py` → `evaluate` |
| Syslog + webhook sinks | `alerts.py` → `emit`, `load_alert_config` |
| Realistic normal access types (why the SSH rule is quiet) | `ml/generate_test_events.py` → `NORMAL_PATH_ACCESS` |
| The low-and-slow chain attacks | `ml/generate_test_events.py` → `CHAIN_ATTACKS` |
| Kernel-level attribution + bounded retries | `auditd_integration.py` → `find_process_for_file`, `_query_audit` |
| Alert-sink configuration | `policy_v2.yaml` → `alerting:` |
| Live scoring failures are visible, not silent | `collector.py` → `_score_errors` branch in `_score_event` |
| Live events store the accessed file path | `collector.py` → `insert_event(artifact_path=src ...)` |
| Test coverage | `tests/` (81 tests) |

### What `demo.sh` actually checks

The script does not "look like" it worked — it reads the collector log it wrote
and asserts three things, then prints a pass/fail line for each:

| Check | How it is decided |
|---|---|
| Benign access stayed quiet | No `RISK ALERT` / `CHAIN ALERT` on the benign file's own event block |
| The chain was caught | At least one `CHAIN ALERT` in the log |
| The sweep was caught | At least one `RISK ALERT` in the log |

In `--self` mode it reads the log. In the two-terminal mode it instead walks
`collector.db` for sessions newer than five minutes and lists the rules that
fired in them — which works because live events are stored with their real file
paths, so the chain rules can match them after the fact.

### Why the demo order is chain-then-sweep

The collector resolves each event's process by shelling out to `ausearch`.
A 30-file sweep generates events faster than that can drain, and when the
handler falls behind, the kernel's inotify queue overflows and **drops events
silently**. Two fixes are already in place — the retry budget is bounded
(3 × 0.15s, was 5 × 0.5s) and `ausearch` uses `-ts recent` (a 10-minute window)
instead of `-ts today` (a log that grows all day, re-parsed per event). Running
the light chain scenario first keeps the handler clear for it. This is a real
scalability property, not a demo trick — and it's a good answer if someone
notices the pacing.
