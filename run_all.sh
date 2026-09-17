#!/usr/bin/env bash
# =============================================================================
# run_all.sh — reset and rebuild the full demo state in one command.
#
# Usage:
#   ./run_all.sh              # standard rebuild (seed 42) + live smoke test
#   ./run_all.sh --skip-live  # skip the live collector smoke test
#
# Safe to re-run at any time. Restores the project to the exact state
# documented in README.md / SESSION_SUMMARY.txt.
# =============================================================================

set -euo pipefail

SEED=42
PYTHONPYCACHEPREFIX=/tmp/pycache
PY="env PYTHONPYCACHEPREFIX=$PYTHONPYCACHEPREFIX venv/bin/python"

PASS=0
FAIL=0

step()      { echo -e "\n\033[1m==> $1\033[0m"; }
ok()        { echo -e "  \033[32m✓ $1\033[0m";  PASS=$((PASS+1)); }
fail()      { echo -e "  \033[31m✗ $1\033[0m";  FAIL=$((FAIL+1)); }
fail_exit() { fail "$1"; echo -e "\n\033[31mABORTED at: $1\033[0m"; exit 1; }

SKIP_LIVE=false
[[ "${1:-}" == "--skip-live" ]] && SKIP_LIVE=true

cd "$(dirname "$0")"

[[ -x venv/bin/python ]] || fail_exit "venv not found — run: python3 -m venv venv && venv/bin/pip install -r requirements.txt"

# -----------------------------------------------------------------------------
step "1/8  Unit test suite"
# -----------------------------------------------------------------------------
# `|| true` keeps `set -e` from aborting before we can report which test failed.
TEST_OUT=$($PY -m unittest discover -s tests -t . 2>&1 || true)
echo "$TEST_OUT" | grep -E "^(Ran |OK|FAILED)" | sed 's/^/  /'
if echo "$TEST_OUT" | grep -q "^OK"; then
    ok "unit tests passed"
else
    echo "$TEST_OUT" | tail -30 | sed 's/^/    /'
    fail_exit "unit tests failed — run: python -m unittest discover -s tests -t ."
fi

# -----------------------------------------------------------------------------
step "2/8  Environment check"
# -----------------------------------------------------------------------------
$PY -m py_compile db.py collector.py baseline.py proc_scanner.py \
    auditd_integration.py artifact_scan.py \
    ml/anomaly_detector.py ml/generate_test_events.py \
    && ok "all 8 modules compile" || fail_exit "syntax error in a module"

$PY -c "import yaml, watchdog, pgmpy" \
    && ok "dependencies import (yaml, watchdog, pgmpy)" \
    || fail_exit "missing dependency — run: venv/bin/pip install -r requirements.txt"

$PY db.py > /dev/null && ok "DB schema initialized" || fail_exit "db.py failed"

# -----------------------------------------------------------------------------
step "3/8  Fresh seeded dataset (seed $SEED)"
# -----------------------------------------------------------------------------
$PY -c "
from db import get_conn
c = get_conn(); c.execute('DELETE FROM events'); c.execute('DELETE FROM baseline'); c.commit(); c.close()
"
$PY ml/generate_test_events.py --seed "$SEED" | tail -3

COUNTS=$($PY -c "
from db import get_conn
c = get_conn()
def n(where):
    return c.execute(f'SELECT COUNT(*) FROM events WHERE {where}').fetchone()[0]
total  = n('1=1')
normal = n(\"session_id LIKE 'normal_%'\")
burst  = n(\"session_id LIKE 'attack_burst_%'\")
chain  = n(\"session_id LIKE 'attack_chain_%'\")
other  = total - normal - burst - chain
print(f'{total} {normal} {burst} {chain} {other}')
c.close()
")
read -r TOTAL NORMAL BURST CHAIN OTHER <<< "$COUNTS"
[[ "$TOTAL" == "660" && "$NORMAL" == "400" && "$BURST" == "180" && "$CHAIN" == "80" && "$OTHER" == "0" ]] \
    && ok "dataset: 660 events (400 normal / 180 burst / 80 chain)" \
    || fail_exit "unexpected dataset: total=$TOTAL normal=$NORMAL burst=$BURST chain=$CHAIN unlabeled=$OTHER"

# -----------------------------------------------------------------------------
step "4/8  Baseline"
# -----------------------------------------------------------------------------
BASELINE_OUT=$($PY baseline.py 2>&1)
PROFILES=$(echo "$BASELINE_OUT" | grep -oP 'Profiles built:\s+\K\d+' || echo 0)
[[ "$PROFILES" -gt 0 ]] && ok "baseline computed: $PROFILES profiles" \
                        || fail_exit "baseline built 0 profiles"

# -----------------------------------------------------------------------------
step "5/8  Train + evaluate anomaly model"
# -----------------------------------------------------------------------------
TRAIN_OUT=$($PY ml/anomaly_detector.py train 2>&1)
TRAINED=$(echo "$TRAIN_OUT" | grep -oP 'Events:\s+\K\d+' || echo 0)
[[ "$TRAINED" == "400" ]] && ok "model trained on 400 normal events" \
                          || fail_exit "expected to train on 400 events, got $TRAINED"

EVAL_OUT=$($PY ml/anomaly_detector.py evaluate 2>/dev/null)
ALL_1000=$(echo "$EVAL_OUT" | grep -c "1\.000" || true)
[[ "$ALL_1000" == "4" ]] && ok "evaluate: Precision/Recall/F1/Accuracy all 1.000" \
                         || fail_exit "metrics regressed — run: python ml/anomaly_detector.py evaluate"

SCORE_OUT=$($PY ml/anomaly_detector.py score-all --report 2>/dev/null)
FLAGGED=$(echo "$SCORE_OUT" | grep -oP 'Flagged events \(\K\d+' || echo 0)
ALERTS=$($PY -c "import json; print(len(json.load(open('alerts.json'))['alerts']))")
[[ "$FLAGGED" == "180" && "$ALERTS" == "180" ]] \
    && ok "score-all: 180 attacks flagged, alerts.json valid (180 alerts)" \
    || fail_exit "flagging mismatch: flagged=$FLAGGED alerts.json=$ALERTS"

# -----------------------------------------------------------------------------
step "6/8  Sequence (chain) layer"
# -----------------------------------------------------------------------------
BN_CHAIN=$($PY ml/anomaly_detector.py evaluate 2>/dev/null | grep -oP 'BN alone:\s+\K[0-9]+/[0-9]+' || echo "?")
SEQ_OUT=$($PY sequences.py --evaluate 2>/dev/null)
CHAIN_HIT=$(echo "$SEQ_OUT" | grep -oP 'Chain sessions:\s+\K[0-9]+/[0-9]+' || echo "?")
SEQ_FP=$(echo "$SEQ_OUT" | grep -oP 'Normal sessions:\s+\K[0-9]+' || echo "?")
[[ "$CHAIN_HIT" == "20/20" && "$SEQ_FP" == "0" ]] \
    && ok "sequence layer: $CHAIN_HIT chain sessions caught, $SEQ_FP false positives (BN alone: $BN_CHAIN)" \
    || fail_exit "sequence layer regressed: chain=$CHAIN_HIT fp=$SEQ_FP"

# -----------------------------------------------------------------------------
step "7/8  Live smoke test (collector + real-time scoring)"
# -----------------------------------------------------------------------------
if $SKIP_LIVE; then
    echo "  (skipped — --skip-live)"
else
    mkdir -p ~/.azure
    # Launch via subshell with `trap - INT`: background jobs in non-interactive
    # bash inherit SIGINT ignored, which would make `kill -INT` a no-op and
    # hang the wait below. Resetting the disposition lets the collector's
    # KeyboardInterrupt handler run so audit rules are cleaned up on exit.
    ( trap - INT; exec env PYTHONPYCACHEPREFIX=$PYTHONPYCACHEPREFIX venv/bin/python collector.py ) > /tmp/collector_test.log 2>&1 &
    COLLECTOR_PID=$!
    sleep 6

    grep -q "Real-time scoring enabled" /tmp/collector_test.log \
        && ok "collector started with real-time scoring" \
        || { kill $COLLECTOR_PID 2>/dev/null; fail_exit "collector did not enable real-time scoring (see /tmp/collector_test.log)"; }

    # (a) Benign single-file access must stay quiet — low-false-positive guard.
    #     A shell redirect emits a sub-second cluster of events on ONE file,
    #     which must not read as a credential sweep.
    echo benign > ~/.azure/.smoke_runall_normal
    sleep 3

    # (b) A multi-step chain no single event would flag: a private key is
    #     touched, then authorized_keys is modified — the classic backdoor.
    #     Only the sequence layer can see this. Run it BEFORE the sweep: every
    #     event costs an `ausearch` call, and a still-busy handler would make
    #     the kernel drop these events.
    touch ~/.azure/id_rsa
    sleep 3
    echo attacker >> ~/.azure/authorized_keys
    sleep 4

    # (c) A credential sweep touches MANY distinct files quickly. The model
    #     only escalates once the distinct-file count exceeds the normal
    #     session size (>5), so 12 files is plenty to cross the line.
    for i in $(seq 1 12); do
        touch ~/.azure/.smoke_runall_$i
        sleep 0.15
    done
    sleep 8
    kill -INT $COLLECTOR_PID 2>/dev/null
    # Bounded shutdown: give the collector up to 10s to exit gracefully
    # (SIGINT -> KeyboardInterrupt -> audit rules removed), then force-kill.
    for _ in $(seq 1 10); do
        kill -0 $COLLECTOR_PID 2>/dev/null || break
        sleep 1
    done
    if kill -0 $COLLECTOR_PID 2>/dev/null; then
        kill -TERM $COLLECTOR_PID 2>/dev/null
        sleep 1
    fi
    wait $COLLECTOR_PID 2>/dev/null || true

    # `|| true` avoids the "0\n0" trap: grep -c prints 0 AND exits non-zero.
    EVENTS=$(grep -c "Event #" /tmp/collector_test.log || true)
    ALERTS_LOG=$(grep -c "RISK ALERT" /tmp/collector_test.log || true)
    [[ "$EVENTS" -ge 20 && "$ALERTS_LOG" -ge 1 ]] \
        && ok "live test: $EVENTS events captured, $ALERTS_LOG RISK ALERTs (log: /tmp/collector_test.log)" \
        || fail "live test produced $EVENTS events / $ALERTS_LOG alerts — inspect /tmp/collector_test.log"

    # The benign single-file access above must not have raised any alert.
    BENIGN_ALERTS=$(awk '/Event #/{f = ($0 ~ /smoke_runall_normal/); next} f && /RISK ALERT/{n++} END{print n+0}' /tmp/collector_test.log)
    [[ "$BENIGN_ALERTS" == "0" ]] \
        && ok "live test: benign single-file access produced 0 false-positive alerts" \
        || fail "live test: benign access raised $BENIGN_ALERTS false-positive alert(s)"

    # The multi-step sequence above must raise a chain alert in real time.
    CHAIN_ALERTS=$(grep -c "CHAIN ALERT" /tmp/collector_test.log || true)
    [[ "$CHAIN_ALERTS" -ge 1 ]] \
        && ok "live test: $CHAIN_ALERTS CHAIN ALERT(s) from the multi-step sequence" \
        || fail "live test: the ssh_key_injection sequence raised no CHAIN ALERT"

    # Cleanup: remove smoke-test rows so the labeled dataset stays pristine
    CLEANED=$($PY -c "
from db import get_conn
c = get_conn()
n = c.execute(\"DELETE FROM events WHERE artifact_path LIKE '%/.smoke_runall_%' OR artifact_path LIKE '%/smoke_runall_%' OR session_id NOT LIKE 'normal_%' AND session_id NOT LIKE 'attack_%'\").rowcount
c.commit()
total = c.execute('SELECT COUNT(*) FROM events').fetchone()[0]
attack = c.execute(\"SELECT COUNT(*) FROM events WHERE session_id LIKE 'attack_%'\").fetchone()[0]
print(f'{n} {total} {attack}')
c.close()
")
    read -r DELETED TOTAL2 ATTACK2 <<< "$CLEANED"

    # Remove the scratch files the smoke test created on disk
    rm -f ~/.azure/.smoke_runall_normal ~/.azure/.smoke_runall_* \
          ~/.azure/id_rsa ~/.azure/authorized_keys
    [[ "$TOTAL2" == "660" && "$ATTACK2" == "260" ]] \
        && ok "cleanup: removed $DELETED smoke rows, dataset back to 660/260" \
        || fail_exit "cleanup failed: total=$TOTAL2 attack=$ATTACK2 — wipe and rebuild with ./run_all.sh"
fi

# -----------------------------------------------------------------------------
step "8/8  Final state"
# -----------------------------------------------------------------------------
$PY ml/anomaly_detector.py evaluate 2>/dev/null | grep -E "Precision|Recall|F1|Accuracy" | sed 's/^/  /'

echo -e "\n=============================================="
if [[ "$FAIL" == "0" ]]; then
    echo -e "\033[32mALL CHECKS PASSED ($PASS steps)\033[0m — demo state ready."
else
    echo -e "\033[31m$FAIL check(s) failed, $PASS passed.\033[0m"
    exit 1
fi
echo "  Live demo:      python collector.py   (terminal 1)"
echo "  Trigger event:  echo test >> ~/.azure/config   (terminal 2)"
echo "=============================================="
