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
step "1/6  Environment check"
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
step "2/6  Fresh seeded dataset (seed $SEED)"
# -----------------------------------------------------------------------------
$PY -c "
from db import get_conn
c = get_conn(); c.execute('DELETE FROM events'); c.execute('DELETE FROM baseline'); c.commit(); c.close()
"
$PY ml/generate_test_events.py --seed "$SEED" | tail -3

COUNTS=$($PY -c "
from db import get_conn
c = get_conn()
total   = c.execute('SELECT COUNT(*) FROM events').fetchone()[0]
normal  = c.execute(\"SELECT COUNT(*) FROM events WHERE session_id LIKE 'normal_%'\").fetchone()[0]
attack  = c.execute(\"SELECT COUNT(*) FROM events WHERE session_id LIKE 'attack_%'\").fetchone()[0]
other   = total - normal - attack
print(f'{total} {normal} {attack} {other}')
c.close()
")
read -r TOTAL NORMAL ATTACK OTHER <<< "$COUNTS"
[[ "$TOTAL" == "580" && "$NORMAL" == "400" && "$ATTACK" == "180" && "$OTHER" == "0" ]] \
    && ok "dataset: 580 events (400 normal / 180 attack / 0 unlabeled)" \
    || fail_exit "unexpected dataset: total=$TOTAL normal=$NORMAL attack=$OTHER unlabeled=$OTHER"

# -----------------------------------------------------------------------------
step "3/6  Baseline"
# -----------------------------------------------------------------------------
BASELINE_OUT=$($PY baseline.py 2>&1)
PROFILES=$(echo "$BASELINE_OUT" | grep -oP 'Profiles built:\s+\K\d+' || echo 0)
[[ "$PROFILES" -gt 0 ]] && ok "baseline computed: $PROFILES profiles" \
                        || fail_exit "baseline built 0 profiles"

# -----------------------------------------------------------------------------
step "4/6  Train + evaluate anomaly model"
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
step "5/6  Live smoke test (collector + real-time scoring)"
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

    for i in 1 2 3 4 5; do
        touch ~/.azure/.smoke_runall_$i
        sleep 0.2
        rm -f ~/.azure/.smoke_runall_$i
    done
    sleep 5
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

    EVENTS=$(grep -c "Event #" /tmp/collector_test.log || echo 0)
    ALERTS_LOG=$(grep -c "RISK ALERT" /tmp/collector_test.log || echo 0)
    [[ "$EVENTS" -ge 5 && "$ALERTS_LOG" -ge 1 ]] \
        && ok "live test: $EVENTS events captured, $ALERTS_LOG RISK ALERTs (log: /tmp/collector_test.log)" \
        || fail "live test produced $EVENTS events / $ALERTS_LOG alerts — inspect /tmp/collector_test.log"

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
    [[ "$TOTAL2" == "580" && "$ATTACK2" == "180" ]] \
        && ok "cleanup: removed $DELETED smoke rows, dataset back to 580/180" \
        || fail_exit "cleanup failed: total=$TOTAL2 attack=$ATTACK2 — wipe and rebuild with ./run_all.sh"
fi

# -----------------------------------------------------------------------------
step "6/6  Final state"
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
