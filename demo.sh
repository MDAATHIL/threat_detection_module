#!/usr/bin/env bash
# =============================================================================
# demo.sh — the live demo from DEMO_RUNBOOK.md §4, as a single command.
#
# Fires the three scenarios in the order that works, with presenter-friendly
# pacing, and always cleans up after itself:
#
#   (1) normal access    -> must stay quiet      (risk: NORMAL)
#   (2) multi-step chain -> CHAIN ALERT          (order, not statistics)
#   (3) credential sweep -> RISK ALERT           (the statistical layer)
#
# The chain runs BEFORE the sweep on purpose. Every event costs an `ausearch`
# call; burying the handler lets the kernel's inotify queue overflow and drop
# events silently. See DEMO_RUNBOOK.md §10 for the full explanation.
#
# Usage:
#   ./demo.sh                 # collector already running in another terminal
#   ./demo.sh --self          # this script starts and stops the collector
#   ./demo.sh --with-metrics  # print batch metrics first (run BEFORE live)
#   ./demo.sh --fast          # shorter waits + smaller sweep (rehearsal)
#   ./demo.sh --help
#
# Only touches scratch files inside ~/.azure; your real credentials are never
# read, written, or deleted.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

ARTIFACT_DIR="$HOME/.azure"
BENIGN_FILE="$ARTIFACT_DIR/.demo_normal"
KEY_FILE="$ARTIFACT_DIR/id_rsa"          # basename is what the chain rule matches
AUTH_FILE="$ARTIFACT_DIR/authorized_keys"
SWEEP_PREFIX="$ARTIFACT_DIR/.sneaky_"
SWEEP_COUNT=30
DRAIN_SECONDS=15

COLLECTOR_LOG="${DEMO_COLLECTOR_LOG:-/tmp/demo_collector.log}"

# Everything this script creates. Registered before the first scenario runs so
# cleanup can tell our scratch files apart from anything that was already there.
SCRATCH_FILES=("$BENIGN_FILE" "$KEY_FILE" "$AUTH_FILE")
PREEXISTING=""

snapshot_scratch() {
    local f
    for f in "${SCRATCH_FILES[@]}" "$SWEEP_PREFIX"*; do
        [[ -e "$f" ]] && PREEXISTING="$PREEXISTING$f"$'\n'
    done
    return 0
}

was_preexisting() { [[ "$PREEXISTING" == *"$1"$'\n'* ]]; }

SELF_MODE=false
FAST=false
WITH_METRICS=false
DEMO_RAN=false
COLLECTOR_PID=""

PY="python3"
[[ -x "venv/bin/python" ]] && PY="venv/bin/python"

# --------------------------------------------------------------------------- #
# Presentation helpers
# --------------------------------------------------------------------------- #

if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; RED=$'\033[31m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; GREEN=""; YELLOW=""; RED=""; CYAN=""; RESET=""
fi

stage() { echo; echo "${BOLD}${CYAN}=== $* ===${RESET}"; }
say()   { echo "${DIM}    $*${RESET}"; }
ok()    { echo "  ${GREEN}✓${RESET} $*"; }
warn()  { echo "  ${YELLOW}!${RESET} $*"; }
bad()   { echo "  ${RED}✗${RESET} $*"; }

usage() {
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

# A visible countdown so the presenter knows exactly when the next action fires.
pause() {
    local secs="${1:-3}"
    while [[ "$secs" -gt 0 ]]; do
        printf "\r${DIM}    ... next action in %2ds ${RESET}" "$secs"
        sleep 1
        secs=$((secs - 1))
    done
    printf "\r\033[K"
}

# Narration pause — shortened in --fast mode (which is why the audit-drain wait
# below uses `pause` directly instead: it must stay long enough to work).
nap() {
    local secs="${1:-3}"
    if $FAST && [[ "$secs" -gt 3 ]]; then
        secs=3
    fi
    pause "$secs"
}

# --------------------------------------------------------------------------- #
# Collector lifecycle
# --------------------------------------------------------------------------- #

stop_collector() {
    [[ -z "$COLLECTOR_PID" ]] && return 0
    if kill -0 "$COLLECTOR_PID" 2>/dev/null; then
        kill -INT "$COLLECTOR_PID" 2>/dev/null || true
        for _ in $(seq 1 10); do
            kill -0 "$COLLECTOR_PID" 2>/dev/null || break
            sleep 1
        done
        kill -TERM "$COLLECTOR_PID" 2>/dev/null || true
    fi
    COLLECTOR_PID=""
}

cleanup() {
    stop_collector
    # Remove only what we created. A file that existed before this run is never
    # touched — so a real ~/.azure/authorized_keys cannot be deleted by cleanup.
    local f kept=""
    for f in "${SCRATCH_FILES[@]}" "$SWEEP_PREFIX"*; do
        [[ -e "$f" ]] || continue
        if was_preexisting "$f"; then
            kept="$kept $f"
        else
            rm -f "$f" 2>/dev/null || true
        fi
    done
    # Reported here rather than in main so the message cannot outrun cleanup.
    if $DEMO_RAN; then
        if [[ -n "$kept" ]]; then
            ok "scratch files removed — pre-existing files left alone:$kept"
        else
            ok "scratch files removed"
        fi
    fi
}
# Files are removed even if the presenter hits Ctrl+C mid-demo.
trap cleanup EXIT

start_collector() {
    : > "$COLLECTOR_LOG"
    # `trap - INT` so the background job does not inherit an ignored SIGINT,
    # which would make our clean shutdown a no-op.
    ( trap - INT; exec "$PY" collector.py ) > "$COLLECTOR_LOG" 2>&1 &
    COLLECTOR_PID=$!

    for _ in $(seq 1 40); do
        grep -q "Collector started" "$COLLECTOR_LOG" 2>/dev/null && return 0
        kill -0 "$COLLECTOR_PID" 2>/dev/null || return 1
        sleep 0.5
    done
    return 1
}

collector_is_running() {
    pgrep -f "collector\.py" >/dev/null 2>&1
}

# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #

scenario_normal() {
    stage "1/3  Normal access — must stay quiet"
    say "One file, one append. Several inotify events, a one-file session."
    echo "test" >> "$BENIGN_FILE"
    say "expect:  risk: NORMAL   (no alert)"
    nap 4
}

scenario_chain() {
    stage "2/3  The chain — order, not statistics"
    say "touch a private key, wait, then append to authorized_keys."
    touch "$KEY_FILE"
    nap 3
    echo "attacker" >> "$AUTH_FILE"
    say "expect:  CHAIN ALERT: SSH_KEY_INJECTION [HIGH]  (events=[...])"
    nap 5
}

scenario_sweep() {
    stage "3/3  The sweep — the statistical layer"
    say "$SWEEP_COUNT distinct credential files, touched quickly."
    local i
    for i in $(seq 1 "$SWEEP_COUNT"); do
        touch "${SWEEP_PREFIX}${i}"
        sleep 0.15
    done
    say "expect:  RISK ALERT: SUSPICIOUS (risk ~70–85) streaming in"

    # Never shortened below the point where the alerts actually appear.
    local drain="$DRAIN_SECONDS"
    if $FAST; then drain=8; fi
    say "draining the audit queue — let the alerts scroll while you narrate."
    pause "$drain"
}

# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #

show_batch_metrics() {
    stage "Batch metrics — run BEFORE any live events"
    say "Live events land in the same collector.db and would skew the labels."
    echo
    "$PY" ml/anomaly_detector.py evaluate 2>/dev/null
    echo
    "$PY" sequences.py --evaluate 2>/dev/null
}

# Reads the collector log when this script owns the collector.
verify_from_log() {
    [[ -f "$COLLECTOR_LOG" ]] || return 0

    local events chains risks benign_alerts
    events=$(grep -c "Event #" "$COLLECTOR_LOG" || true)
    chains=$(grep -c "CHAIN ALERT" "$COLLECTOR_LOG" || true)
    risks=$(grep -c "RISK ALERT" "$COLLECTOR_LOG" || true)
    # Alerts that fired on the benign file's own event lines.
    benign_alerts=$(awk '/Event #/{f = ($0 ~ /\.demo_normal/); next}
                         f && /RISK ALERT|CHAIN ALERT/{n++} END{print n+0}' \
                         "$COLLECTOR_LOG")

    stage "Result"
    echo "  events captured:        $events"
    echo "  RISK ALERTs:            $risks"
    echo "  CHAIN ALERTs:           $chains"
    echo "  false positives (benign): $benign_alerts"
    echo

    [[ "$benign_alerts" == "0" ]] \
        && ok "benign access stayed quiet" \
        || bad "benign access raised $benign_alerts false-positive alert(s)"
    [[ "$chains" -ge 1 ]] \
        && ok "the multi-step chain was caught" \
        || bad "no CHAIN ALERT — see $COLLECTOR_LOG"
    [[ "$risks" -ge 1 ]] \
        && ok "the credential sweep was caught" \
        || bad "no RISK ALERT — see $COLLECTOR_LOG"
}

# Works whether or not this script owns the collector, because the live events
# are in the database either way.
verify_from_db() {
    "$PY" - <<'PYEOF'
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, ".")
import sequences

cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp()
recent, rules = 0, set()
for session_id, events in sequences.sessions_from_db().items():
    if session_id.startswith(("normal_", "attack_")):
        continue
    times = [e.t for e in events if e.t is not None]
    if not times or max(times) < cutoff:
        continue
    recent += 1
    for match in sequences.detect_chains(events):
        rules.add(match.rule)

print(f"  live sessions from this run:  {recent}")
print("  chains found in them:        " + (", ".join(sorted(rules)) or "none"))
PYEOF
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

for arg in "$@"; do
    case "$arg" in
        --self|-s)      SELF_MODE=true ;;
        --fast|-f)      FAST=true ;;
        --with-metrics) WITH_METRICS=true ;;
        --help|-h)      usage ;;
        *) echo "Unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done

if $FAST; then
    SWEEP_COUNT=12
fi

mkdir -p "$ARTIFACT_DIR"
snapshot_scratch

echo "${BOLD}Live demo — benign → chain → sweep${RESET}"
if $FAST; then warn "fast mode: shortened waits"; fi

echo
if $SELF_MODE; then
    say "starting the collector (this takes a few seconds)..."
    if start_collector; then
        ok "collector started (pid $COLLECTOR_PID) — log: $COLLECTOR_LOG"
    else
        bad "collector failed to start — log: $COLLECTOR_LOG"
        tail -5 "$COLLECTOR_LOG" 2>/dev/null || true
        exit 1
    fi
else
    if collector_is_running; then
        ok "using the collector already running in your other terminal"
    else
        bad "no collector is running."
        say "Start one in another terminal:  $PY collector.py"
        say "…or run this script self-contained:  ./demo.sh --self"
        exit 1
    fi
fi

if $WITH_METRICS; then
    show_batch_metrics
fi

DEMO_RAN=true
scenario_normal
scenario_chain
scenario_sweep

echo
if $SELF_MODE; then
    verify_from_log
    say "stopping the collector..."
    stop_collector
else
    stage "Result"
    say "check your collector terminal — you should see:"
    echo "    4× risk: NORMAL"
    echo "    1× CHAIN ALERT: SSH_KEY_INJECTION [HIGH]"
    echo "    a run of RISK ALERT: SUSPICIOUS"
    echo
    verify_from_db
fi

echo
warn "the demo wrote live events into collector.db — restore the seeded state with:"
echo "      ./run_all.sh --skip-live"
