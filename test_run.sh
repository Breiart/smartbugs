#!/bin/bash

set -euo pipefail

#
# Timed test cases
# 1) 10 minutes, then send Ctrl+C (SIGINT) to the running command
# 2) 20 minutes
# 3) 30 minutes
# 4) 1 hour
# 5) 2 hours
#
# Notes:
# - By default, these tests run a long sleep as the workload so their
#   duration is controlled precisely. You can change the command by setting
#   the CMD array below (e.g., to run smartbugs or another workload).
# - We send SIGINT (Ctrl+C) only for Test #1 as requested; the others are
#   stopped with SIGTERM at their time limit.
#

# Default long-running command (can be customized)
# Example to run smartbugs instead:
#   CMD=( ./smartbugs -t slither -f samples/OriginalSamples/* )
CMD=( sleep 2147483647 )
# If the script is invoked with arguments, use them as the command
if [[ $# -gt 0 ]]; then
  CMD=( "$@" )
fi

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }

# Send a signal to a process group (fallback to PID if needed)
SELF_PGID=$(ps -o pgid= -p "$$" | tr -d ' ')

send_signal() {
  local pid="$1" pgid="$2" sig="$3"
  # Prefer signaling the child's process group if it's distinct from ours.
  if [[ -n "${pgid}" && "${pgid}" != "${SELF_PGID}" ]]; then
    kill -s "${sig}" "-${pgid}" 2>/dev/null || kill -s "${sig}" "${pid}" 2>/dev/null || true
  else
    kill -s "${sig}" "${pid}" 2>/dev/null || true
  fi
}

run_test() {
  local name="$1" duration_secs="$2" sig_on_timeout="$3"
  shift 3
  local -a cmd=("$@")

  log "Starting ${name} for ${duration_secs}s: ${cmd[*]}"

  # Start the command in background
  "${cmd[@]}" &
  local pid=$!

  # Obtain the process group id of the child
  local pgid; pgid=$(ps -o pgid= -p "$pid" | tr -d ' ')
  pgid=${pgid:-$pid}

  # Expose current child IDs for trap forwarding
  CURRENT_PID="$pid"
  CURRENT_PGID="$pgid"

  log "${name} started (PID=${pid}, PGID=${pgid})"

  # Sleep for the requested duration, then signal if still running
  sleep "$duration_secs"
  if kill -0 "$pid" 2>/dev/null; then
    if [[ -n "$sig_on_timeout" ]]; then
      log "${name} time elapsed. Sending SIG${sig_on_timeout}."
      send_signal "$pid" "$pgid" "$sig_on_timeout"
    fi
  fi

  # Wait for the process to terminate (ignore exit code)
  wait "$pid" 2>/dev/null || true
  log "${name} finished."
}

# Trap Ctrl+C on the script and forward to the running test, if any
CURRENT_PID=""; CURRENT_PGID=""
trap 'if [[ -n "$CURRENT_PID" ]]; then log "Script caught Ctrl+C. Forwarding to running test."; send_signal "$CURRENT_PID" "$CURRENT_PGID" INT; fi' INT

# Test definitions (durations in seconds)
TEN_MIN=$((10*60))
TWENTY_MIN=$((20*60))
THIRTY_MIN=$((30*60))
ONE_HOUR=$((60*60))
TWO_HOURS=$((2*60*60))

# Run tests sequentially

# Test #1: 10 minutes, then simulate Ctrl+C (SIGINT)
CURRENT_PGID=""
run_test "Test #1 (10m, Ctrl+C)" "$TEN_MIN" INT "${CMD[@]}"

# Test #2: 20 minutes (terminate at time limit)
CURRENT_PGID=""
run_test "Test #2 (20m)" "$TWENTY_MIN" TERM "${CMD[@]}"

# Test #3: 30 minutes (terminate at time limit)
CURRENT_PGID=""
run_test "Test #3 (30m)" "$THIRTY_MIN" TERM "${CMD[@]}"

# Test #4: 1 hour (terminate at time limit)
CURRENT_PGID=""
run_test "Test #4 (1h)" "$ONE_HOUR" TERM "${CMD[@]}"

# Test #5: 2 hours (terminate at time limit)
CURRENT_PGID=""
run_test "Test #5 (2h)" "$TWO_HOURS" TERM "${CMD[@]}"

log "All timed tests completed."
