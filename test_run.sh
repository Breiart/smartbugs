#!/bin/bash

# Run the first command 5 times with different time budgets,
# measuring runtime and sending Ctrl+C (SIGINT) exactly at the limit.

set -u

run_with_interrupt() {
  local duration_sec=$1
  shift
  # Command to run (as separate args)
  local cmd=("$@")

  echo "\n=== Starting run with budget: ${duration_sec}s ==="
  echo "Command: ${cmd[*]}"

  local start_ts end_ts elapsed

  start_ts=$(date +%s)

  # Start command in background
  "${cmd[@]}" &
  local cmd_pid=$!

  # Determine process group ID to send SIGINT to the whole group
  local pgid
  pgid=$(ps -o pgid= "${cmd_pid}" | tr -d ' ')

  # Safety: if we couldn't get a PGID, fall back to the PID
  if [[ -z "${pgid}" ]]; then
    pgid=${cmd_pid}
  fi

  # Timer that sends Ctrl+C (SIGINT) to the process group right at the limit
  (
    sleep "${duration_sec}"
    echo "[Timer] Budget reached (${duration_sec}s). Sending Ctrl+C..."
    # Send SIGINT to the whole process group if possible, else to the pid
    kill -INT -"${pgid}" 2>/dev/null || kill -INT "${cmd_pid}" 2>/dev/null || true
  ) &
  local timer_pid=$!

  # When this script receives Ctrl+C, forward it and cleanup timer
  trap 'kill -INT -"${pgid}" 2>/dev/null || kill -INT "${cmd_pid}" 2>/dev/null; kill "${timer_pid}" 2>/dev/null; wait "${cmd_pid}" 2>/dev/null; exit 130' INT

  # Wait for the command to finish
  wait "${cmd_pid}"
  local exit_code=$?

  # Stop timer if still running
  kill "${timer_pid}" 2>/dev/null || true
  wait "${timer_pid}" 2>/dev/null || true

  end_ts=$(date +%s)
  elapsed=$(( end_ts - start_ts ))

  echo "=== Run finished. Exit: ${exit_code}, Elapsed: ${elapsed}s ===\n"
  return ${exit_code}
}

# Time budgets in seconds: 10, 20, 30, 60, 120 minutes
budgets=(600 1200 1800 3600 7200)

for sec in "${budgets[@]}"; do
  # Build the base command (repeat the first command with varying --time-budget)
  run_with_interrupt "${sec}" \
    ./smartbugs -t slither -f samples/Split1/* --time-budget "${sec}"
done
