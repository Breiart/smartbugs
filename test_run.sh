#!/usr/bin/env bash

# Precise wall-clock budgeting wrapper for SmartBugs runs, implemented entirely here.
# - Sends SIGINT at the target second to let SmartBugs/Docker perform cleanup.
# - Escalates to SIGKILL after a short grace to avoid lingering processes.
# - No changes to other files are required.

set -euo pipefail

# Default durations (seconds) if none are provided as args
DEFAULT_BUDGETS=(600 1200 1800 3600 7200)

# Default grace period (seconds) between SIGINT and SIGKILL
GRACE_SECONDS=10

usage() {
  cat <<EOF
Usage: $(basename "$0") [--grace N] [dur1 dur2 ...]

Examples:
  $(basename "$0") 300                # single 5-minute run
  $(basename "$0") --grace 15 600 900 # 10- and 15-minute runs, 15s grace

Notes:
  - Durations are wall-clock seconds.
  - Uses SIGINT for graceful cleanup; SIGKILL after grace if needed.
EOF
}

budgets=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage; exit 0;;
    --grace)
      [[ $# -ge 2 ]] || { echo "--grace requires a value" >&2; exit 2; }
      GRACE_SECONDS="$2"; shift 2;;
    --) shift; break;;
    -*) echo "Unknown option: $1" >&2; usage; exit 2;;
    *) budgets+=("$1"); shift;;
  esac
done

if [[ ${#budgets[@]} -eq 0 ]]; then
  budgets=("${DEFAULT_BUDGETS[@]}")
fi

# Prefer coreutils timeout if available; fall back to a Python watchdog that
# starts the child in a new process group and delivers SIGINT then SIGKILL.
find_timeout() {
  if command -v timeout >/dev/null 2>&1; then
    echo timeout
  elif command -v gtimeout >/dev/null 2>&1; then
    echo gtimeout
  else
    echo ""  # no timeout binary
  fi
}

run_with_deadline() {
  local seconds="$1"; shift
  local grace="$1"; shift

  local to_bin
  to_bin=$(find_timeout)
  if [[ -n "$to_bin" ]]; then
    # Use SIGINT to encourage Python finally-block cleanup in Docker runner
    # Exit code 124 indicates timeout in coreutils
    "$to_bin" -s INT -k "${grace}s" "${seconds}s" "$@"
    return $?
  else
    # Python fallback that sends SIGINT after N seconds, then SIGKILL after grace
    WALL_SEC="$seconds" WALL_GRACE="$grace" python3 - "$@" <<'PY'
import os, sys, time, signal, subprocess

sec = int(os.environ.get('WALL_SEC', '0'))
grace = int(os.environ.get('WALL_GRACE', '10'))
cmd = sys.argv[1:]

try:
    p = subprocess.Popen(cmd, preexec_fn=os.setsid)
except FileNotFoundError as e:
    print(f"Failed to start command: {e}", file=sys.stderr)
    sys.exit(127)

deadline = time.monotonic() + sec
while True:
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        rc = p.wait(timeout=remaining)
        sys.exit(rc)
    except subprocess.TimeoutExpired:
        break

# Try graceful stop first
try:
    os.killpg(p.pid, signal.SIGINT)
except ProcessLookupError:
    pass

try:
    rc = p.wait(timeout=grace)
    sys.exit(rc)
except subprocess.TimeoutExpired:
    pass

# Escalate
try:
    os.killpg(p.pid, signal.SIGKILL)
except ProcessLookupError:
    pass

try:
    rc = p.wait()
except Exception:
    rc = 137

# Mirror coreutils timeout semantics
if rc == 0:
    sys.exit(124)
sys.exit(124)
PY
    return $?
  fi
}

echo "Enforcing wall-clock limits in test_run.sh only"
echo "Grace period after SIGINT: ${GRACE_SECONDS}s"

for sec in "${budgets[@]}"; do
  echo
  echo "=== Starting run with target duration: ${sec}s ==="
  start_ts=$(date +%s)

  # Use SmartBugs' --time-budget for its own second-phase planning (advisory),
  # while this wrapper enforces the hard wall-clock limit.
  if ! run_with_deadline "${sec}" "${GRACE_SECONDS}" \
    ./smartbugs -t slither -f samples/Split1/* --time-budget "${sec}"; then
    exit_code=$?
  else
    exit_code=0
  fi

  end_ts=$(date +%s)
  elapsed=$(( end_ts - start_ts ))

  # Interpret coreutils-like timeout code 124 as "timed out"
  if [[ $exit_code -eq 124 ]]; then
    status="timeout"
  else
    status="exit ${exit_code}"
  fi
  echo "=== Run finished. Status: ${status}, Elapsed: ${elapsed}s (target: ${sec}s, grace: ${GRACE_SECONDS}s) ==="
done
