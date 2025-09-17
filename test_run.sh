#!/bin/bash

#!/bin/bash

# Run SmartBugs 5 times with exact wall-clock limits using the new --max-duration.
# This avoids external signals that can cause segfaults inside child tools.

set -euo pipefail

if [[ $# -gt 0 ]]; then
  budgets=("$@")
else
  budgets=(600 1200 1800 3600 7200)
fi

echo "Using internal wall-clock limits via --max-duration"
for sec in "${budgets[@]}"; do
  echo
  echo "=== Starting run with target duration: ${sec}s ==="
  start_ts=$(date +%s)
  # Pass both: --time-budget to plan second-phase work and --max-duration to enforce total wall time
  ./smartbugs -t slither -f samples/Split1/* --time-budget "${sec}" --max-duration "${sec}"
  exit_code=$?
  end_ts=$(date +%s)
  elapsed=$(( end_ts - start_ts ))
  echo "=== Run finished. Exit: ${exit_code}, Elapsed: ${elapsed}s (target: ${sec}s) ==="
done
