#!/bin/bash
# Run all topology E2E tests sequentially.
# Usage: ./run-all.sh [t1 t2 t3 ...] (defaults to all)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS="${@:-t1 t2 t3 t4 t5 t6 t7}"

PASS=0
FAIL=0

for t in $TESTS; do
    SCRIPT="$SCRIPT_DIR/run-${t}.sh"
    if [ ! -x "$SCRIPT" ]; then
        echo "SKIP: $SCRIPT not found or not executable"
        continue
    fi
    echo ""
    echo "================================================================"
    echo "  Running $t"
    echo "================================================================"
    if bash "$SCRIPT"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "  $t FAILED"
    fi
done

echo ""
echo "================================================================"
echo "  OVERALL: $PASS passed, $FAIL failed out of $((PASS + FAIL))"
echo "================================================================"

[ "$FAIL" -eq 0 ]
