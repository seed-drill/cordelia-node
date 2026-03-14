#!/bin/bash
# Run all topology E2E tests sequentially.
# Usage: ./run-all.sh [t1 t2 t3 ...] (defaults to all)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS="${@:-t1 t2 t3 t4 t5 t6 t7}"

PASS=0
FAIL=0

# Flush kernel conntrack table between runs to prevent stale UDP flow
# entries from interfering with QUIC connections (BV-23).
# Requires: sudo apt-get install conntrack
# Requires: sysctl net.netfilter.nf_conntrack_udp_timeout=10
#           sysctl net.netfilter.nf_conntrack_udp_timeout_stream=30
flush_conntrack() {
    sudo conntrack -F 2>/dev/null || true
}

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
    flush_conntrack
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
