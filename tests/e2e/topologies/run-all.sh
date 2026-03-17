#!/bin/bash
# Run all topology E2E tests sequentially.
# Usage: ./run-all.sh [t1 t2 t3 ...] (defaults to all)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS="${@:-t1 t2 t3 t4 t5 t6 t7}"

PASS=0
FAIL=0

E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Clean root-owned artifacts from previous runs (containers write as root)
echo "Cleaning previous run artifacts..."
sudo rm -rf "$E2E_DIR/keys" "$E2E_DIR/logs" "$E2E_DIR/scale/keys" 2>/dev/null || true
for t in $TESTS; do
    docker compose -f "$SCRIPT_DIR/${t}.yml" down --volumes 2>/dev/null || true
done

# Pre-flight: verify Docker image is fresh (not stale from previous build)
# Cordelia lesson: spent hours debugging "missing feature" that was a stale image.
REPO_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BINARY="$REPO_DIR/target/x86_64-unknown-linux-musl/release/cordelia"
if [ -f "$BINARY" ]; then
    BINARY_TIME=$(stat -c %Y "$BINARY" 2>/dev/null || stat -f %m "$BINARY" 2>/dev/null || echo 0)
    IMAGE_TIME=$(docker inspect cordelia-test:latest --format '{{.Created}}' 2>/dev/null | xargs -I{} date -d {} +%s 2>/dev/null || echo 0)
    if [ "$BINARY_TIME" -gt "$IMAGE_TIME" ] 2>/dev/null; then
        echo "WARNING: Binary is newer than Docker image. Rebuilding..."
        bash "$REPO_DIR/tests/e2e/build-image.sh" || {
            echo "ERROR: Image rebuild failed. Aborting."
            exit 1
        }
    fi
fi

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
