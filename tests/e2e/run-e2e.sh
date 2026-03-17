#!/bin/bash
# Cordelia E2E Test Harness
#
# Builds the test Docker image, then runs topology tests.
#
# Usage:
#   ./tests/e2e/run-e2e.sh          # Run all topologies
#   ./tests/e2e/run-e2e.sh t1       # Run single topology
#   ./tests/e2e/run-e2e.sh --skip-build t1  # Skip image build
#
# Spec: seed-drill/specs/topology-e2e.md §5

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_NAME="cordelia-test:latest"
SKIP_BUILD=false
TOPOLOGIES=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true; shift ;;
        t[1-7]) TOPOLOGIES+=("$1"); shift ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# Default: run all available topologies
if [ ${#TOPOLOGIES[@]} -eq 0 ]; then
    for f in "$SCRIPT_DIR"/topologies/run-t*.sh; do
        [ -f "$f" ] && TOPOLOGIES+=("$(basename "$f" .sh | sed 's/run-//')")
    done
fi

echo "Cordelia E2E Test Harness"
echo "========================="
echo "Topologies: ${TOPOLOGIES[*]}"
echo ""

# ── Build ────────────────────────────────────────────────────────────

if [ "$SKIP_BUILD" = false ]; then
    echo "Building cordelia binary (release, musl)..."
    cd "$REPO_ROOT"
    cargo build --release --target x86_64-unknown-linux-musl --bin cordelia 2>&1 | tail -3

    echo "Building Docker image..."
    cp target/x86_64-unknown-linux-musl/release/cordelia cordelia-bin
    DOCKER_BUILDKIT=0 docker build --no-cache -t "$IMAGE_NAME" \
        -f tests/e2e/Dockerfile \
        --build-arg BINARY=cordelia-bin \
        . 2>&1 | tail -3
    rm -f cordelia-bin
    echo "Image built: $IMAGE_NAME"
    echo ""
fi

# ── Run topologies ──────────────────────────────────────────────────

TOTAL_PASS=0
TOTAL_FAIL=0

for topo in "${TOPOLOGIES[@]}"; do
    echo ""
    echo "╔═══════════════════════════════════════╗"
    echo "║  Running: $topo"
    echo "╚═══════════════════════════════════════╝"

    SCRIPT="$SCRIPT_DIR/topologies/run-${topo}.sh"
    if [ ! -f "$SCRIPT" ]; then
        echo "  SKIP: $SCRIPT not found"
        continue
    fi

    if bash "$SCRIPT"; then
        TOTAL_PASS=$((TOTAL_PASS + 1))
    else
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi
done

# ── Final summary ───────────────────────────────────────────────────

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  E2E Suite Complete                   ║"
echo "║  Topologies: $TOTAL_PASS passed, $TOTAL_FAIL failed"
echo "╚═══════════════════════════════════════╝"

exit $TOTAL_FAIL
