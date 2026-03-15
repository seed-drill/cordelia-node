#!/bin/bash
# Run S1 scale test: convergence at scale.
# Usage: run-scale.sh <node_count>
#
# Publishes 5 items on p1, waits for all personal nodes to receive them.
# Measures convergence time.

set -euo pipefail

TOTAL=${1:-20}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$SCRIPT_DIR/s${TOTAL}"
COMPOSE="$OUT_DIR/s${TOTAL}.yml"
PROJECT="s${TOTAL}-scale"

source "$E2E_DIR/assertions/common.sh"

echo "S1: Convergence at scale (${TOTAL} nodes)"
echo "=========================================="

# Generate topology if not present
if [ ! -f "$COMPOSE" ]; then
    bash "$SCRIPT_DIR/generate-scale.sh" "$TOTAL"
fi

# Count personal nodes
PERSONAL=$(grep -c "role = \"personal\"" "$OUT_DIR/configs/"*.toml)
echo "Personal nodes: $PERSONAL"

# Generate PSK
CHANNEL_NAME="test-channel"
CHANNEL_ID=$(channel_id_for "$CHANNEL_NAME")
mkdir -p "$E2E_DIR/keys"
dd if=/dev/urandom bs=32 count=1 of="$E2E_DIR/keys/${CHANNEL_ID}.key" 2>/dev/null
echo "Channel ID: $CHANNEL_ID"

# Cleanup
cleanup() {
    echo ""
    echo "Collecting logs..."
    mkdir -p "$E2E_DIR/logs/s${TOTAL}"
    for c in $(docker compose -f "$COMPOSE" -p "$PROJECT" ps -q 2>/dev/null); do
        name=$(docker inspect --format '{{.Name}}' "$c" | sed 's/^\///')
        docker logs "$c" > "$E2E_DIR/logs/s${TOTAL}/${name}.log" 2>&1 || true
    done
    echo "Tearing down..."
    docker compose -f "$COMPOSE" -p "$PROJECT" down -v --remove-orphans 2>/dev/null || true
    if [ -d "$E2E_DIR/keys" ]; then
        rm -rf "$E2E_DIR/keys" 2>/dev/null || sudo rm -rf "$E2E_DIR/keys" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Flush conntrack
sudo conntrack -F 2>/dev/null || true

# Start
echo ""
echo "Step 1: Starting ${TOTAL} nodes..."
START_TIME=$(date +%s)
docker compose -f "$COMPOSE" -p "$PROJECT" up -d 2>&1 | tail -5

# Wait for health
echo ""
echo "Step 2: Waiting for all nodes healthy..."
wait_for "b1 healthy" \
    "docker exec s${TOTAL}-b1 curl -sf http://localhost:9473/api/v1/health" 60

# Wait for a sample of personal nodes
for i in 1 5 $PERSONAL; do
    [ "$i" -gt "$PERSONAL" ] && continue
    wait_for "p${i} healthy" \
        "docker exec s${TOTAL}-p${i} curl -sf http://localhost:9473/api/v1/health" 60
done

HEALTHY_TIME=$(date +%s)
echo "  All sampled nodes healthy in $((HEALTHY_TIME - START_TIME))s"

# Subscribe all personal nodes
echo ""
echo "Step 3: Subscribing ${PERSONAL} nodes to test-channel..."
for i in $(seq 1 "$PERSONAL"); do
    api_post "s${TOTAL}-p${i}" "channels/subscribe" \
        "{\"channel\": \"$CHANNEL_NAME\"}" > /dev/null 2>&1 || true
done

# Publish
echo ""
echo "Step 4: Publishing 5 items on p1..."
PUBLISH_TIME=$(date +%s)
for i in 1 2 3 4 5; do
    api_post "s${TOTAL}-p1" "channels/publish" \
        "{\"channel\": \"$CHANNEL_NAME\", \"content\": \"scale test $i\", \"item_type\": \"message\"}" > /dev/null 2>&1
    sleep 0.3
done

# Wait for convergence
echo ""
echo "Step 5: Waiting for convergence..."
CONVERGED=0
for attempt in $(seq 1 60); do
    TOTAL_WITH_ITEMS=0
    for i in $(seq 1 "$PERSONAL"); do
        COUNT=$(db_query "s${TOTAL}-p${i}" \
            "SELECT COUNT(*) FROM items WHERE channel_id='$CHANNEL_ID' AND is_tombstone=0" 2>/dev/null || echo "0")
        if [ "$COUNT" -ge 5 ] 2>/dev/null; then
            TOTAL_WITH_ITEMS=$((TOTAL_WITH_ITEMS + 1))
        fi
    done
    CONVERGENCE_TIME=$(($(date +%s) - PUBLISH_TIME))
    echo "  ${attempt}: ${TOTAL_WITH_ITEMS}/${PERSONAL} nodes have all items (${CONVERGENCE_TIME}s)"
    if [ "$TOTAL_WITH_ITEMS" -ge "$PERSONAL" ]; then
        CONVERGED=1
        break
    fi
    sleep 5
done

# Results
echo ""
echo "=========================================="
if [ "$CONVERGED" -eq 1 ]; then
    echo "PASS: All ${PERSONAL} personal nodes converged in ${CONVERGENCE_TIME}s"
else
    echo "FAIL: Only ${TOTAL_WITH_ITEMS}/${PERSONAL} nodes converged after ${CONVERGENCE_TIME}s"
fi

# Per-node item counts
echo ""
echo "Per-node item counts:"
for i in $(seq 1 "$PERSONAL"); do
    COUNT=$(db_query "s${TOTAL}-p${i}" \
        "SELECT COUNT(*) FROM items WHERE channel_id='$CHANNEL_ID' AND is_tombstone=0" 2>/dev/null || echo "?")
    HOT=$(api_get "s${TOTAL}-p${i}" status 2>/dev/null | jq -r ".peers_hot // 0" 2>/dev/null || echo "?")
    WARM=$(api_get "s${TOTAL}-p${i}" status 2>/dev/null | jq -r ".peers_warm // 0" 2>/dev/null || echo "?")
    echo "  p${i}: items=${COUNT} hot=${HOT} warm=${WARM}"
done

echo ""
echo "Scale: ${TOTAL} nodes, Convergence: ${CONVERGENCE_TIME}s"
[ "$CONVERGED" -eq 1 ]
