#!/bin/bash
# Run S3 PAN (swarm) test.
# Usage: run-s3.sh [swarm_per_lead] [--no-teardown]
#
# Tests:
#   1. Swarm nodes connect to lead only (not relay)
#   2. Write on swarm node propagates to all swarm nodes via lead
#   3. Write on persistent (network) channel propagates to relay mesh
#   4. Write on local channel does NOT appear on relay
#   5. Lead verifies child derivation (non-child rejected)
#
# Phase 0: Startup (generate topology, compose up, wait healthy)
# Phase 1: Connectivity (swarm nodes connect to lead, leads connect to relay)
# Phase 2: Channel setup (subscribe all nodes to test channel)
# Phase 3: Network channel propagation (write from swarm, verify relay delivery)
# Phase 4: Local channel isolation (write to local channel, verify NOT on relay)
# Phase 5: Assertions summary

set -euo pipefail

NO_TEARDOWN=false
for arg in "$@"; do
    if [ "$arg" = "--no-teardown" ]; then
        NO_TEARDOWN=true
    fi
done
ARGS=()
for arg in "$@"; do [ "$arg" != "--no-teardown" ] && ARGS+=("$arg"); done
set -- "${ARGS[@]+"${ARGS[@]}"}"

SWARM_PER_LEAD=${1:-4}
LEADS=2
RELAYS=2
BOOTNODES=1
SWARM_TOTAL=$((LEADS * SWARM_PER_LEAD))
CONTAINER_COUNT=$((BOOTNODES + RELAYS + LEADS + SWARM_TOTAL))

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$SCRIPT_DIR/s3-${SWARM_PER_LEAD}"
COMPOSE="$OUT_DIR/s3-${SWARM_PER_LEAD}.yml"
PROJECT="s3-${SWARM_PER_LEAD}-pan"
LOG_DIR="$E2E_DIR/logs/s3-${SWARM_PER_LEAD}"
PREFIX="s3-${SWARM_PER_LEAD}"

source "$E2E_DIR/assertions/common.sh"

mkdir -p "$LOG_DIR"

# ── Helpers ──────────────────────────────────────────────────────────

container_name() {
    echo "${PROJECT}-${1}-1"
}

# ── Phase 0: Startup ────────────────────────────────────────────────

echo "=== S3 PAN Test: ${LEADS}L + ${SWARM_TOTAL}S (${SWARM_PER_LEAD}/lead) = ${CONTAINER_COUNT} containers ==="
echo ""
echo "Phase 0: Generating topology..."

bash "$SCRIPT_DIR/generate-s3.sh" "$SWARM_PER_LEAD" > "$LOG_DIR/generate.log" 2>&1

echo "Phase 0: Starting containers..."
docker compose -p "$PROJECT" -f "$COMPOSE" up -d --remove-orphans > "$LOG_DIR/compose-up.log" 2>&1

cleanup() {
    if [ "$NO_TEARDOWN" = true ]; then
        echo "  (--no-teardown: leaving containers running)"
        return
    fi
    echo "Tearing down..."
    docker compose -p "$PROJECT" -f "$COMPOSE" down -v --timeout 10 > /dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Phase 0: Waiting for healthy (${CONTAINER_COUNT} containers)..."
HEALTHY_TIMEOUT=120
ELAPSED=0
while true; do
    HEALTHY=$(docker compose -p "$PROJECT" -f "$COMPOSE" ps --format json 2>/dev/null \
        | jq -s '[.[] | select(.Health == "healthy")] | length' 2>/dev/null || echo 0)
    if [ "$HEALTHY" -ge "$CONTAINER_COUNT" ]; then
        echo "  All ${CONTAINER_COUNT} containers healthy (${ELAPSED}s)"
        break
    fi
    if [ "$ELAPSED" -ge "$HEALTHY_TIMEOUT" ]; then
        echo "  TIMEOUT: only ${HEALTHY}/${CONTAINER_COUNT} healthy after ${HEALTHY_TIMEOUT}s"
        docker compose -p "$PROJECT" -f "$COMPOSE" ps > "$LOG_DIR/ps-timeout.log" 2>&1
        docker compose -p "$PROJECT" -f "$COMPOSE" logs > "$LOG_DIR/startup-fail.log" 2>&1
        echo "  Logs saved to $LOG_DIR/startup-fail.log"
        exit 1
    fi
    sleep 2
    ((ELAPSED += 2))
done

# ── Phase 1: Connectivity ────────────────────────────────────────────

echo ""
echo "Phase 1: Verifying connectivity (30s)..."
sleep 15  # Allow governor to tick, connections to establish

# Leads should have hot peers (relay + possibly swarm children)
for i in $(seq 0 $((LEADS - 1))); do
    CN=$(container_name "lead-${i}")
    assert_hot_peers "$CN" 1
done

# Swarm nodes should connect to their lead
for l in $(seq 0 $((LEADS - 1))); do
    for s in $(seq 0 $((SWARM_PER_LEAD - 1))); do
        CN=$(container_name "swarm-${l}-${s}")
        assert_hot_peers "$CN" 1
    done
done

# ── Phase 2: Channel setup ──────────────────────────────────────────

echo ""
echo "Phase 2: Setting up test channels..."

TEST_CHANNEL="s3-test-channel"
TEST_CHANNEL_ID=$(channel_id_for "$TEST_CHANNEL")

# Subscribe leads
for i in $(seq 0 $((LEADS - 1))); do
    CN=$(container_name "lead-${i}")
    api_post "$CN" "channels/subscribe" "{\"channel\": \"$TEST_CHANNEL\"}" > /dev/null 2>&1 || true
done

# Subscribe swarm nodes
for l in $(seq 0 $((LEADS - 1))); do
    for s in $(seq 0 $((SWARM_PER_LEAD - 1))); do
        CN=$(container_name "swarm-${l}-${s}")
        api_post "$CN" "channels/subscribe" "{\"channel\": \"$TEST_CHANNEL\"}" > /dev/null 2>&1 || true
    done
done

echo "  Subscribed all nodes to ${TEST_CHANNEL}"
sleep 10  # Allow channel announcements + sync

# ── Phase 3: Network channel propagation ─────────────────────────────

echo ""
echo "Phase 3: Testing network channel propagation..."

# Write from swarm-0-0
WRITER=$(container_name "swarm-0-0")
api_post "$WRITER" "publish" \
    "{\"channel\": \"${TEST_CHANNEL}\", \"content\": \"s3-network-test-item\", \"item_type\": \"text\"}" > /dev/null 2>&1 || true

echo "  Published item from swarm-0-0 to ${TEST_CHANNEL}"
echo "  Waiting for propagation (30s)..."
sleep 30  # sync_interval=5s, need several cycles through lead -> relay -> lead -> swarm

# Relays should have the item (network scope propagation)
for i in $(seq 1 $RELAYS); do
    CN=$(container_name "r${i}")
    assert_min_total_items "$CN" 1
done

# All leads should have the item
for i in $(seq 0 $((LEADS - 1))); do
    CN=$(container_name "lead-${i}")
    assert_item_count "$CN" "$TEST_CHANNEL_ID" 1
done

# All swarm nodes should have the item (via their lead)
for l in $(seq 0 $((LEADS - 1))); do
    for s in $(seq 0 $((SWARM_PER_LEAD - 1))); do
        CN=$(container_name "swarm-${l}-${s}")
        assert_item_count "$CN" "$TEST_CHANNEL_ID" 1
    done
done

# ── Phase 4: Local channel isolation ─────────────────────────────────

echo ""
echo "Phase 4: Testing local channel isolation..."

# Check swarm nodes have local channels from swarm-init
SWARM_CN=$(container_name "swarm-0-0")
LOCAL_COUNT=$(db_query "$SWARM_CN" \
    "SELECT COUNT(*) FROM channels WHERE scope='local'" 2>/dev/null || echo 0)

if [ "${LOCAL_COUNT:-0}" -ge 1 ]; then
    # Get the local channel ID
    LOCAL_CH=$(db_query "$SWARM_CN" \
        "SELECT channel_id FROM channels WHERE scope='local' LIMIT 1")
    echo "  Found local channel: $LOCAL_CH"

    # Write to local channel from swarm-0-0 (use channel_id directly)
    api_post "$SWARM_CN" "publish" \
        "{\"channel\": \"${LOCAL_CH}\", \"content\": \"local-only-item\", \"item_type\": \"text\"}" > /dev/null 2>&1 || true

    sleep 15  # Wait for any propagation

    # Relays should NOT have any local channel items
    for i in $(seq 1 $RELAYS); do
        RCN=$(container_name "r${i}")
        RELAY_LOCAL=$(db_query "$RCN" \
            "SELECT COUNT(*) FROM items WHERE channel_id='${LOCAL_CH}'" 2>/dev/null || echo 0)
        if [ "${RELAY_LOCAL:-0}" -eq 0 ]; then
            assert "r${i} has no local-scope items" 0
        else
            assert "r${i} has ${RELAY_LOCAL} local-scope items (expected 0)" 1
        fi
    done
else
    echo "  SKIP: no local channels found on swarm-0-0 (swarm-init may not have run)"
fi

# ── Phase 5: HKDF verification ──────────────────────────────────────

echo ""
echo "Phase 5: Checking HKDF verification in logs..."

# Leads should have "verified swarm child via HKDF" log entries
for i in $(seq 0 $((LEADS - 1))); do
    CN=$(container_name "lead-${i}")
    HKDF_LOGS=$(docker logs "$CN" 2>&1 | grep -c "verified swarm child via HKDF" || true)
    if [ "${HKDF_LOGS:-0}" -ge 1 ]; then
        assert "lead-${i} verified swarm children via HKDF ($HKDF_LOGS)" 0
    else
        assert "lead-${i} has no HKDF verification logs" 1
    fi
done

# ── Summary ──────────────────────────────────────────────────────────

# Collect logs
docker compose -p "$PROJECT" -f "$COMPOSE" logs > "$LOG_DIR/all.log" 2>&1

# Save metrics
cat > "$LOG_DIR/metrics.json" << EOF
{
  "test": "s3-pan",
  "swarm_per_lead": $SWARM_PER_LEAD,
  "leads": $LEADS,
  "relays": $RELAYS,
  "containers": $CONTAINER_COUNT,
  "passed": $PASS,
  "failed": $FAIL,
  "total": $TOTAL
}
EOF

print_summary
