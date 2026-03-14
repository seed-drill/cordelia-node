#!/bin/bash
# T1: Minimal topology test (2P + 1B)
#
# Properties tested:
#   P1 (Delivery): items published on P1 arrive on P2
#   P3 (Channel isolation): items only stored for subscribed channels
#   P7 (Bootstrap): both personal nodes discover peers via bootnode
#
# Spec: seed-drill/specs/topology-e2e.md §3.2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/t1.yml"
PROJECT="t1-minimal"

# Source assertion framework
source "$E2E_DIR/assertions/common.sh"

# ── Setup ───────────────────────────────────────────────────────────

echo "T1: Minimal topology (2P + 1B)"
echo "───────────────────────────────"

# Generate PSK for test-channel
CHANNEL_NAME="test-channel"
CHANNEL_ID=$(channel_id_for "$CHANNEL_NAME")
mkdir -p "$E2E_DIR/keys"
dd if=/dev/urandom bs=32 count=1 of="$E2E_DIR/keys/${CHANNEL_ID}.key" 2>/dev/null
echo "Channel ID: $CHANNEL_ID"

# ── Teardown handler ────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "Collecting logs..."
    mkdir -p "$E2E_DIR/logs/t1"
    docker logs t1-b1 > "$E2E_DIR/logs/t1/b1.log" 2>&1 || true
    docker logs t1-p1 > "$E2E_DIR/logs/t1/p1.log" 2>&1 || true
    docker logs t1-p2 > "$E2E_DIR/logs/t1/p2.log" 2>&1 || true
    echo "Tearing down..."
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT" down -v --remove-orphans 2>/dev/null || true
    rm -rf "$E2E_DIR/keys"
}
trap cleanup EXIT

# ── Step 1: Start topology ──────────────────────────────────────────

echo ""
echo "Step 1: Starting topology..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT" up -d

# ── Step 2: Wait for health ─────────────────────────────────────────

echo ""
echo "Step 2: Waiting for nodes to be healthy..."
wait_for "b1 healthy" \
    "docker exec t1-b1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "p1 healthy" \
    "docker exec t1-p1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "p2 healthy" \
    "docker exec t1-p2 curl -sf http://localhost:9473/api/v1/health" 30

# ── Step 3: Wait for bootstrap ──────────────────────────────────────

echo ""
echo "Step 3: Waiting for peer discovery..."
wait_for "p1 has hot peers" \
    '[ "$(api_get t1-p1 status | jq -r ".peers_hot // 0")" -ge 1 ]' 30
wait_for "p2 has hot peers" \
    '[ "$(api_get t1-p2 status | jq -r ".peers_hot // 0")" -ge 1 ]' 30

# ── Step 4: Subscribe to channel ────────────────────────────────────

echo ""
echo "Step 4: Subscribing to test-channel..."
api_post t1-p1 "channels/subscribe" \
    "{\"channel_name\": \"$CHANNEL_NAME\"}" || true
api_post t1-p2 "channels/subscribe" \
    "{\"channel_name\": \"$CHANNEL_NAME\"}" || true

# ── Step 5: Publish items ───────────────────────────────────────────

echo ""
echo "Step 5: Publishing 3 items on P1..."
for i in 1 2 3; do
    api_post t1-p1 "channels/publish" \
        "{\"channel_id\": \"$CHANNEL_ID\", \"content\": \"test message $i\", \"item_type\": \"message\"}"
    sleep 0.5
done

# ── Step 6: Wait for delivery ───────────────────────────────────────

echo ""
echo "Step 6: Waiting for items to arrive on P2..."
wait_for "p2 has 3 items" \
    '[ "$(db_query t1-p2 "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$CHANNEL_ID'"'"' AND is_tombstone=0")" -ge 3 ]' 30

# ── Step 7: Assertions ──────────────────────────────────────────────

echo ""
echo "Step 7: Running assertions..."

# P1: Delivery
assert_item_count t1-p1 "$CHANNEL_ID" 3
assert_item_count t1-p2 "$CHANNEL_ID" 3

# P3: Channel isolation
assert_channel_isolation t1-p1 "$CHANNEL_ID"
assert_channel_isolation t1-p2 "$CHANNEL_ID"

# P7: Bootstrap
assert_hot_peers t1-p1 1
assert_hot_peers t1-p2 1

# P4: Bootnode role isolation (bonus check)
assert_zero_items t1-b1

# P9: Bootnode silence (bonus check)
assert_zero_log_matches t1-b1 "protocol send: type=0x0[4-7]" \
    "b1 has zero replication protocol sends"

# ── Summary ─────────────────────────────────────────────────────────

print_summary
