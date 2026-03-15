#!/bin/bash
# T6: Bootnode Loss (3P + 1B)
#
# Properties tested:
#   P1 (Delivery): items still delivered after bootnode killed
#   P7 (Bootstrap): personal nodes maintain hot peers after bootnode loss
#   P9 (Bootnode silence): bootnode sends zero replication messages
#
# Spec: seed-drill/specs/topology-e2e.md §3.7

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/t6.yml"
PROJECT="t6-bootnode-loss"

# Source assertion framework
source "$E2E_DIR/assertions/common.sh"

# -- Setup ---------------------------------------------------------------

echo "T6: Bootnode Loss (3P + 1B)"
echo "----------------------------"

# Generate PSK for test-channel
CHANNEL_NAME="test-channel"
CHANNEL_ID=$(channel_id_for "$CHANNEL_NAME")
mkdir -p "$E2E_DIR/keys"
dd if=/dev/urandom bs=32 count=1 of="$E2E_DIR/keys/${CHANNEL_ID}.key" 2>/dev/null
echo "Channel ID: $CHANNEL_ID"

# -- Teardown handler ----------------------------------------------------

cleanup() {
    echo ""
    echo "Collecting logs..."
    mkdir -p "$E2E_DIR/logs/t6"
    docker logs t6-b1 > "$E2E_DIR/logs/t6/b1.log" 2>&1 || true
    docker logs t6-p1 > "$E2E_DIR/logs/t6/p1.log" 2>&1 || true
    docker logs t6-p2 > "$E2E_DIR/logs/t6/p2.log" 2>&1 || true
    docker logs t6-p3 > "$E2E_DIR/logs/t6/p3.log" 2>&1 || true
    echo "Tearing down..."
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT" down -v --remove-orphans 2>/dev/null || true
    if [ -d "$E2E_DIR/keys" ]; then
        rm -rf "$E2E_DIR/keys" 2>/dev/null || sudo rm -rf "$E2E_DIR/keys" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# -- Step 1: Start topology ----------------------------------------------

echo ""
echo "Step 1: Starting topology..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT" up -d

# -- Step 2: Wait for health ---------------------------------------------

echo ""
echo "Step 2: Waiting for nodes to be healthy..."
wait_for "b1 healthy" \
    "docker exec t6-b1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "p1 healthy" \
    "docker exec t6-p1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "p2 healthy" \
    "docker exec t6-p2 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "p3 healthy" \
    "docker exec t6-p3 curl -sf http://localhost:9473/api/v1/health" 30

# -- Step 3: Wait for bootstrap ------------------------------------------

echo ""
echo "Step 3: Waiting for peer discovery..."
wait_for "p1 has 1+ hot peers" \
    '[ "$(api_get t6-p1 status | jq -r ".peers_hot // 0")" -ge 1 ]' 30
wait_for "p2 has 1+ hot peers" \
    '[ "$(api_get t6-p2 status | jq -r ".peers_hot // 0")" -ge 1 ]' 30
wait_for "p3 has 1+ hot peers" \
    '[ "$(api_get t6-p3 status | jq -r ".peers_hot // 0")" -ge 1 ]' 30

# -- Step 4: Subscribe to channel ----------------------------------------

echo ""
echo "Step 4: Subscribing to test-channel..."
api_post t6-p1 "channels/subscribe" \
    "{\"channel\": \"$CHANNEL_NAME\"}" || true
api_post t6-p2 "channels/subscribe" \
    "{\"channel\": \"$CHANNEL_NAME\"}" || true
api_post t6-p3 "channels/subscribe" \
    "{\"channel\": \"$CHANNEL_NAME\"}" || true

# -- Step 5: Pre-bootnode-loss baseline -----------------------------------

echo ""
echo "Step 5: Publishing 2 baseline items on P1..."
for i in 1 2; do
    api_post t6-p1 "channels/publish" \
        "{\"channel\": \"$CHANNEL_NAME\", \"content\": \"baseline $i\", \"item_type\": \"message\"}"
    sleep 0.5
done

wait_for "p2 has 2 baseline items" \
    '[ "$(db_query t6-p2 "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$CHANNEL_ID'"'"' AND is_tombstone=0")" -ge 2 ]' 30
wait_for "p3 has 2 baseline items" \
    '[ "$(db_query t6-p3 "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$CHANNEL_ID'"'"' AND is_tombstone=0")" -ge 2 ]' 30

# -- Step 6: P9 check before killing bootnode ----------------------------

echo ""
echo "Step 6: Checking bootnode silence (P9)..."
assert_zero_items t6-b1
assert_zero_log_matches t6-b1 "protocol send: type=0x0[4-7]" \
    "b1 has zero replication protocol sends"

# -- Step 7: Kill bootnode -----------------------------------------------

echo ""
echo "Step 7: Killing bootnode..."
docker stop t6-b1
sleep 5

# -- Step 8: Post-bootnode-loss delivery ----------------------------------

echo ""
echo "Step 8: Publishing 3 more items on P1 (bootnode dead)..."
for i in 3 4 5; do
    api_post t6-p1 "channels/publish" \
        "{\"channel\": \"$CHANNEL_NAME\", \"content\": \"post-loss $i\", \"item_type\": \"message\"}"
    sleep 0.5
done

# -- Step 9: Wait for delivery -------------------------------------------

echo ""
echo "Step 9: Waiting for items to arrive..."
wait_for "p2 has 5 items" \
    '[ "$(db_query t6-p2 "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$CHANNEL_ID'"'"' AND is_tombstone=0")" -ge 5 ]' 30
wait_for "p3 has 5 items" \
    '[ "$(db_query t6-p3 "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$CHANNEL_ID'"'"' AND is_tombstone=0")" -ge 5 ]' 30

# -- Step 10: Assertions -------------------------------------------------

echo ""
echo "Step 10: Running assertions..."

# P1: Delivery -- all 5 items on all personal nodes
assert_item_count t6-p1 "$CHANNEL_ID" 5
assert_item_count t6-p2 "$CHANNEL_ID" 5
assert_item_count t6-p3 "$CHANNEL_ID" 5

# P7: Bootstrap -- personal nodes maintain hot peers after bootnode loss
assert_hot_peers t6-p1 1
assert_hot_peers t6-p2 1
assert_hot_peers t6-p3 1

# P3: Channel isolation (bonus)
assert_channel_isolation t6-p1 "$CHANNEL_ID"
assert_channel_isolation t6-p2 "$CHANNEL_ID"
assert_channel_isolation t6-p3 "$CHANNEL_ID"

# -- Summary --------------------------------------------------------------

print_summary
