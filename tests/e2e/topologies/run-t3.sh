#!/bin/bash
# T3: Pull-Only (2P + 1B + 1R)
#
# Properties tested:
#   P2 (Pull delivery): items arrive on P2 exclusively via Item-Sync
#   P8 (Push silence): P2 sends zero outbound Item-Push messages
#
# Spec: seed-drill/specs/topology-e2e.md §3.4

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/t3.yml"
PROJECT="t3-pull-only"

# Source assertion framework
source "$E2E_DIR/assertions/common.sh"

# -- Setup ---------------------------------------------------------------

echo "T3: Pull-Only (2P + 1B + 1R)"
echo "------------------------------"

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
    mkdir -p "$E2E_DIR/logs/t3"
    docker logs t3-b1 > "$E2E_DIR/logs/t3/b1.log" 2>&1 || true
    docker logs t3-r1 > "$E2E_DIR/logs/t3/r1.log" 2>&1 || true
    docker logs t3-p1 > "$E2E_DIR/logs/t3/p1.log" 2>&1 || true
    docker logs t3-p2 > "$E2E_DIR/logs/t3/p2.log" 2>&1 || true
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
    "docker exec t3-b1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "r1 healthy" \
    "docker exec t3-r1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "p1 healthy" \
    "docker exec t3-p1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "p2 healthy" \
    "docker exec t3-p2 curl -sf http://localhost:9473/api/v1/health" 30

# -- Step 3: Wait for bootstrap ------------------------------------------

echo ""
echo "Step 3: Waiting for peer discovery..."
wait_for "p1 has 2+ hot peers" \
    '[ "$(api_get t3-p1 status | jq -r ".peers_hot // 0")" -ge 2 ]' 30
wait_for "p2 has 2+ hot peers" \
    '[ "$(api_get t3-p2 status | jq -r ".peers_hot // 0")" -ge 2 ]' 30

# -- Step 4: Subscribe to channel ----------------------------------------

echo ""
echo "Step 4: Subscribing to test-channel..."
api_post t3-p1 "channels/subscribe" \
    "{\"channel\": \"$CHANNEL_NAME\"}" || true
api_post t3-p2 "channels/subscribe" \
    "{\"channel\": \"$CHANNEL_NAME\"}" || true

# -- Step 5: Publish items -----------------------------------------------

echo ""
echo "Step 5: Publishing 3 items on P1..."
for i in 1 2 3; do
    api_post t3-p1 "channels/publish" \
        "{\"channel\": \"$CHANNEL_NAME\", \"content\": \"pull test $i\", \"item_type\": \"message\"}"
    sleep 0.5
done

# -- Step 6: Wait for pull delivery --------------------------------------
# P2 is pull_only with sync_interval_realtime_secs=5
# Items should arrive within 5-15s via anti-entropy pull

echo ""
echo "Step 6: Waiting for items to arrive on P2 via pull..."
wait_for "p2 has 3 items" \
    '[ "$(db_query t3-p2 "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$CHANNEL_ID'"'"' AND is_tombstone=0")" -ge 3 ]' 45

# -- Step 7: Assertions --------------------------------------------------

echo ""
echo "Step 7: Running assertions..."

# P2: Pull delivery -- all items arrived
assert_item_count t3-p1 "$CHANNEL_ID" 3
assert_item_count t3-p2 "$CHANNEL_ID" 3

# P8: Push silence -- P2 sent zero outbound Item-Push messages
P2_PUSHES=$(docker logs t3-p2 2>&1 | grep -c "Item-Push send\|push.*item.*peer\|protocol send: type=0x06" || true)
if [ "$P2_PUSHES" -eq 0 ]; then
    assert "p2 sent zero Item-Push messages" 0
else
    assert "p2 sent $P2_PUSHES Item-Push messages (expected 0)" 1
fi

# P4: Role isolation (bonus)
assert_zero_items t3-b1
# Note: relay has 1 PSK from personal channel created during init.
R1_TEST_PSK=$(docker exec t3-r1 sh -c \
    "[ -f /data/cordelia/channel-keys/${CHANNEL_ID}.key ] && echo 1 || echo 0")
if [ "$R1_TEST_PSK" -eq 0 ]; then
    assert "r1 does not hold test-channel PSK" 0
else
    assert "r1 holds test-channel PSK (expected none)" 1
fi

# P3: Channel isolation (bonus)
assert_channel_isolation t3-p1 "$CHANNEL_ID"
assert_channel_isolation t3-p2 "$CHANNEL_ID"

# -- Summary --------------------------------------------------------------

print_summary
