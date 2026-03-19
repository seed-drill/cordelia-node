#!/bin/bash
# T2: Relay Path (2P + 1B + 1R)
#
# Properties tested:
#   P1 (Delivery): items published on P1 arrive on P2 via relay
#   P4 (Role isolation): relay stores ciphertext, no PSKs; bootnode stores nothing
#   P5 (Loop termination): relay re-push is bounded
#
# Spec: seed-drill/specs/topology-e2e.md §3.3

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/t2.yml"
PROJECT="t2-relay-path"

# Source assertion framework
source "$E2E_DIR/assertions/common.sh"

# -- Setup ---------------------------------------------------------------

echo "T2: Relay Path (2P + 1B + 1R)"
echo "-------------------------------"

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
    mkdir -p "$E2E_DIR/logs/t2"
    docker logs t2-b1 > "$E2E_DIR/logs/t2/b1.log" 2>&1 || true
    docker logs t2-r1 > "$E2E_DIR/logs/t2/r1.log" 2>&1 || true
    docker logs t2-p1 > "$E2E_DIR/logs/t2/p1.log" 2>&1 || true
    docker logs t2-p2 > "$E2E_DIR/logs/t2/p2.log" 2>&1 || true
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
    "docker exec t2-b1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "r1 healthy" \
    "docker exec t2-r1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "p1 healthy" \
    "docker exec t2-p1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "p2 healthy" \
    "docker exec t2-p2 curl -sf http://localhost:9473/api/v1/health" 30

# -- Step 3: Wait for bootstrap ------------------------------------------

echo ""
echo "Step 3: Waiting for peer discovery..."
wait_for "p1 has 1+ hot peers" \
    '[ "$(api_get t2-p1 status | jq -r ".peers_hot // 0")" -ge 1 ]' 30
wait_for "p2 has 1+ hot peers" \
    '[ "$(api_get t2-p2 status | jq -r ".peers_hot // 0")" -ge 1 ]' 30
# Zone model: R1 must promote P1+P2 from cold->warm->hot before items flow.
# Without this, R1 rejects item_push as "data protocol from non-hot peer".
wait_for "r1 has 3 hot peers (b1+p1+p2)" \
    '[ "$(api_get t2-r1 status | jq -r ".peers_hot // 0")" -ge 3 ]' 30

# -- Step 4: Subscribe to channel ----------------------------------------

echo ""
echo "Step 4: Subscribing to test-channel..."
api_post t2-p1 "channels/subscribe" \
    "{\"channel\": \"$CHANNEL_NAME\"}" || true
api_post t2-p2 "channels/subscribe" \
    "{\"channel\": \"$CHANNEL_NAME\"}" || true

# -- Step 5: Publish items -----------------------------------------------

echo ""
echo "Step 5: Publishing 5 items on P1..."
for i in 1 2 3 4 5; do
    api_post t2-p1 "channels/publish" \
        "{\"channel\": \"$CHANNEL_NAME\", \"content\": \"relay test $i\", \"item_type\": \"message\"}"
    sleep 0.5
done

# -- Step 6: Wait for delivery -------------------------------------------

echo ""
echo "Step 6: Waiting for items to arrive on P2..."
wait_for "p2 has 5 items" \
    '[ "$(db_query t2-p2 "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$CHANNEL_ID'"'"' AND is_tombstone=0")" -ge 5 ]' 60

# -- Step 7: Assertions --------------------------------------------------

echo ""
echo "Step 7: Running assertions..."

# P1: Delivery
assert_item_count t2-p1 "$CHANNEL_ID" 5
assert_item_count t2-p2 "$CHANNEL_ID" 5

# P4: Role isolation -- relay stores ciphertext, no user-channel PSKs
# Note: relay has 1 PSK from personal channel created during init.
# The assertion checks that the relay does NOT have the test-channel PSK.
R1_TEST_PSK=$(docker exec t2-r1 sh -c \
    "[ -f /data/cordelia/channel-keys/${CHANNEL_ID}.key ] && echo 1 || echo 0")
if [ "$R1_TEST_PSK" -eq 0 ]; then
    assert "r1 does not hold test-channel PSK" 0
else
    assert "r1 holds test-channel PSK (expected none)" 1
fi
assert_min_total_items t2-r1 1

# P4: Role isolation -- bootnode stores nothing
assert_zero_items t2-b1

# P5: Loop termination -- relay push count is bounded
# Check relay logs for re-push events (should be bounded, not infinite)
R1_PUSHES=$(docker logs t2-r1 2>&1 | grep -c "Item-Push send\|push.*item\|re-push" || true)
echo "  INFO: R1 push count from logs: $R1_PUSHES"
if [ "$R1_PUSHES" -le 50 ]; then
    assert "r1 push count bounded ($R1_PUSHES <= 50)" 0
else
    assert "r1 push count unbounded ($R1_PUSHES > 50)" 1
fi

# P3: Channel isolation (bonus)
assert_channel_isolation t2-p1 "$CHANNEL_ID"
assert_channel_isolation t2-p2 "$CHANNEL_ID"

# -- Summary --------------------------------------------------------------

print_summary
