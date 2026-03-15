#!/bin/bash
# T7: Channel Isolation (3P + 1R + 1B)
#
# Properties tested:
#   P3 (Channel isolation): ch-alpha items never on ch-beta-only nodes
#   P4 (Role isolation): relay stores ciphertext, no PSKs; bootnode nothing
#
# Spec: seed-drill/specs/topology-e2e.md §3.8

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/t7.yml"
PROJECT="t7-channel-isolation"

# Source assertion framework
source "$E2E_DIR/assertions/common.sh"

# -- Setup ---------------------------------------------------------------

echo "T7: Channel Isolation (3P + 1R + 1B)"
echo "--------------------------------------"

# Generate PSKs for both channels
ALPHA_NAME="ch-alpha"
BETA_NAME="ch-beta"
ALPHA_ID=$(channel_id_for "$ALPHA_NAME")
BETA_ID=$(channel_id_for "$BETA_NAME")
mkdir -p "$E2E_DIR/keys"
dd if=/dev/urandom bs=32 count=1 of="$E2E_DIR/keys/${ALPHA_ID}.key" 2>/dev/null
dd if=/dev/urandom bs=32 count=1 of="$E2E_DIR/keys/${BETA_ID}.key" 2>/dev/null
echo "Alpha channel ID: $ALPHA_ID"
echo "Beta channel ID:  $BETA_ID"

# -- Teardown handler ----------------------------------------------------

cleanup() {
    echo ""
    echo "Collecting logs..."
    mkdir -p "$E2E_DIR/logs/t7"
    docker logs t7-b1 > "$E2E_DIR/logs/t7/b1.log" 2>&1 || true
    docker logs t7-r1 > "$E2E_DIR/logs/t7/r1.log" 2>&1 || true
    docker logs t7-p1 > "$E2E_DIR/logs/t7/p1.log" 2>&1 || true
    docker logs t7-p2 > "$E2E_DIR/logs/t7/p2.log" 2>&1 || true
    docker logs t7-p3 > "$E2E_DIR/logs/t7/p3.log" 2>&1 || true
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
    "docker exec t7-b1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "r1 healthy" \
    "docker exec t7-r1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "p1 healthy" \
    "docker exec t7-p1 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "p2 healthy" \
    "docker exec t7-p2 curl -sf http://localhost:9473/api/v1/health" 30
wait_for "p3 healthy" \
    "docker exec t7-p3 curl -sf http://localhost:9473/api/v1/health" 30

# -- Step 3: Wait for bootstrap ------------------------------------------

echo ""
echo "Step 3: Waiting for peer discovery..."
wait_for "p1 has 1+ hot peers" \
    '[ "$(api_get t7-p1 status | jq -r ".peers_hot // 0")" -ge 1 ]' 30
wait_for "p2 has 1+ hot peers" \
    '[ "$(api_get t7-p2 status | jq -r ".peers_hot // 0")" -ge 1 ]' 30
wait_for "p3 has 1+ hot peers" \
    '[ "$(api_get t7-p3 status | jq -r ".peers_hot // 0")" -ge 1 ]' 30

# -- Step 4: Subscribe to channels ---------------------------------------

echo ""
echo "Step 4: Subscribing to channels..."
# P1: ch-alpha only
api_post t7-p1 "channels/subscribe" \
    "{\"channel\": \"$ALPHA_NAME\"}" || true
# P2: ch-beta only
api_post t7-p2 "channels/subscribe" \
    "{\"channel\": \"$BETA_NAME\"}" || true
# P3: both channels
api_post t7-p3 "channels/subscribe" \
    "{\"channel\": \"$ALPHA_NAME\"}" || true
api_post t7-p3 "channels/subscribe" \
    "{\"channel\": \"$BETA_NAME\"}" || true

# -- Step 5: Publish items -----------------------------------------------

echo ""
echo "Step 5: Publishing 3 items to ch-alpha on P1..."
for i in 1 2 3; do
    api_post t7-p1 "channels/publish" \
        "{\"channel\": \"$ALPHA_NAME\", \"content\": \"alpha $i\", \"item_type\": \"message\"}"
    sleep 0.3
done

echo "Publishing 3 items to ch-beta on P2..."
for i in 1 2 3; do
    api_post t7-p2 "channels/publish" \
        "{\"channel\": \"$BETA_NAME\", \"content\": \"beta $i\", \"item_type\": \"message\"}"
    sleep 0.3
done

# -- Step 6: Wait for delivery -------------------------------------------

echo ""
echo "Step 6: Waiting for delivery..."
# P3 should have 6 items total (3 alpha + 3 beta)
wait_for "p3 has 3 alpha items" \
    '[ "$(db_query t7-p3 "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$ALPHA_ID'"'"' AND is_tombstone=0")" -ge 3 ]' 60
wait_for "p3 has 3 beta items" \
    '[ "$(db_query t7-p3 "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$BETA_ID'"'"' AND is_tombstone=0")" -ge 3 ]' 60

# -- Step 7: Assertions --------------------------------------------------

echo ""
echo "Step 7: Running assertions..."

# P3: Channel isolation -- each node only has items for its subscribed channels
# P1: only ch-alpha
assert_item_count t7-p1 "$ALPHA_ID" 3
assert_channel_isolation t7-p1 "$ALPHA_ID"

# P2: only ch-beta
assert_item_count t7-p2 "$BETA_ID" 3
assert_channel_isolation t7-p2 "$BETA_ID"

# P3: both channels
assert_item_count t7-p3 "$ALPHA_ID" 3
assert_item_count t7-p3 "$BETA_ID" 3
assert_channel_isolation t7-p3 "$ALPHA_ID" "$BETA_ID"

# P4: Role isolation -- relay stores ciphertext, no user-channel PSKs
# Note: relay has 1 PSK from personal channel created during init.
R1_ALPHA_PSK=$(docker exec t7-r1 sh -c \
    "[ -f /data/cordelia/channel-keys/${ALPHA_ID}.key ] && echo 1 || echo 0")
R1_BETA_PSK=$(docker exec t7-r1 sh -c \
    "[ -f /data/cordelia/channel-keys/${BETA_ID}.key ] && echo 1 || echo 0")
if [ "$R1_ALPHA_PSK" -eq 0 ] && [ "$R1_BETA_PSK" -eq 0 ]; then
    assert "r1 does not hold test-channel PSKs" 0
else
    assert "r1 holds test-channel PSK (expected none)" 1
fi
assert_min_total_items t7-r1 1

# P4: Bootnode stores nothing
assert_zero_items t7-b1

# -- Summary --------------------------------------------------------------

print_summary
