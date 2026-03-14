#!/bin/bash
# T5: Partition/Heal (2P + 2R + 1B)
#
# Properties tested:
#   P6 (Convergence): items published during partition delivered after heal
#
# Topology: P1 -- R1 -- R2 -- P2 (partition between R1 and R2)
#                   |
#                  B1
#
# Spec: seed-drill/specs/topology-e2e.md §3.6

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/t5.yml"
PROJECT="t5-partition-heal"

# Source assertion framework
source "$E2E_DIR/assertions/common.sh"

# -- Setup ---------------------------------------------------------------

echo "T5: Partition/Heal (2P + 2R + 1B)"
echo "------------------------------------"

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
    mkdir -p "$E2E_DIR/logs/t5"
    for node in b1 r1 r2 p1 p2; do
        docker logs "t5-$node" > "$E2E_DIR/logs/t5/$node.log" 2>&1 || true
    done
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
for node in b1 r1 r2 p1 p2; do
    wait_for "$node healthy" \
        "docker exec t5-$node curl -sf http://localhost:9473/api/v1/health" 30
done

# -- Step 3: Wait for bootstrap ------------------------------------------

echo ""
echo "Step 3: Waiting for peer discovery..."
# P1 connects to R1 only (hot_max=1), P2 connects to R2 only (hot_max=1)
wait_for "p1 has 1 hot peer" \
    '[ "$(api_get t5-p1 status | jq -r ".peers_hot // 0")" -ge 1 ]' 30
wait_for "p2 has 1 hot peer" \
    '[ "$(api_get t5-p2 status | jq -r ".peers_hot // 0")" -ge 1 ]' 30
# R1 and R2 must be connected to each other (via B1 peer-sharing)
wait_for "r1 has 2+ hot peers" \
    '[ "$(api_get t5-r1 status | jq -r ".peers_hot // 0")" -ge 2 ]' 30
wait_for "r2 has 2+ hot peers" \
    '[ "$(api_get t5-r2 status | jq -r ".peers_hot // 0")" -ge 2 ]' 30

# -- Step 4: Subscribe to channel ----------------------------------------

echo ""
echo "Step 4: Subscribing to test-channel..."
api_post t5-p1 "channels/subscribe" \
    "{\"channel\": \"$CHANNEL_NAME\"}" || true
api_post t5-p2 "channels/subscribe" \
    "{\"channel\": \"$CHANNEL_NAME\"}" || true

# -- Step 5: Pre-partition baseline --------------------------------------

echo ""
echo "Step 5: Publishing 2 baseline items on P1..."
for i in 1 2; do
    api_post t5-p1 "channels/publish" \
        "{\"channel\": \"$CHANNEL_NAME\", \"content\": \"baseline $i\", \"item_type\": \"message\"}"
    sleep 0.5
done

wait_for "p2 has 2 baseline items" \
    '[ "$(db_query t5-p2 "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$CHANNEL_ID'"'"' AND is_tombstone=0")" -ge 2 ]' 60

echo "  Baseline delivery confirmed."

# -- Step 6: Apply partition (R1 <-> R2) ---------------------------------

echo ""
echo "Step 6: Applying network partition (R1 <-> R2)..."
docker exec t5-r1 iptables -A INPUT -s 172.28.0.21 -j DROP
docker exec t5-r1 iptables -A OUTPUT -d 172.28.0.21 -j DROP
docker exec t5-r2 iptables -A INPUT -s 172.28.0.20 -j DROP
docker exec t5-r2 iptables -A OUTPUT -d 172.28.0.20 -j DROP
echo "  Partition active."

# -- Step 7: Publish during partition ------------------------------------

echo ""
echo "Step 7: Publishing during partition..."
echo "  3 items on P1 (left partition)..."
for i in 3 4 5; do
    api_post t5-p1 "channels/publish" \
        "{\"channel\": \"$CHANNEL_NAME\", \"content\": \"left $i\", \"item_type\": \"message\"}"
    sleep 0.5
done

echo "  2 items on P2 (right partition)..."
for i in 6 7; do
    api_post t5-p2 "channels/publish" \
        "{\"channel\": \"$CHANNEL_NAME\", \"content\": \"right $i\", \"item_type\": \"message\"}"
    sleep 0.5
done

# -- Step 8: Verify partition holds --------------------------------------

echo ""
echo "Step 8: Verifying partition holds (5s)..."
sleep 5

P1_COUNT=$(db_query t5-p1 "SELECT COUNT(*) FROM items WHERE channel_id='$CHANNEL_ID' AND is_tombstone=0")
P2_COUNT=$(db_query t5-p2 "SELECT COUNT(*) FROM items WHERE channel_id='$CHANNEL_ID' AND is_tombstone=0")
echo "  P1 has $P1_COUNT items (expected 5: 2 baseline + 3 during partition)"
echo "  P2 has $P2_COUNT items (expected 4: 2 baseline + 2 during partition)"

# -- Step 9: Heal partition ----------------------------------------------

echo ""
echo "Step 9: Healing partition..."
docker exec t5-r1 iptables -D INPUT -s 172.28.0.21 -j DROP
docker exec t5-r1 iptables -D OUTPUT -d 172.28.0.21 -j DROP
docker exec t5-r2 iptables -D INPUT -s 172.28.0.20 -j DROP
docker exec t5-r2 iptables -D OUTPUT -d 172.28.0.20 -j DROP
echo "  Partition healed."

# -- Step 10: Wait for convergence ---------------------------------------

echo ""
echo "Step 10: Waiting for convergence..."
# Convergence budget: QUIC idle timeout (60s) to detect dead connections
# + peer-share reconnection (5-10s) + pull-sync cycle (10s) = ~80s.
# Use 120s to be safe.
wait_for "p1 has 7 items" \
    '[ "$(db_query t5-p1 "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$CHANNEL_ID'"'"' AND is_tombstone=0")" -ge 7 ]' 120
wait_for "p2 has 7 items" \
    '[ "$(db_query t5-p2 "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$CHANNEL_ID'"'"' AND is_tombstone=0")" -ge 7 ]' 120

# -- Step 11: Assertions -------------------------------------------------

echo ""
echo "Step 11: Running assertions..."

# P6: Convergence -- both nodes have identical item sets
assert_item_count t5-p1 "$CHANNEL_ID" 7
assert_item_count t5-p2 "$CHANNEL_ID" 7
assert_convergence t5-p1 t5-p2 "$CHANNEL_ID"

# P4: Role isolation (bonus)
assert_zero_items t5-b1

# P3: Channel isolation (bonus)
assert_channel_isolation t5-p1 "$CHANNEL_ID"
assert_channel_isolation t5-p2 "$CHANNEL_ID"

# -- Summary --------------------------------------------------------------

print_summary
