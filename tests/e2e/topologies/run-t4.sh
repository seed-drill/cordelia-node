#!/bin/bash
# T4: Multi-Relay (3P + 1B + 2R)
#
# Properties tested:
#   P1 (Delivery): items reach all personal nodes through multiple relays
#   P5 (Loop termination): relay re-push bounded, no infinite loops
#
# Spec: seed-drill/specs/topology-e2e.md §3.5

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/t4.yml"
PROJECT="t4-multi-relay"

# Source assertion framework
source "$E2E_DIR/assertions/common.sh"

# -- Setup ---------------------------------------------------------------

echo "T4: Multi-Relay (3P + 1B + 2R)"
echo "--------------------------------"

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
    mkdir -p "$E2E_DIR/logs/t4"
    for node in b1 r1 r2 p1 p2 p3; do
        docker logs "t4-$node" > "$E2E_DIR/logs/t4/$node.log" 2>&1 || true
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
for node in b1 r1 r2 p1 p2 p3; do
    wait_for "$node healthy" \
        "docker exec t4-$node curl -sf http://localhost:9473/api/v1/health" 30
done

# -- Step 3: Wait for bootstrap ------------------------------------------

echo ""
echo "Step 3: Waiting for peer discovery..."
for node in p1 p2 p3; do
    wait_for "$node has 1+ hot peers" \
        '[ "$(api_get t4-'"$node"' status | jq -r ".peers_hot // 0")" -ge 1 ]' 30
done
# Zone model: relays must form mesh AND promote personal nodes before items flow.
# R1 needs: B1 + P1 + P2 + R2 = 4 hot. R2 needs: B1 + P3 + R1 = 3 hot.
# R1<->R2 discovery happens via peer-sharing from B1 (takes a few cycles).
wait_for "r1 has 4+ hot peers (b1+p1+p2+r2)" \
    '[ "$(api_get t4-r1 status | jq -r ".peers_hot // 0")" -ge 4 ]' 60
wait_for "r2 has 3+ hot peers (b1+p3+r1)" \
    '[ "$(api_get t4-r2 status | jq -r ".peers_hot // 0")" -ge 3 ]' 60

# -- Step 4: Subscribe to channel ----------------------------------------

echo ""
echo "Step 4: Subscribing to test-channel..."
for node in p1 p2 p3; do
    api_post "t4-$node" "channels/subscribe" \
        "{\"channel\": \"$CHANNEL_NAME\"}" || true
done

# -- Step 5: Publish items -----------------------------------------------

echo ""
echo "Step 5: Publishing 5 items on P1..."
for i in 1 2 3 4 5; do
    api_post t4-p1 "channels/publish" \
        "{\"channel\": \"$CHANNEL_NAME\", \"content\": \"multi-relay test $i\", \"item_type\": \"message\"}"
    sleep 0.5
done

# -- Step 6: Wait for delivery -------------------------------------------

echo ""
echo "Step 6: Waiting for items to arrive..."
# Zone model: items traverse P1->R1->internet->R2->P3 (multi-hop).
# Pull-sync fallback adds sync_interval_realtime_secs latency per hop.
for node in p2 p3; do
    wait_for "$node has 5 items" \
        '[ "$(db_query t4-'"$node"' "SELECT COUNT(*) FROM items WHERE channel_id='"'"'$CHANNEL_ID'"'"' AND is_tombstone=0")" -ge 5 ]' 60
done

# -- Step 7: Assertions --------------------------------------------------

echo ""
echo "Step 7: Running assertions..."

# P1: Delivery -- all 5 items on all personal nodes
assert_item_count t4-p1 "$CHANNEL_ID" 5
assert_item_count t4-p2 "$CHANNEL_ID" 5
assert_item_count t4-p3 "$CHANNEL_ID" 5

# No duplicate items on any personal node
for node in p1 p2 p3; do
    DUP_COUNT=$(db_query "t4-$node" \
        "SELECT COUNT(*) FROM (SELECT item_id FROM items WHERE channel_id='$CHANNEL_ID' GROUP BY item_id HAVING COUNT(*) > 1)")
    if [ "$DUP_COUNT" -eq 0 ]; then
        assert "$node has zero duplicate items" 0
    else
        assert "$node has $DUP_COUNT duplicate item_ids" 1
    fi
done

# P5: Loop termination -- relay push counts are bounded
for relay in r1 r2; do
    PUSHES=$(docker logs "t4-$relay" 2>&1 | grep -c "Item-Push send\|push.*item\|re-push" || true)
    echo "  INFO: $relay push count from logs: $PUSHES"
    if [ "$PUSHES" -le 100 ]; then
        assert "$relay push count bounded ($PUSHES <= 100)" 0
    else
        assert "$relay push count unbounded ($PUSHES > 100)" 1
    fi
done

# P4: Role isolation (bonus)
assert_zero_items t4-b1

# P3: Channel isolation (bonus)
for node in p1 p2 p3; do
    assert_channel_isolation "t4-$node" "$CHANNEL_ID"
done

# -- Summary --------------------------------------------------------------

print_summary
