#!/bin/bash
# Diagnose a running S2 test. Run after run-s2.sh --no-teardown.
# Usage: diagnose-s2.sh [relays] [personal_per_zone] [channel_id]
#
# Inspects live containers to understand why items aren't converging.

set -euo pipefail

RELAYS=${1:-30}
PERSONAL_PER_ZONE=${2:-7}
CHANNEL_ID=${3:-""}
PREFIX="s2-${RELAYS}"
PERSONAL=$((RELAYS * PERSONAL_PER_ZONE))
DB_PATH="/data/cordelia/cordelia.db"

# Auto-detect channel_id from first relay if not provided
if [ -z "$CHANNEL_ID" ]; then
    CHANNEL_ID=$(docker exec "${PREFIX}-r1" sqlite3 "$DB_PATH" \
        "SELECT channel_id FROM items LIMIT 1" 2>/dev/null || echo "")
    if [ -z "$CHANNEL_ID" ]; then
        CHANNEL_ID=$(docker exec "${PREFIX}-p1" sqlite3 "$DB_PATH" \
            "SELECT channel_id FROM channels LIMIT 1" 2>/dev/null || echo "unknown")
    fi
fi
echo "Channel: $CHANNEL_ID"
echo "Topology: ${RELAYS}R, ${PERSONAL}P (${PERSONAL_PER_ZONE}/zone)"
echo ""

# ── 1. Per-relay item counts + distinct items ─────────────────────
echo "=== Relay item counts ==="
RELAY_ITEMS=()
ALL_ITEM_IDS=""
for i in $(seq 1 "$RELAYS"); do
    COUNT=$(docker exec "${PREFIX}-r${i}" sqlite3 "$DB_PATH" \
        "SELECT COUNT(*) FROM items WHERE channel_id='$CHANNEL_ID'" 2>/dev/null || echo "ERR")
    IDS=$(docker exec "${PREFIX}-r${i}" sqlite3 "$DB_PATH" \
        "SELECT item_id FROM items WHERE channel_id='$CHANNEL_ID' ORDER BY item_id" 2>/dev/null || echo "")
    RELAY_ITEMS+=("$COUNT")
    # Hash the item set for quick comparison
    HASH=$(echo "$IDS" | md5sum 2>/dev/null | cut -c1-8 || echo "?")
    echo "  r${i}: ${COUNT} items (set: ${HASH})"
    ALL_ITEM_IDS="${ALL_ITEM_IDS}${IDS}"$'\n'
done

# Unique items across all relays
TOTAL_UNIQUE=$(echo "$ALL_ITEM_IDS" | sort -u | grep -c . || echo 0)
echo ""
echo "Total unique items across relay mesh: $TOTAL_UNIQUE"

# ── 2. Per-relay log analysis ─────────────────────────────────────
echo ""
echo "=== Relay push/sync activity (last 100 log lines) ==="
for i in $(seq 1 "$RELAYS"); do
    REPUSH_Q=$(docker logs "${PREFIX}-r${i}" 2>&1 | grep -c "repush queued" || echo 0)
    REPUSH_D=$(docker logs "${PREFIX}-r${i}" 2>&1 | grep -c "repush delivered" || echo 0)
    REPUSH_F=$(docker logs "${PREFIX}-r${i}" 2>&1 | grep -c "repush failed\|repush open_bi failed" || echo 0)
    PUSH_IN=$(docker logs "${PREFIX}-r${i}" 2>&1 | grep -c "processed inbound push" || echo 0)
    SYNC_SERVED=$(docker logs "${PREFIX}-r${i}" 2>&1 | grep -c "served sync request\|served channel list" || echo 0)
    SYNC_COMPLETE=$(docker logs "${PREFIX}-r${i}" 2>&1 | grep -c "pull-sync complete" || echo 0)
    PHASE0=$(docker logs "${PREFIX}-r${i}" 2>&1 | grep -c "discovered channels\|served channel list" || echo 0)
    REJECTED=$(docker logs "${PREFIX}-r${i}" 2>&1 | grep -c "rejected\|rate limit exceeded" || echo 0)
    echo "  r${i}: push_in=${PUSH_IN} repush_q=${REPUSH_Q} repush_d=${REPUSH_D} repush_f=${REPUSH_F} sync_served=${SYNC_SERVED} sync_got=${SYNC_COMPLETE} phase0=${PHASE0} rejected=${REJECTED}"
done

# ── 3. Sample personal node status ────────────────────────────────
echo ""
echo "=== Personal node sample (p1, p43, p85, p127, p169 = publishers) ==="
for i in 1 2 3 43 85 127 169 210; do
    [ "$i" -gt "$PERSONAL" ] && continue
    COUNT=$(docker exec "${PREFIX}-p${i}" sqlite3 "$DB_PATH" \
        "SELECT COUNT(*) FROM items WHERE channel_id='$CHANNEL_ID'" 2>/dev/null || echo "ERR")
    SYNC_GOT=$(docker logs "${PREFIX}-p${i}" 2>&1 | grep -c "pull-sync complete" || echo 0)
    ANNOUNCE=$(docker logs "${PREFIX}-p${i}" 2>&1 | grep -c "sent channel announcements" || echo 0)
    echo "  p${i}: ${COUNT} items, sync_got=${SYNC_GOT}, announced=${ANNOUNCE}"
done

# ── 4. Publisher push path ────────────────────────────────────────
echo ""
echo "=== Publisher push targets ==="
for i in 1 43 85 127 169; do
    [ "$i" -gt "$PERSONAL" ] && continue
    PUSH=$(docker logs "${PREFIX}-p${i}" 2>&1 | grep "push batch assembled\|push batch delivered" | tail -3)
    echo "  p${i}:"
    echo "$PUSH" | sed 's/^/    /'
done

# ── 5. Relay hot peer counts ─────────────────────────────────────
echo ""
echo "=== Relay hot peer counts ==="
for i in $(seq 1 "$RELAYS"); do
    HOT=$(docker logs "${PREFIX}-r${i}" 2>&1 | grep "gov: tick complete" | tail -1 | grep -oP 'hot=\K[0-9]+' || echo "?")
    echo "  r${i}: hot=${HOT}"
done

# ── 6. Items only on 1 relay (unique to single relay) ─────────────
echo ""
echo "=== Items with limited distribution ==="
# Build a map of item_id -> relay count
declare -A ITEM_RELAY_COUNT
for i in $(seq 1 "$RELAYS"); do
    IDS=$(docker exec "${PREFIX}-r${i}" sqlite3 "$DB_PATH" \
        "SELECT item_id FROM items WHERE channel_id='$CHANNEL_ID'" 2>/dev/null || echo "")
    while IFS= read -r id; do
        [ -z "$id" ] && continue
        ITEM_RELAY_COUNT["$id"]=$(( ${ITEM_RELAY_COUNT["$id"]:-0} + 1 ))
    done <<< "$IDS"
done
for id in "${!ITEM_RELAY_COUNT[@]}"; do
    count=${ITEM_RELAY_COUNT[$id]}
    if [ "$count" -lt "$RELAYS" ]; then
        echo "  ${id}: on ${count}/${RELAYS} relays"
    fi
done

echo ""
echo "=== Done ==="
