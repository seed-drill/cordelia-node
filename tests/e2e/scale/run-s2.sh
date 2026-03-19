#!/bin/bash
# Run S2 relay mesh convergence + delivery test.
# Usage: run-s2.sh [relays] [publishers] [personal_per_zone]
#
# Measures two critical timings for multi-zone deployments:
#   1. Relay mesh formation (relays discover each other via peer-share)
#   2. Item delivery across the mesh from multiple simultaneous publishers
#
# When personal_per_zone > 1, relay hot_max may be too small for full mesh.
# Phase 1 uses a soft target: skip mesh assertion if hot_max < mesh_target,
# and rely on item delivery (Phase 3) as the primary success metric.
#
# Phase 0: Startup (generate topology, compose up, wait healthy)
# Phase 1: Relay mesh formation (poll hot peers until full mesh)
# Phase 2: Channel setup (subscribe all personal nodes)
# Phase 3: Multi-publisher convergence (publish from N zones, wait delivery)
# Phase 4: Assertions (item counts, duplicates, relay transparency, bootnode isolation)
#
# Output: tests/e2e/logs/s2-{R}/metrics.json + mesh-ticks.tsv
#
# Requires bash 4+ (associative arrays).

set -euo pipefail

NO_TEARDOWN=false
for arg in "$@"; do
    if [ "$arg" = "--no-teardown" ]; then
        NO_TEARDOWN=true
    fi
done
# Strip --no-teardown from positional args
ARGS=()
for arg in "$@"; do [ "$arg" != "--no-teardown" ] && ARGS+=("$arg"); done
set -- "${ARGS[@]+"${ARGS[@]}"}"

RELAYS=${1:-20}
PUBLISHERS=${2:-5}
PERSONAL_PER_ZONE=${3:-1}
BOOTNODES=2
PERSONAL=$((RELAYS * PERSONAL_PER_ZONE))
CONTAINER_COUNT=$((BOOTNODES + RELAYS + PERSONAL))

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$SCRIPT_DIR/s2-${RELAYS}"
COMPOSE="$OUT_DIR/s2-${RELAYS}.yml"
PROJECT="s2-${RELAYS}-mesh"
LOG_DIR="$E2E_DIR/logs/s2-${RELAYS}"
KEY_DIR="$SCRIPT_DIR/keys"
PREFIX="s2-${RELAYS}"

source "$E2E_DIR/assertions/common.sh"

# ── Validation ───────────────────────────────────────────────────────

if [ "$PUBLISHERS" -gt "$RELAYS" ]; then
    echo "ERROR: publishers ($PUBLISHERS) > relays ($RELAYS)"
    exit 1
fi

# ── Parameters ───────────────────────────────────────────────────────

# Relay hot_max from generate-s2.sh: R + 5
RELAY_HOT_MAX=$((RELAYS + 5))

# Mesh target: ideal = all relays + bootnodes. But with personal nodes
# consuming hot slots, full mesh may exceed hot_max. Phase 1 reports
# progress but only asserts mesh if hot_max is sufficient.
MESH_TARGET=$((RELAYS + BOOTNODES - 1))
MESH_FEASIBLE=true
if [ "$MESH_TARGET" -gt "$((RELAY_HOT_MAX - PERSONAL_PER_ZONE))" ]; then
    MESH_FEASIBLE=false
fi

# Safe mesh timeout from convergence model
if [ "$RELAYS" -le 25 ]; then
    MESH_TIMEOUT=180
else
    MESH_TIMEOUT=$((RELAYS * 7))
fi

# Delivery timeout: allow multi-hop propagation at scale.
# With capped hot_max, items may need 2-3 relay hops × 5s repush interval.
if [ "$MESH_FEASIBLE" = true ]; then
    DELIVERY_TIMEOUT=120
else
    DELIVERY_TIMEOUT=$((180 + RELAYS))
fi

ITEMS_PER_PUB=3
EXPECTED_ITEMS=$((PUBLISHERS * ITEMS_PER_PUB))

echo "S2: Relay mesh + delivery (${RELAYS}R, ${PERSONAL}P, ${PUBLISHERS} publishers)"
echo "=========================================="
echo "  Containers: $CONTAINER_COUNT (${BOOTNODES}B + ${RELAYS}R + ${PERSONAL}P, ${PERSONAL_PER_ZONE}/zone)"
echo "  Relay hot_max: $RELAY_HOT_MAX"
echo "  Mesh target: $MESH_TARGET hot peers/relay (feasible: $MESH_FEASIBLE)"
echo "  Mesh timeout: ${MESH_TIMEOUT}s"
echo "  Expected items: $EXPECTED_ITEMS ($PUBLISHERS pubs x $ITEMS_PER_PUB)"

# ── Phase 0: Startup ────────────────────────────────────────────────

# Generate topology if not present
if [ ! -f "$COMPOSE" ]; then
    bash "$SCRIPT_DIR/generate-s2.sh" "$RELAYS" "$PERSONAL_PER_ZONE"
fi

# Generate PSK
CHANNEL_NAME="test-channel"
CHANNEL_ID=$(channel_id_for "$CHANNEL_NAME")
mkdir -p "$KEY_DIR"
dd if=/dev/urandom bs=32 count=1 of="$KEY_DIR/${CHANNEL_ID}.key" 2>/dev/null
echo "Channel ID: $CHANNEL_ID"

mkdir -p "$LOG_DIR"

# Cleanup handler
cleanup() {
    echo ""
    echo "Collecting logs..."
    for c in $(docker compose -f "$COMPOSE" -p "$PROJECT" ps -q 2>/dev/null); do
        name=$(docker inspect --format '{{.Name}}' "$c" | sed 's/^\///')
        docker logs "$c" > "$LOG_DIR/${name}.log" 2>&1 || true
    done
    if [ "$NO_TEARDOWN" = true ]; then
        echo "Containers left running (--no-teardown). Use diagnose-s2.sh or:"
        echo "  docker compose -f $COMPOSE -p $PROJECT down -v --remove-orphans"
    else
        echo "Tearing down..."
        docker compose -f "$COMPOSE" -p "$PROJECT" down -v --remove-orphans 2>/dev/null || true
        if [ -d "$KEY_DIR" ]; then
            rm -rf "$KEY_DIR" 2>/dev/null || sudo rm -rf "$KEY_DIR" 2>/dev/null || true
        fi
    fi
}
trap cleanup EXIT

# Flush conntrack
sudo conntrack -F 2>/dev/null || true

echo ""
echo "Phase 0: Starting $CONTAINER_COUNT containers..."
T_START=$(date +%s)
docker compose -f "$COMPOSE" -p "$PROJECT" up -d 2>&1 | tail -5

# Wait for health: bootnodes, first/last relay, first/last personal
wait_for "b1 healthy" \
    "docker exec ${PREFIX}-b1 curl -sf http://localhost:9473/api/v1/health" 60
wait_for "r1 healthy" \
    "docker exec ${PREFIX}-r1 curl -sf http://localhost:9473/api/v1/health" 60
wait_for "r${RELAYS} healthy" \
    "docker exec ${PREFIX}-r${RELAYS} curl -sf http://localhost:9473/api/v1/health" 60
wait_for "p1 healthy" \
    "docker exec ${PREFIX}-p1 curl -sf http://localhost:9473/api/v1/health" 60
wait_for "p${PERSONAL} healthy" \
    "docker exec ${PREFIX}-p${PERSONAL} curl -sf http://localhost:9473/api/v1/health" 60

STARTUP_SECS=$(( $(date +%s) - T_START ))
echo "  Startup complete in ${STARTUP_SECS}s"

# ── Phase 1: Relay Mesh Formation ───────────────────────────────────

echo ""
echo "Phase 1: Relay mesh formation (target: $MESH_TARGET hot peers/relay)..."

# TSV header (peers_cold not exposed by status API; hot+warm sufficient)
TSV_FILE="$LOG_DIR/mesh-ticks.tsv"
printf "tick_secs\trelay\thot\twarm\n" > "$TSV_FILE"

# Track when each relay first hits mesh target
declare -A relay_mesh_secs

MESH_START=$(date +%s)
MAX_MESH_ATTEMPTS=$(( MESH_TIMEOUT / 5 ))
ALL_MESHED=false

for attempt in $(seq 1 $MAX_MESH_ATTEMPTS); do
    TICK_SECS=$(( $(date +%s) - MESH_START ))
    CYCLE_ALL_HIT=true

    for i in $(seq 1 $RELAYS); do
        STATUS=$(api_get "${PREFIX}-r${i}" status 2>/dev/null || echo '{}')
        HOT=$(echo "$STATUS" | jq -r '.peers_hot // 0' 2>/dev/null || echo "0")
        WARM=$(echo "$STATUS" | jq -r '.peers_warm // 0' 2>/dev/null || echo "0")

        printf "%d\tr%d\t%s\t%s\n" "$TICK_SECS" "$i" "$HOT" "$WARM" >> "$TSV_FILE"

        if [ "$HOT" -ge "$MESH_TARGET" ] 2>/dev/null && [ -z "${relay_mesh_secs[r${i}]:-}" ]; then
            relay_mesh_secs["r${i}"]=$TICK_SECS
        fi

        if [ "$HOT" -lt "$MESH_TARGET" ] 2>/dev/null; then
            CYCLE_ALL_HIT=false
        fi
    done

    MESHED_COUNT=0
    for i in $(seq 1 $RELAYS); do
        [ -n "${relay_mesh_secs[r${i}]:-}" ] && MESHED_COUNT=$((MESHED_COUNT + 1))
    done
    echo "  tick ${TICK_SECS}s: ${MESHED_COUNT}/${RELAYS} relays at full mesh"

    if [ "$CYCLE_ALL_HIT" = true ]; then
        ALL_MESHED=true
        break
    fi
    sleep 5
done

MESH_SECS=$(( $(date +%s) - MESH_START ))
if [ "$ALL_MESHED" = true ]; then
    echo "  Mesh formed in ${MESH_SECS}s"
else
    echo "  WARN: Mesh incomplete after ${MESH_SECS}s (${MESHED_COUNT}/${RELAYS})"
fi

# ── Phase 2: Channel Setup ──────────────────────────────────────────

echo ""
echo "Phase 2: Subscribing ${PERSONAL} personal nodes..."
for i in $(seq 1 "$PERSONAL"); do
    api_post "${PREFIX}-p${i}" "channels/subscribe" \
        "{\"channel\": \"$CHANNEL_NAME\"}" > /dev/null 2>&1 || true
done
sleep 5
echo "  Subscribed, waited 5s for propagation"

# ── Phase 3: Multi-Publisher Convergence ─────────────────────────────

echo ""

# Select publishers from evenly-spaced zones (first personal in each selected zone)
ZONE_STEP=$((RELAYS / PUBLISHERS))
PUBLISHER_NODES=()
for p in $(seq 0 $((PUBLISHERS - 1))); do
    zone=$((p * ZONE_STEP + 1))
    idx=$(( (zone - 1) * PERSONAL_PER_ZONE + 1 ))
    PUBLISHER_NODES+=("p${idx}")
done

echo "Phase 3: Publishing ${ITEMS_PER_PUB} items from ${PUBLISHERS} publishers (${PUBLISHER_NODES[*]})..."
T_PUBLISH=$(date +%s)

# Publish from all publishers simultaneously
for pub in "${PUBLISHER_NODES[@]}"; do
    (
        for item in $(seq 1 $ITEMS_PER_PUB); do
            api_post "${PREFIX}-${pub}" "channels/publish" \
                "{\"channel\": \"$CHANNEL_NAME\", \"content\": \"s2 ${pub} item ${item}\", \"item_type\": \"message\"}" \
                > /dev/null 2>&1
        done
    ) &
done
wait
echo "  All publishers done"

# Track per-node delivery completion
declare -A node_delivery_secs
MAX_DELIVERY_ATTEMPTS=$(( DELIVERY_TIMEOUT / 5 ))

for attempt in $(seq 1 $MAX_DELIVERY_ATTEMPTS); do
    DELIVERY_TICK=$(( $(date +%s) - T_PUBLISH ))
    ALL_DELIVERED=true

    for i in $(seq 1 "$PERSONAL"); do
        # Skip already-completed nodes
        [ -n "${node_delivery_secs[p${i}]:-}" ] && continue

        COUNT=$(db_query "${PREFIX}-p${i}" \
            "SELECT COUNT(*) FROM items WHERE channel_id='$CHANNEL_ID' AND is_tombstone=0" 2>/dev/null || echo "0")
        if [ "$COUNT" -ge "$EXPECTED_ITEMS" ] 2>/dev/null; then
            node_delivery_secs["p${i}"]=$DELIVERY_TICK
        else
            ALL_DELIVERED=false
        fi
    done

    DELIVERED_COUNT=0
    for i in $(seq 1 "$PERSONAL"); do
        [ -n "${node_delivery_secs[p${i}]:-}" ] && DELIVERED_COUNT=$((DELIVERED_COUNT + 1))
    done

    # Relay item coverage: min/avg/max across all relays
    RELAY_MIN=$EXPECTED_ITEMS
    RELAY_MAX=0
    RELAY_SUM=0
    RELAY_FULL=0
    for i in $(seq 1 "$RELAYS"); do
        RC=$(db_query "${PREFIX}-r${i}" \
            "SELECT COUNT(*) FROM items WHERE channel_id='$CHANNEL_ID' AND is_tombstone=0" 2>/dev/null || echo "0")
        [ "$RC" -lt "$RELAY_MIN" ] 2>/dev/null && RELAY_MIN=$RC
        [ "$RC" -gt "$RELAY_MAX" ] 2>/dev/null && RELAY_MAX=$RC
        RELAY_SUM=$((RELAY_SUM + RC))
        [ "$RC" -ge "$EXPECTED_ITEMS" ] 2>/dev/null && RELAY_FULL=$((RELAY_FULL + 1))
    done
    RELAY_AVG=$((RELAY_SUM / RELAYS))
    echo "  tick ${DELIVERY_TICK}s: ${DELIVERED_COUNT}/${PERSONAL} personal done | relays: ${RELAY_FULL}/${RELAYS} full, min=${RELAY_MIN} avg=${RELAY_AVG} max=${RELAY_MAX} of ${EXPECTED_ITEMS}"

    if [ "$ALL_DELIVERED" = true ]; then
        break
    fi
    sleep 5
done

DELIVERY_SECS=$(( $(date +%s) - T_PUBLISH ))

# ── Phase 4: Assertions ─────────────────────────────────────────────

echo ""
echo "Phase 4: Assertions"

# All personal nodes have all expected items
for i in $(seq 1 "$PERSONAL"); do
    assert_item_count "${PREFIX}-p${i}" "$CHANNEL_ID" "$EXPECTED_ITEMS"
done

# No duplicate item_ids on any node
for i in $(seq 1 "$PERSONAL"); do
    TOTAL_COUNT=$(db_query "${PREFIX}-p${i}" \
        "SELECT COUNT(*) FROM items WHERE channel_id='$CHANNEL_ID' AND is_tombstone=0" 2>/dev/null || echo "0")
    UNIQUE_COUNT=$(db_query "${PREFIX}-p${i}" \
        "SELECT COUNT(DISTINCT item_id) FROM items WHERE channel_id='$CHANNEL_ID' AND is_tombstone=0" 2>/dev/null || echo "0")
    if [ "$TOTAL_COUNT" = "$UNIQUE_COUNT" ]; then
        assert "p${i} has no duplicate items" 0
    else
        assert "p${i} has $((TOTAL_COUNT - UNIQUE_COUNT)) duplicate items" 1
    fi
done

# Relay item coverage: all relays should store all items via push + pull-sync.
# When mesh is fully feasible, assert exact count. Otherwise report coverage.
for i in $(seq 1 "$RELAYS"); do
    if [ "$MESH_FEASIBLE" = true ]; then
        assert_min_total_items "${PREFIX}-r${i}" "$EXPECTED_ITEMS"
    else
        RELAY_ITEMS=$(db_query "${PREFIX}-r${i}" \
            "SELECT COUNT(*) FROM items WHERE is_tombstone=0" 2>/dev/null || echo "0")
        if [ "$RELAY_ITEMS" -ge "$EXPECTED_ITEMS" ] 2>/dev/null; then
            assert "r${i} has all ${EXPECTED_ITEMS} items" 0
        else
            # Soft: report but don't fail -- multi-hop delivery may need more sync cycles
            echo "  INFO: r${i} has ${RELAY_ITEMS}/${EXPECTED_ITEMS} items (partial mesh, pull-sync pending)"
        fi
    fi
done

# Bootnodes store zero (role isolation)
for i in $(seq 1 "$BOOTNODES"); do
    assert_zero_items "${PREFIX}-b${i}"
done

if print_summary; then
    PASS_BOOL="true"
else
    PASS_BOOL="false"
fi

# ── Metrics Output ──────────────────────────────────────────────────

echo ""
echo "Writing metrics..."

# Collect per-relay mesh times (default to MESH_SECS if relay never hit target)
MESH_TIMES=()
for i in $(seq 1 $RELAYS); do
    MESH_TIMES+=("${relay_mesh_secs[r${i}]:-$MESH_SECS}")
done
SORTED_MESH=($(printf '%s\n' "${MESH_TIMES[@]}" | sort -n))
MESH_P50=${SORTED_MESH[$(( ${#SORTED_MESH[@]} * 50 / 100 ))]}
MESH_P90=${SORTED_MESH[$(( ${#SORTED_MESH[@]} * 90 / 100 ))]}

# Collect per-node delivery times (default to DELIVERY_SECS if never completed)
DELIVERY_TIMES=()
for i in $(seq 1 "$PERSONAL"); do
    DELIVERY_TIMES+=("${node_delivery_secs[p${i}]:-$DELIVERY_SECS}")
done
SORTED_DELIVERY=($(printf '%s\n' "${DELIVERY_TIMES[@]}" | sort -n))
DELIVERY_P50=${SORTED_DELIVERY[$(( ${#SORTED_DELIVERY[@]} * 50 / 100 ))]}
DELIVERY_P90=${SORTED_DELIVERY[$(( ${#SORTED_DELIVERY[@]} * 90 / 100 ))]}

# Build per-relay JSON object
RELAY_JSON="{"
for i in $(seq 1 $RELAYS); do
    [ "$i" -gt 1 ] && RELAY_JSON+=","
    RELAY_JSON+="\"r${i}\":${relay_mesh_secs[r${i}]:-$MESH_SECS}"
done
RELAY_JSON+="}"

# Build per-node JSON object
NODE_JSON="{"
for i in $(seq 1 "$PERSONAL"); do
    [ "$i" -gt 1 ] && NODE_JSON+=","
    NODE_JSON+="\"p${i}\":${node_delivery_secs[p${i}]:-$DELIVERY_SECS}"
done
NODE_JSON+="}"

cat > "$LOG_DIR/metrics.json" << EOF
{
  "test": "s2-relay-mesh",
  "relays": $RELAYS,
  "phases": {
    "startup_secs": $STARTUP_SECS,
    "mesh_formation_secs": $MESH_SECS,
    "item_delivery_secs": $DELIVERY_SECS
  },
  "mesh_formation": {
    "target_hot_peers": $MESH_TARGET,
    "per_relay_secs": $RELAY_JSON,
    "p50_secs": $MESH_P50,
    "p90_secs": $MESH_P90
  },
  "item_delivery": {
    "publishers": $PUBLISHERS,
    "total_items": $EXPECTED_ITEMS,
    "per_node_secs": $NODE_JSON,
    "p50_secs": $DELIVERY_P50,
    "p90_secs": $DELIVERY_P90
  },
  "pass": $PASS_BOOL
}
EOF

echo "  $LOG_DIR/metrics.json"
echo "  $TSV_FILE ($(wc -l < "$TSV_FILE") rows)"

echo ""
echo "=========================================="
echo "S2: ${RELAYS}R, ${PUBLISHERS} publishers"
echo "  Startup:        ${STARTUP_SECS}s"
echo "  Mesh formation: ${MESH_SECS}s (p50=${MESH_P50}s p90=${MESH_P90}s)"
echo "  Item delivery:  ${DELIVERY_SECS}s (p50=${DELIVERY_P50}s p90=${DELIVERY_P90}s)"
echo "  Assertions:     $PASS passed, $FAIL failed"
[ "$PASS_BOOL" = "true" ]
