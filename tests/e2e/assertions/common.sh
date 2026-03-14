#!/bin/bash
# Shared assertion functions for topology E2E tests.
#
# Spec: seed-drill/specs/topology-e2e.md §4.1

TIMEOUT=${ASSERT_TIMEOUT:-30}
POLL_INTERVAL=${ASSERT_POLL:-2}
DB_PATH="/data/cordelia/cordelia.db"
TOKEN_PATH="/data/cordelia/node-token"

PASS=0
FAIL=0
TOTAL=0

# ── Helpers ─────────────────────────────────────────────────────────

# Derive channel_id from human-readable name.
# channels-api.md §3.1: channel_id = hex(SHA-256("cordelia:channel:" + lowercase(name)))
channel_id_for() {
    local name
    name=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    printf '%s' "cordelia:channel:${name}" | sha256sum | cut -d' ' -f1
}

# Wait for a condition to become true, polling at interval.
wait_for() {
    local description="$1"
    local check_cmd="$2"
    local timeout="${3:-$TIMEOUT}"
    local interval="${4:-$POLL_INTERVAL}"
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        if eval "$check_cmd" >/dev/null 2>&1; then
            echo "  OK: $description (${elapsed}s)"
            return 0
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    echo "  TIMEOUT: $description (${timeout}s)"
    return 1
}

# POST to a node's REST API
api_post() {
    local container="$1"
    local endpoint="$2"
    local body
    body="${3:-"{}"}"
    local token
    token=$(docker exec "$container" cat "$TOKEN_PATH" 2>/dev/null)
    docker exec "$container" curl -sf \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$body" \
        "http://localhost:9473/api/v1/$endpoint"
}

# GET from a node's REST API
api_get() {
    local container="$1"
    local endpoint="$2"
    local token
    token=$(docker exec "$container" cat "$TOKEN_PATH" 2>/dev/null)
    docker exec "$container" curl -sf \
        -H "Authorization: Bearer $token" \
        "http://localhost:9473/api/v1/$endpoint"
}

# Query a node's SQLite database
db_query() {
    local container="$1"
    local sql="$2"
    docker exec "$container" sqlite3 "$DB_PATH" "$sql"
}

# ── Assertions ──────────────────────────────────────────────────────

assert() {
    local description="$1"
    local result="$2" # 0 = pass, non-zero = fail
    TOTAL=$((TOTAL + 1))
    if [ "$result" -eq 0 ]; then
        PASS=$((PASS + 1))
        echo "  PASS: $description"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $description"
    fi
}

# Assert item count on a node for a channel
assert_item_count() {
    local container="$1"
    local channel_id="$2"
    local expected="$3"
    local actual
    actual=$(db_query "$container" \
        "SELECT COUNT(*) FROM items WHERE channel_id='$channel_id' AND is_tombstone=0")
    if [ "$actual" -eq "$expected" ] 2>/dev/null; then
        assert "$container has $expected items for channel" 0
    else
        assert "$container has $actual items (expected $expected)" 1
    fi
}

# Assert no items for a channel on a node
assert_no_items() {
    assert_item_count "$1" "$2" 0
}

# Assert node has at least N hot peers
assert_hot_peers() {
    local container="$1"
    local min_peers="$2"
    local actual
    actual=$(api_get "$container" "status" 2>/dev/null | jq -r '.peers_hot // 0')
    if [ "$actual" -ge "$min_peers" ] 2>/dev/null; then
        assert "$container has $actual hot peers (>= $min_peers)" 0
    else
        assert "$container has ${actual:-0} hot peers (expected >= $min_peers)" 1
    fi
}

# Assert zero PSK files (relay/bootnode role isolation)
assert_no_psks() {
    local container="$1"
    local count
    count=$(docker exec "$container" sh -c \
        '[ -d /data/cordelia/channel-keys ] && find /data/cordelia/channel-keys -name "*.key" | wc -l || echo 0')
    if [ "$count" -eq 0 ]; then
        assert "$container has zero PSK files" 0
    else
        assert "$container has $count PSK files (expected 0)" 1
    fi
}

# Assert total items >= expected (any channel)
assert_min_total_items() {
    local container="$1"
    local min_items="$2"
    local actual
    actual=$(db_query "$container" "SELECT COUNT(*) FROM items")
    if [ "$actual" -ge "$min_items" ] 2>/dev/null; then
        assert "$container has $actual stored items (>= $min_items)" 0
    else
        assert "$container has ${actual:-0} stored items (expected >= $min_items)" 1
    fi
}

# Assert zero items stored (bootnode role isolation)
assert_zero_items() {
    local container="$1"
    local count
    count=$(db_query "$container" "SELECT COUNT(*) FROM items")
    if [ "$count" -eq 0 ]; then
        assert "$container stores zero items" 0
    else
        assert "$container stores $count items (expected 0)" 1
    fi
}

# Assert no cross-channel leakage
assert_channel_isolation() {
    local container="$1"; shift
    local in_clause=""
    for cid in "$@"; do
        [ -n "$in_clause" ] && in_clause="${in_clause},"
        in_clause="${in_clause}'${cid}'"
    done
    local count
    count=$(db_query "$container" \
        "SELECT COUNT(*) FROM items WHERE channel_id NOT IN ($in_clause)")
    if [ "$count" -eq 0 ]; then
        assert "$container has no cross-channel items" 0
    else
        assert "$container has $count items from unexpected channels" 1
    fi
}

# Assert convergence: two nodes have identical item sets
assert_convergence() {
    local container_a="$1"
    local container_b="$2"
    local channel_id="$3"
    local items_a items_b
    items_a=$(db_query "$container_a" \
        "SELECT item_id FROM items WHERE channel_id='$channel_id' AND is_tombstone=0 ORDER BY item_id")
    items_b=$(db_query "$container_b" \
        "SELECT item_id FROM items WHERE channel_id='$channel_id' AND is_tombstone=0 ORDER BY item_id")
    if [ "$items_a" = "$items_b" ]; then
        assert "$container_a and $container_b have converged" 0
    else
        assert "convergence: item sets differ ($container_a vs $container_b)" 1
    fi
}

# Assert zero log entries matching a pattern
assert_zero_log_matches() {
    local container="$1"
    local pattern="$2"
    local description="$3"
    local count
    count=$(docker logs "$container" 2>&1 | grep -c "$pattern" || true)
    if [ "$count" -eq 0 ]; then
        assert "$description" 0
    else
        assert "$description ($count matches)" 1
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "═══════════════════════════════════════"
    echo "Results: $PASS passed, $FAIL failed, $TOTAL total"
    echo "═══════════════════════════════════════"
    if [ "$FAIL" -gt 0 ]; then
        return 1
    fi
    return 0
}
