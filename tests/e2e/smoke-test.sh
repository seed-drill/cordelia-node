#!/usr/bin/env bash
# Single-Node E2E Smoke Test
#
# Tests the full cordelia lifecycle against the real compiled binary:
#   init -> start -> API exercise -> CLI exercise -> cleanup
#
# Spec: seed-drill/decisions/2026-03-10-testing-strategy-bdd.md (Layer 1)
#
# Usage:
#   cargo build && ./tests/e2e/smoke-test.sh
#   CORDELIA_BIN=target/release/cordelia ./tests/e2e/smoke-test.sh

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CORDELIA_BIN="${CORDELIA_BIN:-$REPO_ROOT/target/debug/cordelia}"
PORT="${SMOKE_TEST_PORT:-19473}"
BASE_URL="http://127.0.0.1:${PORT}/api/v1"
TMPDIR_ROOT="$(mktemp -d)"
CORDELIA_HOME="$TMPDIR_ROOT/cordelia-home"
CONFIG_FILE="$TMPDIR_ROOT/config.toml"
DAEMON_PID=""

PASS=0
FAIL=0
TOTAL=0

# ── Helpers ────────────────────────────────────────────────────────

cleanup() {
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR_ROOT"
}
trap cleanup EXIT

assert_eq() {
    local name="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$expected" = "$actual" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $name (expected '$expected', got '$actual')"
    fi
}

assert_contains() {
    local name="$1" haystack="$2" needle="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$haystack" | grep -q "$needle"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $name (expected to contain '$needle')"
    fi
}

assert_not_empty() {
    local name="$1" value="$2"
    TOTAL=$((TOTAL + 1))
    if [ -n "$value" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $name (expected non-empty value)"
    fi
}

api_post() {
    local endpoint="$1" body="$2"
    curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$body" \
        "$BASE_URL/channels/$endpoint"
}

api_get() {
    local endpoint="$1"
    curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$BASE_URL/$endpoint"
}

wait_for_server() {
    local max_attempts=30
    for i in $(seq 1 $max_attempts); do
        if curl -s -o /dev/null "http://127.0.0.1:${PORT}/api/v1/channels/identity" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    echo "FATAL: Server did not start within ${max_attempts} attempts"
    exit 1
}

# ── Pre-flight ─────────────────────────────────────────────────────

if [ ! -f "$CORDELIA_BIN" ]; then
    echo "FATAL: Binary not found at $CORDELIA_BIN"
    echo "Run: cargo build"
    exit 1
fi

echo "Cordelia Single-Node E2E Smoke Test"
echo "  Binary:  $CORDELIA_BIN"
echo "  Home:    $CORDELIA_HOME"
echo "  Port:    $PORT"
echo ""

# ── Phase 1: Init ──────────────────────────────────────────────────

echo "Phase 1: cordelia init"

# Write a minimal config pointing to our temp directory and port
mkdir -p "$CORDELIA_HOME"
cat > "$CONFIG_FILE" <<TOML
[identity]
entity_id = ""
public_key = ""

[node]
http_port = $PORT
p2p_port = 19474
data_dir = "$CORDELIA_HOME"

[api]
bind_address = "127.0.0.1"

[network]
role = "personal"

[logging]
level = "warn"
TOML

INIT_OUTPUT=$("$CORDELIA_BIN" --config "$CONFIG_FILE" init --name smoke-test --non-interactive --force --show-secrets 2>&1)

assert_contains "init: keypair generated"   "$INIT_OUTPUT" "Ed25519"
assert_contains "init: entity ID"           "$INIT_OUTPUT" "smoke-test_"
assert_contains "init: public key"          "$INIT_OUTPUT" "cordelia_pk1"
assert_contains "init: x25519 key"          "$INIT_OUTPUT" "cordelia_xpk1"
assert_contains "init: node ready"          "$INIT_OUTPUT" "Node is ready"

# Verify files were created
assert_eq "init: identity.key exists" "true" "$([ -f "$CORDELIA_HOME/identity.key" ] && echo true || echo false)"
assert_eq "init: cordelia.db exists"  "true" "$([ -f "$CORDELIA_HOME/cordelia.db" ] && echo true || echo false)"
assert_eq "init: node-token exists"   "true" "$([ -f "$CORDELIA_HOME/node-token" ] && echo true || echo false)"

# Read bearer token for API calls
TOKEN=$(cat "$CORDELIA_HOME/node-token")
assert_not_empty "init: token non-empty" "$TOKEN"

echo "  $PASS/$TOTAL passed"

# ── Phase 2: Status (offline) ─────────────────────────────────────

echo "Phase 2: cordelia status (offline)"

STATUS_OUTPUT=$("$CORDELIA_BIN" --config "$CONFIG_FILE" status 2>&1)
assert_contains "status: version"     "$STATUS_OUTPUT" "Cordelia v"
assert_contains "status: entity"      "$STATUS_OUTPUT" "smoke-test_"
assert_contains "status: public key"  "$STATUS_OUTPUT" "cordelia_pk1"

echo "  $PASS/$TOTAL passed"

# ── Phase 3: Start daemon ─────────────────────────────────────────

echo "Phase 3: cordelia start"

"$CORDELIA_BIN" --config "$CONFIG_FILE" start &
DAEMON_PID=$!
wait_for_server

assert_eq "start: daemon running" "true" "$(kill -0 $DAEMON_PID 2>/dev/null && echo true || echo false)"

echo "  $PASS/$TOTAL passed"

# ── Phase 4: Identity endpoint ─────────────────────────────────────

echo "Phase 4: API -- identity"

RESP=$(api_post "identity" "{}")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

assert_eq      "identity: status 200"      "200" "$HTTP_CODE"
assert_contains "identity: ed25519 key"     "$BODY" "cordelia_pk1"
assert_contains "identity: x25519 key"      "$BODY" "cordelia_xpk1"

echo "  $PASS/$TOTAL passed"

# ── Phase 5: Subscribe + Publish + Listen ──────────────────────────

echo "Phase 5: API -- subscribe, publish, listen"

# Subscribe
RESP=$(api_post "subscribe" '{"channel":"smoke-channel","mode":"realtime","access":"open"}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "subscribe: status 200"     "200" "$HTTP_CODE"
assert_contains "subscribe: channel name"   "$BODY" "smoke-channel"
CHANNEL_ID=$(echo "$BODY" | jq -r '.channel_id // empty')
assert_not_empty "subscribe: channel_id"    "$CHANNEL_ID"

# Publish
RESP=$(api_post "publish" '{"channel":"smoke-channel","content":{"text":"hello from smoke test"},"item_type":"message"}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "publish: status 200"       "200" "$HTTP_CODE"
ITEM_ID=$(echo "$BODY" | jq -r '.item_id // empty')
assert_not_empty "publish: item_id"         "$ITEM_ID"

# Listen
RESP=$(api_post "listen" '{"channel":"smoke-channel","limit":10}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "listen: status 200"        "200" "$HTTP_CODE"
ITEMS_COUNT=$(echo "$BODY" | jq '.items | length')
assert_eq       "listen: 1 item"            "1" "$ITEMS_COUNT"
CONTENT_TEXT=$(echo "$BODY" | jq -r '.items[0].content.text // empty')
assert_eq       "listen: content decrypted" "hello from smoke test" "$CONTENT_TEXT"
SIG_VALID=$(echo "$BODY" | jq -r '.items[0].signature_valid // empty')
assert_eq       "listen: signature valid"   "true" "$SIG_VALID"

echo "  $PASS/$TOTAL passed"

# ── Phase 6: Search ────────────────────────────────────────────────

echo "Phase 6: API -- search"

RESP=$(api_post "search" '{"channel":"smoke-channel","query":"smoke test","limit":10}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "search: status 200"        "200" "$HTTP_CODE"
SEARCH_TOTAL=$(echo "$BODY" | jq '.total // 0')
assert_eq       "search: found 1 result"    "1" "$SEARCH_TOTAL"

echo "  $PASS/$TOTAL passed"

# ── Phase 7: Channel info + list ───────────────────────────────────

echo "Phase 7: API -- info, list"

RESP=$(api_post "info" '{"channel":"smoke-channel"}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "info: status 200"          "200" "$HTTP_CODE"
assert_contains "info: exists true"         "$BODY" '"exists":true'

RESP=$(api_post "list" '{}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "list: status 200"          "200" "$HTTP_CODE"
LIST_COUNT=$(echo "$BODY" | jq '.channels | length')
assert_eq       "list: 1 channel"           "1" "$LIST_COUNT"

echo "  $PASS/$TOTAL passed"

# ── Phase 8: DM ────────────────────────────────────────────────────

echo "Phase 8: API -- DM"

# Generate a peer key (just use a dummy bech32 key for the DM endpoint)
# We need a valid Ed25519 public key. Use a known test vector.
# Create a second identity to get a valid peer key
PEER_DIR="$TMPDIR_ROOT/peer"
mkdir -p "$PEER_DIR"
PEER_CONFIG="$TMPDIR_ROOT/peer-config.toml"
cat > "$PEER_CONFIG" <<TOML
[identity]
entity_id = ""
public_key = ""
[node]
http_port = 19999
p2p_port = 19998
[storage]
data_dir = "$PEER_DIR"
[api]
bind_address = "127.0.0.1"
[network]
role = "personal"
[logging]
level = "warn"
TOML
PEER_INIT=$("$CORDELIA_BIN" --config "$PEER_CONFIG" init --name peer --non-interactive 2>&1)
PEER_PK=$(echo "$PEER_INIT" | grep "Public key:" | awk '{print $NF}')

RESP=$(api_post "dm" "{\"peer\":\"$PEER_PK\"}")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "dm: status 200"            "200" "$HTTP_CODE"
assert_contains "dm: is_new true"           "$BODY" '"is_new":true'

RESP=$(api_post "list-dms" '{}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "list-dms: status 200"      "200" "$HTTP_CODE"
DM_COUNT=$(echo "$BODY" | jq '.dms | length')
assert_eq       "list-dms: 1 DM"            "1" "$DM_COUNT"

echo "  $PASS/$TOTAL passed"

# ── Phase 9: Group ─────────────────────────────────────────────────

echo "Phase 9: API -- group"

RESP=$(api_post "group" '{"mode":"realtime"}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "group: status 200"         "200" "$HTTP_CODE"
GROUP_ID=$(echo "$BODY" | jq -r '.channel_id // empty')
assert_not_empty "group: channel_id"        "$GROUP_ID"

RESP=$(api_post "list-groups" '{}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "list-groups: status 200"   "200" "$HTTP_CODE"
GROUP_COUNT=$(echo "$BODY" | jq '.groups | length')
assert_eq       "list-groups: 1 group"      "1" "$GROUP_COUNT"

echo "  $PASS/$TOTAL passed"

# ── Phase 10: Delete item ──────────────────────────────────────────

echo "Phase 10: API -- delete-item"

RESP=$(api_post "delete-item" "{\"channel\":\"smoke-channel\",\"item_id\":\"$ITEM_ID\"}")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "delete: status 200"        "200" "$HTTP_CODE"
assert_contains "delete: ok true"           "$BODY" '"ok":true'

# Verify search no longer returns it
RESP=$(api_post "search" '{"channel":"smoke-channel","query":"smoke test","limit":10}')
BODY=$(echo "$RESP" | sed '$d')
SEARCH_AFTER=$(echo "$BODY" | jq '.total // 0')
assert_eq       "delete: search excludes"   "0" "$SEARCH_AFTER"

echo "  $PASS/$TOTAL passed"

# ── Phase 11: PSK rotation ────────────────────────────────────────

echo "Phase 11: API -- rotate-psk"

RESP=$(api_post "rotate-psk" '{"channel":"smoke-channel"}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "rotate: status 200"        "200" "$HTTP_CODE"
NEW_VER=$(echo "$BODY" | jq '.new_key_version // 0')
assert_eq       "rotate: key_version 2"     "2" "$NEW_VER"

echo "  $PASS/$TOTAL passed"

# ── Phase 12: Unsubscribe ─────────────────────────────────────────

echo "Phase 12: API -- unsubscribe"

RESP=$(api_post "unsubscribe" '{"channel":"smoke-channel"}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "unsub: status 200"         "200" "$HTTP_CODE"
assert_contains "unsub: ok true"            "$BODY" '"ok":true'

# Verify channel gone from list
RESP=$(api_post "list" '{}')
BODY=$(echo "$RESP" | sed '$d')
LIST_AFTER=$(echo "$BODY" | jq '.channels | length')
assert_eq       "unsub: channel removed"    "0" "$LIST_AFTER"

echo "  $PASS/$TOTAL passed"

# ── Phase 13: Metrics endpoint ─────────────────────────────────────

echo "Phase 13: API -- metrics (Prometheus)"

RESP=$(api_get "metrics")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
assert_eq       "metrics: status 200"       "200" "$HTTP_CODE"
assert_contains "metrics: uptime"           "$BODY" "cordelia_uptime_seconds"
assert_contains "metrics: channels"         "$BODY" "cordelia_channels_subscribed"
assert_contains "metrics: storage"          "$BODY" "cordelia_storage_bytes"
assert_contains "metrics: sync errors"      "$BODY" "cordelia_sync_errors_total"
assert_contains "metrics: peers hot"        "$BODY" "cordelia_peers_hot"
assert_contains "metrics: peers warm"       "$BODY" "cordelia_peers_warm"

echo "  $PASS/$TOTAL passed"

# ── Phase 14: Auth enforcement ─────────────────────────────────────

echo "Phase 14: Auth enforcement"

NO_AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -d '{}' \
    "$BASE_URL/channels/identity")
assert_eq "auth: no token -> 401" "401" "$NO_AUTH_CODE"

BAD_AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer wrong-token" \
    -H "Content-Type: application/json" \
    -d '{}' \
    "$BASE_URL/channels/identity")
assert_eq "auth: bad token -> 401" "401" "$BAD_AUTH_CODE"

echo "  $PASS/$TOTAL passed"

# ── Phase 15: CLI commands ─────────────────────────────────────────

echo "Phase 15: CLI commands"

CHANNELS_OUTPUT=$("$CORDELIA_BIN" --config "$CONFIG_FILE" channels 2>&1)
assert_contains "cli: channels header"      "$CHANNELS_OUTPUT" "CHANNEL"

STATS_OUTPUT=$("$CORDELIA_BIN" --config "$CONFIG_FILE" stats 2>&1)
assert_contains "cli: stats storage"        "$STATS_OUTPUT" "Storage:"

PEERS_OUTPUT=$("$CORDELIA_BIN" --config "$CONFIG_FILE" peers 2>&1)
assert_contains "cli: peers header"         "$PEERS_OUTPUT" "ENTITY"

echo "  $PASS/$TOTAL passed"

# ── Summary ────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════"
echo "  Smoke Test: $PASS/$TOTAL passed, $FAIL failed"
echo "════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
