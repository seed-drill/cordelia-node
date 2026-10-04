#!/bin/bash
# Container entrypoint for Cordelia E2E test nodes.
# Initialises identity if not present, copies topology config, starts node.
#
# Spec: seed-drill/specs/topology-e2e.md §2.4

set -euo pipefail

CORDELIA_DATA_DIR="${CORDELIA_DATA_DIR:-/data/cordelia}"
NODE_NAME="${NODE_NAME:-test-node}"

# Copy topology-specific config (mounted read-only) BEFORE init
# so that init reads the correct data_dir, ports, etc.
if [ -f /config/config.toml ]; then
    mkdir -p "$CORDELIA_DATA_DIR"
    cp /config/config.toml "$CORDELIA_DATA_DIR/config.toml"
fi

CONFIG="$CORDELIA_DATA_DIR/config.toml"

# A node started with no configuration runs on the defaults, and the
# defaults dial the public relays. A test node is not started so.
if [ ! -f "$CONFIG" ]; then
    echo "FATAL: no configuration at /config/config.toml or $CONFIG." >&2
    echo "A test node is not started on the defaults: they dial the public relays." >&2
    exit 1
fi

# Nor is a personal node whose configuration names no relay: it dials the
# public ones as well. (Personal is also the role of a configuration that
# states none.)
# (The role is the one in the `[network]` table. A `role` in any other
# table is not the node's.)
ROLE=$(awk '
    /^[[:space:]]*\[/ { network = ($0 ~ /^[[:space:]]*\[network\][[:space:]]*(#.*)?$/) }
    network && /^[[:space:]]*role[[:space:]]*=[[:space:]]*"[^"]*"/ {
        sub(/^[^"]*"/, ""); sub(/".*$/, ""); print; exit
    }' "$CONFIG")
if [ "${ROLE:-personal}" = "personal" ] \
    && ! grep -Eq '^[[:space:]]*\[\[network\.bootnodes\]\]' "$CONFIG"; then
    echo "FATAL: $CONFIG is a personal node's and names no relay." >&2
    echo "A test node is not started so: it would dial the public relays." >&2
    exit 1
fi

# Pre-seeded identity: if /keys/lead.identity.key exists and this is a lead
# (not a swarm child), copy it to the data dir BEFORE init so `cordelia init`
# uses the pre-generated key instead of generating a new one.
if [ -f "/keys/lead.identity.key" ] && [ -z "${CORDELIA_SWARM_INDEX:-}" ]; then
    if [ ! -f "$CORDELIA_DATA_DIR/identity.key" ]; then
        mkdir -p "$CORDELIA_DATA_DIR"
        cp /keys/lead.identity.key "$CORDELIA_DATA_DIR/identity.key"
        chmod 600 "$CORDELIA_DATA_DIR/identity.key"
    fi
fi

# Initialise if no identity exists.
# Pre-seeded leads already have identity.key (copied above) but still need
# init to create DB, token, config. cordelia init handles existing identity
# gracefully (loads it, skips keygen).
NEEDS_INIT=false
if [ ! -f "$CORDELIA_DATA_DIR/identity.key" ]; then
    NEEDS_INIT=true
elif [ ! -f "$CORDELIA_DATA_DIR/cordelia.db" ]; then
    # Pre-seeded identity but no DB yet (lead with mounted key)
    NEEDS_INIT=true
fi

if [ "$NEEDS_INIT" = true ]; then
    if [ -n "${CORDELIA_SWARM_INDEX:-}" ] && [ -n "${CORDELIA_LEAD_IDENTITY:-}" ] && [ -n "${CORDELIA_LEAD_ENTITY_ID:-}" ]; then
        # Swarm nodes use swarm-init with derived identity (§8.2.2)
        cordelia --config "$CONFIG" swarm-init \
            --index "$CORDELIA_SWARM_INDEX" \
            --lead-identity "$CORDELIA_LEAD_IDENTITY" \
            --lead-entity-id "$CORDELIA_LEAD_ENTITY_ID"
    else
        cordelia --config "$CONFIG" init --name "$NODE_NAME" --non-interactive
    fi
fi

# Start node (--config is a top-level arg, must precede subcommand)
exec cordelia --config "$CONFIG" start
