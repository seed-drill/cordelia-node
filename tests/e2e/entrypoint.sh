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
