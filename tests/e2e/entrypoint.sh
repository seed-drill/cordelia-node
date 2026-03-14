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

# Initialise if no identity exists
if [ ! -f "$CORDELIA_DATA_DIR/identity.key" ]; then
    cordelia --config "$CONFIG" init --name "$NODE_NAME" --non-interactive
fi

# Start node (--config is a top-level arg, must precede subcommand)
exec cordelia --config "$CONFIG" start
