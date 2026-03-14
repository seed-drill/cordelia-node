#!/bin/bash
# Container entrypoint for Cordelia E2E test nodes.
# Initialises identity if not present, copies topology config, starts node.
#
# Spec: seed-drill/specs/topology-e2e.md §2.4

set -euo pipefail

CORDELIA_DATA_DIR="${CORDELIA_DATA_DIR:-/data/cordelia}"
NODE_NAME="${NODE_NAME:-test-node}"

# Initialise if no identity exists
if [ ! -f "$CORDELIA_DATA_DIR/identity.key" ]; then
    cordelia init --name "$NODE_NAME" --non-interactive \
        --config "$CORDELIA_DATA_DIR/config.toml"
fi

# Copy topology-specific config (mounted read-only)
if [ -f /config/config.toml ]; then
    cp /config/config.toml "$CORDELIA_DATA_DIR/config.toml"
fi

# Start node
exec cordelia start --config "$CORDELIA_DATA_DIR/config.toml"
