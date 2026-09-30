#!/bin/sh
# Start a relay: create its identity on first start (on the /data volume),
# then run the node. Idempotent: later starts reuse the same identity, so
# the relay keeps its node ID across restarts and redeploys.
set -eu

CONFIG="${CORDELIA_CONFIG:-/etc/cordelia/relay1.toml}"

if [ ! -f "${CORDELIA_DATA_DIR}/identity.key" ]; then
    echo "cordelia-relay: first start, creating identity in ${CORDELIA_DATA_DIR}"
    cordelia --config "$CONFIG" init --non-interactive --name relay
fi

echo "cordelia-relay: node key $(cordelia --config "$CONFIG" id)"
exec cordelia --config "$CONFIG" start
