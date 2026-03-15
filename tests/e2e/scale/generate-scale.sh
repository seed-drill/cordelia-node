#!/bin/bash
# Generate Docker Compose + configs for scale testing.
# Usage: generate-scale.sh <total_nodes> <bootnodes> <relays>
#
# Example: generate-scale.sh 20 2 3
# Creates: 2 bootnodes, 3 relays, 15 personal nodes = 20 total

set -euo pipefail

TOTAL=${1:-20}
BOOTNODES=${2:-2}
RELAYS=${3:-3}
PERSONAL=$((TOTAL - BOOTNODES - RELAYS))

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$SCRIPT_DIR/s${TOTAL}"
COMPOSE="$OUT_DIR/s${TOTAL}.yml"
CONFIG_DIR="$OUT_DIR/configs"

mkdir -p "$CONFIG_DIR"

echo "Generating S${TOTAL}: ${BOOTNODES}B + ${RELAYS}R + ${PERSONAL}P = ${TOTAL} nodes"

# IP scheme: bootnodes 172.28.0.10+, relays 172.28.0.20+, personal 172.28.0.50+
bootnode_ips=()
for i in $(seq 0 $((BOOTNODES - 1))); do
    bootnode_ips+=("172.28.0.$((10 + i))")
done

# Generate bootnode configs
for i in $(seq 0 $((BOOTNODES - 1))); do
    ip="${bootnode_ips[$i]}"
    name="b$((i + 1))"
    cat > "$CONFIG_DIR/${name}.toml" << TOML
[identity]
entity_id = "${name}_test"

[node]
http_port = 9473
p2p_port = 9474
data_dir = "/data/cordelia"

[network]
listen_addr = "0.0.0.0:9474"
role = "bootnode"
allow_private_addresses = true
dns_discovery = ""
bootnodes = []

[governor]
hot_min = 10
hot_max = 20
warm_min = 5
warm_max = 50
cold_max = 200
tick_interval_secs = 2
min_warm_tenure_secs = 5
keepalive_timeout_secs = 30

[api]
bind_address = "127.0.0.1"

[logging]
level = "debug"
TOML
done

# Generate relay configs
for i in $(seq 0 $((RELAYS - 1))); do
    name="r$((i + 1))"
    # Each relay connects to all bootnodes
    bootnode_entries=""
    for bip in "${bootnode_ips[@]}"; do
        bootnode_entries+="
[[network.bootnodes]]
addr = \"${bip}:9474\"
"
    done
    cat > "$CONFIG_DIR/${name}.toml" << TOML
[identity]
entity_id = "${name}_test"

[node]
http_port = 9473
p2p_port = 9474
data_dir = "/data/cordelia"

[network]
listen_addr = "0.0.0.0:9474"
role = "relay"
allow_private_addresses = true
dns_discovery = ""
${bootnode_entries}

[governor]
hot_min = 10
hot_max = 50
warm_min = 10
warm_max = 100
cold_max = 200
tick_interval_secs = 2
min_warm_tenure_secs = 5
keepalive_timeout_secs = 30

[replication]
sync_interval_realtime_secs = 10
tombstone_retention_days = 1
max_batch_size = 50

[api]
bind_address = "127.0.0.1"

[logging]
level = "info"
TOML
done

# Generate personal node configs
for i in $(seq 0 $((PERSONAL - 1))); do
    name="p$((i + 1))"
    # Each personal node connects to first bootnode + first relay
    cat > "$CONFIG_DIR/${name}.toml" << TOML
[identity]
entity_id = "${name}_test"

[node]
http_port = 9473
p2p_port = 9474
data_dir = "/data/cordelia"

[network]
listen_addr = "0.0.0.0:9474"
role = "personal"
push_policy = "subscribers_only"
allow_private_addresses = true
dns_discovery = ""

[[network.bootnodes]]
addr = "${bootnode_ips[0]}:9474"

[[network.bootnodes]]
addr = "172.28.0.20:9474"

[governor]
hot_min = 10
hot_max = 20
warm_min = 5
warm_max = 30
cold_max = 200
tick_interval_secs = 2
min_warm_tenure_secs = 5
keepalive_timeout_secs = 30

[replication]
sync_interval_realtime_secs = 10
tombstone_retention_days = 1
max_batch_size = 50

[api]
bind_address = "127.0.0.1"

[logging]
level = "info"
TOML
done

# Generate Docker Compose
cat > "$COMPOSE" << YAML
# S${TOTAL}: Scale test (${BOOTNODES}B + ${RELAYS}R + ${PERSONAL}P)
name: s${TOTAL}-scale

services:
YAML

# Bootnodes
for i in $(seq 0 $((BOOTNODES - 1))); do
    name="b$((i + 1))"
    ip="${bootnode_ips[$i]}"
    cat >> "$COMPOSE" << YAML
  ${name}:
    image: \${CORDELIA_IMAGE:-cordelia-test:latest}
    container_name: s${TOTAL}-${name}
    hostname: ${name}
    cap_add: [NET_ADMIN]
    environment:
      - NODE_NAME=${name}
      - CORDELIA_DATA_DIR=/data/cordelia
    volumes:
      - ./configs/${name}.toml:/config/config.toml:ro
      - ../../entrypoint.sh:/entrypoint.sh:ro
    entrypoint: ["/bin/bash", "/entrypoint.sh"]
    stop_grace_period: 30s
    networks:
      cordelia-net:
        ipv4_address: ${ip}
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:9473/api/v1/health"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 15s

YAML
done

# Relays
for i in $(seq 0 $((RELAYS - 1))); do
    name="r$((i + 1))"
    ip="172.28.0.$((20 + i))"
    cat >> "$COMPOSE" << YAML
  ${name}:
    image: \${CORDELIA_IMAGE:-cordelia-test:latest}
    container_name: s${TOTAL}-${name}
    hostname: ${name}
    cap_add: [NET_ADMIN]
    environment:
      - NODE_NAME=${name}
      - CORDELIA_DATA_DIR=/data/cordelia
    volumes:
      - ./configs/${name}.toml:/config/config.toml:ro
      - ../../entrypoint.sh:/entrypoint.sh:ro
    entrypoint: ["/bin/bash", "/entrypoint.sh"]
    stop_grace_period: 30s
    networks:
      cordelia-net:
        ipv4_address: ${ip}
    depends_on:
      b1:
        condition: service_healthy

YAML
done

# Personal nodes
for i in $(seq 0 $((PERSONAL - 1))); do
    name="p$((i + 1))"
    ip="172.28.0.$((50 + i))"
    cat >> "$COMPOSE" << YAML
  ${name}:
    image: \${CORDELIA_IMAGE:-cordelia-test:latest}
    container_name: s${TOTAL}-${name}
    hostname: ${name}
    cap_add: [NET_ADMIN]
    environment:
      - NODE_NAME=${name}
      - CORDELIA_DATA_DIR=/data/cordelia
    volumes:
      - ./configs/${name}.toml:/config/config.toml:ro
      - ../../entrypoint.sh:/entrypoint.sh:ro
      - ../keys:/data/cordelia/channel-keys
    entrypoint: ["/bin/bash", "/entrypoint.sh"]
    stop_grace_period: 30s
    networks:
      cordelia-net:
        ipv4_address: ${ip}
    depends_on:
      b1:
        condition: service_healthy

YAML
done

# Network
cat >> "$COMPOSE" << YAML
networks:
  cordelia-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/22
YAML

echo "Generated: $COMPOSE ($(wc -l < "$COMPOSE") lines)"
echo "Configs: $CONFIG_DIR/ ($(ls "$CONFIG_DIR" | wc -l) files)"
