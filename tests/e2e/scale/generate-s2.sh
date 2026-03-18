#!/bin/bash
# Generate Docker Compose + configs for S2 relay mesh convergence test.
# Usage: generate-s2.sh [relays]
#
# Topology: 2B + R relays + R personal = 2+2R containers, R+1 networks
# Each relay on internet + its own home zone. 1 personal node per zone.
# Isolates relay mesh behaviour from zone fan-out effects.
#
# Relay hot_max = R + 5 (must fit all other relays + bootnodes).
#
# IP scheme per zone (172.28.{zone}.0/24):
#   .10-.11  bootnodes
#   .20      relay (1 per zone)
#   .30      personal (1 per zone)

set -euo pipefail

RELAYS=${1:-20}
BOOTNODES=2
PERSONAL=$RELAYS  # 1 personal per zone
CONTAINER_COUNT=$((BOOTNODES + RELAYS + PERSONAL))
NUM_ZONES=$RELAYS

# Relay hot_max: must fit all other relays + bootnodes
RELAY_HOT_MAX=$((RELAYS + 5))

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/s2-${RELAYS}"
COMPOSE="$OUT_DIR/s2-${RELAYS}.yml"
CONFIG_DIR="$OUT_DIR/configs"

mkdir -p "$CONFIG_DIR"

echo "Generating S2-${RELAYS}: ${BOOTNODES}B + ${RELAYS}R + ${PERSONAL}P = ${CONTAINER_COUNT} nodes"
echo "  Zones: $NUM_ZONES (1 personal/zone, 1 relay/zone)"
echo "  Networks: 1 internet + $NUM_ZONES home zones"
echo "  Relay hot_max: $RELAY_HOT_MAX"

# Bootnode IPs on internet
bootnode_ips_internet=()
for i in $(seq 0 $((BOOTNODES - 1))); do
    bootnode_ips_internet+=("172.28.0.$((10 + i))")
done

# ── Node configs ─────────────────────────────────────────────────────

# Bootnodes: internet + all home zones, high hot_max
for i in $(seq 0 $((BOOTNODES - 1))); do
    name="b$((i + 1))"
    cat > "$CONFIG_DIR/${name}.toml" << TOML
# S2 bootnode (internet + all home zones)
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
hot_max = $((RELAY_HOT_MAX + 10))
warm_min = 5
warm_max = $((RELAY_HOT_MAX + 50))
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

# Relays: internet + own home zone, bootstrap via all bootnodes
for i in $(seq 0 $((RELAYS - 1))); do
    name="r$((i + 1))"
    bootnode_entries=""
    for bip in "${bootnode_ips_internet[@]}"; do
        bootnode_entries+="
[[network.bootnodes]]
addr = \"${bip}:9474\"
"
    done
    cat > "$CONFIG_DIR/${name}.toml" << TOML
# S2 relay (internet + home-$((i + 1)))
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
hot_max = ${RELAY_HOT_MAX}
warm_min = 10
warm_max = $((RELAY_HOT_MAX + 50))
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

# Personal nodes: 1 per zone, bootstrap from zone bootnode + relay
for z in $(seq 1 "$NUM_ZONES"); do
    name="p${z}"
    relay_zone_ip="172.28.${z}.20"
    bootnode_zone_ip="172.28.${z}.10"

    cat > "$CONFIG_DIR/${name}.toml" << TOML
# S2 personal node (home-${z})
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
addr = "${bootnode_zone_ip}:9474"

[[network.bootnodes]]
addr = "${relay_zone_ip}:9474"

[governor]
hot_min = 2
hot_max = 5
warm_min = 2
warm_max = 10
cold_max = 50
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

# ── Docker Compose ───────────────────────────────────────────────────

cat > "$COMPOSE" << YAML
# S2-${RELAYS}: Relay mesh convergence test (${BOOTNODES}B + ${RELAYS}R + ${PERSONAL}P)
# 1 relay/zone, 1 personal/zone. Isolates relay mesh from zone fan-out.
name: s2-${RELAYS}-mesh

services:
YAML

# Bootnodes -- on internet + all home zones
for i in $(seq 0 $((BOOTNODES - 1))); do
    name="b$((i + 1))"
    internet_ip="172.28.0.$((10 + i))"

    networks_block="    networks:
      internet:
        ipv4_address: ${internet_ip}"
    for z in $(seq 1 "$NUM_ZONES"); do
        networks_block+="
      home-${z}:
        ipv4_address: 172.28.${z}.$((10 + i))"
    done

    cat >> "$COMPOSE" << YAML
  ${name}:
    image: \${CORDELIA_IMAGE:-cordelia-test:latest}
    container_name: s2-${RELAYS}-${name}
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
${networks_block}
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:9473/api/v1/health"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 15s

YAML
done

# Relays -- on internet + own home zone
for i in $(seq 0 $((RELAYS - 1))); do
    name="r$((i + 1))"
    internet_ip="172.28.0.$((20 + i))"
    zone_num=$((i + 1))

    cat >> "$COMPOSE" << YAML
  ${name}:
    image: \${CORDELIA_IMAGE:-cordelia-test:latest}
    container_name: s2-${RELAYS}-${name}
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
      internet:
        ipv4_address: ${internet_ip}
      home-${zone_num}:
        ipv4_address: 172.28.${zone_num}.20
    depends_on:
      b1:
        condition: service_healthy

YAML
done

# Personal nodes -- 1 per zone, keys mounted
for z in $(seq 1 "$NUM_ZONES"); do
    name="p${z}"
    ip="172.28.${z}.30"

    cat >> "$COMPOSE" << YAML
  ${name}:
    image: \${CORDELIA_IMAGE:-cordelia-test:latest}
    container_name: s2-${RELAYS}-${name}
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
      home-${z}:
        ipv4_address: ${ip}
    depends_on:
      b1:
        condition: service_healthy

YAML
done

# Networks
cat >> "$COMPOSE" << YAML
networks:
  internet:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/24
YAML

for z in $(seq 1 "$NUM_ZONES"); do
    cat >> "$COMPOSE" << YAML
  home-${z}:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.${z}.0/24
YAML
done

echo "Generated: $COMPOSE ($(wc -l < "$COMPOSE") lines)"
echo "Configs: $CONFIG_DIR/ ($(ls "$CONFIG_DIR" | wc -l) files)"
echo "Networks: 1 internet + $NUM_ZONES home zones"
