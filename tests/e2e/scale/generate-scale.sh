#!/bin/bash
# Generate Docker Compose + configs for zone-based scale testing.
# Usage: generate-scale.sh <total_nodes> [bootnodes] [relays] [zone_size]
#
# Zone model: personal nodes grouped into neighborhoods of ZONE_SIZE.
# Each zone is a separate Docker network. Relays bridge zone <-> internet.
# Bootnodes present on internet + all zones for discovery.
#
# Example: generate-scale.sh 500 2 10 50
#   488 personal / 50 per zone = 10 zones
#   10 relays (1 per zone), 2 bootnodes on all networks
#   12 Docker networks total (1 internet + 10 home + 1 spare)
#
# IP scheme per zone (172.28.{zone}.0/24):
#   .10-.19  bootnodes
#   .20-.29  relays
#   .30-.79  personal nodes (max 50 per zone)

set -euo pipefail

TOTAL=${1:-20}
BOOTNODES=${2:-2}
RELAYS=${3:-3}
ZONE_SIZE=${4:-50}
PERSONAL=$((TOTAL - BOOTNODES - RELAYS))

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$SCRIPT_DIR/s${TOTAL}"
COMPOSE="$OUT_DIR/s${TOTAL}.yml"
CONFIG_DIR="$OUT_DIR/configs"

mkdir -p "$CONFIG_DIR"

# Calculate zones
NUM_ZONES=$(( (PERSONAL + ZONE_SIZE - 1) / ZONE_SIZE ))
# Ensure at least as many relays as zones (1 relay per zone minimum)
if [ "$RELAYS" -lt "$NUM_ZONES" ]; then
    echo "WARNING: $RELAYS relays < $NUM_ZONES zones. Some zones will share relays."
fi

echo "Generating S${TOTAL}: ${BOOTNODES}B + ${RELAYS}R + ${PERSONAL}P = ${TOTAL} nodes"
echo "  Zones: $NUM_ZONES (${ZONE_SIZE} personal/zone)"
echo "  Networks: 1 internet + $NUM_ZONES home zones"

# Bootnode IPs on internet network
bootnode_ips_internet=()
for i in $(seq 0 $((BOOTNODES - 1))); do
    bootnode_ips_internet+=("172.28.0.$((10 + i))")
done

# Assign relays to zones (round-robin)
declare -a zone_relays
for z in $(seq 0 $((NUM_ZONES - 1))); do
    zone_relays[$z]=""
done
for i in $(seq 0 $((RELAYS - 1))); do
    z=$((i % NUM_ZONES))
    if [ -z "${zone_relays[$z]}" ]; then
        zone_relays[$z]="$((i + 1))"
    else
        zone_relays[$z]="${zone_relays[$z]} $((i + 1))"
    fi
done

# Generate bootnode configs (unchanged -- bootstrap via internet)
for i in $(seq 0 $((BOOTNODES - 1))); do
    name="b$((i + 1))"
    cat > "$CONFIG_DIR/${name}.toml" << TOML
# Scale bootnode (internet + all home zones)
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

# Generate relay configs (bootstrap via B1 on internet)
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
# Scale relay (internet + assigned home zone)
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

# Generate personal node configs (zone-local bootnode + relay IPs)
personal_idx=0
for z in $(seq 0 $((NUM_ZONES - 1))); do
    zone_num=$((z + 1))
    # First relay assigned to this zone
    first_relay=$(echo "${zone_relays[$z]}" | awk '{print $1}')
    relay_zone_ip="172.28.${zone_num}.20"
    bootnode_zone_ip="172.28.${zone_num}.10"

    # Personal nodes in this zone
    zone_start=$((z * ZONE_SIZE))
    zone_end=$((zone_start + ZONE_SIZE - 1))
    if [ "$zone_end" -ge "$PERSONAL" ]; then
        zone_end=$((PERSONAL - 1))
    fi

    for p in $(seq "$zone_start" "$zone_end"); do
        name="p$((p + 1))"
        cat > "$CONFIG_DIR/${name}.toml" << TOML
# Scale personal node (home-${zone_num} zone)
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

# Bootnodes: B1 + R${first_relay} on home-${zone_num} zone
[[network.bootnodes]]
addr = "${bootnode_zone_ip}:9474"

[[network.bootnodes]]
addr = "${relay_zone_ip}:9474"

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
        personal_idx=$((personal_idx + 1))
    done
done

# -- Generate Docker Compose ------------------------------------------------

cat > "$COMPOSE" << YAML
# S${TOTAL}: Scale test (${BOOTNODES}B + ${RELAYS}R + ${PERSONAL}P)
# Zone model: 1 internet + ${NUM_ZONES} home zones (${ZONE_SIZE} personal/zone)
name: s${TOTAL}-scale

services:
YAML

# Bootnodes -- on internet + all home zones
for i in $(seq 0 $((BOOTNODES - 1))); do
    name="b$((i + 1))"
    internet_ip="172.28.0.$((10 + i))"

    # Build networks block: internet + all home zones
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
${networks_block}
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:9473/api/v1/health"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 15s

YAML
done

# Relays -- on internet + assigned home zone(s)
for i in $(seq 0 $((RELAYS - 1))); do
    name="r$((i + 1))"
    internet_ip="172.28.0.$((20 + i))"
    assigned_zone=$(( (i % NUM_ZONES) + 1 ))

    networks_block="    networks:
      internet:
        ipv4_address: ${internet_ip}
      home-${assigned_zone}:
        ipv4_address: 172.28.${assigned_zone}.20"

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
${networks_block}
    depends_on:
      b1:
        condition: service_healthy

YAML
done

# Personal nodes -- on their home zone only
personal_idx=0
for z in $(seq 0 $((NUM_ZONES - 1))); do
    zone_num=$((z + 1))
    zone_start=$((z * ZONE_SIZE))
    zone_end=$((zone_start + ZONE_SIZE - 1))
    if [ "$zone_end" -ge "$PERSONAL" ]; then
        zone_end=$((PERSONAL - 1))
    fi

    for p in $(seq "$zone_start" "$zone_end"); do
        name="p$((p + 1))"
        # IP within zone: .30 + offset within zone
        zone_offset=$((p - zone_start))
        ip="172.28.${zone_num}.$((30 + zone_offset))"

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
      home-${zone_num}:
        ipv4_address: ${ip}
    depends_on:
      b1:
        condition: service_healthy

YAML
        personal_idx=$((personal_idx + 1))
    done
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
