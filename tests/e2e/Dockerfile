# Cordelia E2E test container
# Single image for all node roles (personal, bootnode, relay).
# Role determined by config.toml at runtime.
#
# Build:
#   cargo build --release --target x86_64-unknown-linux-gnu
#   docker build -t cordelia-test:latest -f tests/e2e/Dockerfile \
#     --build-arg BINARY=target/x86_64-unknown-linux-gnu/release/cordelia .
#
# Spec: seed-drill/specs/topology-e2e.md §2.2

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates sqlite3 iproute2 iptables curl jq \
    && rm -rf /var/lib/apt/lists/*

VOLUME /data/cordelia
ENV CORDELIA_DATA_DIR=/data/cordelia

# P2P (QUIC/UDP) + REST API (TCP, localhost only inside container)
EXPOSE 9474/udp 9473/tcp

# Binary COPY last -- this layer changes every build
ARG BINARY=cordelia
COPY ${BINARY} /usr/local/bin/cordelia
RUN chmod 755 /usr/local/bin/cordelia

# Entrypoint handles init + config copy + start
COPY tests/e2e/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
