# Cordelia E2E test container
# Single image for all node roles (personal, bootnode, relay).
# Role determined by config.toml at runtime.
#
# Build (MUST use musl for static linking):
#   cargo build --release --target x86_64-unknown-linux-musl --bin cordelia
#   DOCKER_BUILDKIT=0 docker build --no-cache -t cordelia-test:latest \
#     -f tests/e2e/Dockerfile \
#     --build-arg BINARY=target/x86_64-unknown-linux-musl/release/cordelia .
#
# IMPORTANT: Always use DOCKER_BUILDKIT=0 and --no-cache. The buildx builder
# caches stale layers that contain dynamically-linked binaries, causing
# GLIBC_2.38 errors at runtime. See topology-e2e.md §2.2.
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
RUN chmod 755 /usr/local/bin/cordelia && \
    ldd /usr/local/bin/cordelia 2>&1 | grep -q "statically linked" || \
    (echo "ERROR: Binary is dynamically linked. Use musl target." && exit 1)

# Entrypoint handles init + config copy + start
COPY tests/e2e/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
