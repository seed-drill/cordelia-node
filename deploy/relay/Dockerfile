# Cordelia relay image. One image for every relay; the config is chosen at
# run time with CORDELIA_CONFIG (see deploy/relay/README.md).
#
# Build (from the repository root):
#   docker build -t cordelia-relay -f deploy/relay/Dockerfile .
#
# Nothing secret is in the image: the node's identity key is created on
# first start, on the /data volume, and never leaves it.

# Keep in sync with rust-toolchain.toml. bookworm matches the runtime image.
FROM rust:1.98.1-slim-bookworm AS builder

WORKDIR /build
COPY . .
RUN cargo build --release --locked --bin cordelia

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/cordelia /usr/local/bin/cordelia
COPY deploy/relay/relay1.toml deploy/relay/relay2.toml /etc/cordelia/
COPY deploy/relay/entrypoint.sh /usr/local/bin/cordelia-relay

ENV CORDELIA_DATA_DIR=/data/cordelia \
    CORDELIA_CONFIG=/etc/cordelia/relay1.toml

VOLUME /data
EXPOSE 9474/udp

ENTRYPOINT ["/usr/local/bin/cordelia-relay"]
