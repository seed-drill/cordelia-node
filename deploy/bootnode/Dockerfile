# Cordelia bootnode Docker image
# Build: docker build -t cordelia-bootnode -f deploy/bootnode/Dockerfile .
# Run:   docker run -p 9474:9474/udp -p 9473:9473 cordelia-bootnode

FROM rust:1.83-slim AS builder

WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/cordelia /usr/local/bin/cordelia
COPY deploy/bootnode/config.toml /etc/cordelia/config.toml

RUN mkdir -p /data/cordelia && \
    cordelia init --config /etc/cordelia/config.toml --non-interactive

EXPOSE 9474/udp
EXPOSE 9473/tcp

ENV CORDELIA_DATA_DIR=/data/cordelia

CMD ["cordelia", "start", "--config", "/etc/cordelia/config.toml"]
