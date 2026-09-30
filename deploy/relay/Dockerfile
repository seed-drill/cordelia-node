# Cordelia relay image. One image for every relay; the config is chosen at
# run time with CORDELIA_CONFIG. See deploy/relay/README.md.
#
# The binary comes from one of two places, chosen with CORDELIA_SOURCE:
#   release  a published release's static Linux binary, checked against the
#            sha256 you pin (CORDELIA_VERSION, CORDELIA_SHA256). Preferred.
#   build    compiled here from this checkout. Record the commit you deploy
#            (`git rev-parse HEAD`); use this only before a release exists.
#
# Base images are pinned by digest. Nothing secret is in the image: the
# relay's identity key is created on first start, on the /data volume.
# Needs BuildKit (the default for `docker compose` and `docker build`).

ARG CORDELIA_SOURCE=release

# ── The binary, from a release ─────────────────────────────────────
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS bin-release
ARG CORDELIA_VERSION
ARG CORDELIA_SHA256
ARG CORDELIA_ARCH=amd64
ARG CORDELIA_URL=https://github.com/seed-drill/cordelia-node/releases/download/${CORDELIA_VERSION}/cordelia-linux-${CORDELIA_ARCH}
RUN if [ -z "$CORDELIA_VERSION" ] || [ -z "$CORDELIA_SHA256" ]; then \
        echo "Set CORDELIA_VERSION and CORDELIA_SHA256, or CORDELIA_SOURCE=build" >&2; exit 1; \
    fi \
    && apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL -o /cordelia "$CORDELIA_URL" \
    && echo "$CORDELIA_SHA256  /cordelia" | sha256sum -c - \
    && chmod 755 /cordelia

# ── The binary, built from this checkout ───────────────────────────
# Keep the toolchain in step with rust-toolchain.toml.
FROM rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS bin-build
WORKDIR /build
COPY . .
RUN cargo build --release --locked --bin cordelia && cp target/release/cordelia /cordelia

FROM bin-${CORDELIA_SOURCE} AS bin

# ── The relay ──────────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

# An unprivileged user owns /data, so a new named volume starts out owned
# by it too.
RUN useradd --system --user-group --uid 10001 --home-dir /data --no-create-home \
        --shell /usr/sbin/nologin cordelia \
    && mkdir -p /data && chown cordelia:cordelia /data

COPY --from=bin /cordelia /usr/local/bin/cordelia
COPY deploy/relay/relay1.toml deploy/relay/relay2.toml /etc/cordelia/
COPY deploy/relay/entrypoint.sh /usr/local/bin/cordelia-relay

ENV CORDELIA_DATA_DIR=/data/cordelia \
    CORDELIA_CONFIG=/etc/cordelia/relay1.toml \
    HOME=/data

USER cordelia
VOLUME /data
EXPOSE 9474/udp

ENTRYPOINT ["/usr/local/bin/cordelia-relay"]
