#!/bin/bash
# Build the E2E test Docker image with a statically-linked musl binary.
#
# Usage: ./build-image.sh
#
# Prerequisites:
#   rustup target add x86_64-unknown-linux-musl
#   apt install musl-tools  (on Ubuntu/Debian)
#
# This script handles the full Docker cache/buildx issues that cause
# GLIBC_2.38 errors. See topology-e2e.md §2.2 for details.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Building musl binary..."
cd "$REPO_DIR"
cargo build --release --target x86_64-unknown-linux-musl --bin cordelia

echo "Verifying static linking..."
file target/x86_64-unknown-linux-musl/release/cordelia | grep -q "static" || {
    echo "ERROR: Binary is not statically linked"
    exit 1
}

echo "Cleaning Docker caches..."
docker builder prune -af >/dev/null 2>&1 || true
docker image prune -af >/dev/null 2>&1 || true

echo "Building Docker image (classic builder, no cache)..."
DOCKER_BUILDKIT=0 docker build --no-cache \
    -t cordelia-test:latest \
    -f tests/e2e/Dockerfile \
    --build-arg BINARY=target/x86_64-unknown-linux-musl/release/cordelia \
    .

echo "Verifying image..."
docker run --rm --entrypoint ldd cordelia-test:latest /usr/local/bin/cordelia

echo "Done. Image: cordelia-test:latest"
