#!/bin/sh
# Cordelia install script
# Usage: curl -sSL https://install.seeddrill.ai | sh
#
# Detects platform/architecture, downloads binary from GitHub Releases,
# verifies SHA-256 checksum, installs to ~/.cordelia/bin/, sets up
# system service (launchctl on macOS, systemd on Linux).
#
# Spec: seed-drill/specs/operations.md §1

set -eu

REPO="seed-drill/cordelia-node"
INSTALL_DIR="$HOME/.cordelia/bin"
DATA_DIR="$HOME/.cordelia"
VERSION="${CORDELIA_VERSION:-latest}"

# ── Platform detection ──────────────────────────────────────────────

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Darwin) PLATFORM="darwin" ;;
        Linux)  PLATFORM="linux" ;;
        *)
            echo "Error: unsupported OS: $OS"
            echo "Cordelia supports macOS and Linux. Windows users: install via WSL2."
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)
            echo "Error: unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    BINARY="cordelia-${PLATFORM}-${ARCH}"
    echo "Detected: ${PLATFORM}/${ARCH}"
}

# ── Download ────────────────────────────────────────────────────────

resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        VERSION=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | cut -d'"' -f4)
        if [ -z "$VERSION" ]; then
            echo "Error: could not determine latest version"
            exit 1
        fi
    fi
    echo "Version: ${VERSION}"
}

download_binary() {
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
    BINARY_URL="${BASE_URL}/${BINARY}"
    CHECKSUM_URL="${BASE_URL}/${BINARY}.sha256"

    echo "Downloading ${BINARY}..."
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    curl -sSL -o "${TMPDIR}/cordelia" "$BINARY_URL"
    curl -sSL -o "${TMPDIR}/checksum.sha256" "$CHECKSUM_URL"

    # Verify checksum
    echo "Verifying checksum..."
    EXPECTED=$(cat "${TMPDIR}/checksum.sha256" | awk '{print $1}')
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "${TMPDIR}/cordelia" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL=$(shasum -a 256 "${TMPDIR}/cordelia" | awk '{print $1}')
    else
        echo "Warning: no sha256sum or shasum found, skipping verification"
        ACTUAL="$EXPECTED"
    fi

    if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "Error: checksum mismatch"
        echo "  expected: ${EXPECTED}"
        echo "  actual:   ${ACTUAL}"
        exit 1
    fi
    echo "Checksum verified."
}

# ── Install ─────────────────────────────────────────────────────────

install_binary() {
    mkdir -p "$INSTALL_DIR"

    # Backup existing binary for rollback (§10.4)
    if [ -f "${INSTALL_DIR}/cordelia" ]; then
        cp "${INSTALL_DIR}/cordelia" "${INSTALL_DIR}/cordelia.prev"
        echo "Previous version backed up to cordelia.prev"
    fi

    cp "${TMPDIR}/cordelia" "${INSTALL_DIR}/cordelia"
    chmod +x "${INSTALL_DIR}/cordelia"
    echo "Installed to ${INSTALL_DIR}/cordelia"
}

# ── PATH setup ──────────────────────────────────────────────────────

setup_path() {
    CORDELIA_BIN="$INSTALL_DIR"
    PATH_LINE="export PATH=\"${CORDELIA_BIN}:\$PATH\""

    # Check if already in PATH
    case ":$PATH:" in
        *":${CORDELIA_BIN}:"*) return ;;
    esac

    # Detect shell and RC file
    SHELL_NAME=$(basename "${SHELL:-/bin/sh}")
    case "$SHELL_NAME" in
        zsh)  RC_FILE="$HOME/.zshrc" ;;
        bash) RC_FILE="$HOME/.bashrc" ;;
        *)    RC_FILE="$HOME/.profile" ;;
    esac

    if [ -f "$RC_FILE" ] && grep -q "\.cordelia/bin" "$RC_FILE" 2>/dev/null; then
        return
    fi

    echo "" >> "$RC_FILE"
    echo "# Cordelia" >> "$RC_FILE"
    echo "$PATH_LINE" >> "$RC_FILE"
    echo "Added ${CORDELIA_BIN} to PATH in ${RC_FILE}"
    echo "  Run: source ${RC_FILE}  (or open a new terminal)"
}

# ── System service ──────────────────────────────────────────────────

install_service() {
    case "$PLATFORM" in
        darwin) install_launchctl ;;
        linux)  install_systemd ;;
    esac
}

install_launchctl() {
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST_FILE="${PLIST_DIR}/ai.seeddrill.cordelia.plist"

    mkdir -p "$PLIST_DIR"
    mkdir -p "${DATA_DIR}/logs"

    cat > "$PLIST_FILE" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.seeddrill.cordelia</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/cordelia</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${DATA_DIR}/logs/cordelia.log</string>
    <key>StandardErrorPath</key>
    <string>${DATA_DIR}/logs/cordelia.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>CORDELIA_DATA_DIR</key>
        <string>${DATA_DIR}</string>
    </dict>
</dict>
</plist>
PLIST

    echo "LaunchAgent installed: ${PLIST_FILE}"
    echo "  Start:  launchctl load ${PLIST_FILE}"
    echo "  Stop:   launchctl unload ${PLIST_FILE}"
    echo "  Logs:   tail -f ${DATA_DIR}/logs/cordelia.log"
}

install_systemd() {
    SERVICE_DIR="$HOME/.config/systemd/user"
    SERVICE_FILE="${SERVICE_DIR}/cordelia.service"

    mkdir -p "$SERVICE_DIR"

    cat > "$SERVICE_FILE" << SERVICE
[Unit]
Description=Cordelia - Encrypted pub/sub for AI agents
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/cordelia start
Restart=on-failure
RestartSec=5
Environment=CORDELIA_DATA_DIR=${DATA_DIR}

[Install]
WantedBy=default.target
SERVICE

    echo "systemd user service installed: ${SERVICE_FILE}"
    echo "  Enable: systemctl --user enable cordelia"
    echo "  Start:  systemctl --user start cordelia"
    echo "  Status: systemctl --user status cordelia"
    echo "  Logs:   journalctl --user -u cordelia -f"

    # Check for lingering (required for user services to run without active session)
    if command -v loginctl >/dev/null 2>&1; then
        if ! loginctl show-user "$(whoami)" 2>/dev/null | grep -q "Linger=yes"; then
            echo ""
            echo "  Note: run 'sudo loginctl enable-linger $(whoami)' to keep"
            echo "  the service running after logout."
        fi
    fi
}

# ── Init ────────────────────────────────────────────────────────────

maybe_init() {
    if [ ! -f "${DATA_DIR}/identity.key" ]; then
        echo ""
        echo "Running cordelia init..."
        export PATH="${INSTALL_DIR}:$PATH"
        cordelia init --non-interactive
    fi
}

# ── Main ────────────────────────────────────────────────────────────

main() {
    echo "Cordelia installer"
    echo ""

    detect_platform
    resolve_version
    download_binary
    install_binary
    setup_path
    install_service
    maybe_init

    echo ""
    echo "Cordelia installed successfully."
    echo ""
    echo "Next steps:"
    echo "  cordelia status    # verify installation"
    echo "  cordelia start     # start the node"
    echo ""
}

main "$@"
