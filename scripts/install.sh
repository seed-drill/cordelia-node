#!/bin/sh
# Cordelia install script
# Usage: curl -fsSL https://github.com/seed-drill/cordelia-node/releases/latest/download/install.sh | sh
#        Pre-release: CORDELIA_VERSION=v0.2.0-alpha.9 sh install.sh
#
# Detects platform/architecture, downloads binary from GitHub Releases,
# verifies SHA-256 checksum, installs to ~/.cordelia/bin/, sets up
# system service (launchctl on macOS, systemd on Linux).
#
# Run on a machine whose node is running as that service, it restarts the
# node on the version it installed, and waits until the node says so.
# CORDELIA_NO_RESTART=1 leaves the node as it is.
#
# Where the install completes, the last line it prints is for a program:
#   cordelia-install: installed=<version> running=<version|none|unknown> restart=<done|not-needed|needed|failed>
# running: the version of the node on this machine; none where no node is
# there; unknown where one is there and does not say (it does not answer,
# or is from before nodes said their version).
# It exits 0 where the node that is running, if one is, is the version
# installed, or was left as it is because that was asked; 3 where a node
# is on another version, or does not answer, when it ends; and otherwise
# (1, or the code of the step that failed) where the install did not
# complete: what it printed then says why, and has no such line.
#
# Spec: seed-drill/specs/operations.md §1

set -eu

REPO="seed-drill/cordelia-node"
INSTALL_DIR="$HOME/.cordelia/bin"
DATA_DIR="$HOME/.cordelia"
VERSION="${CORDELIA_VERSION:-latest}"
# A count of seconds from the environment, or the default where it is none.
seconds_or() {
    case "$1" in
        ''|*[!0-9]*|??????*) echo "$2" ;;
        *)           echo "$1" ;;
    esac
}
# How long to wait for a restarted node to say that it is the new version,
# and for a node whose service is running to answer at all.
RESTART_WAIT_SECS=$(seconds_or "${CORDELIA_RESTART_WAIT_SECS:-}" 60)
ANSWER_WAIT_SECS=$(seconds_or "${CORDELIA_ANSWER_WAIT_SECS:-}" 10)

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
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
            | grep '"tag_name"' | head -1 | cut -d'"' -f4) || true
        if [ -z "$VERSION" ]; then
            echo "Error: could not determine the latest release of ${REPO}."
            echo "  If only pre-releases exist, pin one: CORDELIA_VERSION=v0.2.0-alpha.9 sh install.sh"
            echo "  Releases: https://github.com/${REPO}/releases"
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
    # Also the new binary where it was put beside the old one and did not
    # take its place.
    trap 'rm -rf "$TMPDIR"; rm -f "${INSTALL_DIR}/cordelia.new"' EXIT

    if ! curl -fsSL -o "${TMPDIR}/cordelia" "$BINARY_URL"; then
        echo "Error: download failed: ${BINARY_URL}"
        exit 1
    fi
    if ! curl -fsSL -o "${TMPDIR}/checksum.sha256" "$CHECKSUM_URL"; then
        echo "Error: download failed: ${CHECKSUM_URL}"
        exit 1
    fi

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

    # Put the new binary beside the old one, then rename it into place: a
    # running node keeps its old file, and a plain copy over it would fail
    # ("Text file busy").
    cp "${TMPDIR}/cordelia" "${INSTALL_DIR}/cordelia.new"
    chmod +x "${INSTALL_DIR}/cordelia.new"

    # It has to run here before it takes the place of one that does.
    INSTALLED=$("${INSTALL_DIR}/cordelia.new" --version 2>"${TMPDIR}/version.err" \
        | awk '{print $2; exit}') || true
    INSTALLED=$(printf '%s' "$INSTALLED" | tr -cd '0-9A-Za-z.+-') || true
    if [ -z "$INSTALLED" ]; then
        # What the system said of it, where it said anything. (The new
        # binary goes as the script ends.)
        sed 's/^/  /' "${TMPDIR}/version.err" 2>/dev/null || true
        echo "Error: the downloaded binary does not run on this machine. Nothing was changed."
        exit 1
    fi

    # Keep the version before for rollback (§10.4), unless it is this one:
    # a second run of the same version leaves the earlier copy alone.
    if [ -f "${INSTALL_DIR}/cordelia" ] \
        && ! cmp -s "${INSTALL_DIR}/cordelia" "${INSTALL_DIR}/cordelia.new"; then
        cp "${INSTALL_DIR}/cordelia" "${INSTALL_DIR}/cordelia.prev"
        echo "Previous version backed up to cordelia.prev"
    fi

    mv -f "${INSTALL_DIR}/cordelia.new" "${INSTALL_DIR}/cordelia"
    echo "Installed to ${INSTALL_DIR}/cordelia"
}

# Whether the node is running as a service now, which makes this an upgrade.
# A unit that is starting counts: it has a node, or is about to.
service_running() {
    case "$PLATFORM" in
        linux)
            UNIT_STATE=$(systemctl --user is-active cordelia 2>/dev/null) || true
            [ "$UNIT_STATE" = active ] || [ "$UNIT_STATE" = activating ]
            ;;
        darwin) launchctl list 2>/dev/null | grep -q ai.seeddrill.cordelia ;;
        *)      return 1 ;;
    esac
}

# The command just installed, run as the service runs it: with the
# service's data directory, and none of the settings that the shell this
# script runs in may carry for another node.
as_the_service() {
    (
        unset CORDELIA_CONFIG CORDELIA_HTTP_PORT CORDELIA_P2P_PORT CORDELIA_BIND_ADDRESS
        CORDELIA_DATA_DIR="$DATA_DIR"
        export CORDELIA_DATA_DIR
        "${INSTALL_DIR}/cordelia" "$@"
    )
}

# What the command says of the node on this machine, on one line.
node_status() {
    as_the_service status --json 2>/dev/null | tr -d ' \n\t' || true
}

# Whether a node answers on this machine, however it was started.
node_answers() {
    node_status | grep -q '"running":true'
}

# The version of the node that answers on this machine. Nothing where no
# node answers, or where the node is from before nodes said their version.
running_version() {
    node_status | sed -n 's/.*"node_version":"\([^"]*\)".*/\1/p' | tr -cd '0-9A-Za-z.+-'
}

restart_service() {
    case "$PLATFORM" in
        linux)  systemctl --user daemon-reload && systemctl --user restart cordelia ;;
        darwin) launchctl kickstart -k "gui/$(id -u)/ai.seeddrill.cordelia" ;;
        *)      return 1 ;;
    esac
}

# Wait, for so many tries a second apart, until the node answers.
wait_for_answer() {
    waited=0
    until node_answers; do
        if [ "$waited" -ge "$ANSWER_WAIT_SECS" ]; then
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
}

# Wait, for so many tries a second apart, until the node that answers is
# the version just installed.
wait_for_installed() {
    waited=0
    while :; do
        RUNNING=$(running_version)
        if [ "$RUNNING" = "$INSTALLED" ]; then
            return 0
        fi
        if [ "$waited" -ge "$RESTART_WAIT_SECS" ]; then
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
}

# Bring a node that is already running onto the version just installed,
# and set THERE (a node is on this machine), RUNNING (the version it says)
# and RESTART to what was found and done.
settle_running_node() {
    RUNNING=""
    RESTART="not-needed"
    THERE=""

    if service_running; then
        THERE=yes
        RUNNING=$(running_version)
        if [ "$RUNNING" = "$INSTALLED" ]; then
            return
        fi
        if [ "${CORDELIA_NO_RESTART:-}" = 1 ]; then
            RESTART="needed"
            echo "The node was left as it is, as asked. To switch it to this version:"
            echo "  ${RESTART_CMD}"
            return
        fi
        # A node that does not answer may be in the middle of starting: it
        # is given time, and is not restarted while it says nothing.
        if ! wait_for_answer; then
            RESTART="needed"
            echo "The service is running and the node does not answer: it may still be"
            echo "starting. Look before restarting it:"
            echo "  cordelia status"
            echo "  ${LOGS_CMD}"
            echo "If it stays on the previous version: ${RESTART_CMD}"
            return
        fi
        RUNNING=$(running_version)
        if [ "$RUNNING" = "$INSTALLED" ]; then
            return
        fi
        echo "A node is running: restarting it on ${INSTALLED}..."
        if ! restart_service; then
            RESTART="failed"
            RUNNING=$(running_version)
            echo "The restart command failed. The node may not be running now. Look"
            echo "before running it again:"
            echo "  cordelia status"
            echo "  ${LOGS_CMD}"
            echo "  ${RESTART_CMD}"
        elif wait_for_installed; then
            RESTART="done"
            echo "The node was restarted and is running ${INSTALLED}."
        else
            RESTART="failed"
            echo "The node was restarted and does not yet say that it is ${INSTALLED}."
            echo "It may still be starting. Look before restarting it again:"
            echo "  cordelia status"
            echo "  ${LOGS_CMD}"
        fi
        if [ "$RESTART" = failed ] && [ -f "${INSTALL_DIR}/cordelia.prev" ]; then
            echo "The version before is kept as ${INSTALL_DIR}/cordelia.prev"
        fi
        return
    fi

    if node_answers; then
        # A node that was not started as the service this script sets up.
        THERE=yes
        RUNNING=$(running_version)
        if [ "$RUNNING" != "$INSTALLED" ]; then
            RESTART="needed"
            echo "A node is running here that was not started as the service, on another"
            echo "version. Stop it and start it again to switch it to this one."
        fi
    fi
}

# The line for a program, and the exit code that goes with it.
finish() {
    if [ -z "$THERE" ]; then
        SHOWN="none"
    elif [ -z "$RUNNING" ]; then
        SHOWN="unknown"
    else
        SHOWN="$RUNNING"
    fi
    printf 'cordelia-install: installed=%s running=%s restart=%s\n' "$INSTALLED" "$SHOWN" "$RESTART"
    case "$RESTART" in
        failed) exit 3 ;;
        needed) [ "${CORDELIA_NO_RESTART:-}" = 1 ] || exit 3 ;;
    esac
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

    START_CMD="launchctl load ${PLIST_FILE}"
    RESTART_CMD="launchctl kickstart -k gui/$(id -u)/ai.seeddrill.cordelia"
    LOGS_CMD="tail -n 50 ${DATA_DIR}/logs/cordelia.log"
    echo "LaunchAgent installed: ${PLIST_FILE}"
    echo "  Start:  ${START_CMD}"
    echo "  Stop:   launchctl unload ${PLIST_FILE}"
    echo "  Logs:   tail -f ${DATA_DIR}/logs/cordelia.log"
}

install_systemd() {
    SERVICE_DIR="$HOME/.config/systemd/user"
    SERVICE_FILE="${SERVICE_DIR}/cordelia.service"

    mkdir -p "$SERVICE_DIR"

    cat > "$SERVICE_FILE" << SERVICE
[Unit]
Description=Cordelia: your agent's memory on every machine you use
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

    START_CMD="systemctl --user enable --now cordelia"
    RESTART_CMD="systemctl --user daemon-reload && systemctl --user restart cordelia"
    LOGS_CMD="journalctl --user -u cordelia -n 50"
    echo "systemd user service installed: ${SERVICE_FILE}"
    echo "  Start:  ${START_CMD}"
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
        if ! as_the_service init --non-interactive; then
            echo "Error: cordelia init failed. The binary is installed; the node is not set up."
            exit 1
        fi
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
    settle_running_node
    if [ -n "$THERE" ]; then
        echo ""
        finish
        return
    fi
    echo "Next steps:"
    echo "  ${START_CMD}"
    echo "                        # run the node as a background service"
    echo "  cordelia status       # the node and its relays"
    echo "  cordelia id           # this device's key, to pair another device"
    echo "  cordelia sync claude  # turn on memory sync: lists what it found"
    echo "  cordelia sync map <folder>"
    echo "                        # sync Claude Code's memory for that folder"
    echo ""
    echo "Open a new terminal first if 'cordelia' is not found."
    echo ""
    finish
}

main "$@"
