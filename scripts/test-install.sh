#!/bin/sh
# Tests of install.sh: what it does about a node that is already running,
# the line it ends with, and its exit code.
#
# Nothing is downloaded and no service is touched. The script runs in a
# home directory of the test's own, with stand-ins first on PATH for curl,
# the service managers and uname, and a stand-in binary that says which
# version it is and which version the node is running.
#
# Usage: sh scripts/test-install.sh

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

NEW="0.9.0-test.2"
OLD="0.9.0-test.1"
FAILED=0

# ── Stand-ins ───────────────────────────────────────────────────────

STUBS="$WORK/stubs"
mkdir -p "$STUBS"

# The binary that the release would hold. What the node is running is the
# contents of $HOME/.fake/node_version: no such file, and no node answers;
# an empty one, and the node is from before nodes said their version.
cat > "$WORK/cordelia" << 'BINARY'
#!/bin/sh
case "$1" in
    --version) echo "cordelia @NEW@" ;;
    init) touch "$HOME/.cordelia/identity.key" ;;
    status)
        if [ ! -f "$HOME/.fake/node_version" ]; then
            echo '{ "state": "stopped", "running": false, "version": "@NEW@" }'
        elif [ -s "$HOME/.fake/node_version" ]; then
            echo "{ \"state\": \"ok\", \"running\": true, \"version\": \"@NEW@\","
            echo "  \"node_version\": \"$(cat "$HOME/.fake/node_version")\" }"
        else
            echo '{ "state": "ok", "running": true, "version": "@NEW@", "node_version": null }'
        fi
        ;;
esac
BINARY
sed "s/@NEW@/$NEW/g" "$WORK/cordelia" > "$WORK/cordelia.release"

# curl: the binary, or its checksum, by the URL's ending.
cat > "$STUBS/curl" << 'STUB'
#!/bin/sh
out=""; url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift ;;
        -*) ;;
        *)  url="$1" ;;
    esac
    shift
done
case "$url" in
    *.sha256) { sha256sum "$FAKE_RELEASE" 2>/dev/null || shasum -a 256 "$FAKE_RELEASE"; } | awk '{print $1}' > "$out" ;;
    *)        cp "$FAKE_RELEASE" "$out" ;;
esac
STUB

# A restart, as either service manager does it: the node then runs the
# version installed, unless the test says that the restart does not take.
cat > "$STUBS/restarted" << 'STUB'
#!/bin/sh
echo restart >> "$HOME/.fake/calls"
if [ ! -f "$HOME/.fake/restart_does_not_take" ]; then
    "$HOME/.cordelia/bin/cordelia" --version | awk '{print $2}' > "$HOME/.fake/node_version"
fi
STUB

# Each service manager answers only on its own system: called on the
# other, it says so in the calls, and fails.
cat > "$STUBS/systemctl" << 'STUB'
#!/bin/sh
[ "${FAKE_OS:-Linux}" = Linux ] || { echo wrong-manager >> "$HOME/.fake/calls"; exit 1; }
case "$*" in
    *is-active*)     [ -f "$HOME/.fake/service" ] ;;
    *daemon-reload*) echo daemon-reload >> "$HOME/.fake/calls" ;;
    *restart*)       restarted ;;
esac
STUB

cat > "$STUBS/launchctl" << 'STUB'
#!/bin/sh
[ "${FAKE_OS:-Linux}" = Darwin ] || { echo wrong-manager >> "$HOME/.fake/calls"; exit 1; }
case "$1" in
    list)      [ -f "$HOME/.fake/service" ] && echo "123 0 ai.seeddrill.cordelia" ;;
    kickstart) echo "kickstart $2 $3" >> "$HOME/.fake/calls"; restarted ;;
esac
exit 0
STUB

cat > "$STUBS/loginctl" << 'STUB'
#!/bin/sh
echo "Linger=yes"
STUB

cat > "$STUBS/uname" << 'STUB'
#!/bin/sh
case "$1" in
    -s) echo "${FAKE_OS:-Linux}" ;;
    -m) echo "x86_64" ;;
esac
STUB

chmod +x "$STUBS"/*

# ── One run ─────────────────────────────────────────────────────────

# run <name> [VAR=value...]: a new home, set up by `setup`, then the script.
# Leaves OUT (what it printed), LAST (its last line), CODE and HOME_DIR.
run() {
    name="$1"; shift
    HOME_DIR="$WORK/home-$name"
    mkdir -p "$HOME_DIR/.fake"
    : > "$HOME_DIR/.fake/calls"
    ( HOME="$HOME_DIR"; setup )
    set +e
    env "$@" HOME="$HOME_DIR" PATH="$STUBS:$PATH" SHELL=/bin/sh \
        FAKE_RELEASE="$WORK/cordelia.release" \
        CORDELIA_VERSION="v$NEW" CORDELIA_RESTART_WAIT_SECS=2 \
        sh "$HERE/install.sh" > "$HOME_DIR/.fake/out" 2>&1
    CODE=$?
    set -e
    # From the file, not from a variable: a blank line after the line for
    # a program must show as the last line.
    OUT=$(cat "$HOME_DIR/.fake/out")
    LAST=$(tail -n 1 "$HOME_DIR/.fake/out")
}

restarts() {
    grep -c '^restart$' "$HOME_DIR/.fake/calls" || true
}

check() {
    what="$1"; got="$2"; want="$3"
    if [ "$got" != "$want" ]; then
        echo "FAILED: $name: $what"
        echo "    got:  $got"
        echo "    want: $want"
        FAILED=1
    fi
}

expect() {
    check "the last line" "$LAST" "cordelia-install: $1"
    check "the exit code" "$CODE" "$2"
    check "restarts" "$(restarts)" "$3"
    check "calls to the other system's service manager" \
        "$(grep -c '^wrong-manager$' "$HOME_DIR/.fake/calls" || true)" 0
}

# ── The cases ───────────────────────────────────────────────────────

setup() { :; }
run "a-first-install"
expect "installed=$NEW running=none restart=not-needed" 0 0
case "$OUT" in
    *"Next steps:"*) ;;
    *) echo "FAILED: $name: a first install says what to do next"; FAILED=1 ;;
esac

setup() { touch "$HOME/.fake/service"; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-running-node-is-restarted"
expect "installed=$NEW running=$NEW restart=done" 0 1
check "the unit is read again before the restart" \
    "$(tr '\n' ' ' < "$HOME_DIR/.fake/calls")" "daemon-reload restart "

setup() {
    touch "$HOME/.fake/service" "$HOME/.fake/restart_does_not_take"
    echo "$OLD" > "$HOME/.fake/node_version"
}
run "a-restart-that-does-not-take"
expect "installed=$NEW running=$OLD restart=failed" 3 1

setup() { touch "$HOME/.fake/service"; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-node-left-as-it-is-when-asked" CORDELIA_NO_RESTART=1
expect "installed=$NEW running=$OLD restart=needed" 0 0

setup() { touch "$HOME/.fake/service"; echo "$NEW" > "$HOME/.fake/node_version"; }
run "a-node-already-on-this-version"
expect "installed=$NEW running=$NEW restart=not-needed" 0 0

setup() { echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-node-that-is-not-the-service"
expect "installed=$NEW running=$OLD restart=needed" 3 0

setup() { echo "$NEW" > "$HOME/.fake/node_version"; }
run "a-node-that-is-not-the-service-on-this-version"
expect "installed=$NEW running=$NEW restart=not-needed" 0 0

setup() { touch "$HOME/.fake/service"; : > "$HOME/.fake/node_version"; }
run "a-node-from-before-nodes-said-their-version"
expect "installed=$NEW running=$NEW restart=done" 0 1

setup() {
    touch "$HOME/.fake/service" "$HOME/.fake/restart_does_not_take"
    : > "$HOME/.fake/node_version"
}
run "a-node-of-no-known-version-that-does-not-restart"
expect "installed=$NEW running=unknown restart=failed" 3 1

setup() { touch "$HOME/.fake/service"; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-running-node-on-a-mac" FAKE_OS=Darwin
expect "installed=$NEW running=$NEW restart=done" 0 1
check "the agent is restarted by its label" \
    "$(tr '\n' ' ' < "$HOME_DIR/.fake/calls")" \
    "kickstart -k gui/$(id -u)/ai.seeddrill.cordelia restart "

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "install.sh: 10 cases pass"
