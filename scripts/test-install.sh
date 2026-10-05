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
# an empty one, and the node is from before nodes said their version. Its
# `status` has the fields of the real one's, in the real one's order, with
# the objects that a running node's has.
#
# It answers for the service's node only where it is asked as the service
# runs. Asked with a setting for another node, it answers as that other
# node would: running, on the version installed.
cat > "$WORK/cordelia" << 'BINARY'
#!/bin/sh
[ -f "$HOME/.fake/binary_does_not_run" ] && exit 126
case "$1" in
    --version) echo "cordelia @NEW@" ;;
    init)
        [ -f "$HOME/.fake/init_fails" ] && exit 7
        touch "$HOME/.cordelia/identity.key"
        ;;
    status)
        if [ -n "${CORDELIA_CONFIG:-}${CORDELIA_HTTP_PORT:-}${CORDELIA_BIND_ADDRESS:-}" ] \
            || [ "${CORDELIA_DATA_DIR:-}" != "$HOME/.cordelia" ]; then
            echo '{ "state": "ok", "summary": "another node", "version": "@NEW@", "running": true,'
            echo '  "node_version": "@NEW@" }'
            exit 0
        fi
        # A node that says nothing the first few times it is asked.
        if [ -f "$HOME/.fake/late" ]; then
            left=$(cat "$HOME/.fake/late")
            if [ "$left" -gt 0 ]; then
                echo $((left - 1)) > "$HOME/.fake/late"
                echo '{ "state": "stopped", "summary": "", "version": "@NEW@", "running": false }'
                exit 0
            fi
        fi
        # A node that takes some asking before it says the new version.
        if [ -f "$HOME/.fake/slow" ] && [ -f "$HOME/.fake/restarted" ]; then
            asked=$(cat "$HOME/.fake/slow")
            if [ "$asked" -lt 3 ]; then
                echo $((asked + 1)) > "$HOME/.fake/slow"
                echo '{ "state": "stopped", "summary": "", "version": "@NEW@", "running": false }'
                exit 0
            fi
        fi
        if [ ! -f "$HOME/.fake/node_version" ]; then
            echo '{ "state": "stopped", "summary": "", "version": "@NEW@", "running": false }'
        elif [ -s "$HOME/.fake/node_version" ]; then
            echo '{ "state": "ok", "summary": "2 relays", "version": "@NEW@", "running": true,'
            echo '  "device": "cordelia_pk1example", "role": "personal",'
            echo "  \"node_version\": \"$(cat "$HOME/.fake/node_version")\", \"uptime_secs\": 12,"
            echo '  "peers": { "hot": 2, "warm": 0 }, "outbox_waiting": 0, "outbox_refused": 0,'
            echo '  "sync": { "enabled": true, "projects": [ { "project": "running", "mapped": true } ] } }'
        else
            echo '{ "state": "ok", "summary": "", "version": "@NEW@", "running": true,'
            echo '  "node_version": null, "uptime_secs": null }'
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
[ -f "$HOME/.fake/restart_command_fails" ] && exit 1
touch "$HOME/.fake/restarted"
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
    *is-active*)
        if [ -f "$HOME/.fake/service" ]; then
            cat "$HOME/.fake/service"
        else
            echo inactive; exit 3
        fi
        ;;
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
# again <name> [VAR=value...]: the script once more in the home of the run
# before. Each leaves OUT (what it printed), LAST (its last line), CODE
# and HOME_DIR.
CASES=0
run() {
    HOME_DIR="$WORK/home-$1"
    mkdir -p "$HOME_DIR/.fake"
    ( HOME="$HOME_DIR"; setup )
    again "$@"
}

again() {
    CASES=$((CASES + 1))
    name="$1"; shift
    : > "$HOME_DIR/.fake/calls"
    set +e
    # None of the settings of whoever runs the test reach the script.
    env -u CORDELIA_NO_RESTART -u CORDELIA_CONFIG -u CORDELIA_DATA_DIR \
        -u CORDELIA_HTTP_PORT -u CORDELIA_P2P_PORT -u CORDELIA_BIND_ADDRESS \
        HOME="$HOME_DIR" PATH="$STUBS:$PATH" SHELL=/bin/sh \
        FAKE_RELEASE="$WORK/cordelia.release" \
        CORDELIA_VERSION="v$NEW" CORDELIA_RESTART_WAIT_SECS=2 CORDELIA_ANSWER_WAIT_SECS=1 \
        "$@" sh "$HERE/install.sh" > "$HOME_DIR/.fake/out" 2>&1
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

service() { echo "${1:-active}" > "$HOME/.fake/service"; }

setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-running-node-is-restarted"
expect "installed=$NEW running=$NEW restart=done" 0 1
check "the unit is read again before the restart" \
    "$(tr '\n' ' ' < "$HOME_DIR/.fake/calls")" "daemon-reload restart "

setup() {
    service; touch "$HOME/.fake/restart_does_not_take"
    echo "$OLD" > "$HOME/.fake/node_version"
}
run "a-restart-that-does-not-take"
expect "installed=$NEW running=$OLD restart=failed" 3 1

setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-node-left-as-it-is-when-asked" CORDELIA_NO_RESTART=1
expect "installed=$NEW running=$OLD restart=needed" 0 0

setup() { service; echo "$NEW" > "$HOME/.fake/node_version"; }
run "a-node-already-on-this-version"
expect "installed=$NEW running=$NEW restart=not-needed" 0 0

setup() { echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-node-that-is-not-the-service"
expect "installed=$NEW running=$OLD restart=needed" 3 0

setup() { echo "$NEW" > "$HOME/.fake/node_version"; }
run "a-node-that-is-not-the-service-on-this-version"
expect "installed=$NEW running=$NEW restart=not-needed" 0 0

setup() { service; : > "$HOME/.fake/node_version"; }
run "a-node-from-before-nodes-said-their-version"
expect "installed=$NEW running=$NEW restart=done" 0 1

setup() {
    service; touch "$HOME/.fake/restart_does_not_take"
    : > "$HOME/.fake/node_version"
}
run "a-node-of-no-known-version-that-does-not-restart"
expect "installed=$NEW running=unknown restart=failed" 3 1

setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-running-node-on-a-mac" FAKE_OS=Darwin
expect "installed=$NEW running=$NEW restart=done" 0 1
check "the agent is restarted by its label" \
    "$(tr '\n' ' ' < "$HOME_DIR/.fake/calls")" \
    "kickstart -k gui/$(id -u)/ai.seeddrill.cordelia restart "

# What the first ten leave open.

has() {
    case "$OUT" in
        *"$1"*) ;;
        *) echo "FAILED: $name: says \"$1\""; FAILED=1 ;;
    esac
}

# A binary that does not run here takes nobody's place.
setup() {
    service; echo "$OLD" > "$HOME/.fake/node_version"
    mkdir -p "$HOME/.cordelia/bin"; echo "the one before" > "$HOME/.cordelia/bin/cordelia"
    touch "$HOME/.fake/binary_does_not_run"
}
run "a-binary-that-does-not-run"
check "the exit code" "$CODE" 1
check "restarts" "$(restarts)" 0
check "the binary in place" "$(cat "$HOME_DIR/.cordelia/bin/cordelia")" "the one before"
check "the last line" "$LAST" "Error: the downloaded binary does not run on this machine. Nothing was changed."

# The node is asked as the service runs, whatever the shell carries.
setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-shell-with-settings-for-another-node" CORDELIA_CONFIG=/elsewhere/config.toml \
    CORDELIA_DATA_DIR=/elsewhere CORDELIA_HTTP_PORT=9999
expect "installed=$NEW running=$NEW restart=done" 0 1

# The restart command itself fails: said as that, and at once.
setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; touch "$HOME/.fake/restart_command_fails"; }
run "a-restart-command-that-fails"
expect "installed=$NEW running=$OLD restart=failed" 3 1
has "The restart command failed."

# A node that says the new version only after some asking.
setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; echo 0 > "$HOME/.fake/slow"; }
run "a-node-that-takes-a-while-to-come-up" CORDELIA_RESTART_WAIT_SECS=20
expect "installed=$NEW running=$NEW restart=done" 0 1

# A service that is running with a node that does not answer is left alone.
setup() { service; }
run "a-node-that-does-not-answer"
expect "installed=$NEW running=unknown restart=needed" 3 0
has "it may still be"

# One that answers late, and is on this version already, is not restarted.
setup() { service; echo "$NEW" > "$HOME/.fake/node_version"; echo 2 > "$HOME/.fake/late"; }
run "a-node-on-this-version-that-answers-late" CORDELIA_ANSWER_WAIT_SECS=5
expect "installed=$NEW running=$NEW restart=not-needed" 0 0

# A wait for an answer that is no number is the default, and the script ends.
setup() { service; }
run "a-wait-that-is-no-number" CORDELIA_ANSWER_WAIT_SECS=soon
expect "installed=$NEW running=unknown restart=needed" 3 0

# A unit that is starting has a node, or is about to.
setup() { service activating; }
run "a-unit-that-is-starting"
expect "installed=$NEW running=unknown restart=needed" 3 0

setup() { service failed; }
run "a-unit-that-failed"
expect "installed=$NEW running=none restart=not-needed" 0 0

# Only 1 asks for the node to be left.
setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-zero-does-not-ask-for-the-node-to-be-left" CORDELIA_NO_RESTART=0
expect "installed=$NEW running=$NEW restart=done" 0 1

setup() { echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-node-that-is-not-the-service-left-when-asked" CORDELIA_NO_RESTART=1
expect "installed=$NEW running=$OLD restart=needed" 0 0

setup() { service; echo "$NEW" > "$HOME/.fake/node_version"; }
run "a-node-on-this-version-left-when-asked" CORDELIA_NO_RESTART=1
expect "installed=$NEW running=$NEW restart=not-needed" 0 0

# What a node says its version is reaches the last line as a version only.
setup() { service; printf '%s' '0.9.0\\ntest;rm' > "$HOME/.fake/node_version"; }
run "a-version-with-other-characters" CORDELIA_NO_RESTART=1
expect "installed=$NEW running=0.9.0ntestrm restart=needed" 0 0

# The version before is kept once, and a second run leaves that copy.
setup() {
    mkdir -p "$HOME/.cordelia/bin"; echo "the one before" > "$HOME/.cordelia/bin/cordelia"
    touch "$HOME/.cordelia/identity.key"
}
run "the-version-before-is-kept"
expect "installed=$NEW running=none restart=not-needed" 0 0
check "the copy kept" "$(cat "$HOME_DIR/.cordelia/bin/cordelia.prev")" "the one before"
again "the-version-before-is-kept-at-a-second-run"
expect "installed=$NEW running=none restart=not-needed" 0 0
check "the copy kept after a second run" "$(cat "$HOME_DIR/.cordelia/bin/cordelia.prev")" "the one before"

# A first install whose set-up fails says so, and is no success.
setup() { touch "$HOME/.fake/init_fails"; }
run "a-set-up-that-fails"
check "the exit code" "$CODE" 1
check "the last line" "$LAST" "Error: cordelia init failed. The binary is installed; the node is not set up."

setup() { :; }
run "a-first-install-on-a-mac" FAKE_OS=Darwin
expect "installed=$NEW running=none restart=not-needed" 0 0

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "install.sh: $CASES cases pass"
