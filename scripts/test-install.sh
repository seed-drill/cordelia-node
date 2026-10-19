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
if [ -f "$HOME/.fake/binary_does_not_run" ]; then
    echo "cannot execute binary file" >&2
    exit 126
fi
case "$1" in
    --version) echo "cordelia @NEW@" ;;
    init)
        [ -f "$HOME/.fake/init_fails" ] && exit 7
        # Where it is told to, as the real one does. Its configuration
        # file is made as an earlier version made it: open to others.
        mkdir -p "${CORDELIA_DATA_DIR:-$HOME/.cordelia}"
        touch "${CORDELIA_DATA_DIR:-$HOME/.cordelia}/identity.key"
        touch "${CORDELIA_DATA_DIR:-$HOME/.cordelia}/config.toml"
        chmod 664 "${CORDELIA_DATA_DIR:-$HOME/.cordelia}/config.toml"
        # Its last line, as the real one's: run by a script it says
        # nothing of how the node is started.
        case " $* " in
            *" --non-interactive "*) echo "Node is ready." ;;
            *) echo 'Node is ready. Run `cordelia start` to begin.' ;;
        esac
        ;;
    status)
        if [ -n "${CORDELIA_CONFIG:-}${CORDELIA_HTTP_PORT:-}${CORDELIA_P2P_PORT:-}${CORDELIA_BIND_ADDRESS:-}" ] \
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
    # A user session answers, unless the test says that none does.
    *show-environment*) [ ! -f "$HOME/.fake/no_user_session" ] ;;
    *daemon-reload*) echo daemon-reload >> "$HOME/.fake/calls" ;;
    *restart*)       restarted ;;
esac
STUB

# launchctl: bootout takes the agent out, unless the test says that it is
# gone already (it then fails, as launchctl does); bootstrap loads it from
# the plist, which must be there, and starts the node. A bootstrap fails
# while the job booted out is still going (as many times as
# $HOME/.fake/still_going says), or always where the test says so.
cat > "$STUBS/launchctl" << 'STUB'
#!/bin/sh
[ "${FAKE_OS:-Linux}" = Darwin ] || { echo wrong-manager >> "$HOME/.fake/calls"; exit 1; }
case "$1" in
    list)      [ -f "$HOME/.fake/service" ] && echo "123 0 ai.seeddrill.cordelia" ;;
    kickstart) echo "kickstart $2 $3" >> "$HOME/.fake/calls"; restarted ;;
    # The job is in this login's GUI domain, unless the test says that it
    # was loaded in another.
    print)
        echo "print $2" >> "$HOME/.fake/calls"
        if [ -f "$HOME/.fake/job_elsewhere" ]; then
            echo "Could not find service \"ai.seeddrill.cordelia\" in domain for user gui: $(id -u)" >&2
            exit 113
        fi
        echo "state = running"
        ;;
    bootout)
        echo "bootout $2" >> "$HOME/.fake/calls"
        if [ -f "$HOME/.fake/job_gone" ]; then
            echo "Boot-out failed: 3: No such process" >&2
            exit 3
        fi
        ;;
    bootstrap)
        echo "bootstrap $2 $3" >> "$HOME/.fake/calls"
        [ -f "$3" ] || { echo "Bootstrap failed: 2: No such file or directory" >&2; exit 2; }
        if [ -f "$HOME/.fake/bootstrap_fails" ]; then
            echo "Bootstrap failed: 5: Input/output error" >&2
            exit 5
        fi
        if [ -f "$HOME/.fake/still_going" ]; then
            left=$(cat "$HOME/.fake/still_going")
            if [ "$left" -gt 0 ]; then
                echo $((left - 1)) > "$HOME/.fake/still_going"
                echo "Bootstrap failed: 5: Input/output error" >&2
                exit 5
            fi
        fi
        restarted
        ;;
esac
exit 0
STUB

# sleep: as it is, unless the test counts the waits; then each is a call,
# and takes no time.
cat > "$STUBS/sleep" << 'STUB'
#!/bin/sh
if [ -f "$HOME/.fake/count_sleeps" ]; then
    echo "sleep $*" >> "$HOME/.fake/calls"
    exit 0
fi
PATH=$(printf '%s' "$PATH" | sed 's|^[^:]*:||')
exec sleep "$@"
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

has() {
    case "$OUT" in
        *"$1"*) ;;
        *) echo "FAILED: $name: says \"$1\""; FAILED=1 ;;
    esac
}

# Who may read, write and enter what is at $1, as `ls -l` shows it.
mode_of() {
    ls -ld "$1" | cut -c1-10
}

# The data directory is its owner's alone, and so is the configuration
# file in it.
private() {
    check "the data directory's mode" "$(mode_of "$HOME_DIR/.cordelia")" "drwx------"
    check "the configuration file's mode" \
        "$(mode_of "$HOME_DIR/.cordelia/config.toml")" "-rw-------"
}

has_not() {
    case "$OUT" in
        *"$1"*) echo "FAILED: $name: must not say \"$1\""; FAILED=1 ;;
    esac
}

# The closing words of a first install, in their order: the one command
# that starts the node as the service ($1), the three ways on for a
# machine that follows no recovery phrase, each with its command, and
# the two commands of memory sync. Nothing that the script printed says
# `cordelia start`, or names pairing.
first_install_says() {
    want=$(cat << WORDS
Next steps:
  $1
                        # run the node as a background service

Then one of these three:
  cordelia phrase       # this is your first machine: make a phrase here
  cordelia id           # another machine has the phrase: add this one from it.
                        #   Give this key to cordelia add-device there; it
                        #   prints the cordelia accept to run here
  cordelia recover      # every device that has the phrase is lost: recover
                        #   here with it. Do not make a new phrase first

Then:
  cordelia sync claude  # turn on memory sync: lists what it found
  cordelia sync map <folder>
                        # sync Claude Code's memory for that folder

Open a new terminal first if 'cordelia' is not found.
WORDS
)
    check "the closing words" \
        "$(sed -n '/^Next steps:/,/^Open a new terminal/p' "$HOME_DIR/.fake/out")" "$want"
    has "Node is ready."
    has_not "cordelia start"
    has_not "to pair"
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
first_install_says "systemctl --user enable --now cordelia"
private
has_not "could be read, written or entered by others"

service() { echo "${1:-active}" > "$HOME/.fake/service"; }

setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-running-node-is-restarted"
expect "installed=$NEW running=$NEW restart=done" 0 1
# An upgrade ends as it did: with what became of the node, and no steps.
has "The node was restarted and is running $NEW."
has_not "Next steps:"
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

# On a Mac the agent is booted out, then bootstrapped from the plist just
# written, and not kickstarted.
PLIST_OF() { echo "$1/Library/LaunchAgents/ai.seeddrill.cordelia.plist"; }
MAC_RESTART() {
    echo "launchctl bootout gui/$(id -u)/ai.seeddrill.cordelia; launchctl bootstrap gui/$(id -u) \"$(PLIST_OF "$1")\" || (sleep 30; launchctl bootstrap gui/$(id -u) \"$(PLIST_OF "$1")\")"
}
setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-running-node-on-a-mac" FAKE_OS=Darwin
expect "installed=$NEW running=$NEW restart=done" 0 1
check "the agent is booted out, then bootstrapped from its plist" \
    "$(tr '\n' ' ' < "$HOME_DIR/.fake/calls")" \
    "print gui/$(id -u)/ai.seeddrill.cordelia bootout gui/$(id -u)/ai.seeddrill.cordelia bootstrap gui/$(id -u) $(PLIST_OF "$HOME_DIR") restart "
check "the plist bootstrapped names the binary installed" \
    "$(grep -c "<string>$HOME_DIR/.cordelia/bin/cordelia</string>" "$(PLIST_OF "$HOME_DIR")")" 1
has "The node was restarted and is running $NEW."

# A job that is gone by the time it is booted out: the bootout fails, and
# the bootstrap loads it all the same.
setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; touch "$HOME/.fake/job_gone"; }
run "a-mac-agent-that-is-gone-already" FAKE_OS=Darwin
expect "installed=$NEW running=$NEW restart=done" 0 1
check "the bootstrap after the bootout that failed" \
    "$(tr '\n' ' ' < "$HOME_DIR/.fake/calls")" \
    "print gui/$(id -u)/ai.seeddrill.cordelia bootout gui/$(id -u)/ai.seeddrill.cordelia bootstrap gui/$(id -u) $(PLIST_OF "$HOME_DIR") restart "
has_not "Boot-out failed"

# A bootstrap that fails while the job booted out is still going is tried
# again, a second later, and the restart is done.
setup() {
    service; echo "$OLD" > "$HOME/.fake/node_version"
    echo 1 > "$HOME/.fake/still_going"; touch "$HOME/.fake/count_sleeps"
}
run "a-mac-agent-that-is-still-going-once" FAKE_OS=Darwin
expect "installed=$NEW running=$NEW restart=done" 0 1
check "the bootstrap is tried again after a second" \
    "$(grep -v '^sleep 1$' "$HOME_DIR/.fake/calls" | tr '\n' ' ')" \
    "print gui/$(id -u)/ai.seeddrill.cordelia bootout gui/$(id -u)/ai.seeddrill.cordelia bootstrap gui/$(id -u) $(PLIST_OF "$HOME_DIR") bootstrap gui/$(id -u) $(PLIST_OF "$HOME_DIR") restart "
check "the waits before the second bootstrap" \
    "$(sed -n '4,5p' "$HOME_DIR/.fake/calls" | tr '\n' ' ')" \
    "sleep 1 bootstrap gui/$(id -u) $(PLIST_OF "$HOME_DIR") "
has_not "Bootstrap failed"

# One that still fails after the wait has failed for good: it is tried for
# 30 seconds, a second apart, and no longer; what launchctl said is
# printed, and the two commands to run by hand, on one line.
setup() {
    service; echo "$OLD" > "$HOME/.fake/node_version"
    touch "$HOME/.fake/bootstrap_fails" "$HOME/.fake/count_sleeps"
}
run "a-mac-agent-that-does-not-bootstrap" FAKE_OS=Darwin
expect "installed=$NEW running=$OLD restart=failed" 3 0
check "bootouts" "$(grep -c '^bootout ' "$HOME_DIR/.fake/calls")" 1
check "bootstraps, over 30 seconds" "$(grep -c '^bootstrap ' "$HOME_DIR/.fake/calls")" 31
check "waits between them" "$(grep -c '^sleep 1$' "$HOME_DIR/.fake/calls")" 30
has "The restart command failed."
has "  Bootstrap failed: 5: Input/output error"
check "the two commands, on a line of their own" \
    "$(grep -cFx "  $(MAC_RESTART "$HOME_DIR")" "$HOME_DIR/.fake/out")" 1

# The wait is the one given, where one is.
setup() {
    service; echo "$OLD" > "$HOME/.fake/node_version"
    touch "$HOME/.fake/bootstrap_fails" "$HOME/.fake/count_sleeps"
}
run "a-mac-agent-that-does-not-bootstrap-in-a-wait-given" FAKE_OS=Darwin CORDELIA_BOOTSTRAP_WAIT_SECS=2
expect "installed=$NEW running=$OLD restart=failed" 3 0
check "bootstraps, over 2 seconds" "$(grep -c '^bootstrap ' "$HOME_DIR/.fake/calls")" 3

# A job that is loaded, but not in this login's GUI domain (it was loaded
# over ssh, say): nothing is booted out or bootstrapped, the restart is
# needed, and the words say where the job is and what to do.
setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; touch "$HOME/.fake/job_elsewhere"; }
run "a-mac-agent-in-another-domain" FAKE_OS=Darwin
expect "installed=$NEW running=$OLD restart=needed" 3 0
check "the calls: the domain asked, and nothing changed" \
    "$(tr '\n' ' ' < "$HOME_DIR/.fake/calls")" "print gui/$(id -u)/ai.seeddrill.cordelia "
check "what is said" "$(sed -n '/^The service is loaded, but not/,/^or run this installer/p' "$HOME_DIR/.fake/out")" \
"The service is loaded, but not in the GUI domain of this login
(gui/$(id -u)), where the restart acts: it was started from another
session, such as over ssh. Nothing was restarted. In the session that
started it, run:
  launchctl unload \"$(PLIST_OF "$HOME_DIR")\"; launchctl load \"$(PLIST_OF "$HOME_DIR")\"
or run this installer from a terminal of this Mac's own login."
has_not "A node is running: restarting it"

# Where the node is left as it is, or does not answer, the restart that
# is named is the same two commands.
setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-mac-node-left-as-it-is-when-asked" FAKE_OS=Darwin CORDELIA_NO_RESTART=1
expect "installed=$NEW running=$OLD restart=needed" 0 0
check "the two commands, on a line of their own" \
    "$(grep -cFx "  $(MAC_RESTART "$HOME_DIR")" "$HOME_DIR/.fake/out")" 1
check "calls to launchctl that change anything" "$(cat "$HOME_DIR/.fake/calls")" ""

# The line printed, pasted into a shell as it is: the bootstrap that fails
# while the job booted out is still going is tried once more, 30 seconds
# later, and the node runs. One that fails for good is tried twice, and
# the line ends. A home whose name has a space is one path.
pasted() {
    sed -n 's/^  \(launchctl bootout .*\)$/\1/p' "$HOME_DIR/.fake/out" > "$HOME_DIR/.fake/line"
    : > "$HOME_DIR/.fake/calls"
    touch "$HOME_DIR/.fake/count_sleeps"
    set +e
    env HOME="$HOME_DIR" PATH="$STUBS:$PATH" FAKE_OS=Darwin sh -c "$(cat "$HOME_DIR/.fake/line")" \
        > /dev/null 2>&1
    PASTED=$?
    set -e
}
setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-mac-restart-pasted" FAKE_OS=Darwin CORDELIA_NO_RESTART=1
echo 1 > "$HOME_DIR/.fake/still_going"
pasted
check "the line pasted ends well" "$PASTED" 0
check "the calls of the line pasted" "$(tr '\n' ' ' < "$HOME_DIR/.fake/calls")" \
    "bootout gui/$(id -u)/ai.seeddrill.cordelia bootstrap gui/$(id -u) $(PLIST_OF "$HOME_DIR") sleep 30 bootstrap gui/$(id -u) $(PLIST_OF "$HOME_DIR") restart "
check "the node runs" "$(cat "$HOME_DIR/.fake/node_version")" "$NEW"
touch "$HOME_DIR/.fake/bootstrap_fails"
pasted
check "the line pasted ends, failed" "$PASTED" 5
check "the calls of the line pasted that fails" "$(grep -c '^bootstrap ' "$HOME_DIR/.fake/calls")" 2

setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-mac-home with a space" FAKE_OS=Darwin CORDELIA_NO_RESTART=1
expect "installed=$NEW running=$OLD restart=needed" 0 0
pasted
check "the line pasted in a home with a space ends well" "$PASTED" 0
check "the plist bootstrapped in a home with a space" \
    "$(grep -c "^bootstrap gui/$(id -u) $(PLIST_OF "$HOME_DIR")\$" "$HOME_DIR/.fake/calls")" 1

setup() { service; }
run "a-mac-node-that-does-not-answer" FAKE_OS=Darwin
expect "installed=$NEW running=unknown restart=needed" 3 0
has "If it stays on the previous version: $(MAC_RESTART "$HOME_DIR")"
check "calls to launchctl that change anything" "$(cat "$HOME_DIR/.fake/calls")" ""

# What the first ten leave open.


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
has "  cannot execute binary file"
check "the new binary beside it" "$(ls "$HOME_DIR/.cordelia/bin")" "cordelia"

# The node is asked as the service runs, whatever the shell carries.
setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; }
run "a-shell-with-settings-for-another-node" CORDELIA_CONFIG=/elsewhere/config.toml \
    CORDELIA_DATA_DIR=/elsewhere CORDELIA_HTTP_PORT=9999
expect "installed=$NEW running=$NEW restart=done" 0 1
for setting in CORDELIA_CONFIG=/elsewhere/config.toml CORDELIA_HTTP_PORT=9999 \
    CORDELIA_P2P_PORT=9998 CORDELIA_BIND_ADDRESS=::1; do
    setup() { service; echo "$OLD" > "$HOME/.fake/node_version"; }
    run "a-shell-with-${setting%%=*}" "$setting"
    expect "installed=$NEW running=$NEW restart=done" 0 1
done

# A first install sets the node up where the service will look for it.
setup() { :; }
run "a-first-install-in-a-shell-with-settings" CORDELIA_DATA_DIR="$WORK/elsewhere"
expect "installed=$NEW running=none restart=not-needed" 0 0
first_install_says "systemctl --user enable --now cordelia"
check "the key is where the service looks" \
    "$(ls "$HOME_DIR/.cordelia/identity.key" 2>/dev/null)" "$HOME_DIR/.cordelia/identity.key"

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

setup() { service; }
run "a-wait-that-is-too-long-a-number" CORDELIA_ANSWER_WAIT_SECS=99999999999999999999
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
# A later run with no node running ends as it did.
has "  cordelia status       # the node and its relays"
has_not "Then one of these three:"
check "the copy kept" "$(cat "$HOME_DIR/.cordelia/bin/cordelia.prev")" "the one before"
again "the-version-before-is-kept-at-a-second-run"
expect "installed=$NEW running=none restart=not-needed" 0 0
check "the copy kept after a second run" "$(cat "$HOME_DIR/.cordelia/bin/cordelia.prev")" "the one before"

# A data directory that an earlier run left open to others, and the
# configuration file in it, are set to their owner's alone: with a node
# that is running, and with none.
setup() {
    mkdir -p "$HOME/.cordelia/bin"; echo "the one before" > "$HOME/.cordelia/bin/cordelia"
    touch "$HOME/.cordelia/identity.key" "$HOME/.cordelia/config.toml"
    chmod 775 "$HOME/.cordelia"; chmod 664 "$HOME/.cordelia/config.toml"
}
run "a-data-directory-that-was-open-to-others"
expect "installed=$NEW running=none restart=not-needed" 0 0
private
has "/.cordelia could be read, written or entered by others than its owner and its group: setting it to its owner's alone (mode 700)."
check "the key's mode is left as it was" \
    "$(mode_of "$HOME_DIR/.cordelia/identity.key")" "$(mode_of "$HOME_DIR/.fake/calls")"

setup() {
    service; echo "$OLD" > "$HOME/.fake/node_version"
    mkdir -p "$HOME/.cordelia"; touch "$HOME/.cordelia/identity.key" "$HOME/.cordelia/config.toml"
    chmod 775 "$HOME/.cordelia"; chmod 664 "$HOME/.cordelia/config.toml"
}
run "an-upgrade-of-a-data-directory-that-was-open-to-others"
expect "installed=$NEW running=$NEW restart=done" 0 1
private

# A data directory shared with its group on purpose, and open to nobody
# else, is left as it is, and so is the configuration file in it: nothing
# is set, and nothing is said. A first install's own is made private.
setup() {
    mkdir -p "$HOME/.cordelia/bin"; echo "the one before" > "$HOME/.cordelia/bin/cordelia"
    touch "$HOME/.cordelia/identity.key" "$HOME/.cordelia/config.toml"
    chmod 750 "$HOME/.cordelia"; chmod 640 "$HOME/.cordelia/config.toml"
}
run "a-data-directory-shared-with-its-group"
expect "installed=$NEW running=none restart=not-needed" 0 0
check "the data directory's mode" "$(mode_of "$HOME_DIR/.cordelia")" "drwxr-x---"
check "the configuration file's mode" \
    "$(mode_of "$HOME_DIR/.cordelia/config.toml")" "-rw-r-----"
has_not "could be read, written or entered by others"

# A data directory that is a symbolic link to one shared with its group
# is read where the link leads, as the node reads it: it is left as it is,
# and nothing is said. So is one whose others have only the sticky bit.
setup() {
    mkdir -p "$HOME/shared/bin"; echo "the one before" > "$HOME/shared/bin/cordelia"
    touch "$HOME/shared/identity.key" "$HOME/shared/config.toml"
    chmod 750 "$HOME/shared"; chmod 640 "$HOME/shared/config.toml"
    ln -s "$HOME/shared" "$HOME/.cordelia"
}
run "a-data-directory-that-is-a-link-to-one-shared-with-its-group"
expect "installed=$NEW running=none restart=not-needed" 0 0
check "the mode of the directory the link leads to" "$(mode_of "$HOME_DIR/shared")" "drwxr-x---"
check "the configuration file's mode" "$(mode_of "$HOME_DIR/shared/config.toml")" "-rw-r-----"
has_not "could be read, written or entered by others"

setup() {
    mkdir -p "$HOME/.cordelia/bin"; echo "the one before" > "$HOME/.cordelia/bin/cordelia"
    touch "$HOME/.cordelia/identity.key" "$HOME/.cordelia/config.toml"
    chmod 1750 "$HOME/.cordelia"; chmod 640 "$HOME/.cordelia/config.toml"
}
run "a-data-directory-whose-others-have-only-the-sticky-bit"
expect "installed=$NEW running=none restart=not-needed" 0 0
check "the data directory's mode" "$(mode_of "$HOME_DIR/.cordelia")" "drwxr-x--T"
has_not "could be read, written or entered by others"

# A configuration file that is a link is kept elsewhere: no mode is set
# through the link, and the data directory is set as it always is.
setup() {
    mkdir -p "$HOME/.cordelia"; touch "$HOME/.cordelia/identity.key" "$HOME/kept-elsewhere.toml"
    chmod 775 "$HOME/.cordelia"; chmod 664 "$HOME/kept-elsewhere.toml"
    ln -s "$HOME/kept-elsewhere.toml" "$HOME/.cordelia/config.toml"
}
run "a-configuration-file-that-is-a-link"
expect "installed=$NEW running=none restart=not-needed" 0 0
check "the data directory's mode" "$(mode_of "$HOME_DIR/.cordelia")" "drwx------"
check "the mode of the file that the link leads to" \
    "$(mode_of "$HOME_DIR/kept-elsewhere.toml")" "-rw-rw-r--"
check "the configuration file is still a link" \
    "$(mode_of "$HOME_DIR/.cordelia/config.toml" | cut -c1)" "l"

# A machine with no service manager that the script can use: Linux with
# no systemd user session. The next steps name the command that runs the
# node by hand, on a line of its own, and say that it runs until that
# terminal is closed. The command that starts the service cannot work
# there, and is not named.
setup() { touch "$HOME/.fake/no_user_session"; }
run "a-first-install-with-no-systemd-user-session"
expect "installed=$NEW running=none restart=not-needed" 0 0
check "the first of the next steps" \
    "$(sed -n '/^Next steps:/,/^$/p' "$HOME_DIR/.fake/out")" \
    "Next steps:
  cordelia start
                        # run the node yourself: you have no systemd user session here.
                        # It runs until you close that terminal"
has "You have no systemd user session here, so the service cannot start."
has "Then one of these three:"
has "  cordelia sync claude  # turn on memory sync: lists what it found"
has_not "systemctl --user enable --now cordelia"

# A first install whose set-up fails says so, and is no success.
setup() { touch "$HOME/.fake/init_fails"; }
run "a-set-up-that-fails"
check "the exit code" "$CODE" 1
check "the last line" "$LAST" "Error: cordelia init failed. The binary is installed; the node is not set up."

setup() { :; }
run "a-first-install-on-a-mac" FAKE_OS=Darwin
expect "installed=$NEW running=none restart=not-needed" 0 0
first_install_says "launchctl load $HOME_DIR/Library/LaunchAgents/ai.seeddrill.cordelia.plist"
check "calls to launchctl that change anything" "$(cat "$HOME_DIR/.fake/calls")" ""
has "  Stop:   launchctl unload $HOME_DIR/Library/LaunchAgents/ai.seeddrill.cordelia.plist"

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "install.sh: $CASES cases pass"
