# Operations Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-11
**Scope**: Phase 1 (Encrypted Pub/Sub MVP)
**Implements**: WP5 (Local Enrollment CLI), WP7 (Install Script + Packaging), WP13 (CLI Stats + Metrics)
**Depends on**: specs/ecies-envelope-encryption.md, specs/channels-api.md, specs/network-protocol.md

> **v1 status.** Device pairing (§3) is replaced by a recovery phrase and two
> commands: `cordelia phrase` on one device, then `cordelia add-device` there
> and `cordelia accept` on each other (see the README, and the
> [decision record of 2026-10-04](../decisions/2026-10-04-a-persons-devices.md)).
> The commands of this version are in §4.1. The install script pins a release
> with `CORDELIA_VERSION`, and run again with a later one it upgrades and
> restarts the node (`CORDELIA_NO_RESTART=1` leaves the node as it is). Relays
> are run from [`deploy/relay/`](../../deploy/relay/)
> ([decision record of 2026-09-30](../decisions/2026-09-30-agent-memory-sync.md) §4.6).
> The upgrade to this version, the copy that a device makes at its first
> start on it, and how to go back, are in §10.

---

## 1. Installation

### 1.1 One-Line Install

```bash
curl -sSL https://install.seeddrill.ai | sh
```

The install script:

1. Detects platform and architecture
2. Downloads the correct binary from GitHub Releases
3. Verifies SHA-256 checksum (published alongside each release)
4. If a binary already exists at `~/.cordelia/bin/cordelia`, renames it to `cordelia.prev` (for rollback, §10.4)
5. Installs binary to `~/.cordelia/bin/cordelia`
6. Prompts before modifying shell RC files (skipped in `--non-interactive` mode). Adds `~/.cordelia/bin` to `PATH` (appends to `~/.bashrc`, `~/.zshrc`, or `~/.profile`)
7. Runs `cordelia init` if `~/.cordelia/config.toml` does not exist
8. Installs system service (launchctl on macOS, systemd on Linux)

> **v1 status.** The script runs `cordelia init --non-interactive` on a
> machine that has no key yet (`~/.cordelia/identity.key`): so run, `init`
> does not end by saying to run `cordelia start`. Such a first install ends
> with, in this order: the one command that starts the node as the service;
> the three ways on for a machine that follows no recovery phrase (§2.1),
> each with its command (`cordelia phrase`, `cordelia id` for `cordelia
> add-device` on a machine that has the phrase, `cordelia recover`); and
> `cordelia sync claude` and `cordelia sync map <folder>`. A later run ends
> as it did: with what became of the node that is running, and the line for
> a program.

### 1.2 Platform Matrix

| Platform | Architecture | Binary | Service Manager |
|----------|-------------|--------|-----------------|
| macOS | x86_64 | `cordelia-darwin-amd64` | launchctl (LaunchAgent) |
| macOS | ARM64 (Apple Silicon) | `cordelia-darwin-arm64` | launchctl (LaunchAgent) |
| Linux | x86_64 | `cordelia-linux-amd64` | systemd |
| Linux | ARM64 | `cordelia-linux-arm64` | systemd |

Windows is not supported in Phase 1. WSL2 uses the Linux binary.

### 1.3 Binary Verification

Each GitHub Release includes:

| File | Purpose |
|------|---------|
| `cordelia-<platform>-<arch>` | Binary |
| `cordelia-<platform>-<arch>.sha256` | SHA-256 checksum |
| `checksums.txt` | All checksums in one file |

The install script verifies the checksum before installing:

```bash
echo "<expected_hash>  cordelia" | sha256sum -c -
```

If verification fails, the script aborts with exit code 1 and prints the mismatch.

GPG signature verification is Phase 2 (requires Seed Drill signing key infrastructure).

**Integrity note:** The install script is served over HTTPS (TLS). The SHA-256 checksum of the install script itself is published at `https://install.seeddrill.ai/install.sh.sha256` for out-of-band verification. For maximum security, download the script first, inspect it, then run it. Or use the manual install procedure (§1.4) which performs checksum verification externally. This pattern is standard practice (Rust's rustup, Homebrew, nvm).

**Enterprise note:** Enterprise deployments should use the manual install procedure (§1.4) until GPG signature verification is available (Phase 2). SHA-256 checksums from the same server as the binary provide integrity verification against transport corruption but not against server compromise.

### 1.4 Manual Install

```bash
# Download binary
curl -LO https://github.com/seed-drill/cordelia-core/releases/latest/download/cordelia-darwin-arm64

# Verify checksum
curl -LO https://github.com/seed-drill/cordelia-core/releases/latest/download/cordelia-darwin-arm64.sha256
sha256sum -c cordelia-darwin-arm64.sha256

# Install
chmod +x cordelia-darwin-arm64
mv cordelia-darwin-arm64 ~/.cordelia/bin/cordelia

# Initialise
cordelia init
```

### 1.5 Uninstall

```bash
# Stop the node and remove its service:
#   macOS: launchctl unload ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist
#          rm ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist
#   Linux: systemctl --user disable --now cordelia
#          rm ~/.config/systemd/user/cordelia.service && systemctl --user daemon-reload
rm -rf ~/.cordelia/bin/                # remove the binary
```

`cordelia stop` is not implemented: the node is stopped through its service.

Data directory (`~/.cordelia/`) is preserved by default. The user must explicitly delete it to remove keys and data.

---

## 2. First-Run: `cordelia init`

### 2.1 What Happens

```
$ cordelia init
Generating Ed25519 keypair... done.
Deriving X25519 key... done.
Creating personal channel... done.
Starting node on port 9473 (HTTP) / 9474 (P2P)... done.
Discovering network... connected to 2 bootnodes.

Your identity:
  Entity ID:  russwing_a1b2
  Public key: cordelia_pk1...

Node is running. Install SDK: npm install @seeddrill/cordelia
```

> **v1 status.** `cordelia init` creates this device's key, its token, its
> configuration and its database, and no channel: there is no personal
> channel until there is a recovery phrase. `cordelia start` runs the node.
> A device that follows no phrase publishes nothing, and its status says "no
> recovery phrase yet: memory stays on this machine", and then three ways
> on, each on a line of its own, in this order:
>
> - "This is your first machine: make a phrase here (`cordelia phrase`)."
> - "Another machine has the phrase: add this one from it (`cordelia
>   add-device` there, `cordelia accept` here)."
> - "Every device that has the phrase is lost: recover here with it
>   (`cordelia recover`). Do not make a new phrase first."
>
> `cordelia init --new-key` gives a device a new key: it leaves the devices
> it is with, keeps its memory folders and their mappings, and then follows
> no phrase. It asks at a terminal.

### 2.2 Steps

1. **Generate Ed25519 keypair** (CSPRNG, 32-byte seed)
2. **Derive X25519 key** from Ed25519 (for ECIES envelope encryption)
3. **Generate node token** (32-byte random, hex-encoded)
4. **Derive entity ID** from public key (human-memorable: `<name>_<first4hex>`)
5. **Create personal channel** (auto-subscribe, realtime, invite_only, PSK generated)
6. **Write configuration** to `~/.cordelia/config.toml`
7. **Start node temporarily** in the foreground for bootstrap (HTTP API on 9473, P2P on 9474)
8. **Bootstrap peer discovery** (DNS SRV lookup + hardcoded seeds)
9. **Hand off to system service** -- install and enable launchctl/systemd service, then exit the init process. The system service is the long-running daemon.

### 2.3 Files Created

| Path | Mode | Contents |
|------|------|---------|
| `~/.cordelia/config.toml` | 0600 | Node configuration |
| `~/.cordelia/identity.key` | 0600 | Ed25519 seed (32 bytes, raw). X25519 key derived on demand, never persisted separately (ecies-envelope-encryption.md §2). |
| `~/.cordelia/node-token` | 0600 | Bearer token for HTTP API auth (32 bytes CSPRNG, hex-encoded, 64 chars) |
| `~/.cordelia/cordelia.db` | 0600 | SQLite database (items, groups, FTS5) |
| `~/.cordelia/channel-keys/` | 0700 | Directory for channel PSK files |
| `~/.cordelia/channel-keys/<personal_channel_id>.key` | 0600 | Personal channel PSK |

> **v1 status.** In this version the data directory of a personal node
> holds `config.toml`, `identity.key`, `node-token`, `cordelia.db`,
> `history/` (local history, mode 0700), and `node.lock` (mode 0600, empty:
> the file that a running node holds its lock on, §10.5). It holds no `channel-keys/` file
> once the first start on this version is done: the keys of a device's
> channels are derived from the person secret, which is in the database.
> After an upgrade it also holds `before-<version>/` (mode 0700), the copy of
> §10.5. A relay keeps `channel-keys/` for the older kind.
>
> **The data directory itself is mode 0700, and `config.toml` in it 0600.**
> `cordelia init` and the install script make them so. A node that starts on
> a data directory that others can read, write or enter sets it to 0700, and
> the configuration file in it to 0600, and says so once in its log
> (configuration.md §5.4).

### 2.4 Idempotency

`cordelia init` is safe to run multiple times:
- If `~/.cordelia/identity.key` exists: skip key generation, print existing identity
- If `~/.cordelia/config.toml` exists: skip config generation, use existing
- If node is already running: print status and exit
- Force re-initialisation: `cordelia init --force` (warns, requires confirmation)

### 2.5 Entity ID Format

The entity ID is derived from the Ed25519 public key:

```
entity_id = <name>_<first 4 hex chars of SHA-256(public_key)>
```

Where `<name>` is provided interactively during `cordelia init` or via `--name` flag. If omitted, defaults to the OS username (lowercased, non-alphanumeric chars replaced with hyphens).

**Name validation:** Names MUST match `^[a-z][a-z0-9-]{0,30}[a-z0-9]$` (lowercase alphanumeric + hyphens, 2-32 chars, starts with letter, doesn't end with hyphen). Underscore is reserved as the separator before the hex suffix.

```
$ cordelia init --name russwing
Entity ID: russwing_a1b2
```

Entity IDs are informational only. The Ed25519 public key is the canonical identity (ecies-envelope-encryption.md §2).

### 2.6 Non-Interactive Mode

For automated deployments (CI, containers, agent provisioning):

```bash
cordelia init --name agent-01 --non-interactive
```

Skips all prompts. Uses defaults. Prints JSON to stdout:

```json
{
  "entity_id": "agent-01_c3d4",
  "public_key": "cordelia_pk1...",
  "x25519_public_key": "cordelia_xpk1...",
  "node_token": "<written to ~/.cordelia/node-token>",
  "config_path": "/home/agent/.cordelia/config.toml"
}
```

The `node_token` is redacted by default (secrets should not appear in CI logs or container orchestrator output). Use `--show-secrets` to include raw token in output (for automated provisioning that pipes directly to a secrets manager).

---

## 3. Device Pairing: `cordelia pair` / `cordelia join`

> **v1 status.** Not built, and replaced. No key is shared between devices.
> A second device is added with `cordelia add-device <its key>` on a device
> that is in, and `cordelia accept <that device's key>` on the new one,
> within an hour, each at a terminal with its yes. What is handed over is
> the person secret, sealed in an entry of a channel that only those two
> devices can derive (decision 2026-10-04 §6). The phrase is not typed to
> add. Every device shows the addition until a person clears it there
> (`cordelia devices --clear`).

### 3.1 First Device (Initiator)

```
$ cordelia pair
Pairing code: XXXX-XXXX-XXXX
Waiting for second device... (expires in 5 minutes)
Show QR? [y/n]
```

Under the hood:
1. Generate one-time pairing code: 12 chars from uppercase alphanumeric alphabet excluding ambiguous characters (0/O, 1/I/L), effective alphabet of 30 chars, grouped as XXXX-XXXX-XXXX. Entropy: 30^12 = 5.3e17 combinations.
2. Open temporary P2P listener on a random port
3. Register pairing code with configured bootnodes (`network.bootnodes` from config.toml) via Pair-Register message (network-protocol.md §4.8): the pairing code is sent over the TLS-encrypted QUIC connection; the bootnode computes `HMAC-SHA256(bootnode_secret, pairing_code)` and stores only the HMAC with 5-minute TTL.
4. Wait for second device to connect (accepts only ONE connection per pairing session)

### 3.2 Second Device (Joiner)

```
$ cordelia join XXXX-XXXX-XXXX
Connecting to peer... done.
Receiving identity bundle... done.
Syncing channels... 3 channels, 47 items.
Ready. Your node is running.
```

Under the hood:
1. Resolve pairing code via bootnode lookup
2. Connect to first device via QUIC
3. Exchange public keys (mutual authentication)
4. Both devices display fingerprint for visual verification. Initiator user must confirm match before proceeding (in `--non-interactive` mode, fingerprint verification is skipped -- acceptable for automated provisioning in trusted networks)
5. First device sends ECIES-encrypted bundle:
   - Ed25519 private key (ECIES envelope for joiner's X25519 key, derived from joiner's Ed25519)
   - All channel PSKs (one ECIES envelope per channel)
   - Personal channel PSK
6. Second device replaces its init-generated identity with received key, re-derives all keys, starts node, begins replication

### 3.3 Pairing Security

- Pairing code is single-use (consumed on successful join)
- 5-minute expiry (configurable via `--timeout`, max 10 minutes)
- Bootnode computes `HMAC-SHA256(bootnode_secret, pairing_code)` from raw code received over TLS. Only the HMAC is stored. HMAC key is per-bootnode, never shared, preventing offline brute-force even with database access.
- Pairing codes are only registered with configured bootnodes (`network.bootnodes`), not all hot peers. This limits exposure to trusted infrastructure.
- Bootnodes MUST rate-limit pairing lookups: max 10 Pair-Lookup requests per source IP per minute. Exceeding returns a rejection.
- MITM protection: both devices display fingerprint of exchanged public keys for visual verification. Initiator MUST NOT send PairBundle until user confirms fingerprint match.
- Initiator accepts only ONE pairing connection per session. Subsequent connections are rejected with reason `session_in_use`.
- If pairing fails, initiator must generate a new code

**Security warning:** Pairing shares the Ed25519 private key with the second device. A compromised paired device has full access to the identity and all channels. Revocation requires identity rotation (new keypair, re-subscribe to all channels). Phase 4 adds per-device derived keys and selective revocation.

### 3.4 Device Limit

Phase 1: no hard limit on paired devices. All devices share the same Ed25519 identity. Each device is a full node with independent storage that converges via replication.

Phase 4: device management UI, selective revocation via key rotation.

---

## 4. CLI Reference

### 4.1 Subcommands

| Command | Description | Requires Running Node |
|---------|-------------|----------------------|
| `cordelia init` | First-run setup | No |
| `cordelia pair` | Generate pairing code | Yes |
| `cordelia join <code>` | Join with pairing code | No (starts node) |
| `cordelia status` | Node health summary | Yes |
| `cordelia peers` | List connected peers | Yes |
| `cordelia channels` | List subscribed channels | Yes |
| `cordelia stats` | Detailed metrics | Yes |
| `cordelia stop` | Not built: a node is stopped through its service (§7), or by a signal | - |
| `cordelia start` | Start the daemon (see §7 for service integration) | No |
| `cordelia export` | Export channel data (§9.3) | Yes |
| `cordelia version` | Print version and build info | No |
| `cordelia help` | Print help | No |

> **v1 status.** The commands of this version (`cordelia --help`):
>
> | Command | What it does | Asks at a terminal |
> |---------|--------------|--------------------|
> | `cordelia init` | Create this device's key and database. `--new-key` gives the device a new key | `--new-key` does |
> | `cordelia start` | Run the node. (`cordelia stop` is not built: a node is stopped by its service, or by a signal) | |
> | `cordelia status [--line \| --json \| --waybar]` | This device, its peers and memory sync. `--line` for a status bar, `--json` for tools, `--waybar` for a bar module (§4.3) | |
> | `cordelia id` | Print this device's public key | |
> | `cordelia phrase [--name <label>]` | Make the recovery phrase of your devices on this one: twelve words, shown once with their numbers and typed back one at a time | Yes |
> | `cordelia add-device <key> [--name <label>]` | Add another of your devices; then `cordelia accept` on it, within the hour | Yes |
> | `cordelia accept <key>` | Take what the device that added this one hands over | Yes |
> | `cordelia devices [--clear]` | Your devices, what each has applied, and what each relay holds. `--clear` goes through what this device has to tell you | `--clear` does |
> | `cordelia remove-device <key>` | Remove one of your devices. Given a key that this device knows nothing of (it is in no list of the last change, and was not added since), it says so, and that removing it refuses that key for good, and asks a typed answer, `refuse`, before it goes on as any removal | Yes, and the phrase |
> | `cordelia renew` | Give the devices that stay a new secret: of each device added since the last change, you say whether it stays | Yes, and the phrase |
> | `cordelia settle` | Settle two changes that were made apart, on a device that has seen both | Yes, and the phrase |
> | `cordelia recover [--name <label>]` | On a machine that follows no phrase, with no device left that you trust: bring back what the relays hold. It asks the relays that the machine is set up with, and takes no other. Of each device it asks a typed `have`, `lost` or `hands` (§9) | Yes, and the phrase, which it asks for first |
> | `cordelia sync claude [--dir <path>] [--mapped-only] [--no-home] [--reset]` | Turn on Claude Code memory sync. Nothing syncs until a folder is mapped. `--dir` sets the Claude Code directory, and `--reset` goes back to `~/.claude`; `--no-home` unmaps the home directory; `--mapped-only` is taken, and is the only scope there is. `--all` and `--exclude` are refused | |
> | `cordelia sync map <folder> [name] [--home]`, `cordelia sync unmap <folder or name>` | Sync Claude's memory for a folder under a name, and stop. `--home` maps the home directory itself | |
> | `cordelia sync home on\|off` | Map the home directory, or unmap it | |
> | `cordelia sync off` | Stop syncing | |
> | `cordelia sync status [--seen]` | Show what syncs, what was found and what your other devices sync. `--seen` shows the notice of the folders that stopped syncing once more, and puts it away | |
> | `cordelia sync carry [name]` | Bring into the channels of the last change what your devices that count had sent to the relays before it, in each generation that this device left in the last 90 days; with no name, for every name this device holds | |
> | `cordelia sync carry <name> --from [<label or six words>]` | Take what a removed device signed there, in the generations that this device left. `--from` is given once for each device, which it names by its label or by the first six words of its key's fingerprint, in quotes. With no device after it, it lists the removed keys that signed there, takes nothing and asks nothing | With a device named: twice a yes at most, and then the phrase |
> | `cordelia sync carry <name> --phrase` | Read the generations whose secret this device never held, and take what your devices that count signed there. `--from` and `--phrase` together are refused | Yes, and the phrase |
> | `cordelia history [<name or folder>] [--removed] [--since <time>]`, `cordelia history show <id>`, `cordelia history drop`, `cordelia restore <id>...` | Local history: the versions that sync replaced or removed here, printing one, removing kept versions, and putting versions back | |
> | `cordelia peers`, `cordelia channels`, `cordelia stats` | Connected peers; the names this device holds (on a node of another role, the channels of the older kind in which its own key is a member); what the node stores, as counts | |
>
> - **A command that asks at a terminal refuses when its input is not one,**
>   before it asks or does anything. A yes is the word `yes`.
> - **The recovery phrase is typed at the command's own prompt, with echo
>   off:** never as an argument, never over the local API. Its words are
>   asked for by number, one at a time, and nothing that is typed is shown.
>   After each word the command says whether it is a word of the list, and
>   where the phrase is being proved it says nothing more of it (decision
>   2026-10-04 §16). The command signs in its own process and forgets the
>   words before it waits for anything.
>   `remove-device`, `renew`, `settle` and `sync carry --from` ask for it
>   last, after what they show and their yes. `recover` asks for it first and
>   holds it through its prompts, since it reads at the relays with it. What
>   a command waits for afterwards (the sending after a change, the look of a
>   recovery) it waits for in a new process, which never held the phrase.
> - **A command that makes or asks for a phrase asks how the node stands
>   first,** and shows no word where the node is held up (§10.5).
> - **A command that changes anything refuses a node of another version than
>   its own,** with the note that says how to restart it. Turning sync off is
>   the exception. `cordelia status`, `cordelia sync status`, `cordelia
>   devices` and `cordelia history` still answer beside such a node, with the
>   note (decision 2026-10-04 §10.1, rule 6).
> - `cordelia sync exclude`, `cordelia sync include`, `cordelia sync claude
>   --exclude` and `cordelia sync claude --all` are refused, before anything
>   is sent to the node, with what to do instead: only what is mapped syncs,
>   so there is nothing to exclude.
> - `cordelia pair`, `join`, `export` and `version` below are not commands.
>   `cordelia --version` prints the version.

`cordelia start` flags:

| Flag | Description |
|------|-------------|
| `--foreground` | Run in foreground (don't hand off to system service). Useful for debugging. |
| `--persistent` | Run persistently as a daemon process (default when started via system service). Does NOT fork -- the process runs in the foreground but suppresses interactive output. |

### 4.2 Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--config <path>` | Config file path | `~/.cordelia/config.toml` |
| `--log-level <level>` | Log verbosity | `info` |
| `--json` | Output as JSON (machine-readable) | off |
| `--quiet` | Suppress non-error output | off |

### 4.3 `cordelia status`

```
$ cordelia status
Cordelia v0.1.0 (abc1234)
Uptime:     2h 15m
Entity:     russwing_a1b2 (cordelia_pk1...)
Peers:      5 hot, 12 warm
Channels:   7 subscribed
Storage:    24.5 MB
API:        http://127.0.0.1:9473
P2P:        0.0.0.0:9474
```

JSON output (`--json`):

```json
{
  "version": "0.1.0",
  "commit": "abc1234",
  "uptime_seconds": 8100,
  "entity_id": "russwing_a1b2",
  "public_key": "cordelia_pk1...",
  "peers_hot": 5,
  "peers_warm": 12,
  "channels_subscribed": 7,
  "storage_bytes": 25690112,
  "api_address": "127.0.0.1:9473",
  "p2p_listen_address": "0.0.0.0:9474",
  "p2p_external_address": "203.0.113.5:9474"
}
```

> **v1 status.** `cordelia status` shows this device and, while the node
> runs, its peers and memory sync; `cordelia status --json` gives the same as
> data, with a `state` of `synced`, `syncing`, `offline`, `attention`, `off`,
> `stopped` or `uninitialised`. **The status has one level** beside its state
> (decision 2026-10-04 §8, §10.1): red, amber or none. The command works it
> out (`crates/cordelia-node/src/indicator.rs`), and a panel draws it. Red
> is what a person should act on now, and amber what a person should know
> of. The line shows the first thing of the gravest level (`▲` for red, `◆`
> for amber), and the tooltip everything that holds. `--json` carries
> `level` (`red`, `amber` or `null`) and `holds`: everything that holds, red
> first, each with its `level`, a word for what it is (`what`) and what the
> line says of it (`says`).
>
> - **Before any level:** a device that is not set up, a node that is
>   stopped or was not asked, and a relay or a bootnode have states of their
>   own and no level.
> - **Red,** in this order. Whatever sync is set to: this device has stopped
>   (it was removed, or is in no list of the last change, or is in a fork,
>   or was answered with a change that it could not open or apply); the node
>   is held up (its first start on this version has not succeeded, or its
>   database is from a later version: §10.5). With sync on: it follows no
>   phrase, where something is mapped ("not added yet" after the upgrade,
>   "no recovery phrase yet" on a new install); sync errors; a cycle that
>   has stalled; conflict files; files too large; and folders that stopped
>   syncing (the notice of the first start, while it names a folder that no
>   mapping syncs, and until `cordelia sync status --seen`). No phrase is red on every device after this upgrade that has
>   sync on and a folder mapped, and on every new install with a folder
>   mapped, until a person acts: nothing it holds syncs until then. A device
>   that is not to be added turns sync off. With nothing mapped, the notice,
>   errors and a stalled cycle are red all the same.
> - **Amber, of a person's devices,** wherever this device follows a phrase,
>   with sync on or off and with or without a folder mapped: a removal that
>   some device has not applied, for seven days from when this device
>   applied it (after that it is in `cordelia devices` only); a device added
>   since the last change, on every device until a person clears it there
>   (`cordelia devices --clear`) or a statement lists it, as a renewal does
>   (`cordelia renew`); a device that has said it left.
> - **Amber, of folders,** with sync on, something mapped and a report of a
>   cycle: no relay connected for more than five minutes; entries that relays
>   keep refusing; a running node that is not the version the command is; a
>   relay that has been connected for more than five minutes and does not
>   hold the latest change; a relay that has refused something for room, or
>   for the address's allowance, in the last twenty minutes; names that a
>   device which still counts had listed and that no device lists in the
>   channels of the last change, once that has lasted for more than five
>   minutes and for seven days from when this device applied the change; or
>   names not yet sent, for more than five minutes.
> - **The state is as it was, whatever the level,** for a panel that draws
>   from it alone. With sync on, something mapped and no phrase it is
>   `attention`, and so it is on a device that has stopped, on a node that
>   is held up, and with the notice. The line and the level never disagree:
>   where a state is `attention` and there is no level, the line and the bar
>   draw as the state alone has them.
> - `--waybar` gives an icon, a tooltip and a class: the state, then the
>   level (`red` or `amber`) where one holds, and `active` with red, or with
>   `attention` where there is no level.
>
> `cordelia devices` is the one place to look: every device of the last
> change with whether it has applied it and sent what it held, every device
> added since and who added it, every removed key with the label that this
> device knew it by, every key that is in neither list, every device that
> has said it left, the names that no device lists yet and for how many
> more days each can be brought in, what this device has still to send, and
> for each relay whether it holds the latest change. Beside a device that
> has not applied the change, or is still sending, it names `cordelia sync
> carry`.

### 4.4 `cordelia peers`

```
$ cordelia peers
ENTITY          STATE   LATENCY   ADDRESS
relay-eu1       hot     12ms      203.0.113.5:9474
keeper-uk1      hot     8ms       198.51.100.2:9474
alice_f3a1      hot     45ms      192.0.2.10:9474
boot1           warm    22ms      boot1.cordelia.seeddrill.ai:9474
boot2           warm    35ms      boot2.cordelia.seeddrill.ai:9474
```

### 4.5 `cordelia channels`

```
$ cordelia channels
CHANNEL              MODE       ITEMS   LAST ACTIVITY   TYPE
research-findings    realtime   47      2m ago          named
engineering          realtime   123     15m ago         named
archive-2025         batch      891     2d ago          named
__personal           realtime   156     1m ago          [system]

System channels (prefixed `__`) are hidden by default. Use `--all` to include them.
```

> **v1 status.** On a personal node `cordelia channels` lists the names that
> the device holds, each with how many entries it stores of the name's
> channel and when it stored the last. A device holds a name once it follows
> a recovery phrase and a folder is mapped to it.

### 4.6 `cordelia stats`

> **v1 status.** `cordelia stats` prints counts only: the database's size;
> what is stored and its encrypted size (entries of its own channels on a
> personal node, items of the older kind on a relay); the names held, or the
> channels subscribed; the distinct peers seen in the last day and week; and
> the channels active in the last day and week. **On a relay it also prints
> the room of each kind of channel, each against its cap,** which is
> `max_storage_bytes` for both (decision 2026-10-04 §2.5):
>
> ```
> Storage:          <in use> in use of <allowed> allowed, by channels of the older kind
>                   <in use> in use of <allowed> allowed, by channels from their secrets (<n> held, <m> entries)
> ```
>
> The first line is what the items of the older kind are counted at (each
> its content and 1 KB); the second is what the entries of the channels from
> their secrets are counted at, with how many such channels the relay holds
> and how many entries. Neither kind is counted against the other's cap.
> `--json` gives the same for tools: `storage_used_bytes` and
> `storage_max_bytes` for the older kind, and under `entries` the same two
> with `channels_held`, `entries_stored` and `content_bytes_stored`.

```
$ cordelia stats
Storage:        24.5 MB / 1.0 GB (2.4%)
Bandwidth in:   1.2 MB (last hour)
Bandwidth out:  0.6 MB (last hour)
Items pushed:   97
Items synced:   45
Sync errors:    0
Replication lag:
  research-findings   0.5s
  engineering         1.2s
  archive-2025        12m (batch)
```

### 4.7 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments or usage |
| 3 | Configuration error (missing or invalid config.toml) |
| 4 | Node not running (for commands that require it) |
| 5 | Authentication error (invalid or missing node-token) |
| 6 | Network error (cannot reach bootnodes, peer connection failed) |
| 7 | Key error (missing keys, invalid format, permission denied on key files) |
| 8 | Storage error (database corruption, disk full) |

Exit codes are stable across versions. New codes may be added but existing codes will not change meaning.

---

## 5. Configuration

### 5.1 `config.toml` Schema

```toml
# ~/.cordelia/config.toml

[identity]
entity_id = "russwing_a1b2"           # Informational, derived from public key
public_key = "cordelia_pk1..."         # Ed25519 public key (Bech32)

[node]
http_port = 9473                       # REST API port (TCP, localhost only)
p2p_port = 9474                        # P2P transport port (UDP, QUIC)
data_dir = "~/.cordelia"               # Base data directory (~ expanded at startup)
max_storage_bytes = 1073741824         # 1 GB default local storage limit

[network]
listen_addr = "0.0.0.0:9474"          # P2P listen address (UDP, QUIC)
role = "personal"                      # "personal" | "bootnode" | "relay" | "keeper"
push_policy = "subscribers_only"       # "subscribers_only" | "pull_only" (personal nodes only)
bootnodes = [
    "boot1.cordelia.seeddrill.ai:9474",
    "boot2.cordelia.seeddrill.ai:9474",
]
dns_discovery = "_cordelia._tcp.seeddrill.ai"   # SRV record for bootnode discovery
# Governor settings are now in [governor] section (network-protocol.md §12.2).
# See network-protocol.md §8.6 for role-specific profiles:
#   Personal: hot_min=2, hot_max=2, warm_min=3, warm_max=10, cold_max=50
#   Relay:    hot_min=10, hot_max=50, warm_min=20, warm_max=100, cold_max=500
#   Bootnode: hot_min=1, hot_max=5, warm_min=50, warm_max=500, cold_max=1000

[logging]
level = "info"                         # trace, debug, info, warn, error
format = "text"                        # text or json
output = "stderr"                      # stderr, stdout, or file path
file_max_bytes = 10485760              # 10 MB per log file (if output is file path)
file_max_count = 5                     # Keep 5 rotated log files

[api]
bind_address = "127.0.0.1"            # MUST be 127.0.0.1 or ::1 (any other = refuse to start)
token_path = "~/.cordelia/node-token"  # Bearer token file
```

### 5.2 Environment Variables

Environment variables override config.toml values. Prefix: `CORDELIA_`, but for `RUST_LOG`, which is the node's log filter in place of `logging.level` where it is set to one that can be read.

| Variable | Overrides | Example |
|----------|-----------|---------|
| `CORDELIA_HTTP_PORT` | `node.http_port` | `9473` |
| `CORDELIA_P2P_PORT` | `node.p2p_port` | `9474` |
| `CORDELIA_DATA_DIR` | `node.data_dir` | `/data/cordelia` |
| `CORDELIA_LOG_LEVEL` | `logging.level` | `debug` |
| `CORDELIA_LOG_FORMAT` | `logging.format` | `json` |
| `CORDELIA_LISTEN_ADDR` | `network.listen_addr` | `0.0.0.0:9474` |
| `CORDELIA_BIND_ADDRESS` | `api.bind_address` | `127.0.0.1` |

No variable sets the relays or the role; `CORDELIA_CONFIG` sets which file is read (configuration.md SS4.1).

### 5.3 Precedence Order

```
CLI flags  >  Environment variables  >  config.toml  >  Compiled defaults
```

**Path expansion:** The node expands `~` to the user's home directory at startup. Environment variables (`$HOME`) are NOT expanded in config.toml. Use absolute paths in non-interactive deployments (containers, CI).

### 5.4 Security Constraints

- `api.bind_address` MUST be `127.0.0.1` or `::1` (configuration.md SS2.9). With any other value the node refuses to start, and says why. This is a hard security boundary (network-protocol.md §12.2).
- Key files (`~/.cordelia/identity.key`, `~/.cordelia/node-token`, `~/.cordelia/channel-keys/*.key`) MUST have mode 0600. The node MUST warn on startup if permissions are too open and SHOULD refuse to start if key files are world-readable (mode & 0044 != 0).

---

## 6. Logging

### 6.1 Log Levels

| Level | Usage |
|-------|-------|
| `error` | Unrecoverable failures: database corruption, key read failure, bind failure |
| `warn` | Recoverable issues: peer connection dropped, replication lag spike, file permission too open |
| `info` | Operational events: node started, peer connected, channel subscribed, item published |
| `debug` | Protocol detail: CBOR decode, QUIC stream events, forward-compatibility unknown fields |
| `trace` | Wire-level: raw bytes sent/received, encryption timing, GC cycles |

Default: `info`. Recommended for production: `info`. Recommended for debugging: `debug`.

### 6.2 Log Format

**Text format** (default, human-readable):

```
2026-03-11T15:30:00Z INFO  [node] Started on 127.0.0.1:9473 (HTTP), 0.0.0.0:9474 (P2P)
2026-03-11T15:30:01Z INFO  [p2p] Connected to boot1.cordelia.seeddrill.ai:9474 (hot)
2026-03-11T15:30:05Z INFO  [channel] Subscribed to research-findings (3 items synced)
2026-03-11T15:31:00Z WARN  [p2p] Peer relay-eu2 disconnected (timeout after 30s)
2026-03-11T15:31:00Z DEBUG [cbor] Unknown field "future_field" in ChannelDescriptor, ignoring
```

**JSON format** (structured, for log aggregation):

```json
{"ts":"2026-03-11T15:30:00Z","level":"info","module":"node","msg":"Started","http_addr":"127.0.0.1:9473","p2p_addr":"0.0.0.0:9474"}
{"ts":"2026-03-11T15:30:01Z","level":"info","module":"p2p","msg":"Peer connected","peer":"boot1.cordelia.seeddrill.ai:9474","state":"hot"}
```

### 6.3 Log Rotation

When logging to a file:
- Rotate at `file_max_bytes` (default 10 MB)
- Keep `file_max_count` rotated files (default 5)
- Naming: `cordelia.log`, `cordelia.log.1`, ..., `cordelia.log.5`
- Oldest file deleted when count exceeded

When logging to stderr (default): no rotation. Rely on the system service manager (journald, launchd) for log management.

### 6.4 Sensitive Data Redaction

The following MUST NOT appear in log output at any level:
- Private keys (Ed25519, X25519)
- Bearer tokens
- PSK values
- Decrypted content
- Decrypted application metadata

The following MAY appear at `debug` level but MUST NOT appear at `info` or above:
- Channel IDs (use channel names where available)
- Full public keys (truncate to first 8 chars in info logs)
- Peer IP addresses (acceptable at info for connection events)

Structured logging fields use `key_truncated`, `channel_name`, `peer_entity` rather than raw identifiers where possible.

**Access log clarification:** The access log (network-protocol.md §6.2 step 7) is an operational log for debugging, not a compliance audit trail. Phase 4 adds tamper-resistant audit logging with configurable retention suitable for SOC 2 / GDPR accountability.

**Note for keeper/relay operators:** In deployments with centralised log aggregation (e.g., Grafana Loki), peer IP addresses may constitute PII under GDPR. Consider setting log level to `warn` for aggregated logs or configuring IP address redaction at the log collector.

---

## 7. System Service

### 7.1 macOS LaunchAgent

Installed to `~/Library/LaunchAgents/ai.seeddrill.cordelia.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>ai.seeddrill.cordelia</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/USERNAME/.cordelia/bin/cordelia</string>
    <string>start</string>
    <string>--persistent</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/Users/USERNAME/.cordelia/logs/cordelia.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/USERNAME/.cordelia/logs/cordelia.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>CORDELIA_DATA_DIR</key>
    <string>/Users/USERNAME/.cordelia</string>
  </dict>
</dict>
</plist>
```

Control:
```bash
launchctl load ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist     # start
launchctl unload ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist   # stop
cordelia status                                                        # check
```

### 7.2 Linux systemd Unit

Installed to `~/.config/systemd/user/cordelia.service`:

```ini
[Unit]
Description=Cordelia Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/.cordelia/bin/cordelia start --persistent
Restart=on-failure
RestartSec=5
Environment=CORDELIA_DATA_DIR=%h/.cordelia

[Install]
WantedBy=default.target
```

Control:
```bash
systemctl --user start cordelia       # start
systemctl --user stop cordelia        # stop
systemctl --user status cordelia      # check
journalctl --user -u cordelia -f      # follow logs
```

Enable lingering for the service to run without an active login session:
```bash
loginctl enable-linger $USER
```

---

## 8. Monitoring

### 8.1 Health Endpoint

```
GET /api/v1/health
```

No authentication required. Returns:
- `200 OK` with `{"status": "healthy"}` when node is operational
- `503 Service Unavailable` with `{"status": "degraded"}` when unhealthy (no internal details in unauthenticated response)

Degraded conditions (logged internally, not exposed in response):
- Database locked or corrupt
- Zero hot peers for more than 120 seconds
- P2P listener not bound

Detailed health information available via authenticated `POST /api/v1/diagnostics` endpoint (channels-api.md).

Suitable for load balancer probes, container health checks, and monitoring systems. Probe interval: 10s recommended. Timeout: 5s.

**Note:** When exposing the API via reverse proxy or SSH tunnel (§13), consider restricting `/api/v1/health` to specific source IPs or internal networks. The response intentionally omits version, peer count, and other fingerprinting data, but confirms a Cordelia node is running at the address.

### 8.2 Prometheus Metrics

`GET /api/v1/metrics` (bearer token required, Prometheus exposition format). Full metric definitions in channels-api.md §3.15.

### 8.3 Alerting Thresholds

Recommended alerting rules for Prometheus/Alertmanager:

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| PeerCountLow | `cordelia_peers_hot < 2` for 5m | Warning | Check network, verify bootnodes reachable |
| PeerCountZero | `cordelia_peers_hot == 0` for 2m | Critical | Node is isolated. Check firewall, DNS, bootnodes |
| ReplicationLagHigh | `cordelia_replication_lag_seconds > 300` for 5m | Warning | Check peer connectivity, channel mode |
| SyncErrorsSpike | `rate(cordelia_sync_errors_total[5m]) > 1` | Warning | Check logs for specific error type |
| StorageHigh | `cordelia_storage_bytes / max_storage > 0.9` | Warning | Free storage, increase quota, or prune |
| StorageFull | `cordelia_storage_bytes / max_storage > 0.98` | Critical | Publishes will fail. Immediate attention |
| NodeDown | `up{job="cordelia"} == 0` for 1m | Critical | Node process crashed. Check logs, restart |

### 8.4 Grafana Dashboard

Phase 1 ships with a reference Grafana dashboard JSON at `cordelia-core/ops/grafana-dashboard.json`. Panels:

- Peer count (hot/warm) over time
- Items published/synced per channel
- Replication lag per channel
- Storage usage (absolute and percentage)
- Bandwidth in/out
- Sync errors rate
- Uptime

SPOs running Cardano nodes already have Prometheus + Grafana. The Cordelia dashboard imports alongside their existing setup with zero additional infrastructure.

---

## 9. Backup and Recovery

> **v1 status.** What a person keeps is the **recovery phrase**: twelve
> words, written down when `cordelia phrase` shows them. A device's key file
> is that device's alone and is not copied to another: a machine that is
> lost is replaced, and its key removed. The files under `channel-keys/` are
> of the older kind, and a personal node has none. §9.2 to §9.4 below are of
> the design before; what stands in their place:
>
> - **A device is lost, and another remains:** `cordelia remove-device
>   <key>` on one that remains, with the phrase. A new machine is then
>   added with the two commands.
> - **No device remains that you trust:** `cordelia recover` on a new
>   machine, with the phrase. It asks the relays that the machine is set up
>   with; asks of each device a typed `have` (you still have it), `lost` (it
>   is lost or broken) or `hands` (it may be in someone else's hands); looks
>   once at what the relays hold, and brings it back; and stops every other
>   device until each is added again by hand. It takes nothing that a device
>   answered with `hands` wrote: that comes in by `cordelia sync carry <name>
>   --from <device>`, with the phrase. It reaches back 90 days from when the
>   last device was on: a relay is a cache, not a backup.
> - **A device never returned, and had sent edits that no other device
>   took:** `cordelia sync carry <name>` on a device that remains brings in
>   what the relays hold of them, from each generation that the device left
>   in the last 90 days. `--phrase` reads the generations that the device
>   never held the secret of.
> - **The phrase is lost:** devices can still be added, and none can ever be
>   removed or recovered. The way on is to start again on every device:
>   `cordelia phrase` on one, and `cordelia init --new-key` and the two
>   commands on each other.
> - **The database is lost, the key file is not:** the device follows no
>   phrase when it starts. It is handed the last change again by the two
>   commands, from a device that has it, and its folders meet the channels as
>   on a first sync: a copy is kept beside each file that differs.
> - **One machine's mistake** (an edit or a delete that every device took):
>   `cordelia history` and `cordelia restore`, on any device, for 30 days.
>
> Keep your own backup of anything you cannot afford to lose.

### 9.1 What to Back Up

| Data | Location | Priority | Recovery Impact |
|------|----------|----------|-----------------|
| Ed25519 private key | `~/.cordelia/identity.key` | CRITICAL | Without this, identity is lost. All channels inaccessible. |
| Channel PSKs | `~/.cordelia/channel-keys/*.key` | HIGH | Without these, channel content is unreadable. Re-subscribing to open channels restores PSK. Invite-only channels require re-invitation. |
| Node token | `~/.cordelia/node-token` | LOW | Regeneratable. SDK/clients need the new token. |
| Database | `~/.cordelia/cordelia.db` | MEDIUM | Rebuildable via replication from peers. Loss means re-sync delay, not data loss. |
| Config | `~/.cordelia/config.toml` | LOW | Recreatable via `cordelia init`. |

### 9.2 Key Backup

The Ed25519 private key is the most critical piece of data. If lost, the identity cannot be recovered (there is no "forgot password" flow in a decentralised system).

**Recommended backup methods (Phase 1):**

1. **Encrypted file copy**: Copy `~/.cordelia/identity.key` to a secure offline location (USB drive, encrypted cloud storage). The file is 32 bytes, raw.

2. **Paper backup**: `cordelia init --show-backup-key` displays a Bech32-encoded private key (`cordelia_sk1...`). Write it down and store securely. The key is NOT displayed by default (secrets should not appear in terminal output unless explicitly requested). Restore with `cordelia init --import-key cordelia_sk1...`.

3. **Device pairing**: A paired second device holds a copy of the private key. This is the simplest backup: pair your phone or a second machine.

**Phase 4:** Shamir secret sharing (k-of-n recovery across keepers). Distribute key shards to trusted keepers. Recover with any k shards. No single keeper can reconstruct the key.

### 9.3 Data Export

```bash
cordelia export --channel research-findings --output research.json
cordelia export --all --output backup.tar.gz
```

Single-channel export produces a `.jsonl` file (JSON Lines, one item per line), decrypted. `--all` produces a `.tar.gz` containing one `.jsonl` file per channel plus a `manifest.json` with channel metadata and export timestamp. Encrypted export (preserving ciphertext) available via `--encrypted` flag.

```json
{"item_id":"ci_01JARC9B0ETZFGV8QKM3DVNX5P","channel":"research-findings","content":{"type":"insight","text":"..."},"author":"cordelia_pk1...","published_at":"2026-03-10T19:36:00Z"}
```

**Security note:** Export files contain decrypted plaintext and should be treated as sensitive. Encrypt exports at rest if they contain PII. For GDPR data portability (Art. 20), the recipient is responsible for securing exported data. Delete export files after transfer.

### 9.4 Recovery Procedures

**Key loss (no backup):** Identity is permanently lost. Create new identity with `cordelia init`. Re-subscribe to open channels (new PSK distributed). Invite-only channels require re-invitation from owner. Historical items encrypted with old key are unreadable.

**Key loss (with backup):** Restore key file to `~/.cordelia/identity.key` (mode 0600). Run `cordelia init` (detects existing key, skips generation). Node rejoins network with original identity. Channel PSKs re-sync from peers if channels are open, or from paired devices.

**Database corruption:** Delete `~/.cordelia/cordelia.db`. Restart node. Database recreated empty. Items re-sync via replication from peers (may take minutes to hours depending on volume). FTS5 index rebuilt automatically on item arrival.

**Disk full:** Free space. Restart node. Check `cordelia stats` for storage usage. Consider increasing `max_storage_bytes` or pruning old channels via `cordelia channels --prune-older-than 90d` (Phase 2).

---

## 10. Upgrades

### 10.1 Version Checking

```bash
cordelia version
# Cordelia v0.1.0 (abc1234, built 2026-03-15)
```

The node does not auto-update. Operators choose when to upgrade.

### 10.2 Upgrade Procedure

```bash
curl -sSL https://install.seeddrill.ai | sh    # downloads latest, verifies checksum, restarts the service
cordelia status                                  # verify
```

The install script detects an existing installation and performs an in-place binary replacement. Configuration and data are preserved. The node is not stopped first: the script puts the new binary beside the old one, renames it into place, and restarts a node that runs as the service it set up.

### 10.3 Version Compatibility

**Wire protocol versioning:** Mini-protocol IDs (network-protocol.md §3.3) identify protocol capabilities. Nodes that don't recognise a mini-protocol ID ignore it (forward-compatible via CBOR unknown field handling). Incompatible protocol changes use new mini-protocol IDs rather than versioning existing ones.

**Database schema versioning:** SQLite schema migrations run automatically on startup. Each migration is idempotent. The node checks `PRAGMA user_version` against the expected schema version and applies pending migrations in order.

**Backward compatibility guarantees:**
- REST API: Additive changes only (new fields, new endpoints). No field removal or type changes without major version bump.
- CLI output: `--json` output is stable. Text output may change formatting between versions.
- Config: New fields added with defaults. Existing fields never removed without deprecation cycle (warn for one minor version, remove in next major).
- Wire protocol: CBOR forward-compatibility (unknown fields ignored, logged at DEBUG). New capabilities via new mini-protocol IDs.

> **v1 status.** `cordelia --version` prints the version. The install
> script, run again with a later `CORDELIA_VERSION`, replaces the binary,
> restarts a node that is running as the service it set up, and waits until
> the node says that it is the new version. A node and a command that find
> the database at a later schema version than their own name both versions
> and change nothing. §10.5 is the upgrade to this version, which is a new
> start, and how to go back from it.

### 10.4 Rollback

If an upgrade causes issues:

```bash
# Stop the service
systemctl --user stop cordelia                                        # Linux
launchctl unload ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist   # macOS
# Restore previous binary (kept as ~/.cordelia/bin/cordelia.prev by install script)
mv ~/.cordelia/bin/cordelia.prev ~/.cordelia/bin/cordelia
# Start the service
systemctl --user start cordelia                                       # Linux
launchctl load ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist     # macOS
```

> **v1 status.** Going back from this version to the one before puts the
> database back as well: §10.5 has each step.

**Database rollback caveat:** If the new version applied a schema migration, rolling back the binary may fail if the old version doesn't understand the new schema. Schema migrations are designed to be forward-compatible where possible (additive columns, not destructive). If a migration is not forward-compatible, the release notes will state this explicitly.

### 10.5 The Upgrade to This Version, the Copy, and Going Back

> **v1 status.** Decision 2026-10-04 §10 and §10.1.

**Nobody is carried over.** Each device takes this version, starts alone
from its memory folders, and is added again with the two commands. No
device is handed a secret on the strength of what it held before, and there
is one phrase, made once.

**The order:**

1. **Bring every device into step first, on the version it has.** Each is
   on, and has synced, so that every memory folder holds what the others
   hold. This is the one thing the person has to see to: a file that was
   deleted on one device and is still on another comes back, and a device
   that was behind brings its old files as its own.
2. **The relays take this version.** A relay carries the new channels and,
   for one version, the older ones as they are, each kind within a cap of
   its own (`deploy/relay/README.md`).
3. **Each device takes this version.** It keeps its key, its memory folders
   and its mappings. Its folders forget what they had agreed. It follows no
   phrase and publishes nothing, and its status says "not added yet".
4. **On one device, at a terminal, run `cordelia phrase`:** the device whose
   memory is the most up to date, since what it holds is then the channels'
   earliest version of each file.
5. **Add each other device:** `cordelia add-device` on the first, `cordelia
   accept` on the other. Its folders meet the channels as on any first sync:
   a file with the same text on both is agreed; where a file differs, this
   device's text is kept beside the file as a copy and the file takes the
   channel's; a file only here is published; `MEMORY.md` is merged.

Between taking this version and being added, a device can be joined to any
set of devices by `accept` and one yes: add the devices soon after they are
upgraded. `cordelia renew`, run once they are added, puts them in a list that
the person has looked at; without it, the first removal asks about every
device but the first.

**What the upgrade does not carry:** what is in the older channels and in no
folder (the last writes of a device that is gone, and what had been handed
through the local API and not yet sent); removals made before the upgrade,
which are forgotten (the first change removes nobody: a device that was
removed before the upgrade is no device after it, since nothing lists it,
and its key is not refused either, so it is not to be added again: to have
the key refused, remove it once by key after the upgrade, with `cordelia
remove-device <key>`, which asks a typed `refuse` for a key that the device
knows nothing of); a file
of more than 60 KB, where the limit was 64 KB; and the named and direct
channels that the local API of the version before could make. A device left on the
version before goes on in the older channels alone, for as long as the
relays carry them, which is one version.

**The first start.** A personal node that holds anything of the version
before makes a copy and then one step, when it starts (data-formats.md §12):

- **A data directory is one node's.** A node takes a lock on the directory
  (a file in it, `node.lock`) before it opens the database. A second node
  that is started on the same directory, whatever ports it was given, says
  that another is running there, changes nothing, and stops.
- **The copy** is a folder beside the database, `before-<version>`: the
  database as its opening left it (the schema's steps have added tables, and
  have changed no row that was there), and the key files of the older
  channels. It is made and checked before anything is emptied. The node
  answers while it is made: its status says that a copy is being made.
- **Where the copy cannot be made** (no room, no leave to write), the step
  is not taken. The room on the volume is compared with what the copy needs
  before anything is written, and what was written of a copy that failed is
  removed at once. The node stays up, runs no cycle and no pass, refuses
  every request that changes anything but one that turns sync off, and its
  status says why, with the room that is needed and the room there is. It
  tries again by itself and needs no restart: five seconds after the first
  try that failed, and twice as long after each further one, up to ten
  minutes. A copy that was made is used again where only the step failed.
- **The step** empties what the device held of the older kind, and every
  folder forgets what it had agreed. The device's key, its settings, its
  mappings and local history stay.
- **The key files of the older channels are removed after the step.** At a
  later start one is removed only where a `before-` folder holds a file of
  that name with the same bytes: any other is left where it is, and
  `cordelia status` says how many (`Key files:`).
- **A device whose scope was "everything found" is told what stopped:** the
  folders that synced without a mapping sync no longer, and `cordelia sync
  status` names them, each with the command that maps it. Only what is
  mapped syncs: `cordelia sync map` each folder that is to go on, and
  `cordelia sync status --seen` puts the notice away.
- **The copy holds what the device held:** sealed entries, the keys of
  channels that relays keep for up to 90 days more, and also text in the
  clear (removed lines of the index, the names and paths of memory files).
  It is beside memory folders that hold the same memory in the clear. It can
  be deleted once you are content.
- **A database from a later version is refused.** A personal node stays up,
  held up, and its status names both versions: it answers every `GET`, its
  status among them, and no other request, and changes nothing. A relay or a bootnode says
  the same, and stops. A command that opens the database itself is refused
  likewise.

**Going back.** Eight steps, in this order. Each is a command for Linux
(systemd) and for macOS (launchd), with why. The paths are those of a node
that the install script set up: its data directory is `~/.cordelia`.
`<version>` is the version that made the copy: `ls ~/.cordelia` shows the
folder, `before-<version>`.

1. **Stop the service.** The database is replaced below, and a node that
   runs would write to it meanwhile.

   ```bash
   systemctl --user stop cordelia                                        # Linux
   launchctl unload ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist   # macOS
   ```

2. **Put the older binary back.** The install script kept it beside the new
   one, as `cordelia.prev`, when it installed this version.

   ```bash
   ~/.cordelia/bin/cordelia.prev --version      # the version before?
   cp ~/.cordelia/bin/cordelia.prev ~/.cordelia/bin/cordelia
   ```

   Where `cordelia.prev` is another version, install the one before by its
   number instead:

   ```bash
   curl -fsSL https://seeddrill.ai/install.sh | CORDELIA_VERSION=v<the version before> sh
   ```

   **Do not run the "Next steps" that it prints.** They would start the older
   version on the database that this version stepped, and it would stop with
   an error. Go on with step 3.

3. **Remove the database and its two side files,** where they are there.
   Left there, the side files would be replayed over what is put back. (A
   node that stopped cleanly leaves neither of the two, so `rm -f`.)

   ```bash
   rm -f ~/.cordelia/cordelia.db ~/.cordelia/cordelia.db-wal ~/.cordelia/cordelia.db-shm
   ```

4. **Copy the database and the older channels' key files back from the
   copy,** each to where the node keeps it: the database to
   `~/.cordelia/cordelia.db`, and the key files into
   `~/.cordelia/channel-keys/`. The older version reads both.

   ```bash
   cp -p ~/.cordelia/before-<version>/cordelia.db ~/.cordelia/cordelia.db
   cp -p ~/.cordelia/before-<version>/channel-keys/* ~/.cordelia/channel-keys/
   ```

   Run the second command only where the copy has a `channel-keys` folder:
   it has one only where the device held key files.

5. **Move the copy out of the data directory,** to your home directory, say.
   It is what you went back by. A later upgrade then makes a fresh copy, and
   does not rename this one or put another in its place.

   ```bash
   mv ~/.cordelia/before-<version> ~/cordelia-before-<version>
   ```

6. **Have the service manager read the service's file again,** on Linux: the
   install script writes that file anew each time it runs. (launchd reads it
   at the next step.)

   ```bash
   systemctl --user daemon-reload                                        # Linux
   ```

7. **Start the service.** It runs the older binary, on the database that
   was put back.

   ```bash
   systemctl --user start cordelia                                       # Linux
   launchctl load ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist     # macOS
   ```

8. **Check.** The status names the version, and says whether the node runs.

   ```bash
   cordelia status
   ```

What that does not give back: the device's key and its configuration file
were never in the copy, so a device that was given a new key since cannot go
back. The mappings and the sync settings are rows of the database, so they
are as the copy has them, and those made since go with the database that is
removed. And the memory folders are as they are now, so what changed in
them since is published into the older channels as edits.

A version from before this one that is started by mistake on a database
which this version stepped stops with words that say the database was moved
on and where the copy is.

---

## 11. Troubleshooting

### 11.1 Node Won't Start

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| `Error: address already in use` | Another process on port 9473/9474 | `lsof -i :9473` to find process. Stop it or change port in config.toml |
| `Error: permission denied on key file` | Key file permissions too restrictive | `chmod 0600 ~/.cordelia/identity.key` |
| `Error: the node's API address is set to '...'` | `api.bind_address`, or `CORDELIA_BIND_ADDRESS`, is neither `127.0.0.1` nor `::1` | Set it to one of the two. This is a security constraint, not a bug |
| `Error: database locked` | Stale lock from crashed process | Remove `~/.cordelia/cordelia.db-wal` and `cordelia.db-shm`, restart |
| `Error: config parse error` | Invalid TOML | Check `config.toml` syntax. Run `cordelia init` to regenerate |

> **v1 status.** Three more, of this version:
>
> | What is said | Why | What to do |
> |--------------|-----|------------|
> | `another node is running on the data directory ...` | A data directory is one node's: the node that runs holds the lock on it | Stop that node first, or give this one a directory of its own. Nothing was changed |
> | `the database at ... is from a later version of Cordelia than this one` | The database was stepped by a later version | Install the later version again; or put back the copy that it made, as §10.5 says |
> | `cordelia status` says `Held up:` | The first start on this version is not done (the copy could not be made), or the database is from a later version | For the first: make the room that the status names. The node tries again by itself |

### 11.2 No Peers Connecting

```bash
cordelia peers                         # check peer list
cordelia stats                         # check sync errors
```

| Cause | Resolution |
|-------|------------|
| Firewall blocking UDP 9474 | Open UDP 9474 outbound (QUIC requires UDP) |
| DNS resolution failing | Check `dig _cordelia._tcp.seeddrill.ai SRV` |
| Bootnodes unreachable | Try `cordelia status --json` for bootnode connection state. Check `network.bootnodes` in config |
| NAT traversal failing | QUIC handles most NAT. If behind symmetric NAT, need relay |

### 11.3 Replication Lag

```bash
cordelia stats                         # shows per-channel lag
```

| Cause | Resolution |
|-------|------------|
| Batch channel | Expected. Batch channels sync on anti-entropy interval (30s default) |
| Peer disconnected | Check `cordelia peers`. Reconnection is automatic |
| Large item backlog | Normal after extended offline period. Wait for sync to complete |
| Network congestion | Check bandwidth stats. Consider reducing concurrent channels |

### 11.4 Search Not Returning Results

FTS5 indexes are local-only and built from decrypted content.

| Cause | Resolution |
|-------|------------|
| Items not yet replicated | Check replication lag. Wait for sync |
| Index not built | Restart node (indexes rebuild on startup for missing items) |
| Query syntax error | Check FTS5 query syntax (channels-api.md §3.13) |

### 11.5 Diagnostic Commands

```bash
cordelia status --json                 # full status as JSON
cordelia peers --json                  # peer details as JSON
cordelia stats --json                  # all metrics as JSON
CORDELIA_LOG_LEVEL=debug cordelia start --foreground   # debug logging, no daemon
sqlite3 ~/.cordelia/cordelia.db "PRAGMA integrity_check;"   # verify database
```

---

## 12. Security Checklist

Pre-deployment verification:

| Check | Command | Expected |
|-------|---------|----------|
| Key file permissions | `ls -la ~/.cordelia/identity.key` | `-rw-------` |
| Token file permissions | `ls -la ~/.cordelia/node-token` | `-rw-------` |
| API bind address | `grep bind_address ~/.cordelia/config.toml` | `127.0.0.1` |
| Channel key permissions | `ls -la ~/.cordelia/channel-keys/` | `-rw-------` per file |
| Data directory permissions | `ls -ld ~/.cordelia` | `drwx------` |
| No secrets in logs | `grep -rE "cordelia_sk\|[0-9a-f]{64}" ~/.cordelia/logs/` | No matches (catches Bech32 private keys and hex-encoded 64-char strings such as tokens/PSKs; manual review recommended for base64-encoded secrets) |
| Binary checksum | `sha256sum ~/.cordelia/bin/cordelia` | Matches release checksum |

**Breach notification:** If a PSK or identity key is known to be compromised, rotate immediately (§3.11). For deployments processing personal data, establish an incident response procedure including ICO notification within 72 hours per UK DPA / GDPR Art. 33. Phase 4 adds structured incident response tooling.

---

## 13. Container Deployment (Phase 3)

Phase 3 adds Docker support for SPO keeper deployment:

```dockerfile
FROM debian:bookworm-slim
COPY cordelia /usr/local/bin/cordelia
COPY cordelia.sha256 /tmp/cordelia.sha256
RUN cd /usr/local/bin && sha256sum -c /tmp/cordelia.sha256 && rm /tmp/cordelia.sha256
VOLUME /data/cordelia
ENV CORDELIA_DATA_DIR=/data/cordelia
EXPOSE 9473/tcp 9474/udp
ENTRYPOINT ["cordelia", "start", "--persistent"]
```

```bash
docker run -d \
  -v cordelia-data:/data/cordelia \
  -p 9474:9474/udp \
  ghcr.io/seed-drill/cordelia:latest
```

Note: Port 9473 (HTTP API) is NOT exposed externally. Keepers expose only P2P port 9474. API access is local-only or via SSH tunnel.

---

## 14. References

- **specs/ecies-envelope-encryption.md**: Key types, encoding, ECIES envelope format
- **specs/channels-api.md**: REST API endpoints, metrics, error codes
- **specs/network-protocol.md**: P2P transport, peer management, replication, security
- **decisions/2026-03-09-mvp-implementation-plan.md**: WP5 (enrollment), WP7 (install), WP13 (CLI/metrics)
- **decisions/2026-03-09-architecture-simplification.md**: Two-component architecture, deployment profiles

---

*Draft: 2026-03-11. Review with Martin before implementation.*
