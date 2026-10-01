# Cordelia

**Your AI agent's memory on every machine you use, readable only by you.**

AI coding agents keep memory, but it lives in one folder on one machine, filed
under the path the agent ran in. Cordelia keeps it in step across your devices:
end-to-end encrypted, carried by relays that hold only ciphertext and no keys,
and matched by project (git remote) rather than by path. Version 1 syncs Claude
Code's memory.

- **How it works, and what it promises:** [WHITEPAPER.md](WHITEPAPER.md)
- **Where it is going:** [docs/vision.md](docs/vision.md)

## Status

**Pre-release (October 2026).** v1 is built and tested, including end-to-end
tests with real processes over QUIC through a relay. Two relays are running,
and `v0.2.0-alpha.3` is the current pre-release, for macOS and Linux:

```bash
curl -fsSL https://seeddrill.ai/install.sh | CORDELIA_VERSION=v0.2.0-alpha.3 sh
```

It is an alpha: expect rough edges, and keep your own backup of anything you
cannot afford to lose.

## Use

On each machine:

```bash
cordelia init          # create this device's key
cordelia start         # run the node (install.sh sets it up as a service)
```

Pair two machines, one key copied in each direction:

```bash
laptop$  cordelia id                                  # prints cordelia_pk1...
desktop$ cordelia add-device cordelia_pk1... --name laptop
         #   On the other device, run: cordelia accept cordelia_pk1...
laptop$  cordelia accept cordelia_pk1...
```

Then turn on sync on both, and say what to sync:

```bash
cordelia sync claude                  # on: lists what it found, syncs nothing yet
cordelia sync map ~/Work/my-project   # a git project, named by its remote
cordelia sync map ~/notes lab-notes   # any other folder in your home directory, under a name you choose
cordelia sync map ~ --home            # home memory
cordelia sync status                  # what syncs, what was found, what your other devices sync
```

Only what you map syncs. The name is what your devices share: map the same
name on each device and Claude's memory for it stays in step. A git project
is named by its remote (`github.com/owner/repo`), so the same clone at
different paths on two machines needs no name; any other folder needs one.
Claude Code keeps one memory per repository, shared by its folders and
worktrees, so mapping any folder of a repository maps the repository.

A device joins a name's channel only when it maps that name. A device that
has never mapped a name holds neither its memory nor its key, and home memory
is the same.

To sync everything Claude Code has memory for, now and later (home memory and
every git project found), use `cordelia sync claude --all`. With `--all`,
`cordelia sync exclude github.com/client-co/*` keeps projects off this
machine, and `cordelia sync home off` keeps home memory off it.
`cordelia sync claude --mapped-only` goes back to mapped folders only.

Running `cordelia sync claude` again changes nothing; it keeps your settings,
and says so. `cordelia sync unmap <folder or name>` stops syncing a folder
from this device and leaves its files where they are. The folder then stays
out, even with `--all`, until you map it again; mapping it again merges it
with what your other devices have, and deletes nothing. The device stays a
member of the name's channel (its node still receives the encrypted items)
until you remove the device; leaving a channel is not built yet.

Other commands: `cordelia devices`, `cordelia invites`,
`cordelia remove-device <key>` (removes a device everywhere and rotates keys),
`cordelia sync off`.

### Status

`cordelia status` shows this device and, while the node runs, its peers and
memory sync. For status bars:

- `cordelia status --line` prints one short line: `● memory synced`,
  `◐ memory sending 3`, `○ memory offline`, `▲ memory: 1 conflict`, and so on.
  It prints nothing on a machine where Cordelia is not set up.
- `cordelia status --json` gives the same `state` (`synced`, `syncing`,
  `offline`, `attention`, `off`, `stopped`) and `summary`, with everything a
  panel or an agent needs: the connected relays, your devices, each folder
  that syncs and its name, what was found and is not syncing, what your
  other devices sync, items waiting to reach a relay, last change, and the
  conflict files waiting to be merged.

To show it in Claude Code, add this to `~/.claude/settings.json` (use the full
path, e.g. `~/.cordelia/bin/cordelia`, if `cordelia` is not on the `PATH`
Claude Code starts with):

```json
{ "statusLine": { "type": "command", "command": "cordelia status --line" } }
```

If you already have a status line command, add `$(cordelia status --line)` to
what it prints.

On [Omarchy](https://omarchy.org), the
[Cordelia panel](https://github.com/seed-drill/omarchy-cordelia) puts an icon
in the bar and opens a panel to turn sync on and off, choose what syncs, pair
devices and open conflicts:

```bash
omarchy plugin add https://github.com/seed-drill/omarchy-cordelia.git --enable
```

For any other bar, `cordelia status --waybar` prints an icon, a tooltip and
the state as a class, in the JSON that Waybar's custom modules take. The
icons are Nerd Font glyphs.

- **Omarchy, without the panel:** add this to `bar.layout.right` in
  `~/.config/omarchy/shell.json`. The bar highlights the icon when a conflict
  or an error needs you, and a click opens the details.
  ```json
  {
    "id": "cordelia",
    "type": "command",
    "exec": "~/.cordelia/bin/cordelia status --waybar",
    "interval": 5,
    "onClick": "omarchy-launch-floating-terminal-with-presentation '~/.cordelia/bin/cordelia status; echo; ~/.cordelia/bin/cordelia sync status'"
  }
  ```
- **Waybar:** a custom module, styled by class (`synced`, `syncing`,
  `offline`, `attention`, `off`, `stopped`).
  ```json
  "custom/cordelia": {
    "exec": "~/.cordelia/bin/cordelia status --waybar",
    "return-type": "json",
    "interval": 5
  }
  ```

## Build from source

```bash
cargo build --release          # toolchain pinned in rust-toolchain.toml
./target/release/cordelia --help
cargo test --all               # unit, protocol, and end-to-end tests
```

## Repository

| Path | What |
|---|---|
| `crates/cordelia-core` | Types, config, protocol constants (`protocol.rs`) |
| `crates/cordelia-crypto` | Ed25519/X25519 identity, AES-256-GCM, ECIES, sealed channel states, slots |
| `crates/cordelia-storage` | SQLite: channels, items, keys, trust, invites, sync state |
| `crates/cordelia-network` | QUIC transport, governor, mini-protocols, item sync |
| `crates/cordelia-api` | Local REST API; devices, invites, keyed entries, membership |
| `crates/cordelia-sync` | The Claude Code adapter |
| `crates/cordelia-node` | The `cordelia` binary: CLI, daemon, p2p loop |
| `deploy/relay` | Relay image, Docker Compose and a guide to running a relay |
| `docs/decisions` | Decision records; [`2026-09-30-agent-memory-sync.md`](docs/decisions/2026-09-30-agent-memory-sync.md) is the v1 design |
| `docs/specs` | Protocol and component specs, each with a note on what v1 changed |
| `docs/archive` | Pre-v1 documents, kept for history |

The local API (`127.0.0.1:9473`, bearer token in `~/.cordelia/node-token`)
covers channels (`/api/v1/channels/*`, including `entries` and `delete-key` for
keyed items), devices (`/api/v1/devices/*`), invites (`/api/v1/invites/*`), and
sync (`/api/v1/sync/*`).

## Security

Relays and relay operators see channel IDs, device public keys, and item sizes,
types and timing; never content, file names, member lists, or keys. The node
on your machine dials out to the relays (UDP 9474) and listens only on its
local API (127.0.0.1): nothing on a network you join can connect to it. See
[WHITEPAPER.md §4](WHITEPAPER.md#4-security-model) for the full model and its
limits. To report a vulnerability privately, email hello@seeddrill.ai.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
