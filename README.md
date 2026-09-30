# Cordelia

**Your AI agent's memory on every machine you use, readable only by you and the
people you choose.**

AI coding agents keep memory, but it lives in one folder on one machine, filed
under the path the agent ran in. Cordelia keeps it in step across your devices:
end-to-end encrypted, carried by relays that hold only ciphertext and no keys,
and matched by project (git remote) rather than by path. Version 1 syncs Claude
Code's memory.

- **How it works, and what it promises:** [WHITEPAPER.md](WHITEPAPER.md)
- **Where it is going:** [docs/vision.md](docs/vision.md)

## Status

**Pre-release (October 2026).** v1 is built and tested, including end-to-end
tests with real processes over QUIC through a relay. The first two relays are
being deployed; the first pre-release (`v0.2.0-alpha.1`) follows. Until then,
build from source.

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

Then sync Claude Code's memory on both:

```bash
cordelia sync claude       # home memory and every git project in ~/.claude
cordelia sync status       # what syncs, what is waiting, what does not
```

A device joins a project's channel only once it has the project locally, so
it holds keys only for the projects it works on. Per device:
`cordelia sync claude --exclude github.com/client-co/*` (never sync those
projects from this machine) and `--no-home` (leave home memory off it).

Other commands: `cordelia devices`, `cordelia invites`,
`cordelia remove-device <key>` (removes a device everywhere and rotates keys),
`cordelia sync off`.

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
| `deploy/relay` | Relay image and configs (Fly.io and self-hosted) |
| `docs/decisions` | Decision records; [`2026-09-30-agent-memory-sync.md`](docs/decisions/2026-09-30-agent-memory-sync.md) is the v1 design |
| `docs/specs` | Protocol and component specs, each with a note on what v1 changed |
| `docs/archive` | Pre-v1 documents, kept for history |

The local API (`127.0.0.1:9473`, bearer token in `~/.cordelia/node-token`)
covers channels (`/api/v1/channels/*`, including `entries` and `delete-key` for
keyed items), devices (`/api/v1/devices/*`), invites (`/api/v1/invites/*`), and
sync (`/api/v1/sync/*`).

## Security

Relays and relay operators see channel IDs, device public keys, and item sizes,
types and timing; never content, file names, member lists, or keys. See
[WHITEPAPER.md §4](WHITEPAPER.md#4-security-model) for the full model and its
limits. To report a vulnerability privately, email hello@seeddrill.ai.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
