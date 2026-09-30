# Decision: Refocus on Agent Memory Sync

**Date**: 2026-09-30
**Decision maker**: Russell Wing
**Reviewer**: Martin Stevens
**Status**: Accepted. Built in cordelia-node #11 to #20 (2026-09-30).
**Supersedes**: [`2026-03-09-architecture-simplification.md`](2026-03-09-architecture-simplification.md) (positioning and roadmap), and [`memory-model.md`](../archive/specs/memory-model.md) as the Phase 1 target.
**Source**: This is the build-facing part of a decision record kept in Seed Drill's private strategy repository. Section 7 (network effect and traction) and the open questions stay there, and section 9 here lists known limits instead. The other section numbers match that record, because code comments cite them (for example "decision 2026-09-30 §4.3"). Where the build refined the design, the change is marked **As built**.

---

## 0. Principles

Last time we were too ambitious to execute: five phases, a token economy and a theory of memory, with two people and the models of the day. This time the scope is sized to what we can build, run and support. Every decision below is tested against four principles:

- **Simple.** One binary and one command per step. No accounts, no portal, no passphrase ceremony, and no config file for the default path. If a step needs explaining, we redesign the step.
- **Extensible.** New agents plug in as adapters (4.5), anyone can run a relay (4.6), and settlement can be added later. None of these changes the core. New wire fields are optional and versioned.
- **Robust.** It works when one machine is off, and there are two relays in different places run by different means. Sync is idempotent and restartable. A conflict produces a second file, never a lost edit.
- **Secure.** No infrastructure holds a key, each device can be revoked, and the attack surface is small. We serve no open channels, no keepers and no key-exchange protocol. Every security claim we make is one we have tested (section 5).

## 1. Decision

We are cutting Cordelia back to one product: **your AI agent's memory on every machine you use, readable only by you and the people you choose.**

- **v1** syncs Claude Code's memory files between one person's machines, through relays that cannot read them.
- **v1.1** shares a project's memory with a teammate. It uses the same mechanism, so it costs no new design.

We release it as open source and measure whether people share. Anything that v1 or v1.1 doesn't need is either deferred or dropped (section 8).

## 2. Starting point (2026-09-30)

The node was solid: QUIC transport, governor, epidemic relay forwarding, invite-only channels, ECIES wrapping on the sending side and SQLite storage, built and tested. None of it ran for a user:

- **No network to join.** The bootnodes were shut down at the April pause; no public relay had ever been deployed.
- **No release,** so `scripts/install.sh` failed.
- **Two devices couldn't share a key.** Pairing (0x08) existed only as message structs, PSK-Exchange (0x07) was never dispatched, and nothing outside a unit test opened an ECIES envelope.
- **Items couldn't be updated,** and **deletes didn't replicate.** `delete-item` didn't check the item's channel or author.
- **The integration layer targeted the archived API** (`cordelia-proxy`, `cordelia-agent-sdk`).
- **The April review sprint's 22 CRITICAL findings were open,** mostly spec drift.

## 3. The product

```
laptop$  cordelia init                  desktop$ cordelia init
                                        desktop$ cordelia id
                                                 cordelia_pk1...   (copy this)
laptop$  cordelia add-device cordelia_pk1... --name desktop
         Added desktop to 1 channel.
         On the other device, run:
           cordelia accept cordelia_pk1...   (copy this back)
                                        desktop$ cordelia accept cordelia_pk1...
laptop$  cordelia sync claude           desktop$ cordelia sync claude
```

That is one key copied in each direction. Each machine has now been told by you, in person, which key belongs to the other, so each can authenticate the other (4.1).

After that, a memory Claude Code writes on one machine appears on the other. This includes memories written while the other machine was off; they arrive when it next connects.

v1.1 adds a person the same way, with a scope: `cordelia share <project> <key>` shares one project's memory, not everything.

## 4. Design

Five changes to the node, plus one piece of infrastructure.

### 4.1 One key per device; devices are channel members

Each machine keeps the Ed25519 identity that `init` generates. A person's devices are members of that person's invite-only channels, exactly as a teammate would be.

This replaces seed-sharing pairing ([`identity.md`](../specs/identity.md) §6). Seed sharing copies the whole identity to every device, so no single device can be revoked, and it gives two live nodes the same node ID.

**Inbox.** Every node has an inbox channel that anyone can derive from its public key: `inbox_` + hex(SHA-256(`"cordelia:inbox:v1:"` || ed25519_pk)). A node subscribes to its own inbox at startup.

**As built: sealed channel state.** An invite is an item of internal type `invite` in the recipient's inbox, pushed to relays like any other item. Its blob is a *channel state* sealed to the recipient with ECIES (X25519, HKDF-SHA256, AES-256-GCM). It carries the channel's key ring, its slot key (4.3), its member list, an epoch, the sender's key and whether it is the sender's personal channel. On receipt:

- The item's signature must verify, and the sender named inside the ciphertext must equal the item's author, so a state can't be re-signed by someone else and replayed as theirs.
- A state is applied only if it is newer than the one held (by epoch, then author key) and comes from an owner of the channel.
- A state for a channel the node doesn't know is applied only if the sender is trusted.
- Channel IDs must be exactly `grp_<lowercase uuid>`.

Membership changes, key rotations and invites are all the same operation: the owner publishes a new state to each member's inbox.

**Trust.** A node joins a channel automatically only when the state comes from a key it trusts. Everything else waits in a pending list (at most 100, oldest rejected first), which `cordelia invites` shows. Trust comes from two places:

- **`cordelia accept <key>`**, the explicit, out-of-band step. You copy a key from one of your own screens to another, with no pairing code, no bootnode involvement and no fingerprint prompt to skip.
- **Your personal channel.** **As built:** the device roster is the personal channel's member list. Any device in it is trusted, so a third device added from the laptop is trusted by the desktop without another `accept`.

Without a trust check, anyone who knows your public key could add you to a channel. Its content would land in Claude's memory folder, which your agent reads as its own notes.

**Personal channel.** A `grp_` channel that holds the device roster, home memory and the map from project to channel (4.5). A node creates one on first use, and a device that accepts a `device` invite adopts the inviter's personal channel as its own.

**Revocation.** `cordelia remove-device <key>`, run from any remaining device, revokes trust in the key, removes the device from every channel this device owns, rotates each of those channels' keys, and sends the new state to the remaining members through their inboxes. **As built:** since devices join only the projects they have (4.5), the remover may not be in every project channel. Each device that sees a device dropped from the personal channel therefore removes it from the project channels the remover is not in. Of a channel's remaining owners, the one with the lowest key acts, so two devices never rotate the same channel at once. It is run from one device at a time; two devices changing membership at once can lose one of the changes (section 9).

**Roles.** All of a person's devices are equal: any device can add, revoke and rotate, so a device's membership in its person's channels is `owner`.

### 4.2 Invite-only channels only; no keepers

v1 uses only invite-only channels, which it creates as `grp_` channels so relays never see a channel name. The creator wraps the channel key for each member, and no keeper ever holds it. Open channels, which hand their key to any peer that asks, and keepers, which hold keys for open channels, are **deferred**. In v1, no infrastructure holds a key.

### 4.3 Replaceable items

A memory file is edited, not appended to. Items gain an optional `slot` and `rev`:

- **Slot:** `slot = HMAC-SHA256(slot_key, "cordelia:slot:v1:" || logical_key)`.
  - `logical_key` is the file's key within its channel (4.5). Relays can match slots without learning file names.
  - `slot_key` is a random 32-byte key per channel. It is created with the channel, sent in the channel state next to the key ring, and **never rotated**. If slots were derived from the channel key, every rotation would move every file to a new slot. A revoked device keeps the slot key, which tells it only whether two items are the same file.
- **Rev:** a per-slot counter. The writer sets `rev = highest rev seen for this slot + 1`. Wall clocks play no part, so clock skew between machines does no harm.
- **Signature and encryption both cover the slot and rev.** The signed metadata envelope gains `slot` and `rev`, present only on slotted items, so existing items and test vector TV-C1 are unchanged. The item's AES-GCM associated data becomes `channel_id || slot || rev`. A relay can neither relabel an item into another slot nor replay an old revision as a new one.

**Storage keeps the newest rev per `(channel_id, slot, author)`, not per slot.** Relays see slot values but can't tell members from strangers. Under a per-slot rule, anyone who can reach a relay could publish junk with a higher rev into your slot, and the relay would throw your real item away. Keyed by author, an attacker can only replace their own entries. This needs **every node, relays included, to verify an item's signature before storing it.**

**Readers resolve per slot.** Among items whose author is an active member of the channel, which decrypt, and whose key maps back to the slot, the highest `rev` wins, with ties going to the higher `content_hash`. The losing version of a tie is reported as a conflict, and the device that wrote it keeps it as `<file>.conflict-<tag>.md` (the tag is the start of its key), so neither machine's edit is lost.

This is the same idea as Nostr's addressable events (NIP-01, kinds 30000-39999). The API is `publish` with a `key`, `/api/v1/channels/entries` and `/api/v1/channels/delete-key`.

### 4.4 Deletes that replicate

A delete is a new `rev` of the slot, marked as a tombstone. Tombstones are kept for 90 days (`KEYED_TOMBSTONE_RETENTION_DAYS`), so a laptop that has been in a drawer doesn't bring deleted files back; after that, an hourly sweep drops the key's whole slot history. `delete-item` now checks the item's channel and that the caller wrote it.

### 4.4a Fixes to sync and verification that 4.1-4.4 depend on

- **Sync served only what the listen API shows,** which hides internal items and tombstones, so no key envelope or delete had ever reached another node by sync. Sync now has its own query that returns every item.
- **Sync fetched only the newest 100 items per channel.** **As built:** items get an arrival sequence number, and sync pages by it (`after_seq` in the request, `last_seq` in the response) with a cursor per peer and channel, until `has_more` is false.
- **Key distribution never reached the network.** Membership and key changes made through the device commands and the adapter now go through inboxes (4.1). The older endpoints still don't (section 9).
- **A burst of writes was rate-limited and lost** (found by the real-process test). **As built:** new items go into an outbox that is pushed to one relay at a time, at most every 2 seconds, and an item is marked relayed only when the relay acknowledges it.

### 4.5 `cordelia sync claude`: the Claude Code adapter

It runs inside the node binary: one install, and the node stays the encryption boundary ([2026-03-10 decision](2026-03-10-phase1-design-decisions.md) §1). Every 5 seconds it scans `~/.claude/projects/*/memory/`:

- **Project identity comes from the git remote, not the path.** Claude Code names memory folders after the working directory, so paths never match across machines. The adapter reads the `cwd` recorded in the folder's session transcripts and normalises that repository's `origin` remote to `host/owner/repo`.
- **Home memory** (the folder for your home directory) goes to your personal channel, under keys `home/<file>`. Other folders that aren't git repositories are not synced, and `cordelia sync status` lists them.
- **Each project gets its own `grp_` channel,** so sharing it later is just adding a member. The personal channel maps `project/<host/owner/repo>` to the project's channel.
- **As built: devices join only the projects they have.** A project channel starts with its creator as the only member. Another device that has the project locally posts a join request (`join/<channel>/<device>`) in the personal channel; an owner grants it, and only for the device named in it. So each device holds keys only for the projects it works on. `--exclude <pattern>` keeps projects off a device, and `--no-home` keeps home memory off it.
- **`MEMORY.md` is merged, not replaced.** It's an index of one-line pointers, so the merge is the union of lines, minus lines pointing at deleted files.
- **Safety.** Only plain file names are synced, writes are atomic, a file edited during a cycle is left for the next one, and files over 128 KB are reported rather than synced.

Other agents come later as further adapters that map their own memory locations onto the same channels.

### 4.6 Two relays

Personal nodes are outbound-only and there is no NAT traversal, so two devices always meet through a relay. We run two, each also serving as a bootnode, so that losing one doesn't stop sync:

- **`relay1`** and **`relay2`** run at two of our own sites, as Docker containers, from the image and guide in [`deploy/relay/`](../../deploy/relay/). **Changed 2026-09-30:** the record planned `relay1` on Fly.io; running both at our sites is simpler, and the same image still runs on Fly. Running them ourselves also shows that a relay is something anyone can run.
- **DNS:** `relay1.cordelia.seeddrill.ai` and `relay2.cordelia.seeddrill.ai`, UDP 9474. New nodes list both (`FALLBACK_PEERS`), and anyone can add their own. **As built:** nodes keep the names, not the addresses. They resolve them again while running and redial whenever they have no relay, so a node started before its network was up, or a relay whose address changed, is still reached.
- **Retention** for relays is not implemented yet (section 9).

## 5. What we promise about security

- Relays and Seed Drill see channel IDs, device public keys, item sizes, types and timing. They never see content, file names, member lists or keys.
- Only devices you added, and people you shared a project with, can read it.
- On your own machines, memory is as protected as your disk. The node's search index and Claude Code's own files are plaintext at rest.

This replaces the v2.3 whitepaper's "no plaintext at rest on any node, ever", which the code did not meet and v1 doesn't need.

## 6. Why not Syncthing

v1 must beat plain file sync on things it can't do:

- **Neither machine needs to be on at the same time.** The relay holds ciphertext, so a closed laptop still catches up later.
- **Memory follows the project, not the path.** File sync puts `-home-alice-Work` and `-Users-alice-Work` in different folders.
- **`MEMORY.md` merges instead of producing conflict files.**
- **Sharing follows the repo.** You share one project's memory with one person, without sharing a folder tree.

If dogfooding shows these differences don't matter in practice, that is our answer, and it is cheap to get.

## 8. Scope

| Area | v1 | Note |
|---|---|---|
| QUIC transport, governor, relay forwarding, SQLite | **Keep** | |
| Invite-only `grp_` channels, ECIES wrapping | **Keep** | Receiving side added (4.1) |
| Per-device keys, inbox, trust, add-device/accept, revoke | **Built** | 4.1 |
| Sync of all items with paging; key distribution through inboxes; outbox | **Built** | 4.4a |
| Signature verification before storing, on every node | **Built** | 4.3 |
| Replaceable items (`slot`, `rev`) | **Built** | 4.3 |
| Tombstone-as-revision, delete authorisation fix | **Built** | 4.4 |
| `cordelia sync claude` adapter, per-project channels | **Built** | 4.5 |
| Two relays and DNS | **Image and configs built** | 4.6; deployment is next |
| Release: macOS and Linux binaries | **Built** | `release.yml`; Homebrew tap and AUR package to follow |
| Sharing with a teammate (`share`) | **v1.1** | Same mechanism as 4.1 |
| Second agent adapter | **v1.1+** | Proves portability |
| Open channels, secret keepers, PSK-Exchange (0x07) | Defer | Only needed for public channels |
| FTS search, semantic search | Defer | The agent reads the files; v1 needs no search |
| PAN / swarm (`swarm-init`) | Defer | Sub-agents, not devices |
| TypeScript SDK (`cordelia-sdk`) | Defer | |
| Seed-sharing pairing (0x08) | **Drop** | Replaced by 4.1 |
| L0-L3 hierarchy, L1 chain, novelty engine, frame memory | **Drop** | The agent decides what to remember; we carry it |
| Bayesian trust, culture policies, governance voting | **Drop** | |
| SPO economics, Cardano as settlement | **Drop** | No settlement layer is chosen. There are many options and no benefit in picking one before real use shows what is needed; any future layer is optional and pluggable ([`docs/vision.md`](../vision.md) §4). |
| `cordelia-proxy`, `cordelia-agent-sdk`, `cordelia-dashboard`, `rutherford`, `cordelia-portal` | **Archive** | All target the archived API |
| `memory-model.md`, `search-indexing.md`, `sdk-api-reference.md`, `architecture-overview.md`, `game-theory.md` | **Archived** | [`docs/archive/`](../archive/README.md) |

## 9. Known limits

- Two devices changing the membership of the same channel at the same moment can lose one of the changes.
- A project channel that the removing device is not in is rotated by its remaining owner with the lowest key (4.1). If that device is offline, the rotation waits until it next runs, and until then the removed device can still read what others write to that project.
- Relays keep what they store; the retention limit (30 days was proposed) is not implemented.
- The older key-distribution endpoints (`dm`, `group/invite`, `group/remove`, `rotate-psk`) still write key envelopes into the channel itself, which never reach other nodes. v1 doesn't use them; they will move onto sealed channel states or be removed.
- The E2E topology suite (T1-T7) predates v1 and is stale, so its workflow runs only on demand. v1 is covered by real-process tests in `crates/cordelia-node/tests/devices_e2e.rs`.

## 10. Done means

- A memory written on one machine appears on the other within 30 seconds when both are online. If the other is off, it appears within 30 seconds of it reconnecting.
- Editing and deleting a memory propagates too, and a concurrent edit leaves a conflict file rather than losing either version.
- The same project's memory lands in the right folder on macOS and Linux, despite the different paths.
- The relay's database is checked and holds only ciphertext and HMAC slots, with no file names.
- A removed device cannot read anything written after its removal.
- Installing on macOS and on Linux reaches a working sync in under five minutes.
- Sync keeps working when either relay is stopped.

## 11. Sequence

1. **Clean up the public surface** so it matches this decision: whitepaper v3 and [`docs/vision.md`](../vision.md), seeddrill.ai, and this archive. Done.
2. **Build**, each step its own PR: the release pipeline (#12); inbox, trust and devices (#13); replaceable items and verified storage (#14); deletes (#15); the adapter (#16); the relays (#18); per-project channels (#20). Done.
3. **Deploy the relays,** then tag the first pre-release, `v0.2.0-alpha.1`.
4. **Dogfood** on our own machines until section 10 holds. Then release publicly.
