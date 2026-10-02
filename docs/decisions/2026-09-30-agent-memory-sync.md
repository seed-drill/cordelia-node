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

We are cutting Cordelia back to one product: **your AI agent's memory on every machine you use, readable only by you.**

- **v1** syncs Claude Code's memory files between one person's machines, through relays that cannot read them.
- **Changed 2026-10-01.** v1.1 was to share a project's memory with a teammate, and the line above ended "and the people you choose". Memory is now never shared between people (4.7). What follows v1 is channels shared between people that carry messages, skills and secrets, which are designed separately.

We release it as open source and measure whether people use it and keep using it. Anything that v1 doesn't need is either deferred or dropped (section 8).

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
laptop$  cordelia sync map ~/Work/app   desktop$ cordelia sync map ~/code/app
```

That is one key copied in each direction. Each machine has now been told by you, in person, which key belongs to the other, so each can authenticate the other (4.1).

After that, a memory Claude Code writes for that project on one machine appears on the other. This includes memories written while the other machine was off; they arrive when it next connects. Only what is mapped syncs (4.5).

**Changed 2026-10-01.** This section used to end by adding a person the same way, to share one project's memory. Memory is not shared between people (4.7).

## 4. Design

Five changes to the node, plus one piece of infrastructure.

### 4.1 One key per device; devices are channel members

Each machine keeps the Ed25519 identity that `init` generates. A person's devices are members of that person's invite-only channels.

This replaces seed-sharing pairing ([`identity.md`](../specs/identity.md) §6). Seed sharing copies the whole identity to every device, so no single device can be revoked, and it gives two live nodes the same node ID.

**Inbox.** Every node has an inbox channel that anyone can derive from its public key: `inbox_` + hex(SHA-256(`"cordelia:inbox:v1:"` || ed25519_pk)). A node subscribes to its own inbox at startup.

**As built: sealed channel state.** An invite is an item of internal type `invite` in the recipient's inbox, pushed to relays like any other item. Its blob is a *channel state* sealed to the recipient with ECIES (X25519, HKDF-SHA256, AES-256-GCM). It carries the channel's key ring, its slot key (4.3), its member list, an epoch, the sender's key and whether it is the sender's personal channel. On receipt:

- The item's signature must verify, and the sender named inside the ciphertext must equal the item's author, so a state can't be re-signed by someone else and replayed as theirs.
- A state is applied only if it is newer than the one held (by epoch, then author key) and comes from an owner of the channel.
- The epoch is bounded. It is at most 2^53 - 1 (`MAX_EPOCH`), and one state can move it by at most 2^20 (`MAX_EPOCH_STEP`). A device that was away may have missed some changes, so a state may skip epochs. But no member can use the numbers up, after which the list could never change again.
- A state for a channel the node doesn't know is applied only if the sender is trusted.
- Channel IDs must be exactly `grp_<lowercase uuid>`.

Membership changes, key rotations and invites are all the same operation: the owner publishes a new state to each member's inbox.

**Trust.** A node joins a channel automatically only when the state comes from a key it trusts. Everything else waits in a pending list (at most 100, oldest rejected first), which `cordelia invites` shows. Trust comes from two places:

- **`cordelia accept <key>`**, the explicit, out-of-band step. You copy a key from one of your own screens to another, with no pairing code, no bootnode involvement and no fingerprint prompt to skip.
- **Your personal channel.** **As built:** the device roster is the personal channel's member list. Any device in it is trusted, so a third device added from the laptop is trusted by the desktop without another `accept`.

Without a trust check, anyone who knows your public key could add you to a channel. Its content would land in Claude's memory folder, which your agent reads as its own notes.

**Personal channel.** A `grp_` channel that holds the device roster and the map from name to channel (4.5). Until 0.2.0-alpha.3 it also held home memory. A node creates one on first use, and a device that accepts a `device` invite adopts the inviter's personal channel as its own.

**Revocation.** `cordelia remove-device <key>`, run from any remaining device, revokes trust in the key, removes the device from every channel this device owns, rotates each of those channels' keys, and sends the new state to the remaining members through their inboxes. **As built:** since devices join only the projects they have (4.5), the remover may not be in every project channel. Each device that sees a device dropped from the personal channel therefore removes it from the project channels the remover is not in. Of a channel's remaining owners, the one with the lowest key acts, so two devices never rotate the same channel at once. It is run from one device at a time; two devices changing membership at once can lose one of the changes (section 9).

**What a removed device wrote.** Once a device is removed, its entries count for nothing: not when a name is read, not towards a name's next revision, not in the sweep of old deletes. So that the channel keeps what it held:

- Just before it removes a device, the removing device publishes again, under its own name, every entry whose current value the removed device wrote: its content, or its delete. It uses the revision the removed device gave the entry, so the new entry takes the old one's place exactly. A device that already holds the entry sees no change; a device that is behind, or is added later, gets it.
- Only the removing device does this, with what it holds at that moment. A device that learns of the removal later may hold something newer from the removed device. It cannot tell whether that was written before the removal or after it, so it does not publish it. Its sync adapter keeps that version beside the file as a conflict file (4.5), and the file takes the channel's value.
- A revision in the upper half of the range is never reached by editing. An entry that carries one is published again at the next revision after the remaining members', which keeps its content and gives the name its revisions back.
- A device fetches its inbox before its other channels, so whenever it sees a removal it fetches the re-published entries in the same pass, before the removal is applied.

**Roles.** All of a person's devices are equal: any device can add, revoke and rotate, so a device's membership in its person's channels is `owner`.

### 4.2 Invite-only channels only; no keepers

v1 uses only invite-only channels, which it creates as `grp_` channels so relays never see a channel name. The creator wraps the channel key for each member, and no keeper ever holds it. Open channels, which hand their key to any peer that asks, and keepers, which hold keys for open channels, are **deferred**. In v1, no infrastructure holds a key.

### 4.3 Replaceable items

A memory file is edited, not appended to. Items gain an optional `slot` and `rev`:

- **Slot:** `slot = HMAC-SHA256(slot_key, "cordelia:slot:v1:" || logical_key)`.
  - `logical_key` is the file's key within its channel (4.5). Relays can match slots without learning file names.
  - `slot_key` is a random 32-byte key per channel. It is created with the channel, sent in the channel state next to the key ring, and **never rotated**. If slots were derived from the channel key, every rotation would move every file to a new slot. A revoked device keeps the slot key, which tells it only whether two items are the same file.
- **Rev:** a per-slot counter. The writer sets `rev` to one more than the highest rev that a current member of the channel has stored for the slot. Wall clocks play no part, so clock skew between machines does no harm.
  - What anyone else stored in the slot does not count, so neither a stranger nor a removed device can put a name's rev out of reach.
  - A rev is at most 2^53 - 1 (`MAX_REV`). This is checked wherever an item is verified, so no node stores a larger one or passes it on.
- **Signature and encryption both cover the slot and rev.** The signed metadata envelope gains `slot` and `rev`, present only on slotted items, so existing items and test vector TV-C1 are unchanged. The item's AES-GCM associated data becomes `channel_id || slot || rev`. A relay can neither relabel an item into another slot nor replay an old revision as a new one.

**Storage keeps the newest rev per `(channel_id, slot, author)`, not per slot.** Relays see slot values but can't tell members from strangers. Under a per-slot rule, anyone who can reach a relay could publish junk with a higher rev into your slot, and the relay would throw your real item away. Keyed by author, an attacker can only replace their own entries. This needs **every node, relays included, to verify an item's signature before storing it.**

**No storage rule compares one author's items with another's.** That holds for every rule a node applies when it stores:

- A node skips an item only when it already holds the same ciphertext from the same author. If the author did not matter, a copy of your item under someone else's key, stored first, would keep your item out.
- The sweep of old deletes (4.4) never lets one author's delete remove another author's content from a relay.

**Readers resolve per slot.** Among items whose author is an active member of the channel, which decrypt, and whose key maps back to the slot, the highest `rev` wins, with ties going to the higher `content_hash`. The losing version of a tie is reported as a conflict, and the device that wrote it keeps it as `<file>.conflict-<tag>.md` (the tag is the start of its key), so neither machine's edit is lost.

This is the same idea as Nostr's addressable events (NIP-01, kinds 30000-39999). The API is `publish` with a `key`, `/api/v1/channels/entries` and `/api/v1/channels/delete-key`.

### 4.4 Deletes that replicate

A delete is a new `rev` of the slot, marked as a tombstone. Tombstones are kept for 90 days (`KEYED_TOMBSTONE_RETENTION_DAYS`), so a laptop that has been in a drawer doesn't bring deleted files back; after that, an hourly sweep drops the key's whole slot history. What counts as deleted depends on what the node can know:

- A device knows the channel's members. A key is deleted when the newest rev among them is a delete.
- A relay does not, and stores what anyone sends. It drops a key only when every author's newest rev of it is a delete older than 90 days. So a key that one device deleted, and another device still has content for, stays on the relay. That costs a relay some space, and it means a stranger's delete can never erase a member's file there.

`delete-item` now checks the item's channel and that the caller wrote it.

### 4.4a Fixes to sync and verification that 4.1-4.4 depend on

- **Sync served only what the listen API shows,** which hides internal items and tombstones, so no key envelope or delete had ever reached another node by sync. Sync now has its own query that returns every item.
- **Sync fetched only the newest 100 items per channel.** **As built:** items get an arrival sequence number, and sync pages by it (`after_seq` in the request, `last_seq` in the response) with a cursor per peer and channel, until `has_more` is false.
  - **The cursor lasts as long as the connection.** A relay that has lost or replaced its database (it was rebuilt) starts its arrival sequence again, and a cursor kept from before would skip everything it stores from then on. So when a peer connects again, each channel is listed from the start once, and only the items missing here are fetched.
- **Key distribution never reached the network.** Membership and key changes made through the device commands and the adapter now go through inboxes (4.1). The older endpoints still don't (section 9).
- **A burst of writes was rate-limited and lost** (found by the real-process test). **As built:** new items go into an outbox that is pushed to one relay at a time, at most every 2 seconds, and an item is marked relayed only when a relay has stored it or already held it.
  - **A relay's refusal is not delivery.** The relay's answer lists the items it refused and why. Those stay in the outbox and are offered again after a wait that doubles from 4 seconds up to 10 minutes, to the next relay in turn. So a relay that cannot store (a full disk, say) does not make a device believe its writes are safe.
  - A relay from before 0.2.0-alpha.4 says how many items it refused and not which. Nothing in that push is taken as delivered, and that relay is left alone for a while.
  - `cordelia status --json` lists the refused items under `outbox_refused`, and the status line asks for attention once relays have refused an item three times in a row.

### 4.5 `cordelia sync claude`: the Claude Code adapter

It runs inside the node binary: one install, and the node stays the encryption boundary ([2026-03-10 decision](2026-03-10-phase1-design-decisions.md) §1). Every 5 seconds, and as soon as a setting changes, it syncs memory folders under `~/.claude/projects/*/memory/`:

- **What syncs is declared (changed 2026-10-01).** `cordelia sync map <folder> [name]` says that Claude's memory for a folder syncs under a name, and nothing else syncs. On a new machine `cordelia sync claude` therefore syncs nothing: it lists what it found, with the command that maps each. As first built it synced home memory and every git project it found; that is now `--all`, which also covers what turns up later. An install from before this change keeps syncing everything it finds, because a scope is only ever narrowed by its owner. Running `cordelia sync claude` again keeps the stored settings (it used to put the directory back to the default), as does turning sync off and on, and it says what it changed. Every change of scope, mapping or exclusion is logged. `cordelia sync status` shows each folder with its name, when it last sent and received, and any error; `cordelia status --json` adds its channel.
- **A name, not a path, is what devices share.** Claude Code names folders after the working directory, so paths never match across machines. A git project's name defaults to its `origin` remote, normalised to `host/owner/repo`. Any other folder is given a name, and a name can be given to a project too. Home memory is the name `~`, and mapping the home directory has to be asked for (`--home`). `cordelia sync map` refuses a folder outside the home directory, a second name for a mapped folder, a second mapped folder for a name, and two folders that Claude Code keeps in one (it names its folder after the path with every other character turned into a dash).
- **One memory per repository.** Claude Code keeps a repository's memory in the folder of its main working tree, shared by its subdirectories and worktrees, so that is the folder `cordelia sync map` maps, whichever folder of the repository it is given. A mapping syncs the Claude Code folder named after its directory and no other. It is never matched by reading session transcripts, so it cannot come to sync a different folder than the one declared.
- **Each name gets its own `grp_` channel,** which only its owner's devices join (4.7). The personal channel maps `project/<name>` to the channel.
- **Home memory has its own channel (changed 2026-10-01).** As first built it went to the personal channel, under keys `home/<file>`, which every device of the person holds. It now syncs like any other name, in a channel joined only by the devices that map it.
- **As built: devices join only what they map.** A channel starts with its creator as the only member. Another device that maps the same name posts a join request (`join/<channel>/<device>`) in the personal channel; an owner grants it, and only for the device named in it. So each device holds keys only for what it syncs. Each device also lists the names it syncs (`syncing/<device>`) in the personal channel, read only from the device a list is about, so `cordelia sync status` can say what the person's other devices sync.
- **A folder that stops syncing starts afresh (2026-10-01).** Unmapping a folder, turning home memory or sync off, or narrowing the scope forgets what the folder had agreed with its channel. If it syncs again it merges with the channel as a new folder would, so files it lost in between are fetched back and never sent as deletes. An unmapped folder also stays out of `--all` until it is mapped again. A mapped folder whose memory directory has gone missing is reported and nothing is deleted elsewhere. Unmapping does not yet take the device out of the channel (section 9).
- **With `--all`,** the adapter reads the `cwd` recorded in each folder's session transcripts to find its repository. A folder Claude Code named is believed only about the directory it is named after, because a session can move to another directory and a transcript can start there. `cordelia sync exclude <pattern>` keeps projects off a device and `cordelia sync home off` keeps home memory off it. Folders that are neither home nor a git project with a remote need a name, and `cordelia sync status` lists them. Two clones of one repository on a device both sync under its name, so their memory merges.
- **`MEMORY.md` is merged, not replaced.** It's an index of one-line pointers, so the merge is the union of lines, minus lines pointing at deleted files.
- **Safety.** Only plain file names are synced, writes are atomic, a file edited during a cycle is left for the next one, and files over 128 KB are reported rather than synced.

Other agents come later as further adapters that map their own memory locations onto the same channels.

### 4.6 Two relays

Personal nodes are outbound-only and there is no NAT traversal, so two devices always meet through a relay. **As built (0.2.0-alpha.3):** a personal node opens no listening socket at all. It dials out from a port the system picks, where earlier versions bound UDP 9474 and turned inbound peers away after the handshake. `listen = true` under `[network]` keeps a listener, for a node that others dial directly. We run two relays, each also serving as a bootnode, so that losing one doesn't stop sync:

- **`relay1`** and **`relay2`** are Docker containers we operate, from the image and guide in [`deploy/relay/`](../../deploy/relay/): a pinned release checked against its sha256, run unprivileged on a read-only filesystem. **Changed 2026-09-30:** for the alpha we host both ourselves. Before any public announcement, the public relays move to a cloud provider (the Fly.io config is ready for that), and the storage cap and retention ship (section 9).
- **DNS:** `relay1.cordelia.seeddrill.ai` and `relay2.cordelia.seeddrill.ai`, UDP 9474. New nodes list both (`FALLBACK_PEERS`), and anyone can add their own. **As built:** nodes keep the names, not the addresses. They resolve them again while running, so a node started before its network was up, or a relay whose address changed, is still reached.
- **A relay is a name and a key (2026-10-02).** The name says where to dial, and the key is what must answer there. The default relays' keys are compiled in (`FALLBACK_PEER_KEYS`), and a relay of your own takes a `key` beside its `addr`. A node refuses any other key at a relay's address, so answering for a relay's name is not enough to be taken for it. A relay configured without a key is accepted with whichever key answers, and the node says so when it starts.
- **A relay works with the relays it lists (2026-10-02).** It forwards to them and tells them which channels it holds. A node that connects and says it is a relay is an ordinary peer unless it is one of the listed relays, by key. Neither relays nor devices ask peers for the addresses of other peers.
- **A device's network is its configured relays, and nothing else (2026-10-02).** It dials only those. It does not ask a relay for other peers' addresses, and learns of no relay from DNS, so a relay cannot send it anywhere. Each configured relay that is not connected is dialled again at a slowing pace: one governor tick, doubling, up to fifteen minutes while another relay is connected, and at least every half minute while none is. `cordelia peers` and `cordelia status --json` say which relays are not connected, since when, and why. Starting no longer waits on a relay that is unreachable.
- **Retention** for relays is not implemented yet (section 9).

### 4.7 Memory is the boundary (decided 2026-10-01)

An agent's memory is who it is for one person: what it knows about them, how they like to work, what it has been corrected on, and what it is in the middle of. Cordelia treats it as it would a person. It has one owner, and it is not shared.

- **Between one person's devices, memory moves whole.** That is what v1 is for: the same agent, with the same context, is there at the new vantage point. The one you talk to on the laptop is the one you were talking to on the desktop.
- **Between people, memory does not move at all.** v1.1 was going to share a project's memory with a teammate. It will not, for four reasons:
  1. Memory is written to one person's agent. "The user prefers short answers", read by another person's agent, is about the wrong person.
  2. The agent reads its memory folder as its own notes. Nothing marks a file as someone else's, so another person's text, or their compromised agent's, would act with your agent's authority. No label Cordelia could add would be seen where it matters.
  3. Memory mixes facts about a project with facts about a person and about one machine, and nothing separates them. Sharing it shares more than was meant.
  4. What people need to share is shared on purpose and has better homes: the repository for project facts, where they are reviewed; messages for coordination; skills and secrets as things that are published and then chosen.
- **It is enforced, not left to convention.** A channel that carries memory admits only its owner's devices: a device is let in on a request made in the owner's personal channel (4.5), and no command adds anyone else's key to one.
  - **As built (2026-10-02).** Handing a key a channel means handing it everything written there so far, so the rule acts where the keys leave and where a list is taken in, not when a folder next syncs:
    - a channel's keys are sealed only to a device in the owner's personal channel, whatever the channel's own list says, and a state this node builds lists only such devices;
    - a state for one of your channels that names any other key is not applied, whichever of your devices sent it. It is kept, and applies if that key turns out to be a device this one had not heard of yet;
    - the older `group/invite` endpoint refuses a key that is not one of your devices.
  - **Which personal channel a device belongs to** is decided by the person's act on that device, `cordelia accept`, and by nothing the device is sent. The accept is honoured for an hour, for the key it named. A device that is in use, because it has other devices in its personal channel or is syncing, cannot be moved: `accept` says so, and the person turns sync off first if they mean it. Trust in a key is for one purpose, so a key trusted for anything else is not one of your devices. (Adding a device with a code that the new device shows, #75, replaces `accept`.)
- **What comes next is therefore not shared memory.** It is channels shared between people that carry what is shared on purpose: messages between agents first, then skills and secrets. The rule there is the other half of this one: automatic between your own devices, deliberate between people.

This decision is expected to stand. If people later want notes in common, the answer is a note that is published on purpose and shown with its author, and that never lands in the memory folder.

## 5. What we promise about security

- Relays and Seed Drill see channel IDs, device public keys, item sizes, types and timing. They never see content, file names, member lists or keys.
  - For usage counts (distinct peers per day and week), a relay keeps a keyed hash of each peer's key, made with a secret that stays on the relay, for 8 days after the peer was last seen. It reports counts, never keys.
- Only devices you added can read your memory. It is never shared with another person (4.7).
- On your own machines, memory is as protected as your disk. The node's search index and Claude Code's own files are plaintext at rest.

This replaces the v2.3 whitepaper's "no plaintext at rest on any node, ever", which the code did not meet and v1 doesn't need.

## 6. Why not Syncthing

v1 must beat plain file sync on things it can't do:

- **Neither machine needs to be on at the same time.** The relay holds ciphertext, so a closed laptop still catches up later.
- **Memory follows the project, not the path.** File sync puts `-home-alice-Work` and `-Users-alice-Work` in different folders.
- **`MEMORY.md` merges instead of producing conflict files.**
- **Only what you map syncs, and each device holds keys only for that** (4.5).

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
| `cordelia sync claude` adapter, per-project channels, declared mappings | **Built** | 4.5 |
| Two relays and DNS | **Running** | 4.6; hosted by us for the alpha |
| Release: macOS and Linux binaries | **Built** | `release.yml`; Homebrew tap and AUR package to follow |
| Sharing a project's memory with a teammate (`share`) | **Drop** | Memory is not shared between people (4.7) |
| Channels shared between people: messages, skills, secrets | **Next** | Designed separately; never memory (4.7) |
| Second agent adapter | **Later** | Proves portability |
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
- Relays keep what they store: the retention limit (30 days was proposed) is not implemented, and the storage cap (`max_storage_bytes`, 1 GiB by default) is declared but not enforced. Both must ship before any public announcement, because every node dials our relays by default.
- The older key-distribution endpoints (`dm`, `group/invite`, `group/remove`, `rotate-psk`) still write key envelopes into the channel itself, which never reach other nodes. v1 doesn't use them; they will move onto sealed channel states or be removed.
- Home memory synced before 0.2.0-alpha.3 stays in the personal channel as items no version reads any more. A device added later receives them with the rest of that channel, whether or not it maps home memory. Removing them safely needs every device of the person upgraded first (an older version takes a delete there as a delete of its own files), so it is not done yet.
- With `--all`, a folder is found through its session transcripts, which Claude Code deletes after 30 days by default. A project not used for that long stops syncing on that device until it is used again. Mapped folders are not affected.
- The adapter follows Claude Code's default memory location. It does not follow `autoMemoryDirectory` or `CLAUDE_CODE_PROJECT_DIR_NAME`, and a folder whose path is longer than 200 characters cannot be mapped yet, because Claude Code adds a hash to its folder name.
- A name stays in the personal channel's map after the last device stops syncing it, and its channel and items stay on the relays.
- Unmapping a folder stops the sync on that device and leaves it a member of the name's channel: it keeps the key, and its node keeps receiving the encrypted items, until the device is removed. Leaving a channel, with a key rotation, is not built yet.
- Home memory does not sync between a device on 0.2.0-alpha.2 and one on 0.2.0-alpha.3, because the two keep it in different channels. Upgrade every device.
- Where Claude Code keeps memory for a submodule, or for a worktree of a bare repository, is not confirmed. `cordelia sync map` says so when it maps one. Nor is its folder name confirmed for a path with accented characters on macOS.
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
3. **Deploy the relays,** then tag the first pre-release, `v0.2.0-alpha.1`. Done.
4. **Dogfood** on our own machines until section 10 holds. Then release publicly.
