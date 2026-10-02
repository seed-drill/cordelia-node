# Cordelia: Your Agent's Memory on Every Machine You Use

**Russell Wing, Martin Stevens** -- Seed Drill (https://seeddrill.ai)
**Version 3.0 draft** -- October 2026. Supersedes v2.3 (archived at
[`docs/archive/whitepaper-v2.3.md`](docs/archive/whitepaper-v2.3.md)).
Long-term direction: [`docs/vision.md`](docs/vision.md).

---

## Abstract

AI coding agents now keep memory: preferences, decisions, the reasons behind
them. That memory lives in one folder, on one machine, filed under the path of
the directory the agent ran in. Move to another machine and it is gone; clone
the same project somewhere else and it is gone; hand it to a hosted memory
service and someone else holds the plaintext.

Cordelia keeps an agent's memory in step across a person's machines, so that
the same agent, with the same context, is there wherever they work. Memory is
never shared with another person. It is encrypted on the device
that wrote it and travels through relays that store only ciphertext and hold no
keys. Each device has its own key and is added or removed individually. A
project's memory follows the project, matched by its git remote, not by where it
sits on disk. Concurrent edits never silently lose work.

Version 1 does this for Claude Code's memory. This paper describes what v1 is,
how it works, and what it promises; it makes no claim beyond what is built.

---

## 1. The problem

A coding agent that remembers is more useful than one that does not. Claude
Code, for example, writes memory files as it works, one folder per working
directory, and reads them back at the start of the next session. Three things
break that memory in practice:

1. **It is per machine.** A laptop and a desktop each accumulate their own
   memory; neither knows what the other learned.
2. **It is per path.** The folder is named after the directory the agent ran in
   (`-home-sam-Work` on Linux, `-Users-...` on macOS). The same repository
   cloned at two paths, or on two machines, has two unrelated memories.
3. **It is per vendor, or per host.** Syncing it through a hosted memory
   service puts the plaintext on someone else's servers; file sync tools move
   files but do not understand projects, concurrent edits, or who may read what.

What is needed is small and specific: memory that belongs to the person, is
matched by project, stays encrypted end to end, survives machines being off,
and can be shared deliberately.

## 2. What Cordelia does

```
MacBook                               iMac
$ cordelia init                       $ cordelia init
                                      $ cordelia id
                                        cordelia_pk1...    (copy this)
$ cordelia add-device cordelia_pk1... --name imac
    On the other device, run:
    cordelia accept cordelia_pk1...  (copy this back)
                                      $ cordelia accept cordelia_pk1...
$ cordelia sync claude                $ cordelia sync claude
$ cordelia sync map ~/Work/app        $ cordelia sync map ~/code/app
```

After that:

- A memory Claude Code writes on one machine appears on the other, including
  when the other machine was off at the time; it arrives when it next connects.
- Only what is mapped syncs. A mapping gives a folder's memory a name, and the
  name is what a person's devices share. A repository is named by its git
  remote, so it is matched whatever path it is cloned at; any other folder is
  given a name; home memory is mapped by asking for it (`--home`).
- A device that has never mapped a name holds neither its memory nor its key.
- If two machines edit the same memory before hearing from each other, one
  version stays in the file and the other is kept beside it as
  `<name>.conflict-<device>.md`, on every machine. The memory index
  (`MEMORY.md`) is merged line by line instead.
- `cordelia sync status` lists what was found on the machine and is not
  syncing, with the command that maps it, and what the person's other
  devices sync. `cordelia sync claude --all` syncs everything found instead.

## 3. Design

A Cordelia node runs on each device. It holds the device's key, stores
encrypted items in SQLite, talks QUIC to relays, and serves a local API on
loopback to the command line and the sync adapter.

### 3.1 Devices and trust

Each device generates its own Ed25519 key at `cordelia init`. Keys never leave
the device that made them. There is no account and no registration.

A person's devices are **members of that person's channels**, exactly as
another person would be. Adding a device means adding a member; removing a
device means removing a member and rotating the channel keys it held. There is
no shared identity to copy between devices, so any single device can be revoked
without disturbing the rest.

A node applies an invitation only from a key it **trusts**:

- **Explicitly**: `add-device` trusts the device being added; `accept` trusts
  the device that added this one. The person copies a key from one of their own
  screens to the other, in each direction, so each device has been told by its
  owner which key is which.
- **Through the personal channel**: every member of a person's personal channel
  is one of their devices, so a third device added from the MacBook is trusted
  by the iMac without another `accept`.

Anything else waits in `cordelia invites` until accepted (capped at 100,
oldest dropped first; nothing a person's own devices sent is dropped to make
room). Without this, anyone who learned a node's public key
could add it to a channel whose content would land in the agent's memory
folder.

### 3.2 Channels and keys

Memory lives in invite-only **group channels** (`grp_` + a random UUID, so the
channel name is never on the wire). Each channel has:

- a **channel key** (AES-256-GCM), versioned; old versions are kept so earlier
  items stay readable after a rotation;
- a **slot key** (32 random bytes), used to name replaceable items (§3.3), never
  rotated;
- a **member list**, each member an owner or a member;
- an **epoch**: a counter of membership and key changes.

Keys and member lists travel only as **channel states**: one message carrying
a channel's key ring, slot key, member list, and epoch, sealed with ECIES
(X25519, HKDF-SHA256, AES-256-GCM) to a single recipient. An invitation is
simply the first state a node receives for a channel. Adding or removing a
member, or rotating the key, sends the next epoch to every remaining member.

States are delivered through each node's **inbox**, a channel anyone can derive
from the recipient's public key (`inbox_` + SHA-256(`"cordelia:inbox:v1:"` ||
public key)). Relays carry inbox items like any other ciphertext; only the
recipient can open them. On receipt a node checks that:

1. the item's signature is valid;
2. the sealed state names the same sender as the item's author (so a state
   sealed by one node cannot be re-signed by another);
3. for a channel it already has, the sender is an owner and the state is newer:
   a higher epoch, or the same epoch and a higher sender key, so every member
   converges on the same state and an old state replayed later cannot re-admit
   a removed member;
4. for a channel it does not have, the sender is trusted (§3.1).

Channel IDs arriving in states must be exactly `grp_` and a lowercase UUID, and
key files refuse any name that could leave their directory: channel IDs from
other nodes become file names.

### 3.3 Items

Everything a channel holds is an **item**: a blob encrypted with the channel key
and signed by its author with Ed25519. The signature covers a deterministic CBOR
envelope of the author, channel, content hash, tombstone flag, item ID, key
version, publication time, and, for replaceable items, slot and revision. Every
node, relays included, verifies it before storing anything.

A memory file is edited, not appended to, so memory uses **replaceable items**:

- **Slot**: `HMAC-SHA256(slot_key, "cordelia:slot:v1:" || key)`, where the key is
  the file's name within its folder. Relays can tell that two items are
  revisions of the same file without learning the file's name.
- **Revision**: one more than the highest revision the writer has seen for the
  slot. No wall clocks are involved, so clock skew between machines does no
  harm.
- **Binding**: the slot and revision are both signed and bound into the AES-GCM
  associated data (`channel_id || slot || rev`), so an item cannot be moved to
  another slot or channel, or replayed as another revision.

Storage keeps the newest revision **per slot and per author**, never per slot
alone. Relays can see slots but cannot tell members from strangers; keyed by
author, a stranger's higher revision lands in the stranger's own cell and can
never evict a member's item.

Readers resolve each slot from items that are signed, authored by an active
member, decrypt under the key version they claim, and carry a key that maps back
to their slot. The highest revision wins; ties go to the higher content hash, so
every device picks the same winner. Other items at the winning revision are
concurrent edits and are reported as conflicts rather than dropped.

**Deleting** a memory publishes a tombstone revision, which replicates like any
other. When a key's newest revision is a tombstone older than 90 days, every node
drops the key's whole history: dropping only the tombstone would let an older
revision by another author become current again.

### 3.4 Network

Nodes talk QUIC (RFC 9000, TLS 1.3) with CBOR messages. A node's identity is
the key its TLS certificate carries, so nobody can connect or answer under a
key they do not hold. Two roles matter in v1:

- **Personal nodes** run on people's devices. They only dial out, so they work
  behind NAT and firewalls. A personal node dials the relays it was configured
  with and nothing else. It knows each by name and by key, and refuses any
  other key at a relay's address. It opens no listening port: nothing on a
  network the device joins can connect to it.
- **Relays** accept connections, store the ciphertext they receive, and forward
  it to the relays their operator lists, with a seen-table so nothing loops.
  Peer selection follows the hot/warm/cold governor model of Cardano's P2P
  networking layer.
- **A relay is a cache with a cap.** Every device holds its channels whole. A
  relay asks each device that connects to it which channels it holds, and
  fetches what it lacks. So nothing is lost for good when a relay is
  rebuilt, or drops a channel to make room. At its storage cap a relay takes
  no channel it does not already hold, and makes room by dropping the
  channels it came to hold most recently.

Two mechanisms carry items between them:

- **Outbox.** A node's own items stay marked as not relayed until a relay
  has stored them. The node flushes its outbox as a single push at most
  every 2 seconds, which stays within a relay's limits however many items
  were written, and resends anything a relay did not store, across restarts.
  A relay that refuses an item says which and why, and the node offers it
  again after a wait, to the next relay in turn.
- **Pull sync.** Every 10 seconds a personal node pulls each of its channels from
  its relays, paging by the relay's own arrival order (a sequence number that
  never goes backwards), so no item is skipped whatever its author's clock said.
  A device stores only what members of its own channels wrote.

### 3.5 The Claude Code adapter

`cordelia sync claude` runs a cycle every 5 seconds inside the node:

1. **Decide what syncs.** A *mapping*, declared with `cordelia sync map`, says
   that Claude's memory for a folder syncs under a name. Nothing else syncs
   unless the device is set to sync everything it finds (`--all`).
   - The folder is found by name alone. Claude Code keeps one folder per
     working directory under `~/.claude/projects/`, named after the path, and
     keeps a repository's memory in the folder of its main working tree, shared
     by its subdirectories and worktrees. A mapping syncs exactly that folder,
     never one chosen by reading transcripts, so it cannot come to sync a
     different folder than the one declared.
   - The name is what devices share. A repository's name defaults to its
     normalised git remote (lower-cased host and path, without scheme,
     credentials, port, or `.git`); any other folder is given one; home memory
     is `~` and has to be asked for by name.
   - Each name has its own channel, found in a map held in the personal
     channel. The first device to sync a name creates its channel, owned by it
     alone. Another of the person's devices joins only when it maps the name
     too: it posts a join request in the personal channel, and any device that
     owns the channel adds it. A request is honoured only from the device it
     names. So a machine that syncs one project holds keys to that project
     alone, and home memory reaches only the machines that map it.
   - Each device also lists the names it syncs in the personal channel, so the
     others can say what there is to map.
   - With `--all`, the adapter also syncs what it finds: it lists
     `~/.claude/projects/*`, reads each folder's working directory from its
     session transcripts, and syncs home memory and every repository with a
     remote. Per device, projects can then be **excluded** and home memory
     left off.
   - A folder that stops syncing (it is unmapped, or sync is turned off)
     starts afresh if it syncs again: it merges with the channel, and files
     it lost in between are fetched back, never sent as deletes. A mapped
     folder whose memory directory has gone missing is reported, and nothing
     is deleted on the other devices.
2. **Plan each file.** A pure function compares the file on disk, the channel's
   current value, and what the folder last agreed with the channel. Whichever side
   changed is taken. If both changed, the channel's version goes in the file and
   this device's version is kept as a conflict file. An edit beats a delete,
   whichever side made it. `MEMORY.md` is merged: the union of both versions'
   lines, minus pointers to deleted files.
3. **Apply safely.** Files are written atomically (a temporary file, then a
   rename, which never writes through a symlink). Only plain file names are
   accepted from other devices: no separators, no `..`, no hidden files. Before
   replacing or removing a file, the adapter re-reads it; if the agent wrote to it
   during the cycle, the change is deferred to the next cycle instead of
   overwritten. A file that does not fit in one entry (64 KB), or is not
   plain text, takes no part in sync: it is left as it is, reported, and
   deleted nowhere.

## 4. Security model

**What relays, and Seed Drill as a relay operator, can see:** channel IDs, the
public keys of the devices that connect and author items, item sizes, types and
publication times, and which items are revisions of the same slot.

**What they cannot see:** content, file names, project names, member lists, or
any key. No relay holds a channel key in any form.

**Who can read a channel:** the devices its owner added, and nobody else. Memory
is never shared between people: an agent reads its memory as its own notes, so
another person's text there would act with the agent's authority (decision
record §4.7). A removed device keeps what it already had but cannot read
anything written after the key rotation that removal triggers, and its later
writes are ignored because it is no longer a member. What it wrote before is
kept: the device that removes it publishes those entries again.

The threats Cordelia defends against, the ones it does not, and the tests
that prove each claim are in
[docs/security/threat-model.md](docs/security/threat-model.md). CI fails if a
claim loses its test.

**On a person's own machines**, memory is as protected as their disk: the agent's
memory files are plaintext, as they are without Cordelia, and the node's data
directory holds the device key and the keys to that person's channels (files
readable only by the user).

| Threat | Mitigation |
|---|---|
| Relay compromise | Relays hold ciphertext only; no keys. Signatures stop them forging or relabelling items. |
| Someone answers for a relay's name, or claims another node's key | A node's identity is the key its certificate carries. Devices know their relays by key and refuse any other. |
| Stranger writes to a channel | Items from non-members are ignored, and devices do not store them; no storage rule lets one author's items hide, displace or sweep away another's. |
| Stranger invites a device | Invitations apply only from trusted keys; others wait for `accept`. A channel of your own is only ever handed to your own devices. |
| Lost or stolen device | `remove-device` from any other device removes it everywhere and rotates keys. The change is offered until every remaining device confirms it. A device only ever held keys for the projects it had. |
| Replayed old channel state | Epoch ordering: stale states are ignored. Epochs, key versions and revisions are bounded, so none can be run out. |
| Malicious file names | Only plain names are written, only inside the memory folder. |
| Burst writes, floods | One size for every entry (64 KB), checked at every hop. Limits for a connection and for its address; a peer that keeps going over is cut off. A storage cap at relays that keeps what was there first. Pending invites capped. |

**Non-goals for v1.** Hiding that communication happens (traffic metadata is
visible to relays); protecting a device that is itself compromised; resisting a
network-level denial of service; public channels, open membership, or key
escrow.

## 5. What v1 deliberately is not

v1 is small on purpose. It has no public or open channels and no service that
holds keys on anyone's behalf; no token and no economic layer; no semantic search
or memory "extraction" (the agent decides what to remember; Cordelia carries it);
no hosted plaintext of any kind.

## 6. Status and roadmap

**Status (October 2026):** v1 is built and tested, including end-to-end tests
with real processes over QUIC through a relay. Two relays are running, and
alpha pre-releases are published.

**Next:**

- **Channels shared between people,** carrying what is shared on purpose:
  messages between agents first, then skills and secrets. They will not carry
  memory. An agent reads its memory as its own notes, so memory stays with one
  person and moves only between that person's devices (decision record §4.7).
- **More adapters**, starting with a second coding agent, so memory survives a
  change of agent as well as a change of machine.
- **More relays, run by others.** Anyone can run one; the configuration lists
  relays.

Longer-term direction, including how relays might be paid for (no
settlement layer is chosen), is in [`docs/vision.md`](docs/vision.md).

## References

1. RFC 9000, *QUIC: A UDP-Based Multiplexed and Secure Transport*, 2021.
2. RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*, 2017.
3. RFC 7748, *Elliptic Curves for Security* (X25519), 2016.
4. RFC 5869, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*, 2010.
5. RFC 2104, *HMAC: Keyed-Hashing for Message Authentication*, 1997.
6. NIST SP 800-38D, *Galois/Counter Mode (GCM)*, 2007.
7. RFC 8949, *Concise Binary Object Representation (CBOR)*, 2020.
8. D. Coutts, N. Frisby, K. Coutts, *Introduction to the Design of the Data
   Diffusion and Networking for Cardano Shelley*, IOHK, 2020 (governor model).
9. Nostr NIP-01, addressable (formerly "parameterized replaceable") events,
   kinds 30000-39999, for the replaceable-item pattern.

## Appendix: parameters

| Parameter | Value | Where |
|---|---|---|
| Pull-sync interval | 10 s | `REALTIME_SYNC_INTERVAL_SECS` |
| Outbox flush interval | 2 s | `OUTBOX_FLUSH_INTERVAL_SECS` |
| Relay write limit per connection | 36 pushes and 2 MB / min | `WRITES_PER_PEER_PER_MINUTE`, `PUSH_BYTES_PER_PEER_PER_MINUTE` |
| The same, for one address | 5 times a connection's | `MAX_CONNECTIONS_PER_IP` |
| Largest entry, as it travels | 64 KB of ciphertext and at most 1 KB more | `MAX_ITEM_BYTES`, `ENTRY_OVERHEAD_BYTES` |
| Largest synced memory file | what fits in one entry | `cordelia-sync` |
| One channel at a relay | 16 MB | `MAX_CHANNEL_BYTES_AT_RELAY` |
| A relay in total | 1 GiB unless its operator sets it | `max_storage_bytes` |
| Deleted-key retention | 90 days | `KEYED_TOMBSTONE_RETENTION_DAYS` |
| Adapter cycle | 5 s | `cordelia-sync` `CYCLE_SECS` |
| Pending invites kept | 100 | `MAX_PENDING_INVITES` |

Network protocol constants live in `crates/cordelia-core/src/protocol.rs`, with
their derivations in `docs/specs/parameter-rationale.md`; the adapter's live in
`crates/cordelia-sync`, and the invite cap in `cordelia-storage`.

---

*Version 3.0 draft -- Seed Drill -- AGPL-3.0-only*
