# Cordelia Glossary

**Status**: v1.0
**Date**: 2026-03-11
**Scope**: Shared glossary referenced by all Phase 1 specifications

> **v1 status.** The terms added by v1 are in the last two sections. The
> personal channel, relay eviction and the economics terms below describe the
> pre-v1 design. The section "v1 terms (2026-09-30)" is of the
> [decision record of 2026-09-30](../decisions/2026-09-30-agent-memory-sync.md):
> where it speaks of devices, membership and keys it describes the older
> kind of channel, which a relay carries for one version more. The section
> "A person's devices" is of the
> [decision record of 2026-10-04](../decisions/2026-10-04-a-persons-devices.md),
> which replaces that model.

---

## Identity

- **Node**: A running Cordelia process with cryptographic identity (Ed25519 keypair), configuration, and persistent storage (SQLite).
- **Peer**: A network neighbour node connected via QUIC.
- **Entity**: A cryptographic identity (Ed25519 public key + optional human-readable name). May operate one or more nodes.
- **Agent**: A software automation acting on behalf of an entity (Phase 2+).
- **Creator (creator_id)**: The Ed25519 public key of the entity that created a channel, stored in ChannelDescriptor.
- **Author (author_id)**: The Ed25519 public key of the entity that published an item, stored in item metadata.

## Channels

- **Channel**: An encrypted topic for publishing items. Three types: named, DM, group.
- **Named channel**: A channel identified by an RFC 1035-compliant label, mapped to channel_id via SHA-256.
- **DM (Direct Message)**: A bilateral channel with immutable membership (exactly 2 entities), identified by `dm_` prefix + deterministic SHA-256.
- **Group conversation**: A channel with mutable membership (3+ entities), identified by `grp_` prefix + random UUID v4.
- **Personal channel**: The system channel `__personal` created per entity at `cordelia init` for private storage.
- **System channel**: A node-internal channel (prefixed `__`), bypasses RFC 1035 validation, never exposed via API.
- **Protocol channel**: A system-wide channel (prefixed `cordelia:`), e.g. `cordelia:directory`.
- **Access policy**: `open` (auto-approve, PSK discoverable) or `invite_only` (manual invitation, PSK via ECIES envelope).
- **Replication mode**: `realtime` (eager Item-Push, 60s sync) or `batch` (pull-only, 900s sync). Developer-facing terms replacing internal chatty/taciturn.

## Cryptographic

- **PSK (Pre-Shared Key)**: A random 32-byte AES-256-GCM key generated per channel, used to encrypt all items on that channel.
- **ECIES envelope**: A 92-byte structure wrapping a PSK, encrypted to a recipient's X25519 public key.
- **Metadata envelope**: A CBOR-encoded structure of item metadata fields, signed with the author's Ed25519 key. Distinct from ECIES envelope.
- **Descriptor (ChannelDescriptor)**: Signed CBOR metadata record for a channel (creator, mode, access, psk_hash, key_version), replicated via Channel-Announce.
- **Bech32**: BIP-173 base32 encoding for keys. HRPs: `cordelia_pk` (Ed25519 pub), `cordelia_sk` (seed), `cordelia_xpk` (X25519 pub), `cordelia_sig` (signature), `cordelia_psk` (channel PSK).

## Network

- **Personal node**: Node with `role="personal"`, storing only subscribed channels.
- **Bootnode**: Node with `role="bootnode"`, discovery-only (Handshake + Peer-Sharing), never stores or relays items.
- **Relay**: Node with `role="relay"`, store-and-forward with LRU-evicted cache (max 10GB), re-pushes items to peers.
- **Keeper**: Node with `role="keeper"`, anchors channels, holds PSKs for open/gated channels (Phase 2+).
- **Anchor keeper**: A specific keeper designated as PSK authority for a channel (Phase 2+, stored in ChannelDescriptor).
- **Push policy**: Personal node config: `subscribers_only` (default, push to channel peers + relays) or `pull_only` (never push, serve only via Item-Sync).
- **Subscriber**: An entity subscribed to a channel (holds the PSK, receives items).
- **Member**: An entity in a group conversation with mutable membership. Distinct from subscriber in that members can be invited/removed.

## Replication

- **Item**: A published unit of content, encrypted with channel PSK, including metadata, signature, and ciphertext blob.
- **Publish**: Write an item to a channel via the API. Developer-facing term; internal protocol uses "write".
- **Listen**: Retrieve items from a channel via cursor-based polling (REST Phase 1, SSE Phase 2).
- **Item-Push**: Unsolicited sender-initiated item delivery for realtime channels via QUIC.
- **Item-Sync**: Periodic pull-based synchronisation via hash reconciliation (anti-entropy).
- **Channel-Announce**: P2P mini-protocol for broadcasting channel descriptor changes.
- **PSK-Exchange**: P2P request-response mini-protocol for distributing PSKs via ECIES envelope.
- **Tombstone**: Soft-delete marker (`is_tombstone=true`), propagated via replication.
- **Store-and-forward**: Relay behaviour: receive items, store in LRU cache, re-push to peers.
- **LRU eviction**: Least-Recently-Used cache policy on relays, triggered at 10GB storage cap.

## Economics

- **Proof-of-use**: Channel must have >=10 items from >=2 distinct authors/year to renew on-chain registration (Phase 3).
- **Contribution ratio**: `items_relayed / max(items_requested, 1)` -- measures relay reciprocity.
- **Probe**: Zero-length encrypted item published every 300s to verify relay liveness and detect defection.

## v1 terms (2026-09-30)

See the [decision record](../decisions/2026-09-30-agent-memory-sync.md) §4 for each.

- **Device**: One machine running a node, with its own Ed25519 key. A person's devices are members of that person's channels.
- **Personal channel**: A `grp_` channel per person. Its member list is the device roster; it also holds the map from name to channel (keys `project/<name>`), join requests (`join/<channel>/<device>`), and each device's list of the names it syncs (`syncing/<device>`). Before 0.2.0-alpha.3 it also held home memory (keys `home/<file>`). Replaces the derived `__personal` channel.
- **Inbox channel**: `inbox_` + hex(SHA-256("cordelia:inbox:v1:" || ed25519_pk)). Where a node receives sealed channel states.
- **Channel state**: A channel's key ring, slot key, members and epoch, sealed to one member with ECIES and posted in that member's inbox as an item of type `invite`.
- **Trust**: The keys a node accepts channel states from: those accepted with `cordelia accept`, and the members of its personal channel.
- **Keyed item (entry)**: An item published under a key, so later revisions replace it. The unit of a synced memory file.
- **Slot**: HMAC-SHA256(slot_key, "cordelia:slot:v1:" || key). Lets relays group revisions of a key without learning the key.
- **Slot key**: A random 32-byte key per channel, sent in the channel state and never rotated.
- **Rev**: A keyed item's revision number: the highest seen for its slot, plus one.
- **Conflict**: Two revisions of a key with the same rev from different authors. The higher content hash wins; the device whose version lost keeps it as `<file>.conflict-<tag>.md`, where the tag is the first 8 hex digits of its key. A version at a higher rev that is not known to have been written after this device's is taken, and this device's is kept in such a file too (decision record 4.5).
- **Outbox**: Items this node wrote that no relay has acknowledged yet.
- **Adapter**: The part of the node that maps one agent's memory files onto channels. v1 has one, for Claude Code (`cordelia sync claude`).
- **Mapping**: A declaration, on one device, that Claude's memory for a folder syncs under a name (`cordelia sync map`). The name is what a person's devices share: a git project's normalised remote, a name given to a folder, or `~` for home memory.
- **Project channel**: A `grp_` channel per synced name. A device joins it only once it maps that name.
- **Relay (v1)**: Stores and forwards ciphertext, verifies every item's signature before storing it, and holds no keys. v1 relays do not evict.

## A person's devices (decision record of 2026-10-04)

The section of the record is given with each. Where a term here has the name
of one above (personal channel, relay, conflict, slot key), this is what it
means from this version on.

- **The older kind (of channel)**: The kind the record of 2026-09-30 describes: a random ID, a ring of keys, and a list of members. A relay carries it for one version more; a personal node carries none of it (§10).
- **Channel from its secret**: A channel is a secret of 32 bytes. Its entry key, its slot key and its signing key are derived from the secret, and its ID is the public half of the signing key, written `cordelia_ch1...` (§2.1).
- **Person secret**: 32 random bytes, with a number. Every channel of a person's own is derived from it and the channel's name. A device is one of the person's because it holds it. It is never derived from the phrase, and changes only by a statement (§3).
- **Generation**: The channels derived from one person secret. Person secret number n gives generation n. A device's store holds one generation: the one it has applied (§3, §16).
- **Recovery phrase (the phrase)**: Twelve words from the BIP39 English list, made by `cordelia phrase` and shown once. It signs statements and recovers to a new machine. No device stores the words (§5).
- **Statement**: Which devices are a person's and which keys are removed, with a commitment to a new person secret: one for each change of the secret, signed by the phrase. It has a number, from 1 to 256, and names every statement it was made after (§4.1).
- **Change**: What a person makes with the phrase: a removal, a renewal, a settlement or a recovery. Each is one statement. `cordelia devices` speaks of "the last change".
- **Change entry**: The one entry of the phrase's channel: how a statement reaches a device. Always 32 KB. It holds the statement, the new secret sealed to each device the statement lists, and, sealed for the phrase alone, the new secret and up to eight earlier ones. Every device keeps the latest it has seen and shows it to each relay (§4.6).
- **Statement key**: A key derived from the phrase that every device which follows the phrase is given. It opens the statement in a change entry, and not the secret (§4.6).
- **Apply (a statement)**: What a device does with a statement that lists it, in one transaction: it stores the statement and the secret, leaves the generation it was in, and carries what it holds (§4.2).
- **Counts (a device that counts)**: A device of the statement that the reader has applied, or one added since under that statement. A device stores and reads only entries whose signer counts (§4.4).
- **Removed, in no list**: A statement has two lists: its devices, and the keys removed so far. A key in neither is no device under the statement: it is added again by a person, or not at all (§4.1, §4.3).
- **Fork**: Two statements made apart: neither is on the other's chain. A device that sees both stops, in its own channels, until they are settled (§4.5).
- **Settlement**: The statement that `cordelia settle` makes over a fork, with the phrase. Its chain holds both branches, and it undoes no removal (§4.5).
- **Renewal**: A statement that removes nobody: it lists the devices, with those added since, and commits to a new secret (`cordelia renew`, §4.1).
- **Record of an addition**: One device's signed word that it added another, under the statement it names. A device that is in vouches for the new one; the phrase is not typed to add (§6).
- **Hand-over**: The one entry that the device which adds writes in the pair channel: the statement it has applied, the secret, the statement key, the latest change entry, and the record of the addition. The new device takes it only with a key typed at `cordelia accept` within the hour (§6).
- **Pair channel**: The channel that two devices which know each other's keys can each derive, and where nobody else can write. It is used for the hand-over and for nothing else (§2.2).
- **The phrase's channel**: The channel whose secret comes from the phrase. It holds the change entry. Only the phrase can write there, and no device can fetch it (§2.2).
- **Personal channel**: The channel derived from the person secret alone. It holds what a person's devices tell each other: the names each syncs (`name/`), the devices added since the last statement (`added/`), which statement each has applied (`applied/`), and a device's word that it has left (`left/`). It has no member list (§2.2).
- **Name**: What a person's devices share: a git project's normalised remote, a name given to a folder, or `~` for home memory. A name's channel is derived from the person secret and the name. A device **holds** a name while a folder of its own is mapped to it.
- **Entry**: A value under a name's key in a channel from its secret, at a revision, signed by its author and by the channel's key. A store keeps the newest for each author in each slot. Its content is padded to a power of two (§2.3).
- **Version**: A text, or a delete, at a revision. Two entries with one text at one revision are one version, whoever signed them (§2.3).
- **Chain**: What an entry was written after: for each version it descends from, newest first, the start of the hash of that version's text and the start of the key that signed it. At most 100 links. A version is known to follow a folder's text where that text's hash is in its chain and every newer link was signed by a key that counts (§2.3, §7.3). (A statement has a chain too: the statements it was made after.)
- **Revision, band**: A revision is one number. Its top nine bits are its band and the rest its count. Band 0 is ordinary editing, and a statement's band is its number. At a move, a revision in the top half of a band goes to the bottom half of the next (§2.3).
- **Carry**: Writing a version that a device holds in a generation it leaves into the name's new channel, as the carrying device's own entry at the same revision, with the version's chain. A device carries what it holds in the transaction that applies a statement. `cordelia sync carry` brings in, from the relays, what a generation that was left still holds (§7.3).
- **Move**: What happens to a name's channel at a statement: it is left, and each device carries into the new one what it holds. A move changes no file (§7, property 8).
- **Proof**: A signature by a channel's signing key over a value that both ends export from one TLS session, the prover's node key and the channel's ID. A relay hands a channel only to a connection that has made it (§2.4).
- **Show**: A device hands a relay an entry and is told what the relay holds from that author in that slot: the same, none or an earlier one (which the relay then takes), or another, which it hands back. It is how a change reaches a device. After the first on a connection a show can be **short**: the entry's channel, slot, author, revision and ID alone (§2.4).
- **Leave**: The 10 seconds for which a device may use a connection to a relay for its own channels, from an answer there which says that the relay holds no later change than the one the device keeps. A device sends nothing and takes nothing in a channel of its own without it (§4.6).
- **Wake**: A device that starts, or reaches a relay after having reached none, asks every relay it is set up with before it takes or sends anything, or waits 30 seconds (§4.6).
- **Held since, mark**: A relay counts a channel as held since it first took it, and over its cap drops the channels it has held for the shortest time. A mark is 8 random bytes that name one holding of a channel: a place in a channel means something only with its mark (§2.4, §2.5).
- **Relays that work together**: Relays that their operator lists together, by key. They pass entries between them without the proof (§2.4).
- **Relay**: Stores an entry only if both of its signatures hold, with no key, no list of members and no state of the channel. It hands a channel only to a connection that proved the channel's key, and tells nobody which channels it holds. It favours the channels it has held longest, and drops what nobody has used for 90 days (§2.4, §2.5).
- **Conflict (copy beside a file)**: Where a device takes a version that is not known to follow its own text, it keeps its text beside the file as `<file>.conflict-<tag>.md`. A tie at one revision goes to the higher hash of the text, and a text beats a delete (§2.3, §7.3).
- **The level**: The colour of the status line, for a personal node that runs with sync on: red where this device has stopped, has not finished its first start on this version, or follows no phrase with something mapped; amber where something waits on a person or on a relay (a removal that some device has not applied, a device added and not cleared, a relay that does not hold the latest change). The line shows the first thing of the gravest level (§8, §10.1).
- **Notice**: Something a device shows until a person clears it there, at a terminal (`cordelia devices --clear`): a device added since the last change, a device that has left, a key that is not in the last change.
- **First start (on this version)**: What a personal node does once to a database of the version before: a copy into `before-<version>`, and then one step that empties what it held of the older kind (§10.1).
- **Not added yet**: What a device says of itself after the upgrade until a person makes the phrase on it or adds it from a device that has one (§10).

---

*Glossary v1.0. Created 2026-03-11. Referenced by all Phase 1 specs.*
