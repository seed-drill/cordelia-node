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
- **Robust.** It works when one machine is off, and there are two relays in different places run by different means. Sync is idempotent and restartable. A conflict produces a second file, never a lost edit (section 9 lists the cases where that does not yet hold).
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
- The key version is bounded in the same way. A removal moves it by one, with the epoch. So a state may not move it back, nor further than its epoch moved, nor by more than a state has room for keys (1,024, `MAX_STATE_KEYS`). Otherwise a member could send the largest version there is, and no device could be removed afterwards.
- Every member's key must be a usable public key: a point on the curve, of the order every real key has.
  - **Why.** A secret agreed with a point of small order is all zero, whoever agrees it. A state sealed to such a "member" could be opened by anyone who fetched its inbox, and anyone can sign under such a key. Bytes that are not a point are no key at all. A point of mixed order (a real key with a point of small order added) is refused because no device makes one, and libraries do not agree on which signatures under one are good.
  - **Refused everywhere.** `add-device` and `accept` refuse such a key, nothing is sealed to one, and no channel state is taken from a sender that has one. Sealing and opening both refuse an all-zero secret as well.
  - **Left out of a state.** A state that lists one is applied without it, however many it lists, and a state this device builds leaves it out. Refusing the whole state, or holding it, would lose a removal made by a device that still lists such a key. A check costs a multiplication on the curve, and a state that waits is looked at again every few seconds. So what a stranger sent waits unchecked; a state whose sender is not this person's device is held before its keys are looked at; and the answer for a key, which never changes, is remembered while the node runs, so that a state that waits has its keys checked once in a run. That holds while the keys the node is looking at fit in what is remembered (65,536 keys, 64 states of the largest size). Past that each look checks them again, at most a multiplication for each key, with the database held. (The sender's key is checked on every look besides.) Only one of this person's own devices can send that many states that wait, and it ends when that device is removed.
  - **One stored by an earlier version is taken off when the node starts,** where it is still listed or trusted: every row for it, the trust in it, and what was stored to send it. What was written under it no longer counts in a channel. What a device had already taken of it stays in that device's folder, and can go back to the channel from there as that device's own: as a conflict file beside the file, in a merged `MEMORY.md`, or as the file itself. (A delete taken from it does not stay where an earlier version is left: the file comes back.) At that start the node's log names the key and the channels that listed it, as a warning, and says that others may have written as well as read. No command shows them afterwards.
  - **No channel's key is changed on account of such a key,** by the node or by `cordelia remove-device`. What was sealed to it was not sealed to one of this person's devices, so the key of each channel that listed it does need changing. But a change of key is a change of membership that one device publishes, and one made from a list that is behind can undo a removal made on another device. So a channel that listed such a key keeps the key it had (section 9), and removing the key itself is refused. Removing a device publishes that device's entries again, as the remover's; that is not done for such a key. (What a device had already taken of them is the bullet above.)
  - **Each device checks for itself.** A channel is clear of such keys once every device in it runs a version that refuses them. Clear of the keys is not clear of what was sealed to them (section 9).
- A state carries no key above its own version. Kept by the receiver, such a key would wait for the removal that makes that version and be put in place then, so the key after a removal would be one the sender chose.
- A state holds at most 1,024 keys. A channel that has had more sends the newest ones. Devices that hold the older keys keep them; a device added later cannot read what was written under the ones left out. Without this, a ring that had been filled could not be sent at all, and no device could be removed.
- A state for a channel the node doesn't know is applied only if the sender is trusted.
- Channel IDs must be exactly `grp_<lowercase uuid>`.

Membership changes, key rotations and invites are all the same operation: the owner publishes a new state to each member's inbox.

**Trust.** A node joins a channel automatically only when the state comes from a key it trusts. Everything else waits in a pending list (at most 100, oldest rejected first), which `cordelia invites` shows. Trust comes from two places:

- **`cordelia accept <key>`**, the explicit, out-of-band step. You copy a key from one of your own screens to another, with no pairing code, no bootnode involvement and no fingerprint prompt to skip.
- **Your personal channel.** **As built:** the device roster is the personal channel's member list. Any device in it is trusted, so a third device added from the laptop is trusted by the desktop without another `accept`.

Without a trust check, anyone who knows your public key could add you to a channel. Its content would land in Claude's memory folder, which your agent reads as its own notes.

**Personal channel.** A `grp_` channel that holds the device roster and the map from name to channel (4.5). Until 0.2.0-alpha.3 it also held home memory. A node creates one on first use, and a device that accepts a `device` invite adopts the inviter's personal channel as its own.

**Revocation.** `cordelia remove-device <key>`, run from any remaining device, revokes trust in the key, removes the device from every channel this device owns, rotates each of those channels' keys, and sends the new state to the remaining members through their inboxes. The device that removes makes the new key itself, and nothing it was sent or holds can stand in for it: a state carries keys up to its own version and none above, and a key above a channel's version is no part of its key ring. This holds once every device runs 0.2.0-alpha.6 or later: an earlier version that removes a device can still put a key that was waiting in its ring in place. **As built:** since devices join only the projects they have (4.5), the remover may not be in every project channel. Each device that sees a device dropped from the personal channel therefore removes it from the project channels the remover is not in. Of a channel's remaining owners, the one with the lowest key acts, so two devices never rotate the same channel at once. It is run from one device at a time; two devices changing membership at once can lose one of the changes (section 9). For a key that is not a usable public key (4.1) the command is refused: such a key is no device, and no channel's key is changed on its account.

**A change is offered until each member holds it.** Sending a state once is not enough: a relay can lose it, and a member may be away for weeks. A removal that a device never receives leaves it trusting the removed device.

- The device that sends a state remembers it, for each member it was sent to, until that member is seen to hold it.
- A member that applies a state answers its sender with its own state for the channel, which carries the epoch it now holds. Any state from a member at that epoch or a later one counts as the answer. (An answer is not itself waited for, or two devices would answer each other for ever.)
- Until the answer comes, the sender offers the state again: after 1 minute, then 2, then 4, up to every 6 hours. Offering again puts the same item back in the outbox. A relay that still holds it says so; one that lost it stores it again. Nothing new is written.
- `cordelia devices` shows a device that has not confirmed a change for ten minutes or more.
- A device on a version before 0.2.0-alpha.4 applies states and never answers, so it shows as not confirmed until it is upgraded.

**What a removed device wrote.** Once a device is removed, its entries count for nothing: not when a name is read, not towards a name's next revision, not in the sweep of old deletes. So that the channel keeps what it held:

- Just before it removes a device, the removing device publishes again, under its own name, every entry whose current value the removed device wrote: its content, or its delete. It uses the revision the removed device gave the entry, so the new entry takes the old one's place exactly. (Where the removing device has an entry of its own at that revision, having lost a tie to the removed device, it uses the next one.) A device that already holds the entry sees no change; a device that is behind, or is added later, gets it.
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
- **Rev:** a per-slot counter. The writer sets `rev` to one more than the highest rev it holds for the slot from a current member of the channel. (An entry published again at a removal is numbered as 4.1 says.) Wall clocks play no part, so clock skew between machines does no harm.
  - What anyone else stored in the slot does not count, so neither a stranger nor a removed device can put a name's rev out of reach.
  - A rev is at most 2^53 - 1 (`MAX_REV`). This is checked wherever an item is verified, so no node stores a larger one or passes it on.
- **Signature and encryption both cover the slot and rev.** The signed metadata envelope gains `slot` and `rev`, present only on slotted items, so existing items and test vector TV-C1 are unchanged. The item's AES-GCM associated data becomes `channel_id || slot || rev`. A relay can neither relabel an item into another slot nor replay an old revision as a new one.

**Storage keeps the newest rev per `(channel_id, slot, author)`, not per slot.** Relays see slot values but can't tell members from strangers. Under a per-slot rule, anyone who can reach a relay could publish junk with a higher rev into your slot, and the relay would throw your real item away. Keyed by author, an attacker can only replace their own entries. This needs **every node, relays included, to verify an item's signature before storing it.**

**No storage rule compares one author's items with another's.** That holds for every rule a node applies when it stores:

- A node skips an item only when it already holds the same ciphertext from the same author. If the author did not matter, a copy of your item under someone else's key, stored first, would keep your item out.
- The sweep of old deletes (4.4) never lets one author's delete remove another author's content from a relay.

**Readers resolve per slot.** Among items whose author is an active member of the channel, which decrypt, and whose key maps back to the slot, the highest `rev` wins, with ties going to the higher `content_hash`. The losing version of a tie is reported as a conflict, and the device that wrote it keeps it as `<file>.conflict-<tag>.md` (the tag is the start of its key), so at a tie neither machine's edit is lost (section 9 says what happens at a higher revision).

This is the same idea as Nostr's addressable events (NIP-01, kinds 30000-39999). The API is `publish` with a `key`, `/api/v1/channels/entries` and `/api/v1/channels/delete-key`.

### 4.4 Deletes that replicate

A delete is a new `rev` of the slot, marked as a tombstone. Tombstones are kept for 90 days (`KEYED_TOMBSTONE_RETENTION_DAYS`), so that a device that has been away for less than that learns that the file was deleted; after that, an hourly sweep drops the key's whole slot history. What counts as deleted depends on what the node can know:

- A device knows the channel's members. A key is deleted when the newest rev among them is a delete.
- A relay does not, and stores what anyone sends. It drops a key only when every author's newest rev of it is a delete older than 90 days. So a key that one device deleted, and another device still has content for, stays on the relay. That costs a relay some space, and it means a stranger's delete can never erase a member's file there.

`delete-item` now checks the item's channel and that the caller wrote it.

### 4.4a Fixes to sync and verification that 4.1-4.4 depend on

- **Sync served only what the listen API shows,** which hides internal items and tombstones, so no key envelope or delete had ever reached another node by sync. Sync now has its own query that returns every item.
- **Sync fetched only the newest 100 items per channel.** **As built:** items get an arrival sequence number, and sync pages by it (`after_seq` in the request, `last_seq` in the response) with a cursor per peer and channel, until `has_more` is false.
  - **A page's entries come back in one message, and a hundred large ones do not fit.** A node asks for 100 entries a page. When a fetch fails, it asks that peer for fewer of that channel at a time (14, then 3, then 1) until it has caught up there, then goes back to 100. A node that is asked for more than fits ends the stream at once, so the asker learns without waiting. Before this, a channel with more than a megabyte of entries in one page could never be fetched: the same request failed every ten seconds, for ever, and held up the channels after it.
  - **The cursor lasts as long as the connection.** A relay that has lost or replaced its database (it was rebuilt) starts its arrival sequence again, and a cursor kept from before would skip everything it stores from then on. So when a peer connects again, each channel is listed from the start once, and only the items missing here are fetched.
- **Key distribution never reached the network.** Membership and key changes made through the device commands and the adapter now go through inboxes (4.1). The older endpoints still don't (section 9).
- **A burst of writes was rate-limited and lost** (found by the real-process test). **As built:** new items go into an outbox that is pushed to one relay at a time, at most every 2 seconds, and an item is marked relayed only when a relay has stored it or already held it.
  - **A relay's refusal is not delivery.** The relay's answer lists the items it refused and why. Those stay in the outbox and are offered again after a wait that doubles from 4 seconds up to 10 minutes, to the next relay in turn. So a relay that cannot store (a full disk, say) does not make a device believe its writes are safe.
  - A relay from before 0.2.0-alpha.4 says how many items it refused and not which. Nothing in that push is taken as delivered, and that relay is left alone for a while.
  - `cordelia status --json` lists the refused items under `outbox_refused`, and the status line asks for attention once relays have refused an item three times in a row.

### 4.5 `cordelia sync claude`: the Claude Code adapter

It runs inside the node binary: one install, and the node stays the encryption boundary ([2026-03-10 decision](2026-03-10-phase1-design-decisions.md) §1). Every 5 seconds, and as soon as a setting changes, it syncs memory folders under `~/.claude/projects/*/memory/`:

- **What syncs is declared (changed 2026-10-01).** `cordelia sync map <folder> [name]` says that Claude's memory for a folder syncs under a name, and nothing else syncs. On a new machine `cordelia sync claude` therefore syncs nothing: it lists what it found, with the command that maps each. As first built it synced home memory and every git project it found; that is now `--all`, which also covers what turns up later. An install from before this change keeps syncing everything it finds, because a scope is only ever narrowed by its owner. Running `cordelia sync claude` again keeps the stored settings (it used to put the directory back to the default), as does turning sync off and on, and it says what it changed. Every change of scope, mapping or exclusion is logged. `cordelia sync status` shows each folder with its name, when it last sent and received, and any error; `cordelia status --json` adds its channel.
- **A name, not a path, is what devices share.** Claude Code names folders after the working directory, so paths never match across machines. A git project's name defaults to its `origin` remote, normalised to `host/owner/repo`. Any other folder is given a name, and a name can be given to a project too. Mapping the home directory has to be asked for (`--home`), so that a slip does not sync a whole home. It syncs under the name `~` unless it is given another, so that home memory on one machine can share a name with a folder on another. The name `~` is home memory's alone, because every device shows it as that. A name does not start with `-` or `~`, which a command line would read as an option or a path. Mapping a folder that is already mapped, with no name, changes nothing. `cordelia sync map` refuses a folder outside the home directory, a second name for a mapped folder, a second mapped folder for a name, and two folders that Claude Code keeps in one (it names its folder after the path with every other character turned into a dash), and a folder inside a home directory that is itself a git repository, whose memory Claude Code keeps with home's.
- **One memory per repository.** Claude Code keeps a repository's memory in the folder of its main working tree, shared by its subdirectories and worktrees, so that is the folder `cordelia sync map` maps, whichever folder of the repository it is given. A mapping syncs the Claude Code folder named after its directory and no other. It is never matched by reading session transcripts, so it cannot come to sync a different folder than the one declared.
- **Each name gets its own `grp_` channel,** which only its owner's devices join (4.7). The personal channel maps `project/<name>` to the channel.
- **Home memory has its own channel (changed 2026-10-01).** As first built it went to the personal channel, under keys `home/<file>`, which every device of the person holds. It now syncs like any other name, in a channel joined only by the devices that map it.
- **As built: devices join only what they map.** A channel starts with its creator as the only member. Another device that maps the same name posts a join request (`join/<channel>/<device>`) in the personal channel; an owner grants it, and only for the device named in it. So each device holds keys only for what it syncs. Each device also lists the names it syncs (`syncing/<device>`) in the personal channel, read only from the device a list is about, so `cordelia sync status` can say what the person's other devices sync.
- **A folder that stops syncing starts afresh (2026-10-01).** Unmapping a folder, turning home memory or sync off, or narrowing the scope forgets what the folder had agreed with its channel. If it syncs again it merges with the channel as a new folder would, so files it lost in between are fetched back and never sent as deletes. An unmapped folder also stays out of `--all` until it is mapped again. A mapped folder whose memory directory has gone missing is reported and nothing is deleted elsewhere. Unmapping does not yet take the device out of the channel (section 9).
  - **More forgets than stops.** The node knows which mapping a command removes, but which folders a narrower scope no longer finds is known only to a cycle. So each of those commands makes every folder that is not mapped forget, and a change of the Claude Code directory makes every folder forget. A folder that is found and goes on syncing then merges once more than it needed to, and a merge treats what had not yet been exchanged as new on both sides. A file deleted on another device and still here is published again. A file deleted here and still in the channel comes back. A file edited on either side keeps the channel's version, with this device's beside it as a conflict file; `MEMORY.md` is merged. A narrower scope does not touch mapped folders; a change of directory does.
  - **The Claude Code directory is the text that is stored.** Another spelling of the same path is a change of it.
- **A command that stops a folder syncing has stopped it when it answers.** A cycle reads its settings once and then works through its folders file by file. A handler that changes a setting counts the change while it holds the database lock, and in the same step forgets what the folders it stops had agreed (and others with them, as above). A cycle reads that count under the same lock before each memory entry it publishes, before anything it records of what a folder agreed, before it forgets, and before it publishes the names it syncs. A cycle reads the count without the lock before each file it writes or removes and before it takes up the next folder, so one file may still be written, and one channel made or asked for, just after a command has answered. When the count differs from the one the cycle started from, the cycle stops, and the next one starts from the new settings. A cycle that is stopped does not note when each folder last sent or received (that is shown from the last cycle that ran to its end), though the time of the last change of any kind is still noted. Whether sync is on is one of those settings. Turning it off forgets what every folder had agreed, and turning it on forgets again, for anything that was left (an earlier version forgot later, and a write can fail). A handler counts its change before the first thing it writes, so one that fails part-way has still stopped the cycle that was running. What it did not get to forget is forgotten later: by the next cycle that runs to its end and can look up every channel, which forgets every folder that does not sync under the settings it read; or, where sync was left off, when it is turned on. What was published before the command answered is not recalled: it is in the channel, or waiting to be sent.
- **With `--all`,** the adapter reads the `cwd` recorded in each folder's session transcripts to find its repository. A folder Claude Code named is believed only about the directory it is named after, because a session can move to another directory and a transcript can start there. `cordelia sync exclude <pattern>` keeps projects off a device and `cordelia sync home off` keeps home memory off it, whatever name it is mapped under, and `cordelia sync home on` maps it again under the name it had, so that off and on again leaves it in the channel it was in. Folders that are neither home nor a git project with a remote need a name, and `cordelia sync status` lists them. Two clones of one repository on a device both sync under its name, so their memory merges.
- **A name has one spelling:** lower case, with no `.git` and no `/` at its end, however that ending was typed. A name typed at the command line, an exclusion as the node stores it, and the name found from a remote are all tidied by one rule, and tidying twice changes nothing. So a project's name typed as an exclusion is the name the project is found under (`cordelia sync exclude` also takes a remote that is pasted, and gives the name it makes), and what excludes a project includes it again. An exclusion that an earlier version stored with the ending is read without it. A folder in the exclude list keeps a space at the end of its name, when the list is read and when it is written (its separators are tidied, and an entry with `..` in it is no folder). A folder is in the list because it was unmapped, and `cordelia sync claude --exclude`, which replaces the names in the list, leaves the folders in it. A mapping's name that an earlier version stored with the ending stays as it is stored: `cordelia sync unmap` takes a name as it is stored, or else in its one spelling, and takes a word that ends in `/` for a folder. A folder given to `unmap` means the mapping of that folder before the mapping of the repository it is in.
- **An unmap is advised last.** A folder that is mapped under one name and asked for under another is told to unmap first only when the request would then be taken. Unmapping is not free (the folder stops syncing, forgets what it agreed, and is excluded), so a request that would be refused anyway, for its name or for a flag, is refused for that. The home directory named without `--home`, and mapped under another name, is told that it is the home directory and given both steps at once: the command as typed would be refused for the flag after the unmap.
- **`MEMORY.md` is merged where another file would get a conflict file.** It's an index of one-line pointers, so the merge is the union of lines, minus lines pointing at deleted files. Where that is the channel's version as it stands, the file takes it and nothing is published. Where another file is replaced with no conflict file (section 9), so is the index.
- **Safety.** Only plain file names are synced, writes are atomic, a file edited during a cycle is left for the next one, and a file that does not fit in an entry is reported rather than synced.
  - **An edit is published only over the entry it was planned from.** A cycle reads the channel, plans each file, and then publishes. An entry that becomes the channel's version of the file in between is one the plan never read, and publishing over it would replace its text with no conflict file. So before the adapter publishes an edit, a delete or a merged index, it reads that file's entry again, under the lock it publishes under, and goes ahead only if it is the same entry, or there is still none. Otherwise the file waits for the next cycle, which plans from what is there. (Some entries are no version of a file, to the plan and to this check alike. One that is not a text or a delete, written through the API under a file's name, counts as nothing being there. One that 4.3 passes over, such as one this device cannot read, is passed over here too, and the newest of the entries that are left counts.) It is the entry that is compared, not its revision: two devices can publish the same revision, and which of the two counts can change while the number does not. This covers the entry that counts, and no other: see section 9 for an edit that another device has overtaken.
  - An entry is at most 64 KB as it travels (`MAX_ITEM_BYTES`): the file's text, escaped, with its name, plus 28 bytes for sealing. The device that writes it checks this, and so does every relay and every device that is sent it. One small size for everything is what lets limits on rate and storage mean something.
  - A file that is too large, or that is not plain text, takes no part in sync in either direction. It stays as it is on the device that has it, nothing from the channel is written over it, and the other devices keep the last version that did sync. It is never taken for deleted. `cordelia sync status` names it, and the status line asks for attention.
  - A file that fails in a cycle for a reason of its own (it cannot be written here, or its entry is refused for what it is) is reported with why, and the cycle goes on with the other files of the folder. It is tried again in the next cycle. Nothing more is done for it in the cycle that failed, so a text that was to be kept beside the file is never written over without having been kept. A failure that is not one file's (the database, the channel's key, this device's place in the channel) ends the folder's cycle, and the folder's report says why, with what the cycle had done by then. Up to 0.2.0-alpha.5 every failure did, and the files after a file that failed waited for as long as it went on failing.
  - A name that something other than a file has in the folder (a folder, say) takes no part either: no file is written there, and the name is not taken for deleted.
  - A conflict file takes a name only if nothing is there, and its name is never longer than 255 bytes, which is as long as a file name can usually be: for a file whose own name is too long to add to, the name is cut and marked with part of its hash. A text counts as kept already only where a conflict file holds exactly it and is the copy of this conflict: the folder has not yet agreed that text under that name, or it published it there after the version arrived that the file is to take. A copy from before that may have been deleted on another device since, so the text is kept again under the next name. (A file that can be read and not replaced is so kept once for each version that arrives, not once in every cycle.)
  - A file is written through a temporary file whose name is short, so a name as long as a file name can be is written. A file is never written through a link left under its temporary name. A file that arrives makes the memory folder only where the folder was not there when the cycle listed it. A folder that was there and has gone since is not made again, and one that can be listed but not looked into is an error: either would otherwise be read as every file deleted, which would delete them on every other device. A folder that was not there when it was listed, and had agreed files, is reported as gone, whatever is there a moment later; one that had only ever agreed deletes was never made, and is not. A delete is not published for a file that is there again when the cycle comes to it, and a file whose name is not text is not synced.
  - Until 0.2.0-alpha.3 the limit was 128 KB for a file, and a file that grew past it was taken for deleted, which removed it from every other device.

Other agents come later as further adapters that map their own memory locations onto the same channels.

### 4.6 Two relays

Personal nodes are outbound-only and there is no NAT traversal, so two devices always meet through a relay. **As built (0.2.0-alpha.3):** a personal node opens no listening socket at all. It dials out from a port the system picks, where earlier versions bound UDP 9474 and turned inbound peers away after the handshake. `listen = true` under `[network]` keeps a listener, for a node that others dial directly. We run two relays, each also serving as a bootnode, so that losing one doesn't stop sync:

- **`relay1`** and **`relay2`** are Docker containers we operate, from the image and guide in [`deploy/relay/`](../../deploy/relay/): a pinned release checked against its sha256, run unprivileged on a read-only filesystem. **Changed 2026-09-30:** for the alpha we host both ourselves. Before any public announcement, the public relays move to a cloud provider (the Fly.io config is ready for that), and the storage cap and retention ship (section 9).
- **DNS:** `relay1.cordelia.seeddrill.ai` and `relay2.cordelia.seeddrill.ai`, UDP 9474. New nodes list both (`FALLBACK_PEERS`), and anyone can add their own. **As built:** nodes keep the names, not the addresses. They resolve them again while running, so a node started before its network was up, or a relay whose address changed, is still reached.
- **A relay is a name and a key (2026-10-02).** The name says where to dial, and the key is what must answer there. The default relays' keys are compiled in (`FALLBACK_PEER_KEYS`), and a relay of your own takes a `key` beside its `addr`. A node refuses any other key at a relay's address, so answering for a relay's name is not enough to be taken for it. A relay configured without a key is accepted with whichever key answers, and the node says so when it starts.
- **A relay works with the relays it lists (2026-10-02).** It forwards to them and tells them which channels it holds. A node that connects and says it is a relay is an ordinary peer unless it is one of the listed relays, by key. Neither relays nor devices ask peers for the addresses of other peers.
- **A device's network is its configured relays, and nothing else (2026-10-02).** It dials only those. It does not ask a relay for other peers' addresses, and learns of no relay from DNS, so a relay cannot send it anywhere. Each configured relay that is not connected is dialled again at a slowing pace: one governor tick, doubling, up to fifteen minutes while another relay is connected, and at least every half minute while none is. `cordelia peers` and `cordelia status --json` say which relays are not connected, since when, and why. Starting no longer waits on a relay that is unreachable.
- **A device stores only what belongs in its own channels (2026-10-02).** A relay stores what anyone sends to a channel, since it cannot tell a channel's members from anyone else. A device can: it stores an entry only if it and the entry's author are both members of the channel, and it tells from the entry's header, before fetching the rest. Its own inbox takes anything, since an invitation comes from a key that is in no channel with it yet. So a stranger who knows a channel's ID can put entries at a relay, and none of them reaches a device's disk.
  - A member that a device has not heard of yet may already have written. When a state adds members, the device lists the channel again from the start and fetches what it refused.
- **What one connection can cost a node is bounded (2026-10-02).**
  - A peer may have 64 streams open at once, and may send two messages' worth that the node has not read. Before, it was 1,000 streams with a megabyte each.
  - A connection may make 36 pushes a minute and push 2 MB of entries a minute. All the connections from one address share five times that: a key costs nothing to replace, and an address does. A request over a limit is refused at once.
  - An address's allowance lasts as long as what was counted against it, whether or not its connections do. Until 0.2.0-alpha.4 it was forgotten once the address had no connection open, so closing them all and connecting again started it afresh.
  - **An entry is one size in every field, and counts for what it takes.** Each field of an entry other than its ciphertext has a size it must fit in: its ID and its parent's (64 bytes), its channel (96), its type (32), its time (40). So an entry as it travels is at most its ciphertext and a kilobyte (`ENTRY_OVERHEAD_BYTES`). Every limit on bytes counts an entry as its ciphertext plus that kilobyte: the allowance of a connection and of an address, what one channel may hold at a relay, and what a device sends in one push and in one minute. Until 0.2.0-alpha.4 only the ciphertext was bounded and counted. An entry could then carry a megabyte in its type, and a channel of three-byte entries could hold any number of them.
  - A push, and a page that is fetched, is stored in one transaction: one write to disk however many entries it carries.
  - A peer that goes over three times in ten minutes is cut off, and its address is refused for 15 minutes. Before, going over was logged and nothing followed.
  - An address that already has its five connections, or is refused, is turned away as its connection arrives, before the cost of a handshake.
  - Signatures are checked before the database is held, so a peer cannot stall a node by keeping it busy checking.
  - A device paces what it pushes to 1.5 MB a minute to each relay, so it is never the one refused. Two relays that list each other are not limited.
- **A relay is a cache with a cap (2026-10-02).** Its operator sets how much its database may hold (`max_storage_bytes`, 1 GiB by default).
  - At the cap it takes no channel that it does not already hold.
  - A write that takes it over the cap makes it drop the channels it came to hold most recently, until it is under. If the channel written to is the newest, that is the one dropped. So what was there first is never pushed out by what came later, and a flood of new channels cannot displace anyone's.
  - One channel may hold 16 MB. One address may make a relay hold 16 new channels an hour. Two relays that list each other are not counted.
  - A device whose entry is refused for lack of room keeps it, offers it to its other relay, and says so in status.
  - Nothing is lost when a relay drops a channel or is rebuilt: every device holds its channels whole, and a relay asks each peer connected to it which channels it holds and fetches what it lacks, when it has room.
    - It asks its hot peers every cycle: as a rule, the relays it lists. It asks every other peer when that peer connects, and every ten minutes after it has fetched all the peer holds. A device sends what it writes as it writes it, so asking is only for what the relay lost, dropped or had no room for. A device is asked only for the channels it says it holds.
    - What a peer lists is the peer's to write, so it is bounded: only IDs that could be a channel's, and 1,024 of them in one pass. A page with nothing in it is the end of a channel, whatever it says.
    - What a relay keeps for a peer is bounded: its place in the peer's list of a channel, and the size of page it asks for there, for at most 1,024 channels of a peer that is not a relay it lists. For a relay it lists there is no such bound: two relays that list each other hold each other's channels. When it has that many, a caught-up channel's place makes room before one that is still being fetched, and of those the one kept longest ago. Nothing is kept where a peer lists nothing, and what is kept for a peer is forgotten once it has gone. One peer's connecting again costs no other fetch its place, and one channel's being listed again costs another fetch at most the page it has in flight.
    - A peer with more than 1,024 channels is asked about a different 1,024 of them each pass. Its channels are all reached in time, but v1 is not built for a device with that many; one with several thousand, and long channels among them, may wait a long time for those.
    - A relay goes through a peer's list whether or not it can store what is listed, so what follows an entry it refuses is reached. It asks for such an entry again only when it goes through that part of the list again: when the peer connects again; when the channel is to be listed again from the start; when its place there made room for another's; when the relay had no room for the channel, which it does not hold; or when the page was in flight as another channel was set to be listed again.
    - What a relay fetches from a device is bounded as what the device may push is: 2 MB a minute for a connection and five times that for its address, counted apart from what the device pushes, and counting every entry the device sends in answer, asked for or not. Lists of channels and of entries are not counted. The relay asks for a whole page only when the allowance has room for the most a page can cost, and otherwise for as many entries as would fit at the largest size. It holds the device to what was asked for: a page no longer than the one asked for, and only the entries named.
    - When the allowance is used up, the relay asks again a minute later. When there is more to fetch than one pass takes, it asks again at the next cycle.
    - A relay does not ask for a channel it has no room for, so its place in that channel does not move. An entry that a channel the relay holds has no room for is passed over: that channel is at its limit.
    - A write that does not make a channel hold more is always taken: a newer revision, by the device that wrote the one it replaces, that is no larger. So in a channel that is over its share, because it was written before each entry counted for what it takes, a device can still edit and delete what it wrote, and the channel can shrink. What another device writes under the same name is an entry of its own, and is refused there as any new entry is. Only what is stored counts for what a channel holds.
    - Against its address, what is fetched from one connection counts for no more than a connection may be fetched from in a minute, whatever its answers hold. So a few connections cannot use up what every device at their address may be fetched from. An address is still one allowance, shared: a stranger at the same address who connects again and again under new keys can use it up, as for pushes.
    - A channel it dropped is listed again from the start, and is left for ten minutes before it is taken again. Without the wait a relay at its cap would fetch the channel, drop it and fetch it again without end. A channel that is dropped again each time it is taken does not fit: the wait doubles each time, up to 32 times.
    - One fetch runs from a peer at a time.
    - **Until 0.2.0-alpha.4** a relay asked only its hot peers. Two relays that list each other are each other's hot peer, so their devices were never asked: when both lost their databases at once, what was written before did not come back to them ([#92](https://github.com/seed-drill/cordelia-node/issues/92)).
  - An open relay can still be filled: one address can make it take 256 MB an hour, and many addresses more. It then takes no new channel, and stays correct; the answers are a larger cap, retention, and closing the relay to the keys its operator lists.
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
- **What comes next is therefore not shared memory.** It is channels shared between people that carry what is shared on purpose: messages between agents first, then secrets. The rule there is the other half of this one: automatic between your own devices, deliberate between people.
  - **Changed 2026-10-03.** Skills were to travel in these channels too. Skills that people share travel in a repository instead, where a change is reviewed before anyone runs it.

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
- **`MEMORY.md` merges where another file would get a conflict file** (4.5).
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
| Channels shared between people: messages, then secrets | **Next** | Designed separately; never memory (4.7). Skills that people share travel in a repository |
| Second agent adapter | **Later** | Proves portability |
| Open channels, secret keepers, PSK-Exchange (0x07) | **Drop** | Decided 2026-10-03: channels that anyone can join or write to will not be built ([`docs/vision.md`](../vision.md) §6) |
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
- A file that is unchanged on a device since it last agreed with the channel is replaced by the channel's version, with no conflict file, whenever that version's revision is higher than the one agreed (#79). A revision is a number: the highest the writer holds for the file among the entries of the channel's members, plus one. (An entry published again at a removal is numbered as 4.1 says.) So a higher one does not show that its writer had this device's version in front of it. An edit that was published here is lost that way whenever another device publishes at a higher revision without having planned against it. Three examples, not the whole list: it edited twice; it edited once after taking a third device's edit; or the adapter published for it after a tie with a third device (a merged index, a file put back over a delete). The version taken can be a delete, and `MEMORY.md` is no exception. Where the channel's revision equals the agreed one both are kept: of an edit and a delete, the edit; for `MEMORY.md`, the union of lines.
- While a device waits for a key (after a removal, the device that removes writes under the new key at once), it cannot read an entry written under that key, and passes it over. This is the ordinary course after a removal, not a rare race: a removal is not applied when it arrives but later, as a rule when the node next fetches its channels, and until then the device's adapter goes on running. Storage keeps one entry for each writer of a file, so the unread entry has taken the place of any earlier one by its writer, and what this device reads instead is the newest entry by any other writer: often this device's own last publish of the file, however old, or nothing. It plans against that, so a file can move though nothing changed on this device. Examples, not the whole list: an unchanged file goes back to that older text (the text it had is kept beside it as a conflict file, which stays, and the file takes the unread entry's text when the key arrives); `MEMORY.md` is merged with the older text and published; a file whose older entry is a delete is published again; and a file that the writer of the unread entry had deleted, and has now written again, comes back with the older text. Whatever this device publishes for the file meanwhile goes above the entry it could not read, and that entry is then overtaken, with no conflict file, on every device that holds it and has not changed the file since: a text replaced, or a delete undone. This is the limit above, with another cause (#79). An edit made here that equals the older text is itself replaced when the key arrives.
- A channel that listed a key that is no device's key (4.1) keeps the key that was sealed to it. What was sealed to such a key can be opened by others, so what the channel holds may have been read, and what is written to it may be read, until its key changes. That happens when a device that is in the channel is removed, and for no other reason yet: the node changes no key on this account, because a change of key made from a list that is behind can undo a removal, and `cordelia remove-device` is refused for such a key. A node that takes such a key off first names it in its log, as a warning, with the channels that still listed it on that device. No command shows them afterwards. A device that had dropped the key before it was upgraded logs nothing, and a log level above warnings shows nothing: look in the log of each device.
  - Until every device runs 0.2.0-alpha.6 or later, one that does not goes on listing such a key, sealing to it and taking what is written under it, and what it tells the other devices about the personal channel is taken by them. So every device should be upgraded before any device is added or removed.
  - To stop adding to what can be read, stop every folder that syncs to such a channel, on each device. First see which they are: `cordelia status --json` gives the channel of each folder that synced in the last cycle, which is what the log names; a folder that has been stopped is no longer among them. The commands that stop one folder and leave the rest syncing are `cordelia sync unmap <folder>` for a mapped folder and, where it syncs by `--all`, `cordelia sync exclude <name>`, or `cordelia sync home off` for home memory. With `--all`, also exclude each project that the log of any of your devices names, whether or not a folder syncs under it now. The log gives a project's channel as `project:<name>`, and `cordelia sync exclude <name>` takes the name without `project:`; for `project:~`, which is home memory, it is `cordelia sync home off`, and for `personal`, which is the personal channel, there is no command. A folder that is not found today starts by itself in that channel when it is next used. A folder that stops and later starts again in the channel it had merges with it as a new folder would (4.5): what the channel holds comes back into the folder, and what the folder holds that the channel does not is published to it. Turning sync off and on again does that to each folder that then starts, so it is no way to a new name. Where sync is off the adapter writes no memory, and the commands that stop a folder are refused, as `cordelia sync map` is. Turning it on (`cordelia sync claude`) starts every mapped project folder again before a command can unmap it. Given as sync is turned on, `--no-home` and `--mapped-only` leave home memory and what `--all` finds stopped, and they stay set afterwards. A project mapped under a new name (`cordelia sync map <folder> <new name>`, for a folder that command takes) gets a channel with a new key, which helps only once every device is upgraded and any device that is not trusted has been removed. Each device then publishes what is in its folder to the new channel as its own, text written under such a key and taken by that device included, and text removed on one device and left on another comes back: look through the folder on each device first. Home memory, which has no other name, and the personal channel cannot be moved. The personal channel holds the list of devices, the map of names, each device's list of what it syncs, requests to join, and home memory synced before 0.2.0-alpha.3.
  - Removing a device that is trusted, to force a change of key, is not the way: that device is not told, and is left out of its projects.
- A project channel that the removing device is not in is rotated by its remaining owner with the lowest key (4.1). If that device is offline, the rotation waits until it next runs, and until then the removed device can still read what others write to that project.
- Relays keep what they store until they are full: the retention limit (30 days was proposed) is not implemented. It must ship before any public announcement, because every node dials our relays by default. The storage cap is enforced (4.6).
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
- Editing and deleting a memory propagates too, and a concurrent edit leaves a conflict file rather than losing either version (with the exceptions in section 9).
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
