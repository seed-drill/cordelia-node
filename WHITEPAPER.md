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
keys. Each device has its own key. A person's devices hold one secret between
them, from which every channel of that person's memory is derived, and the
person keeps a recovery phrase of twelve words: it removes a device that is
lost, and brings memory back to a new machine. A
project's memory follows the project, matched by its git remote, not by where it
sits on disk. When two devices edit the same memory, both versions are kept.
The design is in two decision records:
`docs/decisions/2026-10-04-a-persons-devices.md` (a person's devices, the
recovery phrase, and what a relay does; its sections 1 and 12 state the
limits) and `docs/decisions/2026-09-30-agent-memory-sync.md` (the sync
adapter, ties, deletes and local history; its section 9 states theirs).

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
matched by project, stays encrypted end to end, and survives machines being
off.

## 2. What Cordelia does

```
Laptop                                Desktop
$ cordelia init                       $ cordelia init
$ cordelia phrase
    twelve words, shown once: write them down, then type them back
                                      $ cordelia id
                                        cordelia_pk1...    (copy this)
$ cordelia add-device cordelia_pk1... --name desktop
    On the other device, within the hour, run:
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
- A device stores only the names it maps. It could read any of them: every
  device of a person's can derive the channel of every name of that person's.
- If two machines edit the same memory before hearing from each other, one
  version stays in the file and the other is kept beside it as
  `<name>.conflict-<device>.md`, on every machine. The memory index
  (`MEMORY.md`) is merged line by line instead. (The decision records list
  the limits.)
- `cordelia sync status` lists what was found on the machine and is not
  syncing, with the command that maps it, and what the person's other
  devices sync.
- `cordelia devices` shows every device, which change each has applied, and
  whether each relay holds the latest.
- A device that is lost is removed from one that remains, with the recovery
  phrase: `cordelia remove-device`. Where none remains that the person
  trusts, `cordelia recover` on a new machine, with the phrase, brings back
  what the relays hold.

Without the twelve words a device can be added, and none can ever be removed
or recovered.

## 3. Design

A Cordelia node runs on each device. It holds the device's key and the
person secret, stores encrypted entries in SQLite, talks QUIC to relays, and
serves a local API on loopback to the command line and the sync adapter.

### 3.1 Devices, the person secret and the recovery phrase

Each device generates its own Ed25519 key at `cordelia init`. Keys never leave
the device that made them. There is no account and no registration.

**One secret for each person.** A person's devices share a *person secret*:
32 random bytes. Every channel of that person's own is derived from it and
the channel's name (§3.2). A device is one of a person's because it holds the
secret. There is nothing to hand over for each channel, nothing to ask for,
and nothing to wait for.

**A recovery phrase.** Twelve words from the BIP39 English list, made by
`cordelia phrase` on one device and shown once. The person writes them down
and types them back before anything is made. The phrase signs the statement
of which devices are the person's, and recovers to a new machine. It is
typed for those things only, at the command's own terminal, never as an
argument and never over the local API, and no device stores it. The person
secret is never derived from the phrase: if it were, a stolen device could
not be cut off. Until there is a phrase a device has no secret, and publishes
nothing.

**The statement.** There is one for each change of the person secret. It
lists the devices that hold the secret, each by its key and the label the
person knows it by; every key removed so far; and a commitment to the new
secret. Only the phrase's key signs one. A device applies a statement only if
the phrase it follows signed it, it was made after the one the device has
applied, it undoes no removal, it lists the device, and the secret that comes
with it opens to the commitment. It applies it in one step, for every
channel, or not at all.

**Adding a device** takes two commands, each at a terminal with its yes: the
new device's key is typed on a device that is in (`add-device`), and that
device's key is typed on the new one (`accept`), within an hour. The device
that adds hands over the statement, the secret and a signed record of the
addition, in a channel that only those two devices can derive. The phrase is
not typed to add: a device that is in vouches for the new one. So every
device shows the addition until a person clears it there, and the next
statement asks of each device added since whether it stays.

**A device follows only a phrase that a person gave it:** by making it there,
by typing it there to recover, or by accepting there, with a yes, a device
that follows it. Nothing a device is sent makes it follow another. Without
this, anyone who learned a device's public key could try to have it sync its
memory to them, or put content of theirs in the agent's memory folder.

### 3.2 A channel is its secret

A channel is a secret of 32 bytes. Three things are derived from it with
HKDF-SHA256, each under a label of its own:

- an **entry key** (AES-256-GCM), for an entry's content;
- a **slot key**, which turns an entry's name into its slot (§3.3), so a
  relay sees no names;
- a **signing key** (Ed25519). Its public half is the channel's ID, written
  `cordelia_ch1...`.

So a channel's ID is a public key, and every entry is signed with the
channel's key as well as its author's. A relay can check, with no key and no
list of members, that an entry was written from inside its channel, and
hands a channel only to a connection that proves it holds that key (§3.4).

Where each channel's secret comes from:

| Channel | Secret | Who can derive it |
|---|---|---|
| Personal | The person secret | Every device of the person. It holds what the devices tell each other: which names each syncs, the devices added since the last statement, and which statement each has applied |
| A name's (memory) | The person secret and the name | Every device of the person, for every name |
| Pair | The two devices' keys (X25519) | Those two devices. It is used for one thing: handing a device what it needs when it is added |
| The phrase's | The phrase | Whoever has the phrase. It holds one entry: the latest statement, as it travels (§3.4) |

A channel has no key ring, no list of members and no owner, and a node has
no inbox. The channels derived from one person secret are a *generation*:
when the secret changes, every channel of the person's changes with it.

### 3.3 Entries

Everything a channel holds is an **entry**: a value under a name, at a
revision. So that every hop can check it, an entry carries in clear its
channel's ID, its slot, its author's key, its revision and whether it is a
delete; then its content; then two signatures over those and the hash of the
content, the author's and the channel's. The content is a nonce and a
ciphertext, padded so that its length is a power of two from 256 bytes to
64 KB: a relay sees a size class and no length. The encryption binds the
content to the channel, the slot and the revision, so an entry cannot be
moved to another slot or channel, or replayed as another revision. Every
node, relays included, checks both signatures before storing anything.

A memory file is edited, not appended to, so an entry replaces the one
before it:

- **Slot**: `HMAC-SHA256(slot_key, "cordelia:slot:v1:" || name)`, where the
  name is the file's name within its folder. Relays can tell that two entries
  are revisions of the same file without learning the file's name.
- **Revision**: one more than the highest revision the writer holds for the
  slot among the entries of devices that count. No wall clocks are involved,
  so clock skew between machines does no harm. A revision is one number in
  two parts, a band and a count: the band is 0 for ordinary editing, or a
  statement's number. That is what brings a name back into reach at the next
  statement, where a device had given it a revision that editing never
  reaches.
- **Inside the ciphertext**: the entry's name, its text, and its **chain**.
  The chain is what the entry was written after: for each version it
  descends from, newest first, the start of the hash of that version's text
  and the start of the key that signed it, for at most 100 versions. A text
  and its name may together be 60 KB; the rest of the 64 KB is kept for the
  chain, so what an entry says always fits.

Storage keeps the newest revision **per slot and per author**, never per slot
alone, and no storage rule compares one author's entries with another's.

Readers resolve each slot from entries whose signer **counts**: a device of
the statement the reader has applied, or one added since. The highest
revision wins. At one revision a text beats a delete, and of two texts the
one with the higher hash of the text wins, so every device that holds the
same entries picks the same one, and a tie is not drawn afresh when an entry
is sealed again. Two entries with one text at one revision are one version,
whoever signed them. The text that loses a tie is kept beside the file.

**What a version is known to follow.** A revision is a number, and a higher
one does not show that its writer had seen this device's text. A version is
known to follow a folder's text where that text's hash is in the version's
chain, and every link newer than it was signed by a key that counts. That is
what git asks of a commit and its ancestors, with a window of 100, because
nothing here keeps a history. A device takes a version without keeping its
own text only where the version is known to follow it. Otherwise it keeps its
own text beside the file first.

**Deleting** a memory publishes a delete, which is a version like any other
and replicates like one. At one revision a text beats a delete, so an edit
made apart from a delete is kept. An entry says in clear that it is a
delete, and nothing else about what it holds.

### 3.4 Network

Nodes talk QUIC (RFC 9000, TLS 1.3) with CBOR messages. A node's identity is
the key its TLS certificate carries, so nobody can connect or answer under a
key they do not hold. Two roles matter in v1:

- **Personal nodes** run on people's devices. They only dial out, so they work
  behind NAT and firewalls. A personal node dials the relays it was configured
  with and nothing else. It knows each by name and by key, and refuses any
  other key at a relay's address. It opens no listening port: nothing on a
  network the device joins can connect to it.
- **Relays** accept connections and store the ciphertext they receive. A
  relay stores and hands over only what belongs to a channel, with no key of
  its own:
  - it stores an entry only if both of its signatures hold and it is within
    the limits, and keeps the newest revision for each author in each slot;
  - it hands a channel's entries only to a connection that has **proved** it
    holds the channel's key: a signature by that key over a value of the one
    TLS session and the prover's own node key, which holds on no other
    connection and needs no clock;
  - it tells nobody which channels it holds. A channel it does not have and
    a proof that fails are answered alike;
  - relays that their operator lists together, by key, pass entries between
    them, with how long each has held a channel.
- **A relay is a cache with a cap.** It favours the channels it has held
  longest: at its cap it takes no channel it does not already hold, a write
  that would take it past its cap is refused and drops nothing, and one
  address may add only so many channels an hour. A channel that nobody has
  used for 90 days is dropped, and so is a slot in which every entry is a
  delete that the relay has held for 90 days. Each device holds what it
  syncs and sends a relay what the relay lacks, so nothing is lost for good
  when a relay is rebuilt while a device still holds it.

Three things happen between a device and a relay:

- **The show.** Each statement travels as one entry in the phrase's channel,
  the *change entry*, always 32 KB: the statement, the new secret sealed to
  each device it lists, and, sealed for the phrase alone, the new secret and
  up to eight before it. Every device keeps the latest it has seen and shows
  it to each relay on every pass. A relay that holds none, or an earlier one,
  takes it; a relay that holds a later one answers with it. So a change
  reaches every relay that any device with it reaches, and every device that
  reaches such a relay.
- **The show comes first.** On a connection to a relay, until a device has
  shown its change entry there and applied what it was answered with, it
  sends nothing in a channel of its own and takes nothing from one. A device
  that wakes asks every relay it is set up with before it does either, or
  waits 30 seconds. So a laptop that was closed over a removal sends none of
  its waiting edits where the removed device can read them, where a relay it
  reaches holds the change.
- **Pull and push.** Every 10 seconds a device pulls each of its channels
  from each relay, by the relay's own order of arrival in that channel, and
  every 2 seconds it pushes what waits. A relay that refuses an entry says
  why, and the device offers it again after a wait. A device stores an entry
  only if its signer counts.

In this version these channels travel between a device and a relay, and
between relays that work together, and nowhere else.

### 3.5 The Claude Code adapter

`cordelia sync claude` runs a cycle every 5 seconds inside the node:

1. **Decide what syncs.** A *mapping*, declared with `cordelia sync map`, says
   that Claude's memory for a folder syncs under a name. Nothing else syncs.
   - The folder is found by name alone. Claude Code keeps one folder per
     working directory under `~/.claude/projects/`, named after the path, and
     keeps a repository's memory in the folder of its main working tree, shared
     by its subdirectories and worktrees. A mapping syncs exactly that folder,
     never one chosen by reading transcripts, so it cannot come to sync a
     different folder than the one declared.
   - The name is what devices share. A repository's name defaults to its
     normalised git remote (lower-cased host and path, without scheme,
     credentials, port, or `.git`); any other folder is given one; home memory
     syncs as `~` unless it is given another name, and has to be asked for.
   - Each name has its own channel, derived from the person secret and the
     name. There is nothing to create and nothing to join: a device that maps
     a name derives its channel, and fetches it from a relay before the
     folder's first cycle there, so that a file another device has already
     sent is not published a second time.
   - Each device says in the personal channel which names it syncs, so the
     others can say what there is to map. A machine stores only the names it
     maps, and home memory reaches only the machines that map it.
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
   lines, minus pointers to deleted files. A version at a higher revision is
   taken. Where its chain does not show that it follows this device's text
   (§3.3), this device's is kept as a conflict file first.
3. **Apply safely.** Files are written atomically (a temporary file, then a
   rename, which never writes through a symlink). Only plain file names are
   accepted from other devices: no separators, no `..`, no hidden files. Before
   replacing or removing a file, the adapter re-reads it; if the agent wrote to it
   during the cycle, the change is deferred to the next cycle instead of
   overwritten. A file that does not fit in one entry (60 KB with its name),
   or is not plain text, takes no part in sync: it is left as it is,
   reported, and deleted nowhere.
4. **Keep what is replaced.** Sync makes one device's mistake every
   device's, so before the adapter replaces or removes a file's text it
   keeps that text in a history on the device: the file as it was, or, for
   an edit or a delete made there, the channel's version. A text that cannot
   be kept is not replaced. `cordelia history` lists what is kept and
   `cordelia restore` puts a version back; where the folder syncs, every
   device follows. History is kept for 30 days and up to 256 MB, on the
   device and in the clear, and is not a backup. It does not notice a
   mistake: a person has to. (Section 4.5b of the decision record of
   2026-09-30.)

### 3.6 Removing a device

`cordelia remove-device <key>` is run on any device that remains. The command
shows the lists it is about to sign, asks a yes, and then asks for the
recovery phrase. It makes one statement: the devices that remain, the
removed key among the keys removed, and a commitment to a new person secret.

- **One moment for every channel.** A device applies the statement in one
  transaction, when it is shown the change entry. It stores the new secret,
  leaves every channel of the generation before, and **carries** what it
  holds: each current version, in each name it holds, is written into the
  name's new channel as its own entry, at the revision it had, with the
  version's chain and a first link for the key that signed it. Every folder's
  record of every file means in the new channel what it meant in the old, so
  the ordinary cycle goes on from where it was, and no file changes.
- **What the removed device loses.** It reads nothing that a device which has
  applied the removal writes afterwards, and it writes nothing into the new
  channels: every entry there is signed by a device that the statement lists,
  or by one added since. What it wrote before is kept where a remaining
  device had taken it. What it had sent to a relay, and no remaining device
  had taken, stays at the relay unless a person asks for it:
  `cordelia sync carry <name> --from <device>`, at a terminal, says what it
  found, asks a yes, and then asks for the phrase.
- **A removal can always be made, sent and seen.** The change entry replaces
  the one before it, at the same size, in a channel a relay already holds: a
  relay at its cap still stores it. The command stays until every relay it
  is set up with holds the change and the device has sent what it carried,
  and says which is missing until then.
- **The limit.** A device that has not heard of the removal still writes
  where the removed device can read, and takes what the removed device
  writes. When it hears, it carries what it holds, and every other device
  keeps its own text beside what arrives. `cordelia devices` shows which
  devices have not applied the change.
- **Only the phrase changes who is removed,** and nothing undoes a removal.
  Two changes made apart, by two devices that had not met, stop every device
  that sees both until `cordelia settle`, with the phrase, makes one
  statement over the two.
- `cordelia renew` makes a statement that removes nobody: it lists the
  devices, with those added since, and commits to a new secret.

### 3.7 Recovery

`cordelia recover`, on a new machine, is for a person who has no device left
that they trust. It asks the relays that the machine is set up with. With
the phrase the command can fetch the phrase's channel, which no device can.
It takes the latest statement there; shows every device, and asks of each a
typed answer: `have` (the person still has it), `lost` (it is lost or
broken) or `hands` (it may be in someone else's hands). It shows the
statement that the phrase will sign and asks a yes; makes the next statement,
with the new machine as the only device; and carries every name that the
personal channel lists, from the relays' copies, in one look. Nothing is
taken from a device that may be in someone else's hands: what it wrote comes
in only by `cordelia sync carry <name> --from <device>`, with the phrase.

The command asks for the phrase first, since it reads at the relays with it,
and forgets it once it has signed. The look is made by the node, and the
command waits for it in a process that never held the phrase. A look that is
interrupted is not taken up again by itself.

Every other device stops when it hears, and each one that the person still
has is added again by hand, with the two commands. A relay is a cache, not a
backup: the phrase brings back what the relays hold, for 90 days after the
last device of the person's was on, and no longer.

## 4. Security model

**What relays, and Seed Drill as a relay operator, can see:** channel IDs,
and all of a person's change at once when a device is removed; the public
keys of the devices that connect and author entries; slots and revisions,
and so which entries are revisions of the same slot; which entries are
deletes; sizes by class, and timing; which connection proved which channel;
each pair of devices that meet when one is added; each time a recovery
phrase is used; and the ID of the phrase's channel, which stays the same for
a person for as long as the phrase does and which each of their devices
presents.

**What they cannot see:** content, file names, project names, the labels of
devices, the list of a person's devices, or any key. No relay holds a key in
any form.

**Who can read a person's memory:** the devices that hold the person secret,
and whoever holds the recovery phrase. Nobody else. Memory is never shared
between people: an agent reads its memory as its own notes, so another
person's text there would act with the agent's authority (decision record of
2026-09-30, §4.7).

**A removed device** keeps what it already had. It reads nothing that a
device which has applied the removal writes afterwards, and writes nothing
into the channels that follow the removal. A device that has not heard of the
removal still writes where the removed device can read, and still takes what
it writes (§3.6). A removed device can still read each later statement: who
the person's devices are, by key and label, and which of them made each
change. It cannot open the secret in it.

**The recovery phrase is one more thing to keep.** Whoever holds a copy of it
reads everything from then on, through every removal, with no sign. Without
it a device can be added, and none can ever be removed or recovered. It
cannot be replaced: the remedy for a phrase that has leaked, or is lost, is
to start again on every device, under a new one.

The threats Cordelia defends against, the ones it does not, and the tests
that prove each claim are in
[docs/security/threat-model.md](docs/security/threat-model.md). CI fails if a
claim loses its test.

**On a person's own machines**, memory is as protected as their disk: the agent's
memory files are plaintext, as they are without Cordelia, and the node's data
directory holds the device key, the person secret, and the local history of
what sync replaced, in the clear (files readable only by the user). Every
device of a person's can read every name of that person's, whether or not it
maps it, so a stolen disk yields every name. Another program that runs as the
same user, an agent with a shell among them, can run every command that asks
only a yes. What it cannot do is anything that asks for the recovery phrase.

| Threat | Mitigation |
|---|---|
| Relay compromise | Relays hold ciphertext only; no keys. Two signatures on every entry stop them forging or relabelling one. |
| Someone answers for a relay's name, or claims another node's key | A node's identity is the key its certificate carries. Devices know their relays by key and refuse any other. |
| Stranger writes to a channel, or fetches it | A relay stores an entry only if the channel's own key signed it, and hands a channel only to a connection that proved it holds that key. A device stores an entry only if its signer counts. |
| Stranger tries to take a device over | A device follows only a phrase that a person gave it, at a terminal. It reads what another device hands it only with a key that a person typed on it within the hour. |
| Lost or stolen device | `remove-device` on a device that remains, with the recovery phrase: one statement, a new secret for every channel at once. A device that has applied it writes nothing the removed device can read. One that has not heard still does, and `cordelia devices` shows which those are (§3.6). |
| No device left | `recover` on a new machine, with the phrase, brings back what the relays hold, and stops every other device until it is added again (§3.7). |
| A device of yours that has been taken over adds a device | Made visible, not prevented: every device shows the addition until a person clears it, and the next statement asks whether it stays. It cannot remove a device: that takes the phrase. |
| Two removals made apart, or an old statement shown again | A statement names every statement it was made after. One that is behind is ignored; two made apart stop every device that sees both until they are settled with the phrase. No statement brings a removed key back. |
| Malicious file names | Only plain names are written, only inside the memory folder. |
| Burst writes, floods | One size for every entry (64 KB), checked at every hop. Limits for a connection and for its address; a peer that keeps going over is cut off. A storage cap at relays that keeps what was there first. |

**Non-goals for v1.** Hiding that communication happens (traffic metadata is
visible to relays); protecting a device that is itself compromised; resisting a
network-level denial of service; a relay that is full, or whose limits for an
address are used up by something at that address; replacing a recovery
phrase; a passphrase on a device's own store; public channels, open
membership, or key escrow.

## 5. What v1 deliberately is not

v1 is small on purpose. It has no public or open channels and no service that
holds keys on anyone's behalf; no token and no economic layer; no semantic search
or memory "extraction" (the agent decides what to remember; Cordelia carries it);
no hosted plaintext of any kind.

## 6. Status and roadmap

**Status (October 2026):** v1 is built and tested, including end-to-end tests
with real processes over QUIC through a relay. Two relays are running, and
alpha pre-releases are published.

The design of a person's devices in this paper (the person secret, the
recovery phrase, statements, and channels from their secrets) is the one the
code has. A relay also carries the channels of the design before it, for one
version more, so that a device that has not been upgraded is not cut off.
The upgrade is a new start: each device takes the version, the phrase is
made on one, and each other is added again (decision record of 2026-10-04,
section 10).

**Not in this version:** replacing a recovery phrase; a passphrase that locks
a device's own store; adding a device by a code that the new device shows;
two of a person's devices meeting without a relay; the operating system's
keystore for the device's key and the person secret.

**Next:**

- **Channels shared between people,** carrying what is shared on purpose:
  messages between agents first, then secrets. They will not carry memory. An
  agent reads its memory as its own notes, so memory stays with one person and
  moves only between that person's devices (decision record §4.7). Skills that
  people share travel in a repository, where a change is reviewed, and not in
  a channel.
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
10. BIP-39, *Mnemonic code for generating deterministic keys*, 2013 (the word
    list of the recovery phrase).
11. RFC 8446, *The Transport Layer Security (TLS) Protocol Version 1.3*, 2018
    (§7.5, exporters: the value a proof is made over).

## Appendix: parameters

| Parameter | Value | Where |
|---|---|---|
| A device's pass at each relay | 10 s | `REALTIME_SYNC_INTERVAL_SECS` |
| A device sends what waits | every 2 s | `OUTBOX_FLUSH_INTERVAL_SECS` |
| Leave from a show | 10 s | `SHOW_LEAVE_SECS` |
| A device that wakes waits for its relays | 30 s | `WAKE_WAIT_SECS` |
| Relay limit per connection | 3,000 requests and 2 MB / min | `ENTRY_REQUESTS_PER_PEER_PER_MINUTE`, `PUSH_BYTES_PER_PEER_PER_MINUTE` |
| The same, for one address | 5 times a connection's | `MAX_CONNECTIONS_PER_IP` |
| Largest entry, as it travels | 64 KB of content and at most 1 KB more | `MAX_ITEM_BYTES`, `ENTRY_OVERHEAD_BYTES` |
| Largest synced memory file, with its name | 60 KB | `MAX_ENTRY_NAME_AND_VALUE_BYTES` |
| An entry's chain | 100 links | `MAX_ENTRY_LINKS` |
| A change entry | 32 KB, always | `CHANGE_ENTRY_BYTES` |
| One channel at a relay | 16 MB | `MAX_ENTRY_CHANNEL_BYTES_AT_RELAY` |
| A relay in total, for each kind of channel | 1 GiB unless its operator sets it | `max_storage_bytes` |
| New channels from one address | 256 an hour | `NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR` |
| A relay keeps a channel that nobody uses | 90 days | `ENTRY_CHANNEL_UNUSED_DAYS` |
| A relay, and a device, keep a delete | 90 days from when they stored it | `KEYED_TOMBSTONE_RETENTION_DAYS` |
| A device keeps the secret of a generation it left | 90 days | `LEFT_SECRET_KEPT_DAYS` |
| Devices a statement lists | 64 | `MAX_STATEMENT_DEVICES` |
| Statements one phrase makes, and keys it removes | 256 each | `MAX_STATEMENT_NUMBER`, `MAX_STATEMENT_REMOVED` |
| A key typed at `accept` opens for | 1 hour | `PAIR_KEY_TYPED_SECS` |
| Adapter cycle | 5 s | `cordelia-sync` `CYCLE_SECS` |
| Local history kept | 30 days, and the newest 256 MB | `HISTORY_DAYS`, `HISTORY_MAX_BYTES` (`[history]`) |

Protocol constants live in `crates/cordelia-core/src/protocol.rs`, with
their reasons in `docs/specs/parameter-rationale.md`; the adapter's live in
`crates/cordelia-sync`.

---

*Version 3.0 draft -- Seed Drill -- AGPL-3.0-only*
