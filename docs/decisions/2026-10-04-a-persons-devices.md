# Decision: a person's devices, and where a channel's secret comes from

**Date**: 2026-10-04
**Status**: Built. It replaces the device and membership model of `2026-09-30-agent-memory-sync.md` (its sections on devices, membership and keys), and that record's section 4.5 where this one says so.
**Cited as**: code comments cite the sections of this record ("decision 2026-10-04 §4.6"), and the numbered rules inside them ("§4.2, rule 3"; "§2.4, item 5"; "§7.1, step 1"; "§10.1, rule 6"). The numbers do not change.

Words used throughout:

- **The record of 2026-09-30** is [`2026-09-30-agent-memory-sync.md`](2026-09-30-agent-memory-sync.md).
- **The older kind** of channel is the kind that record describes: a random ID, a ring of keys, and a list of members.
- **This version** is the version of the node that first carries what is below, and **the version before** is the one it replaces.
- A is the device that makes a change, C a device that is removed, B and D other devices that remain and may be off or behind, R a new machine that has only the phrase.

---

## 0. What this is, in one page

In the record of 2026-09-30 each channel has a random ID and a ring of keys. A device is in a channel because another device sealed the keys to it. Removing a device changes each channel's key, one channel at a time, and each remaining device has to hear of each change. A removal is then as many changes as there are channels and devices, and each of them can be late, be lost or cross another (that record, section 9).

This record replaces that with four things.

1. **One secret for each person.** Every channel of your own is derived from it and the channel's name. A device is in your channels because it holds the secret. There is nothing to hand over for each channel, nothing to ask for, and nothing to wait for.
2. **A channel is its secret.** Its ID is a public key made from the secret, and every entry is signed with it. A relay can therefore check, with no key and no list, that an entry was written from inside its channel, and hands a channel only to a connection that proves it holds that key.
3. **Removing a device is one signed statement.** It names the devices that remain and commits to a new secret. Only the recovery phrase can sign it. It travels in one entry that only the phrase can write, with the new secret sealed to each device that remains: a device that receives it has all it needs, and takes it whole or not at all. The old channels are left behind, and each device carries into the new ones what it holds.
4. **A recovery phrase.** Twelve words, made by the node and shown once. It signs statements and recovers to a new machine. It is typed for those things only.

What it does not do: anything between people; adding a device with a code that the new device shows (section 6); the lock (section 11 fixes its derivation only); replacing the phrase (section 5); leaving behind what a removed device wrote, and a remaining device took, before that device heard of the removal (property 2).

## 1. The properties

Each is a promise to a person, and each has tests (section 13). Where a property has a limit, the limit is stated with it.

1. **A removed device reads nothing that a device which has applied the removal writes afterwards.** Not "nothing written afterwards": a device that has not heard still writes where the removed device can read, and it cannot be otherwise for a device that is off. What this design gives is that a removal is one moment for every channel, and that a person can see in one place which devices have not applied it. (What a removed device can still read is each later statement: it follows the phrase, and every device that ever did can read a statement made with it. Section 12.)
2. **A removed device writes nothing into the new channels.** Every entry there is signed by a device that the statement lists, or by one added since. What a removed device wrote is there only where a device of the person's carried it, and a device carries only what it held when it applied the removal: from then on it takes nothing that the removed device signed, from any channel, except by the one command that names that device and asks for the phrase (7.3, 7.5).
   - **What the removed device wrote before the removal is kept where a remaining device had taken it.** What only the relays held of it (its work in a name that no remaining device had synced since) stays behind, unless a person asks for it, with the phrase (7.3). Nothing can tell that work from what was written after the device was lost: the relays' copy is the removed device's to rewrite until a device of the person's fetches it.
   - **What it wrote between the removal and a device's hearing of it is kept too,** on a device that took it in that time, and carried from there. Two kinds of device can:
     - **one that reaches a relay which holds the change,** in the pass that is under way when the change arrives there. A device asks its relays every ten seconds, and shows its change entry before anything else (4.6);
     - **one that can reach only relays which the removal has not reached,** whether it was off or on, for as long as that lasts. A device cannot tell "nothing has changed" from "this relay has not been told". What narrows it: every device that has applied a change gives it to every relay it reaches, on every pass; relays that work together pass it on; the command that removes says, for each relay that device is set up with, whether it holds the change, and says that the machine may be closed only when all of them do (relays are set on each device: one that is set up with another relay is not covered by that, and `cordelia devices` shows whether it has applied); and a device that wakes asks every relay it is set up with before it takes or sends anything (4.6).
   - **What a removed device wrote late replaces no text without a copy on any other device, and nor does a version written over it.** Each version says which versions it descends from, by the hash of each text and the key that signed it (7.3). A device takes a version without keeping its own text only where its own text is among those, and every version newer than it in that chain was signed by a key that still counts. So where the removed device signed any version between a folder's text and the version it takes, the folder keeps its text beside the file first. (For the index, where the plan merges two indexes, it merges them.) On the device that took a late version before it heard, what that replaced is in its local history.
   - **The record of 2026-09-30 is stricter for a late edit and a late delete.** Section 14 sets the two side by side.
   - Each device's local history shows what it took from which device, and when, with the text it replaced, and puts a version back (the record of 2026-09-30, 4.5b). This design rests on local history. Local history is a way back for a person who looks: it is bounded, and it does not defend against a device of the person's that has been taken over.
3. **A removal is whole or not at all, on each device.** A device applies it in one step, for every channel, when it receives the change entry: the statement, the secret, and its own carry (4.2). After it the device reads and writes none of the old channels, except in a carry that a person asks for (7.5).
4. **A removal can always be made, sent and seen.** Nothing a removed device or a stranger can write stops it being made, or makes a device show it as done when it is not. It travels in the phrase's channel: only the phrase writes there, its one entry is always the same size, and it is the channel of the person's that each relay has held longest, so a relay that makes room drops it after everything else of the person's (2.5). A relay with no room for a new channel delays the memory that follows, not the removal. What can still delay a device's hearing is said in 2.5 and 4.6: a relay that has lost the phrase's channel and has no room to take it again; a device at the same address using up the address's limits; and a device whose only relays no device with the change has reached.
5. **Only the phrase changes who is removed,** and nothing undoes a removal. No device can remove another without it, and no statement, however made, brings a removed key back. Two changes made apart are seen as that by every device that sees a statement of the other branch, however many changes each side has made (4.2, 4.5). **The limit** is a recovery made from a state before a removal, where the relays have lost the later statement: it knows nothing of the removal, carries what the removed device wrote since, and leaves its key in no list, until the two are settled (section 9).
6. **The phrase alone brings back what the relays hold** on a new machine, with what every device wrote that the person does not say may be in someone else's hands, and cuts off from reading every device the person does not add again. A device that the person still has is added again by hand, and until then is no device: what it holds is carried when it is. A recovery that is cut short is taken up by the next one for what the first had sent. What a device that is gone wrote in the files that the first had not sent comes in by the command that names that device and asks for the phrase (section 9).
7. **A relay stores and hands over only what belongs to a channel,** with no key of its own: an entry that the channel's key signed, to a connection that proved it holds that key. **Two exceptions.** Whoever shows a relay an entry is answered with the entry the relay holds from the same author in the same place, if it is another one: that is how a change travels (2.4). And relays that their operator lists together pass entries between them without the proof (2.4). (For the one version in which a relay also carries the older kind of channel, that kind is stored and handed over as before: section 10.)
8. **A move judges one thing, and waits for nobody.** Versions keep their text, their chain and their order: their revisions too, but for one renumbering that every device makes alike and that keeps the order of every two (2.3). So each file is on each device as it would have been had the devices that have applied a change, and those that have not, simply been out of touch for that time: an edit that had won before wins after, an edit that would have been kept beside a file is kept, and an edit not yet published is published as an edit of the version it was made over. The one thing judged is a key that no longer counts: where such a key signed a version anywhere in a chain between a folder's text and the version it takes, the folder keeps its text (7.3). That can only keep more: copies beside files that were not needed (7.4 says where). Every device carries what it holds, so nothing that any remaining device held is left behind, whichever device is lost on the way.
9. **The upgrade is a new start.** Each device takes this version, starts alone from its memory folders, and is added again with the two commands. Section 10 says what that loses.
10. **A device follows only a phrase that a person gave it:** by making it there; by typing the phrase itself there, to recover; or by accepting there, at a terminal and with a yes, a device that follows it. Nothing a device is sent makes it follow another. **The limit:** each of those acts can be done by a program that runs as the person, an agent with a shell among them (section 5).

## 2. The channel

### 2.1 From a secret

A channel is a secret of 32 bytes. Everything about the channel is derived from it with HKDF-SHA256, each thing under its own label:

| What | Label | Use |
|---|---|---|
| The entry key | `cordelia v2 entry` | AES-256-GCM, for an entry's content |
| The slot key | `cordelia v2 slot` | HMAC-SHA256 of an entry's name gives its slot, so a relay sees no names |
| The channel's signing key | `cordelia v2 sign` | An Ed25519 key pair. Its public half is the channel's ID |

The ID is written `cordelia_ch1...`, as a device's key is `cordelia_pk1...`.

### 2.2 The kinds of channel, and where each secret comes from

Each kind has a label of its own, and no label begins another, so that no two kinds can ever derive the same secret. A name is in its one spelling (the record of 2026-09-30, 4.5) and is prefixed with its length as two bytes.

| Kind | Secret | Who can derive it |
|---|---|---|
| **Personal** | HKDF(person secret, `cordelia v2 personal`) | Every device of the person |
| **Own, by name** (memory) | HKDF(person secret, `cordelia v2 own` + length + name) | Every device of the person, for every name |
| **Pair** | HKDF(X25519(device a, device b), `cordelia v2 pair` + the two public keys, the lower first) | Those two devices |
| **The phrase's** | HKDF(phrase, `cordelia v2 recovery`) | Whoever has the phrase |
| **Locked** | Section 11 | Devices where the lock is open |
| **Shared between people** (not in this version) | Random | Whoever was handed it |

- **The personal channel** holds what the person's devices tell each other: the names that exist and what each device syncs (`name/<the name>`), the devices added since the last statement (`added/`), which statement each device has applied (`applied/<its key>`, section 8), and a device's word that it has left (`left/<its key>`, 5.2). It replaces the personal channel of the record of 2026-09-30, with its map from name to channel, its join requests and its lists of what each device syncs (that record, 4.5).
- **A pair channel** is where two devices that know each other's keys can meet, and where nobody else can write. It replaces the inbox, and it is used for one thing: handing a device what it needs when it is added (section 6).
  - A device takes one thing from it, written by the other device's key: the entry under the name `hand-over`. Nothing else there is read.
  - **A hand-over says when it was made, inside itself, and its entry's revision is that time or one above the adder's last:** a pair channel is one channel for as long as both keys exist, whatever phrase either device follows, and a statement's number starts again under each phrase. So a newer hand-over always takes the place of an older one, at a relay and on a device. A device takes a hand-over only where the time it says is within the hour before or after the key was typed there (two devices' clocks more than an hour apart cannot be added to each other, and the command says so).
  - **A device reads a pair channel only with a key that a person typed on it in the last hour** (`cordelia accept`, section 6), and writes one only for a key that a person typed on it (`cordelia add-device`). Outside that hour nothing there is read, so nothing that a removed device goes on writing in its pair channels is.
  - Both keys must be usable (not a point of small order), and a shared secret that is all zeros is refused, as sealing to a key refuses them.
  - It is one secret for each pair, for as long as both keys exist.
- **The phrase's channel** holds one entry, the change entry (4.6, section 9), under the name `change`, signed by the phrase's key. Only the phrase can make one, and nothing else can be written there: every entry of the channel is signed with keys that come from the phrase. No device can fetch the channel, since none can prove its key. A device shows a relay the copy it keeps, and a relay that holds another answers with it (2.4).

### 2.3 An entry

In clear, so that every hop can check it:

- the channel's ID, the slot, the author's key, the revision, and whether it is a delete;
- the content: a nonce and the ciphertext, padded so that its length is a power of two from 256 bytes up to 64 KB, which is the most an entry's content may be (`MAX_ITEM_BYTES`);
- two signatures over one thing (the channel's ID, the slot, the author, the revision, whether it is a delete, and the hash of the content), each under a label of its own: the author's, and the channel's.

**A revision is a band and a count.** The band is the top nine bits and the count the 44 below them, so a revision is still one number, compared as one, and editing still adds one. A band is 0, where ordinary editing begins, or a statement's number, 1 to 256. Revision 0 is no entry's.

- **Which revisions an entry may have.** Under statement n a device takes an entry, in a channel of that generation, only where its revision is in band n, or in the bottom half of a lower band: any other is no version. (A device does not store an entry in a band above n. It stores one in the top half of a lower band, since that counts for the next revision, and reads it as no version.)
- **The next revision is one above the highest that counts for it.** Where that is in the top half of a band below n, it is moved as a move would move it (below), so that devices under two statements give an edit of one version one revision. Where it would be in a band above n, there is none until the next statement. (Under statement 256 there is no next one: a name put out of reach then stays so, and the way on is a new phrase, 4.1.)
- Outside a generation's channels a revision is a plain number.
- Editing does not reach the top half of a band by itself (it is 2^43 edits away): a revision is up there because a device jumped, or because devices edited on above a jump. At the top of band n a name is out of reach, since nothing can be written above it.

**At a move, a revision in the top half of a band goes to the same place in the bottom half of the next band.** So does the revision in a folder's record of it. (A chain holds no revisions, and is not touched.)

- It is one rule, a function of the number alone, the same on every device and at every carry, whatever the device holds and however many statements it was behind. Where it lands, nothing was written before the statement that moves it: the next band is not taken until then. **So it keeps the order of every two revisions that a device holds, and two devices give one version one revision,** and everything that compares revisions gives the answer it gave before: which version is current, what ties, what a version names. A device that was two statements behind moves what it holds once, to where the others moved it.
- A name that a device had put out of reach is 2^43 edits from the top again, and stays out of reach only until the next statement, whichever it is.
- It is one renumbering, the same on every device, and not a carry at another revision: so property 8 has no exception.

**An entry is named by the hash of what is signed.** There is no random ID on the wire. Where a device asks a relay for an entry, that hash is the name. An author can sign two entries at one revision, and they have two names. **Where the adapter publishes only over the entry it planned against** (the record of 2026-09-30, 4.5), **it is the version that is compared:** the text or delete, and the revision. Two entries that are one version (below) are one for that check, whichever of them a device holds.

**Inside the ciphertext,** in a binary form: the entry's name, its text, and **what it was written after: its chain** (7.3). For each version it descends from, newest first, at most 100 links: the first 16 bytes of the hash of that version's text, and the first 16 bytes of the key that signed it. Nothing else. This replaces what an entry says under the record of 2026-09-30 (4.5, "An entry says what it was written after"): devices with their revisions, the hash of the one text it was published over, and a revision below which older entries are left to their revision. None of the three is in an entry.

The encryption binds the content to the channel, the slot and the revision. **Room for what an entry says is kept in every entry:** a text and its name may together be 60 KB (`MAX_ENTRY_NAME_AND_VALUE_BYTES`), and the rest of the 64 KB is for a chain at its longest. So what an entry says always fits, whatever its text: no link is left out for room, and no entry says less in order to fit.

- **Every entry that a node writes says it,** one written through the local API included: the node says what such an entry was published over, as it does for the adapter's.
- **An entry that is no version:** one whose content is larger than that, one that does not open, one that opens and is not an entry's content, and one whose revision is in no band it may be in. A device passes it over when it reads a slot, never takes it into a folder, and carries nothing of it. It still counts where a device works out its next revision, while its signer counts, so a device's next edit is above it: all but an entry in a band above the statement's, which counts for nothing.
- **An entry that lacks what it should say** shows nothing, and is known to follow nothing.

**Against the entry of the record of 2026-09-30:**

| That record | This one |
|---|---|
| A random key for each channel, with a version, and a ring of earlier ones | One key, derived. No version: the field goes |
| A random slot key for each channel, never changed, which a removed device keeps | Derived from the channel's secret, so it changes with it |
| One signature, the author's | Two: the author's and the channel's |
| The type and the parent in clear | Gone from the wire. The kind of an entry is the first part of its name, inside the ciphertext |
| Whether an entry is a delete, in clear and signed | Stays: a relay's sweep of old deletes needs it, and it says only that an entry is a delete |
| No expiry | None |
| A tie at one revision goes to the higher hash of the ciphertext | To the higher hash of the text, and a text beats a delete. **Two entries with one text at one revision are the same version, whoever signed them.** A ciphertext's hash changes whenever an entry is sealed again, and a text's does not: so a tie is not drawn afresh when an entry is carried |
| A revision may be any number up to the bound, and one at the top puts a name out of reach | A band and a count. A revision in the top half of a band is moved to the next band at each move, by a rule that every device applies alike, so a name comes back into reach at the next statement |
| What an entry says can be left out for room, down to nothing | Room is kept for it in every entry, and a text may be 60 KB |

The other limits of that record stand: the clear fields and the signatures are within the 1 KB that every entry is counted with (`ENTRY_OVERHEAD_BYTES`), a store keeps one entry for each author in each slot, and no rule at a relay compares one author's entries with another's.

**The author is who signed.** A version that a device carries into a new channel is that device's entry there, and its chain says which key signed the entry it was carried from (7.3).

**Whose word is read.** The entries of keys that count (4.4). A chain is the word of the key that signed the entry it is in, and 7.3 says why the word of a key that no longer counts decides nothing in one.

**Two entries that are one version** (one text, or a delete, at one revision, whoever signed them) can differ in what they say: two devices made the same edit apart. (Two devices that carried one version made two entries that say the same.)

- **A version of which a device holds several entries is known to follow what a folder agreed only if each of them shows it** (7.3).
- **A device that writes over such a version, or carries it, does so from one of its entries:** its own if it holds one, else the one whose signer has the lowest key. That entry's signer and that entry's chain are what it uses. (One entry's chain is never put behind another entry's signer.)
- A folder's record of a version keeps the signer and the chain of that one entry.

### 2.4 What a relay does

1. **It stores an entry only if** both signatures hold and it is within the limits. It needs nothing else: no list of members, no state of the channel.
2. **It keeps the newest revision for each author in each slot.** A newer revision of an entry it holds, that is no larger, is never refused for room. An entry at the revision of one it holds, from the same author in the same slot, is not stored.
3. **It hands a channel's entries only to a connection that has proved it holds the channel's key.** The proof is a signature by the channel's signing key, under a label of its own (`cordelia v2 proof`), over a value that both ends export from this one TLS session, the node key of the end that makes the proof, and the channel's ID. (Both ends export the same value: without the prover's key in it, a proof sent back to the end that made it would hold there.) The relay checks the signature before it looks the channel up. A proof cannot be replayed on another connection or later, and it needs no clock.
4. **It tells nobody which channels it holds,** the relays it works with aside (item 6). A channel it does not have and a proof that fails are answered alike.
5. **Shown an entry, it answers with the one it holds.** A connection that shows a relay an entry (the whole entry, since the relay may take it; the relay checks its two signatures) is told one of three things: the relay holds that entry; the relay holds none from that author in that slot, or an earlier one, and takes this one; or the relay holds another entry from that author in that slot, at that revision or a later one, and here it is. Only a holder of an entry can ask, what comes back is signed like any entry, and it counts against the asker's limits like anything fetched. This is how a change reaches a device (4.6), and it is the one thing a relay hands to a connection that has proved no key (property 7).
   - **After the first time on a connection, a show can be short.** A relay remembers, for a connection, the last entry that it was shown whole there in each author's slot, where the two signatures held, whatever it answered (at most 8 slots: a ninth is not remembered, and all are forgotten when the connection closes). The connection may then show that same entry by its channel, slot, author, revision and ID alone.
   - **A short show of anything else,** a slot that the relay does not remember included, is answered "show it whole" without a look at what the relay holds. So the short form tells nothing, and hands nothing, to anyone who has not shown that very entry whole.
   - **Where the short show is of the entry remembered,** the relay looks, and answers one of three things: it holds that entry (a use of the channel, as with the whole one, 2.5); it holds none, or an earlier one, "show it whole"; or it holds another at that revision or a later one, and it says that one's revision and ID and no more. A device that is told of another which it does not keep shows its own whole, and is answered with the entry.
   - **Why.** The entry of the phrase's channel is 32 KB and a device shows it on every pass (4.6). Whole each time, that is some 280 MB a day from each idle device to each relay, and a tenth of what a connection may push in a minute. A short show is only ever of the entry shown whole, and its answer is short, because a short show of a revision that the connection had never shown whole would be handed an entry that the whole form would not hand, and a device in a fork would be handed 32 KB on every pass.
6. **Relays that work together are listed by key** by their operator, and pass entries between them without the proof, with how long each has held a channel, and with when it was last used. (A relay that has a channel only from a relay it works with sees no proof and no show of it, and would otherwise drop it every 90 days and take it again.) A relay counts a channel as held from the earlier of two times, when it took it itself and when a relay it works with says that it took it, also for a channel it already holds (2.5). Only a relay that the operator lists can say so.
7. **There is no inbox.** One rule for everything a relay stores.

A device checks the same things on what a relay sends it, and further that the author counts (4.4).

**What a relay still learns:** channel IDs (all of a person's change at once at a removal), authors' keys, slots, revisions, which entries are deletes, sizes by class, timing, which connection proved which channel, each pair of devices that meet in a pair channel, each time a phrase is used, and, in the ID of the phrase's channel, one thing that stays the same for a person for as long as the phrase does and that each of their devices presents.

### 2.5 A relay's room, when every channel is new

A relay favours the channels it has held longest: where a new channel's first entry would take it past its cap it takes none of it, a write that would take it past its cap is refused and drops nothing, a relay whose cap has come down drops the newest first, and one address may add only so many channels an hour. After a removal, and at the upgrade, every channel of the person's own is new, and the generation in use is always the newest.

- **The removal itself needs no new channel and no new room** (4.6, 7.2). The change entry replaces the one before it, at the same size, in a channel the relay already holds. `cordelia devices` shows, for each relay, whether it holds the latest.
- **The phrase's channel is the channel of a person's that a relay has held longest.** Nothing is published before there is a phrase (5.2), `cordelia phrase` writes the change entry before anything else, and a device shows a relay its change entry before it does anything else there (4.6). A relay that takes a person's channels from a relay it works with takes with them how long that relay has held each (2.4). So a relay that makes room drops every other channel of the person's first.
  - **The limit:** a relay that has dropped the phrase's channel and takes it again counts it as new from then.
- **What follows a removal does need room.** The new personal channel and each name's new channel count against the address's allowance. **The allowance for channels of this kind is 256 an hour** (`NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR`). At 16 an hour, which is the allowance of the older kind, a person with thirty names would wait two hours for the last of them, and a home with three devices shares one address. **A pair channel is a new channel too** (section 6): a device is added through a relay only where that relay has room for one.
- **The order for making room is the newest first.** A relay does not drop "the longest unproved first", because proving costs nothing and tenure cannot be faked: a stranger who keeps a connection open would push out every person whose devices are closed.
- **While a relay carries both kinds of channel** (section 10: one version), **each kind is counted against a cap of its own, and has an allowance of its own:** the older kind keeps the cap that the relay has, and the new kind has one of the same size. Neither is refused or dropped to make room for the other. For that one version a relay can hold twice its cap.
  - **Why.** A channel of the older kind takes whatever any key signs. Under one cap, whoever filled the older channels would push out every upgraded person's new ones, the phrase's channel with them. With room made for the new kind from the older kind first, whoever made new channels, which anyone can, would push out every person who had not yet upgraded.
- **What nobody uses goes after 90 days:** a channel whose key no connection has proved, and of which no device has shown an entry the relay holds, for 90 days is dropped. The phrase's channel, which no device can prove, lives for as long as any device shows its copy of the entry (section 9). **Each device proves, once a day, the channel of every name that its personal channel lists,** whether or not it syncs the name: a name whose only device is gone is not dropped while any device of the person's is on. (A relay remembers the proofs of 1,024 channels for one connection, and looks at none beyond them: a person with more names than that is past what this keeps alive.)
- **What is not defended:**
  - A relay that is full takes no new channel: the removal is heard, the removed device is cut off, and memory does not sync through that relay until it has room.
  - Whoever holds the keys of older channels can fill them to their caps, and can keep them: a removed device holds every channel of the generation it was in. **It can go on proving them, so they are never "what nobody uses",** and their room is not given back until an operator acts. A relay that is then full takes none of the new generation. **And a relay that is over its cap drops its newest channels, whoever wrote in the old ones:** a removed device that grows the old channels at such a relay pushes out the new generation.
  - The allowance, the limit on connections and the limit on bytes are all by address. A removed device that is still at the same address as the others, or a stranger behind it, can use each up, and the change and the new channels then wait at that relay.
  - A relay that the removed device does not know is the way round each: it knows every relay the person had set up, so a second relay helps only if it is a new one.
- **Not in this version: a channel that succeeds another,** taking the old one's standing at the relay. Nothing depends on it (section 14).

## 3. The person secret

- **32 random bytes, with a number** that starts at 1 and goes no higher than 256 in this format (4.1). Number n is written S(n), and the channels derived from it are generation n.
- **It is never derived from the phrase.** If it were, a stolen device could not be cut off.
- **It is made with the phrase, and not before** (5.2): a device that follows no phrase has no secret, and publishes nothing.
- **It changes only by a statement** (section 4), which only the phrase can sign.
- **A device holds the one it has applied, and each one it left in the last 90 days** by its own clock: the secret, and nothing else of that generation. They are for a carry that a person asks for (7.3), which fetches from the relays, and for the part of the change entry that is for the phrase (section 9). After its 90 days a secret is forgotten.
- **It is kept in the node's database,** which is readable by its owner alone, so that it changes in one transaction with the statement. (Kept in a file beside the database, as the device's own key is, it would be written in a second step.) The move to the operating system's keystore is a later step (section 14).

## 4. The statement

### 4.1 What it says

One statement for each change of the person secret. In a canonical binary form:

- its **number**;
- its **maker:** the key of the device it was made on;
- **its chain:** the number and the hash of every statement it was made after, back to the first. That is the latest statement its maker had applied, with that statement's own chain. A settlement has the chains of each statement it settles, and those statements (4.5). A hash here is its first 16 bytes: only the phrase signs a statement, so nothing is gained by forging one of these;
- a **commitment to the new secret:** a hash of it, under a label of its own. It is not the ID of the personal channel derived from the secret: every device that ever followed the phrase reads a statement, and need not learn that ID;
- the **devices** that hold it: for each, its public key and the label the person knows it by, as shown at the prompt;
- the keys **removed** so far by the person's word, all of them, and none of them among the devices;
- the **phrase's signing key;**
- a field that is empty in this format, and that a device refuses when it is not (section 5).

It is signed by the phrase's key, under a label of its own.

**Two lists.** A key that is in neither is no device under the statement: a device that the maker did not know of, or one that a recovery or a settlement did not list. It stops, says so, and is added again by a person or not at all (4.3). What it wrote is carried by the devices that hold it (7.3). There is no third list, of keys left out whose word is still believed: nothing needs it, and nothing rests on a device's word across a move.

**A statement has no kind.** What it does is in its lists and its chain: the first has no chain; a settlement's chain holds two branches; a recovery lists one device.

**A renewal removes nobody.** It lists the devices, with those added since (section 6), and commits to a new secret. `cordelia renew` makes one, with the phrase: for a person who wants the devices added since the last change to be in a list they have looked at.

**Bounds:**

- at most 64 devices;
- at most 256 removed keys, and a statement that would list more is refused. **That bound can be used up:** every device that a person declines at a prompt is a removed key, and a device that counts can sign 63 records at a time. A phrase with no room left removes nobody more, and the way on is a new phrase (section 5); a later format lifts the bound;
- a number no higher than 256 and a chain of at most 256 statements (a settlement's chain holds two branches), likewise: **so a phrase makes at most 256 statements in this format,** and each command that makes one says how many are left once fewer than 16 are;
- a label is 1 to 64 bytes of printable ASCII, with no space at either end: it is what a person calls a device, and is kept as it was typed.

At every bound together the statement is about 21 KB, and the change entry that carries it (4.6) about 27 KB, which fits its 32 KB.

### 4.2 When a device applies one

A device applies a statement only if all of these hold:

1. **The signature** is by the key the device follows (property 10).
2. **The number** is above the number of the statement it has applied.
3. **It is in it:** its own key is among the devices; or, for a device that is being added, a record of its addition comes with it (section 6).
4. **It has the secret, and the secret opens to the commitment:** its hash, under the commitment's label, is the one the statement gives.
5. **No removal is undone:** every key that the applied statement lists as removed is listed as removed in this one, and no key is in both of this one's lists.
6. **It was made after the one the device has applied:** that statement, by its number and its hash, is on this one's chain. (A statement made apart from what this device applied is a fork, 4.5, even where it removes everything the applied one removed: what the applied one decided besides, which devices stay, would otherwise be dropped in silence.)

Rules 2, 5 and 6 are asked against the statement the device has applied under the phrase it follows now. A device that takes another phrase by a person's act (5.1) starts afresh under it.

It applies it in one transaction:

- the statement and the secret are stored, and the device leaves the generation it was in;
- each folder's records, which are kept by channel, are moved to the name's new channel, with its records of index lines (the record of 2026-09-30, 4.5), and each revision in them is renumbered as 2.3 says. Local history is left as it is: a record there names the revision that an entry had when the text was kept;
- **it carries:** what it wrote itself in the personal channel, and every current version it holds in each name it holds (the names it syncs, and any that a carry by command or a recovery brought in), is written into the new generation's channel in its own store, as 7.3 says, and waits there to be sent. (A device fetches every name it holds, as it fetches those it syncs: what it carries of a name it does not sync is as current as a syncing device's would be.) What it holds of the generation it left is then dropped from its store.

Nothing else changes in that step: its folders, and what they had agreed, stay as they are. The transaction waits for a sync cycle that is running to stop, and counts as a change of settings: no file is written, and nothing is published, in an old channel after it; what waits in the outbox for an old channel is dropped; and the adapter's notes of the copies it has kept beside files are cleared, as at any change of settings.

**From the moment a device is answered with a change that it can apply, it sends nothing in an old channel, on any connection.** The transaction may wait for a cycle to stop, and nothing goes out meanwhile.

**Where the transaction fails** (the disk is full, the database cannot be written), nothing is changed, and the device has been answered with a change that it has not applied. It goes on sending nothing and taking nothing in a channel of its own, says why in its status, and tries again at each pass.

**Where one version cannot be carried,** the change is applied all the same. That is a file's record in whose slot the device's store holds no version at all: what was there no longer opens. (Where the store holds a newer entry than the record's, one that arrived and that no cycle has taken yet, that entry is carried and the record stays: the next cycle takes the version by the chain's rule.) Nothing can fail for room: what an entry says always fits (2.3). The record is dropped, so that the file meets the new channel as a new file does: it is published as this device's own, or, where the channel has a version of that name, is kept beside it. The log and `cordelia devices` say which files.

A statement stands by itself. A device that was off for two changes applies the second without having seen the first: its own statement is on the second's chain, and the rules above are enough. **A device applies the latest statement it is shown,** and a relay holds only the latest (4.6): it never passes through the ones between.

### 4.3 A statement that does not list this device

A device that sees a statement which passes rules 1, 2, 5 and 6, and is not among its devices, is no longer one of the person's. It stops syncing every channel of its own, publishes nothing more, and says so in its status:

- "this device was removed", where the statement lists its key as removed;
- "this device is not in a change made on <label>: if it is yours, add it again from a device that is", otherwise: a recovery or a settlement did not list it (section 9, 4.5), or the device that made the change did not know of it.

It reads the statement where every device does (4.6). That is a courtesy to a person who removed the wrong one, not a control: a stolen device does not have to listen.

Such a device makes no statement: `cordelia remove-device`, `cordelia renew` and `cordelia settle` refuse on it. Nor does it take a later statement by being shown one, even one that would list it: the way on is a person's (5.1).

**A device that was removed by mistake** cannot come back under its key. `cordelia init --new-key` gives it a new one, keeps its memory folders, and forgets what they had agreed. It is then added as a new device (section 6), and its folders meet the channels as on any first sync. **A device that is in no list** can be added again under its key, by the two commands and their yes (section 6).

### 4.4 Who counts

In a channel of the person's own, a device stores and counts an entry only if its signer is, as that device knows them, among the devices of the statement it has applied, or added since under that statement (section 6). "A device that counts", in this record, is that.

### 4.5 Two changes made apart

A device looks at each statement it is shown that the phrase signed (rule 1), beside the one it has applied.

- **It can be applied** (rules 2, 3, 5 and 6): the device applies it at once. The secret is with it, sealed to this device (4.6). There is no state in between.
- **It is the phrase's, it lists this device, and the secret that comes with it does not open, is short, or is not there:** the device stops, as one in a fork does, and says "a change made on <label> could not be opened here: add this device again from a device that has it". That is a fault in how the change was made, and the way on is a person's: `cordelia accept` takes such a device as it takes one that is in no list (5.1).
- **It is behind:** it is the one the device has applied, or its number is lower and it is on that one's chain. Nothing is done with it. (The relay that showed it takes the later one from this device, 4.6.)
- **It is not well formed** (a bound of 4.1 is passed, or a key is in both lists), **or it was made after the applied one and lacks a removal that the applied one has:** it is refused, as a statement under another phrase is. It is no fork: nothing could settle it, since the two were not made apart.
- **Anything else is a fork:** a statement that is not on the applied one's chain and does not have the applied one on its own. It happens when two devices each make a statement before they have met, or when a recovery was made from an old state.

A device in a fork neither publishes in its own channels nor takes from them, and says so on its status line and in `cordelia devices`: "two changes were made apart: settle it with the phrase (`cordelia settle`)", with both lists, which it can read. It keeps both change entries, goes on showing each relay the one it had applied, and asks again for neither. `cordelia add-device` refuses on a device that is in a fork.

**Which devices see a fork.** A relay holds one statement's entry, the latest it was given (4.6). Where one branch is longer, the relays come to hold its last statement, and the devices of the shorter branch are shown it and see the fork. The devices of the longer branch may never be shown the other, and go on. It is settled from a device that has seen both, and every device applies the settlement.

**It is settled** by `cordelia settle`, with the phrase, on a device that has seen both.

- It makes a statement numbered above both, whose chain holds both and their chains, so that a device on either branch can apply it.
- Its removed keys are every key that either removed: a settlement undoes nothing.
- Its devices are chosen by the person at the prompt from those of both, less the removed; of each other device of either, the person says whether it is removed. One that is neither kept nor removed is in no list, and is added again by hand: the prompt has those three answers for each, and says so.
- A device that was added under the other branch since its statement is not known to this device, and is in no list.
- The part of the settlement's entry that is for the phrase holds the secrets of both branches: the command opens that part of each of the two change entries that the device holds.
- A device that had applied either one applies the settlement like any statement, and carries what it holds (section 7): so what was written under both comes together in the new channels, by revision, as two devices' edits made apart do.

**A statement is numbered one above the highest on its chain,** starts its lists from the statement its maker has applied, and lists as removed every key that any statement on its chain removes.

Until it has seen both, a device goes on under the one it has. That is the limit of property 1 again: it has not seen the other removal.

### 4.6 How a statement reaches a device

**One way: the change entry.** Each statement is published as one entry in the phrase's channel (2.2). Its author is the phrase's key, its revision is the statement's number, and it is always written at one size, 32 KB. Only the command that was given the phrase can make it. It has two parts:

- **For the devices:** the statement, and, for each device the statement lists and in that order, the new secret sealed to that device's key. This part is under the **statement key**: a key derived from the phrase under a label of its own, which every device that follows the phrase is given when it comes to follow it, and which never changes. So every device that follows the phrase, however far behind, can read the statement; only a device it lists can open the secret; and a relay can read neither.
- **For the phrase:** sealed under a key that only the phrase gives: the new secret; and the secrets of the generations before it, as many as eight, the newest first, each with its statement's number (section 9).

**How it travels.**

- **Every device keeps the latest change entry it has seen,** and shows it to each relay on every pass (2.4, item 5). A relay that holds the same one says so. A relay that holds none, or an earlier one, takes it: so a change reaches every relay that any device with it reaches, and not only those its maker reached. A relay that holds another at that number, or a later one, answers with the one it holds.
- **A device that is answered with another entry** checks both signatures, opens the first part, and treats the statement as 4.5 says: it applies it, in the same step, or it is in a fork, or it was removed or is in no list (4.3). It keeps the entry and shows that one from then on, unless it is in a fork, where it keeps both, and does not ask a relay again for one it has.
- **Relays that work together pass it on,** as any entry.

**A show comes before everything, and it is a rule of the connection.** On a connection to a relay, until the device has shown its change entry there and applied what it was answered with, it sends nothing in a channel of its own, answers no request of the relay's for one, and takes nothing that the relay pushes. That covers what the node sends on its own timer, at each publish and from its queue of things to send again; what it announces of its channels; and what it serves when a relay asks it for entries, as a relay does of a device that has just connected. The rule names each of them because a node does each by itself: it sends what waits every two seconds, fetches every ten, announces its channels at each connection, and serves a relay that asks. In a pass that is long (a device that is catching up) the show is made again before each channel.

**It is kept as a rule of time, called leave.**

- **A device has leave on a connection for 10 seconds from an answer there which says that the relay holds no later change than the one the device keeps:** that it holds the entry shown; that it took it; or that it holds none or an earlier one and would have taken this one, and did not, for room or for the address's allowance (the refusal is kept for the status).
- **No other answer gives leave:** not another entry, or word of one (the device deals with it as above, and shows again what it then keeps); not "show it whole" (it shows it whole); not a stream that is reset or that times out.
- **A device in a fork has no leave anywhere, and nor has one that has stopped** (4.3).
- **Leave ends at once, at every relay, when the entry that the device keeps changes.**
- **It is asked when a stream for a channel of the device's own is opened, and again before anything that came back on that stream is taken:** what arrives after the leave has run out is dropped, and asked for again.
- **Whatever finds no leave shows again by itself** (the pass, the timer that sends, a publish), so that a lost answer costs one short show and not a pass.
- The first show on a connection is of the whole entry, and the later ones are short (2.4, item 5); a short show that is not answered is followed by a whole one.

**One channel is read without leave: the pair channel of a key typed at `accept`,** for the hour that `accept` allows (5.1, section 6). A device that follows no phrase has nothing to show, and one that has stopped has no leave, and each has to be handed a change. It proves that channel and pulls it, and writes nothing there; what it takes is a hand-over, judged by the state the device is in (5.1), and nothing else is taken from it.

So a laptop that was closed over a removal sends none of its waiting edits to an old channel, and takes nothing that the removed device wrote there meanwhile, **where a relay it reaches holds the change.**

- **In this version the channels of this record travel between a device and a relay, and between relays that work together, and nowhere else.** A personal node answers none of the relay's streams, and a connection between two personal nodes carries nothing of these channels: a relay's rules count and drop what a store holds as the relay's own, and a device's store is its own. (Meeting directly, under the rule of the show, is a later step: section 14.)
- A relay that asks a device for its entries before the show is answered with nothing, and asks again, as it asks again any device that answers nothing.
- What a device serves to a relay that asks is everything it holds of the channel, what it carried included. The rule that holds a carried entry back where the relay already has that version (7.3) is for what the device sends by itself.

**A device that wakes asks every relay first.** When the node starts, or reaches a relay after having reached none, it neither takes from a channel of its own nor sends to one until each relay it is set up with has answered about the change entry, or 30 seconds have gone since the first of them was reached.

- It is one wait, for all of them together: a relay that is reached later holds nothing up, and is shown the entry before it is used, like any connection.
- **Why.** Connections come up one at a time. Without this, a device that woke would take what the first relay held, and send it what waited, before the second, which had the change, had answered.
- A relay that was not reached is named in its status: "has not heard from <relay> since it woke: a change made while it was off may not have reached it".
- **The cost:** with one relay out of reach, a device that starts, or comes back online, waits 30 seconds before it syncs.

**What can still keep a change from a device:**

- **every relay it reaches lacks it.** No device with the change has reached those relays, and no relay that has it passes it to them. The command that makes a change shows, for each relay the person is set up with, whether it holds it (7.1), and `cordelia devices` shows the same on every device;
- **a relay has lost the phrase's channel** and has no room to take it again (2.5);
- **it is at the same address as a removed device,** which can use up the address's limits at a relay (2.5): three breaches of a limit refuse the whole address there for fifteen minutes, and it can go on.

`cordelia devices` shows, on a device that has applied a change, which devices have applied it. A person who sees one that has not, and has it in hand, can add it again (section 6), which hands it the change directly.

**What a removed device learns by this.** It keeps the statement key and its last change entry. By showing that entry to a relay it is answered with each later one, and can read the statement in it: who the person's devices are, by key and label, which of them made the change, and that the phrase was used. It cannot open the secret, and the statement commits to the secret by a hash, so it does not learn the ID of the new personal channel either. Section 12 counts this as a cost, and says what a later format could do.

## 5. The phrase

- **Twelve words** from the BIP39 English list: 128 bits and a checksum, so a mistyped word is caught.
- **Made by the node,** by `cordelia phrase` at a terminal, shown once. The prompts of `cordelia phrase` and `cordelia recover` say whose words these are: Cordelia's recovery phrase, from the same list a wallet's seed uses, and neither is to be typed into the other's program. `cordelia phrase` asks for the whole phrase to be typed back before it goes on: a phrase written down wrongly is otherwise found out on the day of a removal. It says plainly: without the phrase a device can be added, and none can ever be removed or recovered.
- **What comes from it,** each under a label of its own: a signing key (statements, and the change entry); the secret of the phrase's channel; the statement key (4.6); and the key that seals the part of a change entry that is for the phrase.
- **What a device keeps:** the phrase's signing key, its public half; the ID of the phrase's channel; the statement key; and the latest change entry it has seen. Never the words.
- **Where it is typed:** at the command's own prompt (`cordelia remove-device`, `cordelia renew`, `cordelia recover`, `cordelia settle`, and `cordelia sync carry` with `--from` or `--phrase`, 7.3), never as an argument, never over the local API, never in a chat with an agent. The command reads it from the terminal with echo off and refuses when its input is not a terminal. **The words stay in the command's process,** and the command forgets them as soon as it has signed and sealed, before it waits for anything to be sent.
- **The command signs what it has shown.** The node prepares what is to be signed. The command shows the statement's lists, each key with the first words of its fingerprint, **from the bytes it is about to sign,** and only then asks its yes and the phrase. It signs the statement, seals the part of the change entry that is for the phrase, signs the entry, and hands those back. (A program that runs as the person can answer on the node's port, or change the node's rows. What it cannot do is have the phrase sign a list that the person was not shown.)
- **Every yes in this record is asked by the command, at a terminal.** A yes stops a command that is run by mistake, or by a script that has no terminal. It stops nothing else: the call that the command then makes to the node is one that any program that holds the node's token can make.
- **What a yes does not stop.** An agent that has a shell can give a command a terminal (one wrapper does it), read what it prints and type what it asks; and any program that runs as the same user can make the call itself (the threat model's T17). That is not defended. What it means for each command:
  - `add-device` and `accept` can be run by such a program. What is left is that every device shows the addition until a person clears it (section 6).
  - `cordelia phrase` can be run by it: it reads the twelve words and types them back. The device then starts again under a phrase that something else holds. The devices it left show that it has gone (5.2).
  - `cordelia init --new-key` likewise.
  - **What it cannot do is anything that asks for the phrase:** remove a device, renew, recover, settle, or bring in what a removed device left (7.3). The node does not hold the phrase, and a statement is signed in the command's own process.
- **Replacing the phrase is not in this version** (section 14). What a leaked or a lost one means:
  - **A phrase that has leaked** lets its holder read everything, without a sign, across every later removal: each change entry seals the new secret under the phrase, and anyone with the phrase can fetch it. Its holder can also remove devices, recover to a machine of their own, and stop every device by making a statement.
  - **A phrase that is lost** means that no device can be removed, that nothing can be recovered, and that no statement is ever made again.
  - **The remedy for either is to start again, on every device.** On one: `cordelia phrase`, which leaves the others and makes a new phrase (5.2). On each other: `cordelia init --new-key`, which leaves the others too (5.2), and then the two commands that add it (section 6). Each of those gets a new key and a first sync, with a copy beside each file that differs. Nothing takes the devices out of the old phrase's lists: without that phrase nothing can, and a holder of it still reads what was written under it. The statement keeps a place for a later way: the field that is empty in this format (4.1).

### 5.1 Which phrase a device follows

1. **The device it was made on** follows it from then.
2. **A device takes the phrase of a device it accepts** (section 6): the person types that device's key on it, at a terminal, and says yes to a prompt that names what will happen. What `cordelia accept <key>` does goes by the state the device is in:

   | This device | What `accept` does |
   |---|---|
   | **Follows no phrase** (a new install, or one that has just taken this version) | Asks its yes: "this device, and the N folders it maps, will join <label>'s devices: what is in those folders will be sent to them". It then takes what that key hands over within the hour: its statement, its secret and its phrase |
   | **Is alone under a phrase** (its statement lists no other device, and it has added none), however it came by the phrase: it made it, recovered with it, or removed every other device | Refused while sync is on there: `cordelia sync off` first, so that sending its folders to another set of devices takes two acts. Then its yes says: "the recovery phrase that this device follows stops working here" |
   | **Is one of several** (its statement lists another device, or it has added one) | Asks its yes, and takes within the hour only a hand-over under the phrase it already follows that brings a change it can apply (4.2). That is how a device which no relay has told is told by hand (section 8). Any other hand-over moves nothing: one whose statement is a fork shows as one (4.5), and one under another phrase does nothing. The device is in use, and accepting would move it, with its memory, to whoever's key was typed. To join other devices it leaves these first, by a person's act of its own: it is removed from them, or `cordelia init --new-key` starts it afresh |
   | **Is in no list** of a statement under the phrase it follows (a recovery or a settlement did not list it, or the device that made the change did not know of it), **or is listed in a change that it could not open** (4.5) | Asks its yes. It takes, within the hour, only a hand-over under the phrase it already follows, with the statement that stopped it or one made after that which keeps its removals. It keeps its folders and what they had agreed, and carries what it holds |
   | **Was removed** by a statement under the phrase it follows | Refused: `cordelia init --new-key` first |
   | **Is in a fork** | Refused: the fork is settled first |

   - "Sync is on" is what `cordelia sync off` turns off. A folder that is still declared after that is no reason to refuse.
   - `accept` refuses when its input is not a terminal.
   - **For as long as a device follows no phrase, one yes at a terminal joins it and its folders to whichever device's key is typed.** That is every device between the upgrade and its being added (section 10), and every new install. Its status says "not added yet" until it is, where it came by the upgrade, and 5.2's words for a new install where it did not (10.1).
3. **A machine that recovers** follows the phrase typed on it (section 9). `cordelia recover` refuses on a device that already follows one. A machine that has recovered is alone under its phrase (the table's second row), and is a device like any other: it can settle a fork.
4. **Nothing a device is sent changes the phrase it follows.** A hand-over under another phrase than the one it follows is taken only in the states where the table says so, and otherwise does nothing. (A change entry under another phrase cannot reach a device: a relay answers only with an entry by the author of the one it was shown.)

### 5.2 Before there is a phrase

- **A new install has no secret, and publishes nothing.** Sync can be turned on and folders mapped: what is in them stays on the machine. Its status says: "no recovery phrase yet: memory stays on this machine. Make one here (`cordelia phrase`), or add this machine from one that has one."
  - A machine alone has nobody to sync with, and nothing can be recovered or added without a phrase. And channels published before the phrase would be at a relay before the phrase's channel, which is the one that has to be the oldest (2.5).
- **`cordelia phrase` makes the phrase, S(1) and statement 1,** which lists that one device. It writes the change entry to each relay before anything else, and then publishes the device's folders.
- **On a device that is one of several,** it asks first, at the terminal: "this device leaves the N devices it is with and starts again alone, under a new phrase". It then **writes that it has left, in the personal channel it is leaving,** makes a new phrase and secret, and its folders forget what they had agreed. Each device it left shows "<label> left, and started again under another phrase" until a person clears it at a terminal (`cordelia devices --clear`). A device that has left still holds the secret it had, and is still listed: removing it, with the phrase, is what cuts it off, and the notice says so. (A device that is taken over can be made to leave without a word. One that leaves by its own command says so.)
- **On a device that is alone under a phrase,** it asks: "this replaces the recovery phrase that this device follows: the old one stops working here, and what the relays hold under it is left behind". It then makes a new phrase, S(1) and statement 1, and its folders forget what they had agreed.
- **`cordelia init --new-key`** gives the device a new key. Where it is one of several it first writes that it has left, as above. It keeps its memory folders and their mappings, and forgets everything else that this record gives a device: the phrase it followed, the statement, every secret, the change entry, the records of additions, and what its folders had agreed. It then follows no phrase.
- **Until there is a phrase nothing can be added, removed or recovered,** and status says so.
- **A second machine is set up the same way and then added.** It has no secret until it accepts the first (5.1, section 6). It then takes that device's secret and phrase, and its folders meet the person's channels as on any first sync: memory it had gathered alone is published, not lost.

## 6. Adding a device

A device is added by two commands: its key is typed on a device that is in (`cordelia add-device <key>`), and that device's key is typed on the new one (`cordelia accept <key>`), within an hour. **Each of the two is run at a terminal and asks a yes.** `add-device` says what it hands over: "this gives <label> every name's memory, and the means to read what your devices write from now on".

```
desktop$ cordelia id
         cordelia_pk1...                         (copy this)
laptop$  cordelia add-device cordelia_pk1... --name desktop
         ...
         On the other device, within the hour, run:
           cordelia accept cordelia_pk1...       (copy this back)
desktop$ cordelia accept cordelia_pk1...
```

Adding by a code that the new device shows is a later step, and with it the rule that a device adds and removes nothing in its first day (section 14).

What is sent, and where:

- The two meet in their pair channel, which each can derive once it knows the other's key.
- **The device that adds writes one entry there, the hand-over, and keeps it in its own store for two hours at most, and never past a later statement or its leaving the phrase** (it holds the secret, which a device keeps in one place: section 3). **When it drops it, it writes a delete over it in the pair channel, at each relay that it had sent it to,** so that no relay goes on holding that generation's secret sealed to a key. **The hand-over holds:** the statement the device has applied; the secret; the statement key; the latest change entry it holds, whole, so that the new device can keep it and show it; and a **record of the addition:** the new device's key, a label, the time, and the statement it is made under (its number and hash). The device that adds signs the record as itself, under a label of its own. If it was itself added since that statement, the record of its own addition goes with it.
- It writes the same record in the personal channel, where every other device sees it. That is the announcement: every device shows "new device: <label>, added from <label>" in its status until a person clears it there, at a terminal (`cordelia devices --clear`). It is said in words; how it is drawn is a later step.
- **The new device asks its relays for the pair channel and the personal channel before any other, and fetches a name's channel before a folder's first cycle there:** from at least one relay, and from each other relay it is set up with that answers within the 30 seconds of 4.6. It waits for a relay, and never for a device, and its status says which folder waits. That holds for any folder with no record in a channel yet, on any device: one that has just been added, and one that maps a name. So a file that another device has already sent meets the folder's as on any first sync (section 10, step 5), and is not published a second time as this device's own.
  - Where two devices each publish a file into a channel that was still empty at every relay (the other had not yet sent what it holds), the two meet as a tie: one text is the file, by the tie's rule, and the other is kept beside it. Nothing is lost by it.
  - It does not wait for the device that added it, which may be off for a day. Nor does it go ahead without a fetch, because a folder's cycle runs every five seconds and a fetch every ten: a first cycle that came before the first fetch would publish a second time every file that the device shares with the others.
- **The hand-over goes ahead of whatever a carry has waiting.** The pair channel is a new channel at a relay (2.5): where the address's allowance is used up, the hour that `accept` allows can pass, and `accept` is run again; and through a relay that has no room for a new channel no device can be added.
- The new device applies the statement by rule 3 of 4.2 and follows its phrase (5.1), keeps the change entry, and writes that it has applied it (section 8).
- **The phrase is not typed to add.** A device that is in vouches for the new one. An intruder on a device can therefore add a device (the threat model's T20): that is made visible, not prevented. (What is not visible is a copy: an intruder who reads the device's database has the secret, and reads everything until the next removal, with no sign. Section 12.)
- **`add-device` refuses** a key that the statement lists as removed; refuses on a device that is in a fork, was removed, is in no list, or follows no phrase; refuses on a device that may not add (one that was itself added, since the last statement, by a device added since: a chain is two long at most); and refuses where the device already counts 64 and a record would be made: a key that the statement lists is handed the change again whatever the count. It shows a key that the device counted before, and that the statement does not list, as that ("this key was not in the last change") before its yes.
- **A key that the statement already lists** is handed the change again by the same two commands, with no record: `add-device` says that it is one of the person's devices already, and that this hands it the last change (5.1, section 8).
- **A device that is in no list** (4.3, section 9) is added again by the same two commands. The device that adds it shows it by its label and asks for its key as that device prints it (`cordelia id`): a key is never offered to copy from a list. **A label is whatever the device that added a key called it,** and two keys can have one label: wherever a device is shown for a decision (here, at a removal, at a recovery), the first four words of its key's fingerprint are shown beside its label.

**Who may add, and what counts.** A record counts only under the statement it names, and only for a key that no statement the reader has seen removes. A device that the statement lists may add; so may a device that such a device added. A device added by one of those may not, until the next statement lists it: a chain is two long at most.

- **A reader that has counted a key goes on counting it until it applies a statement that does not list it.** No later record displaces it.
- **A reader counts at most 64 devices in all:** those of the statement, and those added since in the order it saw their records. A record beyond that is shown as "not counted", and a statement makes room. Beyond the bound two readers can differ in which keys they count, since each goes by the order it saw; and a device that counts can use the bound up with records of its own. Both are shown, on every device, and neither displaces a device that was counted.
- Records are not carried to the next statement's personal channel: the next statement's own list is what stands.

**At the next statement** the prompt shows every device added since, with who added it and the first words of its fingerprint, and asks of each whether it stays or is removed. No answer is suggested for any of them: each is typed. A device is asked about before the devices that it added. A device that stays is among the statement's devices. One that does not is among its removed keys: the person has said so, with the phrase, and it is not added again without a new key.

- **A device that the device being removed added** is shown as that, with when it was added. No answer is suggested for it: after the upgrade every other device was added from the first (section 10), and the first can be the device that is lost.
- **The device that makes a statement is always among its devices,** whoever added it.
- **A key that the maker does not know of** (its record had not arrived, or arrives after the prompt) is in no list: it is not a device under the new statement, it says so, and it is added again by a person or not at all. So a record that a removed device signs at the last moment adds nothing, and **no record that arrives after the prompt restarts a command** (7.1).

## 7. Removing a device, and how a channel moves

### 7.1 What the person does

```
desktop$ cordelia remove-device <key>
```

1. It first shows its change entry to each relay and applies anything it is answered with (4.6). Then it fetches the channels of the names this device syncs, from each relay it can reach, up to what each relay held when the command began and for two minutes at most, and runs a sync cycle. It says what it could not fetch. This makes the folders here as current as they can be made. Nothing depends on it being whole: a removal is never held up by what another device, or the device being removed, goes on writing. (`cordelia renew` and `cordelia settle` begin with the same step.)
2. It shows:
   - the device to be removed, and how much it has written that this device received in the last day and in the last week;
   - each device added since the last statement, with who added it, asking of each whether it stays or is removed (section 6);
   - each device that has said that it left (5.2), asking of each whether it stays or is removed, with no answer suggested: its word is kept across a change for as long as its key is listed and nobody has cleared it;
   - every device that will remain;
   - **each name that only the device being removed syncs:** "these stay behind, with what it wrote in them. Map one on another device first if you want it; after the removal it is brought in only with the phrase" (7.3).
3. It asks for a yes, and then for the phrase.
4. It says that the change is made, and that it must not be made again on another device, even if this command is stopped now: two changes made apart have to be settled with the phrase. Then it stays, and shows three things as they come:
   - **for each relay this device is set up with, whether it holds the change.** Until one does, nobody else can hear. A relay that does not is named, for as long as it does not;
   - **what this device has still to send:** what it carried (7.3), as names sent and names to go;
   - each remaining device, with whether it has applied the change, and whether it has sent what it held (section 8).

   **It says that this machine may be closed only when every relay holds the change and this device has sent what it holds.** Before that it says which is missing: "keep this machine on: <relay> does not hold the change yet", or "keep this machine on: 12 names still to send".

What the prompt showed is checked again inside the transaction: if a statement arrived, between the prompt and the phrase, that this device can apply or that makes a fork (4.5), nothing is made and the command asks again. **A record of an addition that arrives after the prompt never does that,** whoever made it: its key is in no list (section 6). The command does not ask again when a device that would be asked about is added meanwhile, because a device that is being removed, or one it had added, could then have the twelve words typed again for as long as it had records to sign.

**What the removed device wrote is kept where a remaining device had taken it,** up to the moment that device applies the removal (property 2). A person who knows that a device was stolen on Tuesday will want to see what it wrote since: each device's local history shows what it took from which device, with the text it replaced, and puts a version back (the record of 2026-09-30, 4.5b).

### 7.2 What A does, in order

1. **The node stops its sync cycle and its fetching, and makes the change in one transaction:** the new secret; the statement and the change entry, which the command has signed and sealed; and its own carry (7.3). A has then applied its own statement (4.2).
2. **A stop before the transaction leaves nothing changed. After it, what is left is what every device does anyway:** showing the change entry to each relay, and sending what it carried.
3. **It shows the change entry to every relay at once,** in room they already hold.
4. **Then it sends what it carried** (7.3), as every device that applies the statement does.

Step 3 waits for nothing in step 4. From the moment a device applies the statement, the removed device reads nothing it writes.

### 7.3 Carrying: what a device does when it applies

**Every version keeps its revision.** A name's new channel is filled from what the devices under the statement hold of the old one, each version at the revision it had (or at the one that the renumbering of 2.3 gives it, which every device gives it alike). So every folder's record of every file (its text, its revision) means in the new channel what it meant in the old, and the ordinary cycle goes on from where it was. There is no list, nothing to wait for, and nothing to settle.

**A device carries what it holds, in the transaction that applies the statement, and fetches nothing to do it** (4.2). For the personal channel and for each name it syncs, each slot's current version, as the device holds it in the generation it is leaving, is written into the name's new channel in the device's own store: the same name, the same text or delete, the same revision. So from the moment a device has applied, its copy of each new channel holds what its copy of the old one held, and a cycle can run at once. What it holds of a generation it left is what it had taken when it applied. It reads the channels it left no more (7.5). It does not carry a name at a time, after a fetch of the new channel, with a record for each name and a rule for which generation a name is carried from: nothing needs any of that.

What a carried entry is, and says:

- **It is the carrying device's own entry:** the same name, the same text or delete, at the same revision, or at the one that the renumbering of 2.3 gives it.
- **It keeps the version's chain.** Where another key signed the entry it is carried from, it puts one link first: the hash of the version's own text, and that key. (Where it holds several entries of the version, it carries from one of them: 2.3.) So a chain always says who signed each version in it, in the word of a device that held that entry and checked its signature.
- An entry that lost a tie is not current, and is not carried. Nor is an entry that is no version (2.3).
- **A record with no version at all in its slot** is dropped, and its file meets the new channel as a new file does (4.2).

**Sending.** What a device carried waits to be sent like anything it writes. Before each batch that it sends into a name's channel it fetches that channel from the relay, and does not send a carried entry where the relay's copy, as the device then holds it, already has, in that slot, that version or an entry at a higher revision. (In the personal channel a device sends what it carried whatever is there: it carried only its own word, in slots of its own.) One that a relay refuses for room, where the channel as then fetched holds that version, is dropped and not offered again. The change entry, and a hand-over to a device that is being added (section 6), go ahead of all of it.

From the personal channel, a device carries what it wrote there itself, the names it holds: its own entry in each slot, whether or not another key's entry there has a higher revision. Records of additions are not carried: the next statement's own list is what stands. **The list of names in a new personal channel is what the devices under the statement say they sync.**

**What a version is known to follow.** The record of 2026-09-30 asks whether a version at a higher revision is known to have been written after what the folder agreed (4.5, "An entry says what it was written after", and #79), and gives several reasons by which it can be known. Here there is one, and it replaces them:

- **A version is known to follow a folder's text where that text's hash is in its chain, and every link that is newer than it was signed by a key that counts** (4.4). Where a hash stands twice, the newest link with it decides.

That is what git asks of a commit and its ancestors, with a window of 100 links, because nothing here keeps a history.

- **A device that writes an entry over a version** puts first the hash of that version's text and the key that signed the entry it holds, and then that version's chain, as far as 100 links allow. The oldest links fall off. A chain that cannot be read is not copied: the entry written over such a version has the one link.
- **A device that publishes a merged index** writes it over the channel's version, as any entry: that version's link first, and then its chain. The version that its own file held is the merge's other source.
  - **Where that version's hash is already in the chain, nothing is added:** the channel's version descends from it, and every link between them stays between them.
  - Where it is not (the two were written apart), its link comes second, and after it the links of the two chains, one from each in turn.
  - **Once a link of one chain is left out because its hash stands further on in the other, nothing more is taken from that chain,** and the other goes on whole: what stood behind that link in its own chain must not come to stand ahead of it. Such a hash is not put at the later of its two places with the rest kept, because the links behind its earlier place would then stand ahead of it, and a folder would be told that a merge followed its text on the word of a key that did not count.
  - The folder's record keeps the chain of the version it agreed, for this. A merge at a folder's first sync has one source.
- **An entry that lacks its chain, or whose chain cannot be read, is known to follow nothing** (2.3). A new file's entry has an empty chain.
- A version held in several entries (2.3) is known to follow only if each of them shows it.
- **The hash is SHA-256 of the text's bytes as the file holds them** (zeros for a delete; for an entry that holds other bytes than a text, of those bytes). So a folder's text is found in a chain wherever a version with that very text stands in it: whatever was written after such a version was written by a device that had that text.

**Why a chain.** The reasons of the record of 2026-09-30 go. Those for a record, and for an entry, from before that rule have nothing left to apply to: the upgrade is a new start (section 10). Nor has the one for an entry that says nothing: every entry a node writes has its chain (2.3). The others read names: a device and a revision. **A name is not bound to a text.** Whoever writes an entry can name any device at any revision, whether or not it ever held what that device wrote there. A hash is bound to its text. A removed device cannot list a text that it cannot read, and it reads nothing in a new channel.

**The key beside each hash is put there by the device that wrote over that entry,** or carried it: a device that held the entry and checked its signature. So where a key that no longer counts signed any version between a folder's text and the version it takes, the chain shows it, and the folder keeps its text. What the removed device says in its own entries reaches only devices that have not heard, which take its entries as they take any device's (property 2). Once a device of the statement writes over one of them, or carries it, the link for it names the removed key, and everything that the removed device listed is behind that link.

**What it closes besides.** The record of 2026-09-30 lists two limits of its rule (section 9): a folder that started afresh, and one that was restored from a backup. There a device's later version did not descend from its earlier one, and a name could not tell. A chain can: the earlier text's hash is not in it.

**What it costs:** copies beside files that were not needed, in two places.

- **A device that was behind a removed device's versions** keeps one for each file where that device signed a version between the folder's text and the one it takes, however honestly it wrote.
- **A device that is more than about a hundred versions of one file behind** keeps one for that file, with no change of devices at all. The record of 2026-09-30 has no such window: there an entry names devices, not versions. The bound is in links, and a merged index of two lines of versions written apart has about fifty for each. For the index of a busy agent a hundred versions can be a few days' work, and a laptop that was closed for longer then finds `MEMORY.conflict-<tag>.md`, as it does whenever both devices wrote the index while apart.
- **A link by a device whose record of addition the reader has not seen yet,** or by a key in no list, costs a copy too.
- A device that is behind by less keeps none, and nor does a device that held the removed device's last version: that version is the folder's text, and nothing newer than it in the chain is the removed device's.
- **One thing a chain does not show.** The put-back of index lines (the record of 2026-09-30, 4.5) adds lines from versions that stand beside the index's entry, and lists no link for them. A late line of a removed device's can enter the index that way. It adds a line, and replaces nothing.

**What the plan then does,** with nothing else changed in it:

- **A file as its record, and the new channel has that version:** nothing.
- **The new channel comes to be ahead** (another device carried or published a higher revision): the file takes it, as it would have in the old channel, by the rule above.
- **The file was edited here and not yet published:** the edit is published over the version it was made on, which this device has carried. It is an edit of that version, and says so.
- **Two devices carry one version:** the two entries are one version (2.3), and nothing follows. A relay holds each until the device that carried it writes the file again.
- **Two devices carry two versions at one revision** (each had edited before it heard): a tie, as it would have been in the old channel, decided by the text, and the text that loses is kept beside the file, as at any tie.

**What no remaining device holds is not carried by itself.** A name that no device under the statement syncs has no channel in the new generation, and what the relays hold of a name beyond what the remaining devices had taken stays where it is. Neither is fetched unasked: after a removal, what a relay holds in a channel that was left is not to be trusted without a person's word.

- `cordelia devices` shows each name that a device which counts had listed in the old personal channel, as this device held it, and that no device lists in the new one. Names that only keys which no longer count had listed are shown apart, as that.
- **A device that comes to sync a name carries it first,** by the command that maps it, where the new channel holds nothing for it and the device still holds the secret of a generation that had it (90 days each, section 3). **`cordelia sync carry <name>` does the same for any name,** one that the device syncs included, **and with no name for every name it holds.** It is how the last edits come in that a device which never returned had sent to the relays, and `cordelia devices` names the command beside a device that has not applied a change. **Each fetches the name's channel in every generation that the device left and still holds the secret of (section 3), the newest first, and takes from each what keys that count signed there:** what the person's own devices wrote, which the removed device cannot have changed. What they bring in is carried as above: this device's own entry, with the version's chain and a first link for the key that signed it. They say how much they left behind that other keys signed, and how much they left because the new channel already holds a higher revision in that slot.
  - What a relay holds can be older than what its writer last wrote, where the relay lost the later entry.
  - A file that the removed device had deleted comes back by this: its delete was the removed device's, and is not taken.
  - A version is brought in only where the new channel holds, in that slot, neither that version nor an entry at a higher revision, as in any carry. One thing more can stop it: a version that ties with an entry of this device's own in the new channel cannot be carried by this device, which has one entry in a slot. The command says so, and another device can bring it. (It is never given another revision to get it in: a relay's copy can be older than what its writer last wrote, and an old version moved above a newer one would take its place.)
- **`cordelia sync carry <name> --from <label>`,** at a terminal, **with the phrase,** also takes what the named removed device signed there, carried as above. It takes one key or several, each by a label or by the first six words of its fingerprint: a statement lists removed keys bare, so a machine that never knew a device has no label for it. It refuses where a label or the words match two removed keys. With no key, it shows each removed key that signed in the generations it can read, with how much, and takes nothing.
  - **Before it asks for the phrase it says what it found:** the keys; how many versions would go into slots where the new channel holds none; how many stand above a version that the new channel holds; and that a device in someone else's hands may have written any of them since.
  - **It brings in the first kind.** With several keys named it judges once which slots are empty, and takes for each the newest version among those keys.
  - **The second kind comes in only on a second yes,** which names the files, and only for a name that has a folder on this device: the text it replaces is then kept beside the file. For a name with no folder it is refused, since nothing would be kept.
- **With the phrase, a carry by command reads every generation whose secret the device's change entry gives the phrase,** and not only those the device itself left: a device that was off through two changes never held the secret between them. `cordelia sync carry <name> --phrase` does that for the keys that count. The prompt says what that is: "what this device wrote, as the relays hold it now. If it was in someone else's hands, they may have changed it since: say no unless you know it was not." It is for a device that was retired, or broke. A yes alone would not do: an agent with a shell can say yes, and a line planted in memory before the removal could ask it to. This is the one way a removed device's later writing comes in by command, so it asks for what an agent does not have.
- Either command can be run again, and takes what the new channel still lacks: a relay that was down the first time is asked the second.
- A name that nobody brings in within 90 days stays in the generation that was left. Status says how many names are not in the new generation, and for how long they still can be brought.

**A delete is a version,** and is carried like a text: no file comes back by a move, with the one exception that the record of 2026-09-30 has too (4.4): a device that was off for longer than a delete is kept, 90 days, never saw it, and carries its text. A delete that is carried is a new entry, so the 90 days after which a relay sweeps it start again at each statement.

### 7.4 What is carried that a person might not expect, and what is not

- **What the removed device wrote, on a device that took it before it applied the removal.** It is that device's version of the file, and is carried as such (property 2). It travels at its revision, so where it was the newest it is the newest in the new channel too. A device that did not take it from the old channel takes it from the new one with what its own file held kept beside it, and likewise a version that a device wrote over it (7.3).
- **That includes a delete.** A file that the removed device deleted in that time, on a device that took the delete, is deleted on every device once the delete is carried, and its line goes from the index where a device merged meanwhile. Every other device keeps its text beside where the file was, as a conflict file; the device that took the delete has it in its history (`cordelia history <name> --removed`).
- **So a text that the removed device had deleted, at any time, comes back as a conflict file** wherever a device still held the file when it met the carried delete; and a conflict file goes to every device.
- **What an agent on a remaining device wrote after reading it** is that device's own.
- **What only the removed device held** is not carried by anyone: an entry it had not yet sent to a relay.
- **What the removed device had sent and no remaining device had taken** is not carried either, unless a person asks, with the phrase (7.3): its work in a name that only it synced, and its last edits in a name whose other devices were all off. That is the price of taking nothing it signed after the removal: nothing tells the two apart.
- **What a device that is off holds and has not sent** is carried when that device returns and applies the statement: its unpublished edits, as edits of the versions they were made on, or kept beside the file where that version has been overtaken.
- **What a remaining device had sent and no other had taken,** where that device never returns: `cordelia sync carry` fetches it, as it was signed by a key that counts.
- **Copies that were not needed.** A device keeps its file's text beside the file where a key that no longer counts signed a version between that text and the version it takes (7.3). For a device that was behind when a device was removed, that is each file that the removed device had written since this device was last in step. A device that is behind by less than the chain's window keeps none (7.3).
- **The same version twice at a relay.** Two devices that send a name at the same moment each write every version, and the channel holds each twice until the device that sent it writes that file again. A name larger than the channel's cap divided by the number of devices that send at once does not fit a second time: the device whose entries are refused for room fetches the channel again, finds the versions there, and drops what it had waiting (7.3).

### 7.5 The old channels

A device that has applied a statement neither reads nor writes the old channels again, and no longer lists them to a relay, with one exception: a carry that a person asked for (7.3). **In such a carry, as in everything a device does after it has applied, it takes from a generation it has left nothing that a key signed which does not count,** except by the one command that names that key and asks for the phrase. It keeps the secret of each generation it left for 90 days (section 3), and nothing else of it. Relays drop the old channels as 2.5 says, where nobody proves them.

The store refuses an entry of an old channel from the transaction that applies the statement: what arrived before it is what the device held, and what arrives after is not taken.

### 7.6 When the device that made the statement is lost

Once a relay holds the change entry, nothing but the maker's own carry waits for the maker. Every other device is answered with the entry, applies it (the secret is in it), and carries what it holds. What only the maker held (edits it had not sent, names only it synced) is lost with it, as a lost device's unsent edits always are. That is why the command says what is still to send (7.1).

**If the maker is lost before any relay held the change,** nobody has heard. The removed device is still a device to every other. The removal is made again, from a device that remains: it has seen no statement, so the one it makes has the number the lost one had. If the lost maker's ever comes to light, the two are a fork, and are settled.

**A statement that no relay held can come to light later.** Whoever holds the lost maker holds its change entry, which the phrase signed, and can show it to a relay that holds none, or an earlier one. A device that is far behind is then answered with it, applies it, and is with the lost device, in a generation whose secret that device holds, until it is shown the other statement. Every device that sees both is in a fork until they are settled; the settlement removes the lost maker, and the statement it held is then behind. This is a device that has not heard, by another road (property 1's limit, and property 2's second kind).

## 8. One place to look

- **Each device that applies a statement writes so** in the new personal channel, under its own key: the statement's number, and, once it has, that it has sent what it carried. It can only do so with the new secret and its own key, so it cannot be claimed for it. A device restored from an older backup shows as having applied a statement that it no longer holds: it is answered with the change entry again (4.6).
- **`cordelia devices`,** on any device that has applied the statement, lists:
  - every device of the statement, with one of: this device; has applied change n and sent what it held; has applied it and is still sending (a device that is lost in that state has left what it had not sent: `cordelia sync carry` brings in what it had sent before, with `--phrase` where this device never held that generation's secret, 7.3); has not yet, with the same command;
  - every device added since, with who added it, and any record that is not counted (section 6);
  - every key the statement removed;
  - **every key this device counted as a device before the statement that is in neither of its lists:** each holds the secret before, and may not know. It is shown as "not in the last change: add it again, or it was meant to go", by its label, until a person clears it there or a later statement lists it. (After a recovery only the new machine has that list: it read it at its prompt);
  - any device that has said it left (5.2);
  - any name that no device lists yet in the new generation (7.3), and what this device has still to send;
  - **for each relay, whether it holds the latest change entry,** and whether this device has heard from it since it woke (4.6).
- **A device that cannot go on says why,** as soon as it can know: it was removed, or is in no list (4.3); a change that lists it could not be opened (4.5); it is in a fork (4.5); its relay has no room for a new channel (2.5); it follows no phrase yet (5.2); it was answered with a change and could not apply it (4.2).
- **The status line** shows as amber (10.1, rule 13): a removal that some device has not applied, for its first seven days (after that it is in `cordelia devices` only: a device in a drawer does not keep every status line amber for good); a device added since the last change that nobody has cleared (section 6); a device that has left; a relay that does not hold the latest change; names not yet in the new generation, or not yet sent. A fork, and a device that was removed or is in no list, are red.
- **What no device can see** is whether a device that has not applied a change is in a drawer, or is on and has not heard: one that has applied reads the old channels no more, so it sees nothing of one that is still there. The remedy is the same for both: add it again from a device that has applied, which hands it the change directly.

## 9. Recovery

```
new$ cordelia recover
```

**Recovery is for a person who has no device left that they trust.** Where a device remains, the removal is made from it (section 7): that stops nobody else, and each remaining device carries what it holds. The command says so before it asks for anything.

1. It asks for the phrase at the prompt, derives the phrase's channel, and fetches it from every relay it is set up with, saying which it could not reach. (`--relay` names another.) With the phrase it can prove the channel's key, which no device can.
2. It takes the change entry with the highest number whose signatures hold and whose secret opens to its statement's commitment. **Any other entry it was given that is not on that one's chain is a fork,** whatever its number (two relays can hold two): it shows both lists and asks which to recover from, and the statement it then makes settles them (4.5).
3. It reads that generation's personal channel, and **shows every device:** those of the statement, and those added since, each with who added it and the first words of its key's fingerprint (a label is the adder's word, section 6). It shows how much each has signed there, and asks of each one of three things: the person still has it (it is added again in step 6); it is lost or broken; or it may be in someone else's hands.
   - **The look of step 5 takes only from the keys shown here, as answered.** A record of an addition that was not shown (it arrives after the prompt) counts for nothing in the look.
   - **From a device that may be in someone else's hands the look takes nothing,** and nor from a key that such a device added, or that a key it added added: each of those is shown as that, and is marked with it. What they wrote comes in only by `cordelia sync carry --from`, which says what that means. Until then, a version of another device's that one of them had written over is what is carried. (For a person whose only device it was, that answer brings back nothing until the command is run, and the prompt says so.)
   - **Every record under the statement is shown, up to 256:** the statement's devices first, and under each the keys it added. No device chooses that order by when it signs. Beyond 256 the command says how many it could not show, and the look takes nothing from those. A device that is not gone is not listed either: the person adds it again by hand (step 6).
4. **It makes the next statement, applies it on this machine, and shows the change entry to every relay at once:** itself as the only device, a new secret, and as removed every device that the person said is gone.
   - Each other device is answered with it on its next pass, reads the statement, and says that it was removed, or that it is not in a change made on the new machine and is to be added again from there (4.3). From then a device that is gone reads nothing that those devices write: they have stopped. A removed device cannot keep the entry from them: only the phrase writes there.
5. **It carries every name that the personal channel lists, from the relays' copies, in one look.** This is the one carry that fetches unasked, and it is a person's act: the phrase was just typed for it.
   - **It first lists the names in its new personal channel,** and sends that list straight after the change entry: so that a recovery which follows this one finds them, whether or not this machine ever maps a folder. A new personal channel needs room at a relay, where the change entry needs none: so a recovery also reads the names, and only the names, in the personal channels of the generations before it, where a key in either list of the statement it recovered from listed them there. (It holds no statement for those generations, and anyone who ever held one of their secrets can write there: a name that such a key did not list is not read.)
   - **From the generation it recovered from** it takes what counts there under that statement when it looks, whoever wrote it, a device that may be in someone else's hands aside (step 3). Marking a device as gone removes its key, and nothing that it wrote: a person with one laptop, which is lost, gets back what the laptop wrote.
   - **From the generations before it,** whose secrets the part for the phrase holds (4.6), it takes what those same keys signed, where the new channel holds, in that slot, neither that version nor an entry at a higher revision, as any carry by command does (7.3).
   - **The look is made once.** The command stays until it has read every name from each relay it reached, says which relays and which names it could not read, and then says "keep this machine on: 12 names still to send". A look that is interrupted is not taken up again by itself. **At the end of the look the command says, for each removed key, how much that key signed in the generations it read that the new channels lack, and names the command that brings it.** Where the machine it recovered from never wrote that it had sent what it carried (section 8), it says that the earlier recovery was cut short. After the look the machine sends what it carried, and fetches nothing more that a removed key signed. What a relay that was down held of a device that is gone comes in by `cordelia sync carry --from <label>`, with the phrase, as for any removed device (7.3).
   - **Why once.** A device that is gone may be in a thief's hands, and the relays' copy of its entries is its to rewrite. The first look is the person's act. A second look that the machine made by itself, hours later, would take what was written in between.

   Every version it carries is its own entry in the new channels, with a first link for the key that signed it (7.3). None of those keys counts under the new statement, so a device that is added again keeps its own text beside what it takes of them.
6. **Each device that the person still has is added again** by the two commands of section 6. The new machine shows it by its label and asks for its key as that device prints it. Until then it has stopped: a recovery stops every other device until each is added by hand. Added again, it carries what it holds.

**A recovery that is cut short.** If the new machine is lost before it has sent what it carried, the next recovery starts from its statement, under which it alone counts.

- It brings back what the first machine had sent, by the names that the first machine listed.
- What the devices that are gone wrote in the files it had not sent is still at the relays, in the generation before. It comes in by `cordelia sync carry --from`, with the phrase, on the second machine: the change entry gives the phrase that generation's secret, and the command finds the key by the first words of its fingerprint, or lists the removed keys that signed there (7.3). **Where two devices are gone, both are named in one run:** the command then takes, for each empty slot, the newest version among them. Named one at a time, the first key's versions fill the slots, and a newer version of the second's then needs the second yes. It takes only into slots where the new channel holds nothing, unless a second yes says otherwise: so what a gone device has written since, over a file that the first machine had sent, does not come in by a slip.
- What the first machine had sent was signed by its key. A third recovery, after a second that was cut short too, brings that back in the same way: by `--from`, with the first machine's key.
- What a device that the person still has wrote comes in when it is added again.

A second recovery does not do the second of those by itself, from a list of keys that the first one left. What a gone device wrote is the relays' copy, which is its to rewrite: it comes in only by the command that asks for the phrase, and that says so.

**How a recovery goes on, on the same machine.** The new machine keeps the secret of the generation it recovered from, and those before it that the entry gave, as a device keeps a secret it left: for 90 days (section 3). After a restart it goes on sending what it carried. At a later statement it carries every name it holds, as any device does (4.2), and so it does after a fork that it was in is settled.

**Why the others are told first.** Told last, once what the new machine carried was at a relay, a recovery that was cut short would leave the relays as they were. It is not done so, because the gone device would read on for as long as the carry took, and could stretch that without end by filling a relay; a change made on a remaining device meanwhile would leave the new machine in a fork it could not settle; and three rules of this record would need an exception for a machine in that state. Telling first needs none of that. Its cost is that every other device stops at once: through a relay with no room for a new channel, none can be added again until it has room (2.5). What a second recovery cannot bring back by itself is brought by the one command that asks for the phrase.

**Why a device the person still has is not listed.** The statement could list it, and the change entry would then hand it the new secret at once. It is not listed so that the person has to read its key from the device itself: a device that the person believes they have, and that is in fact the stolen one, is then not handed anything.

**What such a device holds.** It writes in the old generation until it hears, which is its next pass at a relay that holds the change. Added again, it carries what it holds, and its key counts again from then: a chain is read by who counts when it is read (7.3). Until it is added again it is no device. It is not believed from the moment the person says they still have it: a phone that the person believed they had, and that was the stolen one, would then be believed.

**What a device that is gone could still do before the recovery:**

- **It wrote what the new machine carries.** Everything a gone device wrote up to the moment the new machine looked is what the relays hold, and is carried. A stolen laptop that was a person's only device can have replaced each of its entries with a delete, or with another text, before the phrase was typed: a relay keeps one entry for each author in each slot, and nothing older. Where a first recovery was cut short, what a gone device wrote comes in later only by the command that asks for the phrase, whose prompt says that it may have been changed since.
- **It listed the names.** The names that are carried are those the personal channel lists, and a gone device wrote there too: it can have listed names of its own, filled, for the new machine to fetch. The new machine carries at most 1,024, in this order: the names of the generation it recovered from, those listed by devices the person still has first, then by devices that are lost or broken; then the names of the generations before, the newest first. It carries no name that only a device in someone else's hands listed, and it names the names it left.
- **It may have been named by a label that is not its own.** Devices added since the last statement are shown by what their adder called them. The fingerprint beside each label is what tells two apart.

**The part of the change entry that is for the phrase** holds the statement's secret, and the secrets of the generations before it, as many as eight, the newest first, each with its statement's number (after a settlement two generations can share a number, and each is tried). The command that has the phrase opens that part of the entry which the device holds, and copies its secrets forward. So a maker that never held a generation's secret (it applied the change after it directly) passes it on all the same, and a settlement passes on the secrets of both branches (4.5). Those secrets are for what the relays hold in a generation that was left and that nobody carried: a second change made soon after a first does not put it out of the phrase's reach. Reading that far back has a cost: where a delete has since been swept, an older generation's text of that file can come back.

**What it cannot know** is whether the statement it found is the latest. If the relays have lost a later one, it has recovered from an old state, into channels that the devices which went on never read.

- A device that went on shows the relay its own, later, change entry on its next pass, and the relay takes it in place of the recovery's if its number is higher. Whichever of the two is answered with the other's sees a statement that is not on its chain, and is in a fork: the new machine where the device's number is the higher, the device where the recovery's is, and, where the numbers are equal, the one that shows second, since the relay keeps what it has and answers with it. A device that has seen both says so, and `cordelia settle` on it ends it.
- A removed device can make this more likely: it can show the relays its own copy of an old change entry. A relay that holds a newer one does not take it.
- From an old statement, a device that was since removed is shown among the devices. It is added again only if the person reads its key from it, so only if they hold it.

**So the change entry is kept by every device.** Each device shows it to its relays on each pass, and shows in its status whether each relay holds the latest. The showing is also what keeps the phrase's channel at a relay (2.5).

**Recovery has a term.** A relay drops a channel that nobody has used for 90 days. So the phrase brings back what the relays hold for 90 days after the last device of the person's was on, and no longer. A relay is a cache, not a backup: recovery is as good as the relays' copies.

## 10. The upgrade

**Nobody is carried over.** Each device starts alone on this version, from its memory folders, and is added again with the two commands.

**Why a new start.** No statement is made from the rows of the version before, so nothing a device was sent the old way decides who is a device. No device is handed a secret on the strength of an old row. There is one phrase, made once. And a personal node reads and writes nothing of the older kind from this version on.

**What the version before holds.** A device is one Ed25519 seed. The personal channel is a group channel with a random ID whose member list is the list of the person's devices. Each project has a group channel of its own, found through an entry in the personal channel, and a device holds keys only for the names it maps. Each channel has a random key with a ring of earlier ones, and a random slot key, in files beside the database. Everything a device is told about membership arrives in its inbox, sealed to it.

**The order.**

1. **Every device is brought into step first, on the version it has:** each is on, and has synced, so that every memory folder holds what the others hold. This is the one thing the person has to see to.
2. **The relays take this version.** It carries the new channels under 2.4 and, for one version, the older ones as they are, each kind within a cap of its own (2.5).
3. **Each device takes this version.** It keeps its key, its memory folders and its mappings. Its folders forget what they had agreed, and it reads none of the older channels, keys or rows again. **It follows no phrase, has no secret, and publishes nothing** (5.2), and its status says "not added yet".
4. **On one device, at a terminal, the person runs `cordelia phrase`.** That device publishes its folders, and what it holds is then the channels' earliest version of each file. So it is run on the device whose memory is the most up to date, and the prompt says so.
5. **Each other device is added** with the two commands (section 6): `add-device` on the first, `accept` on the other, at a terminal, with its yes. Its folders then meet the channels as on any first sync:
   - a file with the same text on both: agreed;
   - a file that differs: this device's text is kept beside the file as a copy, and the file takes the channel's;
   - a file only here: published;
   - `MEMORY.md`: merged, as two indexes are.

After step 5 every other device is a device by the first one's record, until the next statement lists them. A removal asks about each of them, with no answer suggested (section 6). **So the first removal after the upgrade asks about every device but the first,** at the moment a person least wants questions. `cordelia renew`, run once the devices are added, puts them in a list that the person has looked at. It is left to the person, and the upgrade does not end with a renewal by itself: a renewal makes every device carry and fetch every name a second time within minutes, and each relay hold the person's channels twice over.

**What it loses, or brings back.**

- **A file deleted on one device and still on another comes back.** A first sync takes no absence for a delete. Step 1 is what keeps this to nothing: devices that are in step have the same files.
- **What is in the older channels and in no surviving folder is left behind:** the last writes of a device that is dead, and on each device what it had fetched and not yet written to a file, and what it had been handed through the local API and had not yet sent. Step 1 again.
- **A device that was behind brings its old files as its own:** each file that changed while it was away becomes a copy beside the file, on every device. If the phrase is made on the device that is behind, its old text takes each file's name, and the newer ones become the copies.
- **A removal made the old way that a device had not applied** left in that device's folders what the removed device wrote since. It goes with the folder, as its own.
- **Removals made the old way are forgotten.** Statement 1 removes nobody. A device that was removed before the upgrade is not a device after it, since nothing lists it; but its key is not refused either, and it could be added again by the two commands. A person who wants it refused removes it once, by key, after the upgrade: `cordelia remove-device <key>` takes a key that this device knows nothing of, says that it is no device it knows and that removing it refuses that key for good, and asks a typed answer before the phrase.
- **Every device stops publishing when it takes this version,** and starts again only when a person acts at a terminal: `cordelia phrase` on the first, `accept` on each other. "Not added yet" never ends by itself.
- **What each file was written after starts again:** every file's first entry in the new channels is written after nothing.
- **Revisions start again at 1,** and every channel is new at once, against a relay's allowance for the address (2.5). The older channels stay at the relays until they have gone unused for 90 days.
- **A name with more than about half of a channel's cap in text may no longer fit:** an entry is padded to a power of two (2.3, section 12).
- **A file of more than 60 KB no longer syncs,** where the limit of the version before is 64 KB: room is kept in every entry for what it says (2.3).
- **Channels of the other kinds that the local API of the version before can make** (named, and direct) are not carried, and a relay stores none of them once it carries the older kind no more.
- **A device left on the version before** goes on in the older channels alone, for as long as the relays carry them, which is one version. It is upgraded and added like the rest.
- **Between taking this version and being added, a device can be joined to any set of devices by `accept` and one yes** (5.1). So the devices are added soon after they are upgraded.

### 10.1 The first start on this version, and only what is mapped syncs

**The rule that only what is mapped syncs comes in with the same version, and this is how the two meet.** No device goes on in a channel that it had (section 10), and the installer restarts the node (#128). So little is needed for a command line or a node of the version before, and what is needed is below.

**When.** A personal node that has no mark of the step (below) makes it at its start: after the port of its local API is bound, so that a node which cannot bind, because another is running, changes nothing; before its sync loop and its first pass are started; and before any write of the older kind, all of which leave a personal node in this version. The schema's own steps have run by then, at the opening of the database, as they do for any command that opens it: they add tables and change no older row.

**Who makes it.** Any mark means done, in this version and in every later one. A personal node with no mark makes the step where it holds rows or key files of the older kind. Where it holds none (a first install on this version), or already follows a phrase, it writes the mark and sets the guard (below), and nothing else.

- **A data directory is one node's:** a node takes a lock on it before it opens the database, and a second node on the same directory, whatever port it was given, changes nothing.
- A relay and a bootnode make no copy and take no step: their databases are stepped as any version steps them, and a relay goes on carrying the older kind (section 10, step 2).
- A device answers a relay's request of the older kind with nothing, as a device that holds no such channel would, so that the relay asks again at its usual pace.

**The copy first.**

1. The node copies its database, as the opening left it, and the key files of the older channels, into a folder beside them named `before-<version>`: mode 0700, each file 0600. The database is copied by the store's own statement for a consistent copy into a new file (`VACUUM INTO`), never by copying a file that is open. It is made under a name that ends `.partial`, flushed, opened again and checked (it opens, it is whole, it is at this schema's version), and only then renamed.
2. A `.partial` that a start finds is removed and made again. A whole folder that a start finds, with no mark in the database, is from a start that did not finish or from a going back: it is kept under `before-<version>.earlier` (taking the place of any before it) and a new copy is made. So there are at most two, and a step that keeps failing does not fill the disk.
3. **Where the copy cannot be made (no room, no leave to write), the step is not taken.** Before anything is written the room on the volume is compared with what is needed, and the copy is not begun where there is less. A `.partial` goes on any failure. The node stays up, runs nothing (below), and its status says why, with the room that is needed and the room there is. A copy that was made and checked is used again where only the step failed, and the tries back off, from five seconds to ten minutes: a start that cannot succeed does not write the copy again every five seconds.
4. **What the copy is for, and what it holds.** The version before opens it as it opens any database: it knows nothing of the tables added since and ignores them. It holds what the device held: sealed entries, the keys of channels that relays keep for up to 90 days more, and also text in the clear (the search index of what was published through the local API, removed lines of the index, the names and paths of memory files). It is beside memory folders that hold the same memory in the clear. It can be deleted once the person is content.

**Then one step, in one transaction, all of it or none:**

- every folder forgets what it had agreed, and the records kept for index lines go with it (section 10, step 3). Local history stays: it is this device's own;
- every row of the older kind that a device holds is emptied: its channels of every type and their members, the items it held of them, what waited to be sent (what was written through the local API and not yet sent included), what was offered and asked of peers, the invitations, the trust of other devices' keys with the labels it gave them, and what the node noted of the older kind for itself (its personal channel, whom it accepted, when it last synced). The counters stay. The device's own key, its settings and its mappings are kept. Every table and key of the older kind is listed in one place in the code, and a test names each;
- **a device whose scope was "everything found" is told what stopped** (rule 3 below), here and nowhere else: where the stored scope is on (or absent with a directory set), whether sync is on or off, the notice is stored: the date, and each folder that the last stored report shows as a target without a mapping. The report is read as the version before stored it, as plain JSON and not through the adapter's types; one that cannot be read is as none, and the notice then has the date alone. The report is removed and the scope is written off. No later request can meet a scope that is on;
- **a guard against a version that does not know:** a trigger on the older kind's table of channels that refuses every new row, with words that say the database was moved on and where the copy is. A version from before this one makes a channel at every start; started on this database by mistake, it would otherwise make a new personal channel and sync the mapped folders into channels that no other device reads. With the guard it stops there with those words. (A relay that is started on a database which a personal node stepped removes the guard: it is a device's.)
- the mark: that the step is done, with the version that made it.

**After the commit, the key files of the older channels are removed.** They are found by their place and name, and looked for again at every start of a personal node, whatever the mark says: a crash after the commit must not leave them for good. **At a start that makes no copy, one is removed only where a `before-` folder holds a file of that name with the same bytes;** any other is left where it is, counted and said (a person who went back out of order, or a version from before this one started here by mistake, must not lose a key that no copy holds). One that cannot be removed is counted and said, and the node goes on.

**Until the step has succeeded the node runs no cycle and no pass, and refuses every request that changes anything, except one that turns sync off;** it answers status, which says why. (A command that would ask for the phrase asks how the node stands first, and shows no word where it is held up.) It tries again each time a cycle would have run. It does not stop: under a service that restarts what stops, stopping would be a loop, and a stopped node can say nothing.

**The device then follows no phrase** (5.2). Its status says "not added yet" where the step ran, and 5.2's words for a new install where it did not.

**A database from a later version is refused.** A node, and any command that opens the database itself, that finds it at a later version than its own names both versions and changes nothing. A node in that case stays up and says so in its status, as above; it writes nothing at all, so there even turning sync off is refused, and the person stops the node or installs the later version. This holds from this version on. A version from before this one does not know to refuse: the guard above is what stops it on a database that was stepped.

**Going back:** stop the node; install the version before, with the installer told to leave the node as it is; remove the database and the two files that the store keeps beside it (their names end `-wal` and `-shm`: left there, they would be replayed over what is put back); put the copy's database and key files where they were; move the `before-<version>` folder away; start the node. What that does and does not give back: the device's key and its configuration file were never in the copy, so a device that was given a new key since cannot go back; mappings and sync settings are rows of the database, so they are again what they were when the copy was made; and the memory folders are as they are now, so what changed in them since is published into the older channels as edits. No memory is lost by it.

**Only what is mapped syncs: the rules.** They replace what the record of 2026-09-30 says of a scope of everything found, of `--all`, and of what is kept off a device (4.5).

| Rule | In this version |
|---|---|
| 1. Only mapped folders sync | A folder syncs because `cordelia sync map` declared it, and for no other reason. After the step a device is in no older channel, and nothing of one is fetched |
| 2. The stored scope is off whenever sync is on | No node that syncs has a scope of everything found |
| 3. A device whose scope was on is told, and told what stopped | At the step only, as above |
| 4. `--all` is refused | A request that turns sync off is never refused, for this or for anything in this section |
| 5. There is nothing left to exclude | Nothing is stored for an older version to read: an older version comes back only by the copy. What an older panel sends is still taken: `exclude` and `home` are accepted and stored as before |
| 6. A command line and a node of two versions | **A command that changes anything refuses a node of another version than its own,** with the note that says how to restart it. Turning sync off is the exception: it is sent to any node. "Changes anything" is every `sync` command but `status` (its `--seen` included), `restore`, `history drop`, `init --new-key`, and each command of a person's devices but `devices` without an act. `cordelia status`, `cordelia sync status`, `cordelia devices` and `cordelia history` still answer beside such a node, with the note |
| 7. Forgetting | The step forgets everything. `map` forgets what the folder it adds had agreed. The cycle's own forgetting stays (the record of 2026-09-30, 4.5). Nothing is forgotten at every start |
| 8. What status and requests carry | For a panel that is not yet brought up to date: `state` and its seven names, with the notice as `attention`; and a found entry's directory, carried only where `map` would sync that folder. Nothing is carried for an older command line or an older node |
| 9. Status offers `map` only where it maps what was found | A command that status prints for a folder it found is one that would sync that folder |
| 10. The panels | They are not in this repository. Until a panel is brought up to date it draws from `state`, and its switch for everything is refused by the node (rule 4) |
| 11. What goes from the code | What served a scope of everything found. The step runs where "When" above says |
| 12. The documents | They say the same as this section: the README (what syncs, which channels a device is in, what stays out, the status lines), the commands' help, the whitepaper, the record of 2026-09-30 (4.5), the threat model's rows, and the install page |
| 13. One level, worked out in the command | With what section 8 adds, below |

**The level, with a person's devices in it** (rule 13, and section 8). A level is for a personal node that runs, with sync on. With nothing mapped, the notice, errors and a stalled cycle are red.

- **Red,** ahead of everything else: this device has stopped (it was removed, or is in no list, or is in a fork, or was answered with a change that it could not open or apply); the step of this section has not succeeded; and then, where something is mapped, that it follows no phrase ("not added yet", or "no recovery phrase yet"). **This is red on every device after this upgrade, and on every new install with a folder mapped, until a person acts,** and that is meant: nothing it holds syncs until then (section 10). A device that is not to be added turns sync off.
- **With no phrase, `state` is `attention`,** so that a panel which is not yet brought up to date does not show the device as synced.
- **Amber,** after what else is amber: a removal that some device has not applied, for its first seven days; a device added since the last change that nobody has cleared; a device that has said it left; a relay that has been connected for more than five minutes, by the node's own clock, and does not hold the latest change; a relay that refuses a new channel for room or for the address's allowance (with the entries that relays keep refusing); names that are not yet in the new generation, or not yet sent, for more than five minutes. (A relay that has not been heard from since the device woke is in `cordelia devices` and not in the level: a machine that wakes is not amber for the seconds it takes to find its relays.)
- The line shows the first thing of the gravest level, and the tooltip everything.

## 11. The lock (its derivation only)

A locked channel is one envelope, not two. Its secret is HKDF(person secret and the lock's key together, `cordelia v2 locked` + length + name). A device without the passphrase cannot compute the channel: it sees nothing, fetches nothing, and cannot write, strip or fill it. **The lock's key is random, and is unwrapped by the passphrase, not derived from it:** the lock can then have several ways of opening, each wrapping the one key, and a change of passphrase re-keys no channel. The derivation takes the lock's key as it is given.

This record fixes only that, so that the lock needs no change to the wire. One rule is kept for it: a locked channel is carried only by a device where the lock is open. The lock itself is not designed here, and follows in a later version (section 14).

## 12. What it costs

- **Every device of yours can read every name of yours,** whether or not it maps it. Under the record of 2026-09-30 a device holds keys only for the names it maps. A stolen disk yields every name, and `add-device` hands over every name: it asks a yes at a terminal, which stops a bare call to the local API and not an agent that has a shell (section 5).
- **The phrase is one more thing to keep,** and without it no device can be removed. In this version it cannot be replaced, only begun again. Whoever holds a copy of it reads everything from then on, through every removal, without a sign (section 5).
- **Nothing syncs, and nothing is at a relay, until there is a phrase** (5.2). A machine set up with no person at a terminal keeps its memory to itself until it is added from one that has a phrase, and `accept` asks its yes at a terminal too.
- **What a removed device wrote, and a remaining device took before it applied the removal, is kept** (property 2), and travels at its revision. In that time the removed device can: put a text at the next revision of any file, or a delete, which a device that has not heard takes with nothing kept beside it if the entry claims to follow what it holds (local history has what it replaced, for 30 days, where history is on); replace the index, or plant a line in it; write files up to the old channel's size, which each such device then carries. Every other device takes each of them, and each version that a device wrote over one, with its own text kept beside the file.
- **A device that can reach only relays which the removal has not reached is such a device,** whether it was off or on, for as long as that lasts (property 2, 4.6). In that time it also sends its own edits to where the removed device reads.
- **What a removed device wrote that no remaining device had taken is left behind,** unless a person asks for it by name, with the phrase (7.3): its work in a name that only it synced, and its last edits where every other device was off.
- **Conflict files that were not needed** (7.3, 7.4): on a device that was behind a removed device's versions, one for each file that the removed device had written since; and on a device more than about a hundred versions of a file behind. And a text that the removed device had deleted comes back as a conflict file wherever a device still held it.
- **After a removal, devices that have not heard of it do not exchange memory with those that have,** until they do. A device that is online hears within one pass.
- **After each statement every device fetches every name it syncs again.** A name that no remaining device syncs is not in the new generation until a device maps it or a person carries it.
- **A recovery stops every other device** until each is added again by hand. A device that the person still has is no device until it is added again. A recovery reaches back 90 days from when the last device was on. Where a first recovery was cut short, the next one brings back what the first had sent; the rest of what a gone device wrote comes in by a command, with the phrase. A machine that recovered holds the secrets of up to eight earlier generations for 90 days, which no other device holds for a generation it was never in.
- **A device that starts, or comes back online, waits up to 30 seconds** for a relay that it cannot reach before it syncs (4.6).
- **A phrase makes at most 256 statements** in this format, and removes at most 256 keys: a device that counts can use that up, 63 declined additions at a time (4.1). The way on is a new phrase.
- **A file may be 60 KB,** where the record of 2026-09-30 allows 64 (2.3).
- **A name that a device has put out of reach stays so until the next statement,** whichever it is: a removal of that device, or a renewal (2.3).
- **For the one version in which a relay carries both kinds of channel, it can hold twice its cap** (2.5).
- **The first removal after the upgrade asks about every device but the first,** unless a renewal was made (section 10).
- **An intruder who reads a device's database has the person secret,** and reads everything until the next removal, with no sign (section 6).
- **Two changes made apart stop every device that sees both,** until a person settles them with the phrase.
- **A relay holds a carried version once for each device that carried it** before it saw another's, each until the device that carried it writes that file again; and the channels that were left, for up to 90 days, or for as long as a removed device goes on proving them (2.5). So a text that was deleted stays at the relays, encrypted, in those copies and channels for that long. An entry is padded to a power of two, so a channel can hold as little as half of its 16 MB in text.
- **A device that is removed by mistake starts again:** a new key, and a first sync, with a copy beside each file that differs. A device that the person declines at a prompt is removed, and is in the same place. So is every device but one after a phrase is lost or has leaked (section 5).
- **Every device that ever followed the phrase can read every later statement:** who the person's devices are, by key and label, and which of them made each change. A removed device keeps the statement key and its last change entry, and is answered with each later one (4.6). It cannot open a secret. A later format could put the statement under the secret before it as well, so that a removed device reads the one change that removed it and no more; that brings back a device that is too far behind to read a change, and is not in this version.
- **A relay hands the change entry to whoever shows it an earlier one,** with no proof of a key (property 7's exception).
- **Every statement starts the 90 days of every delete again:** a delete is carried as a new entry.
- **A statement made on a device that is then lost, before any relay held it,** can be shown later by whoever holds that device: a device that is far behind follows it until it sees the other, and the two are then settled with the phrase (7.6).
- **A pair channel's secret never changes.** It is used when a device is added and at no other time, and a copy of either device's key file opens whatever a relay still holds of it: the hand-over, with the secret of that generation.
- **The device's key, the person secret and the statement key stay in files and in the database.** The move to the operating system's keystore is not in this version.

## 13. Tests

Each property of section 1 has tests. The threat model's rows T16 (a device that was removed) and T20 (a device of yours that has been taken over) name tests of them ([`docs/security/threat-model.md`](../security/threat-model.md)), and CI checks that each test named there exists and runs. The derivations have published vectors (`docs/reference/step4-test-vectors.json`). What is tested, by area:

- **Sequences of edits, passes and changes of devices,** in a harness that runs them over several devices and asks where each text ends. Each edit in it has a text of its own, so a check can ask where a text is, and the harness keeps each version's true history, so a check can ask what a version followed. (A version's true history, in the harness, is the version it was published over, and that one's. A merged index follows both of its sources, and a text that a step puts back by hand follows the version the file held.)
  - **A pass to a device carries the change entry first,** as a relay's answer does: a device that is passed to by one that has applied hears, applies and carries. A step makes a device hear late, or never: its passes then carry no change entry, as from a relay that lacks it, and nothing passes between a device that has applied and one that has not.
  - **The steps:** remove a device (on any device, with the phrase); a removed device goes on writing, at any revision, at the size limit, and saying anything of what it wrote after; a removed device publishes a file again unchanged before it is removed, and signs two versions at one revision; a device hears late, or never; a device takes a late version and edits the file before it hears; a device applies two changes with no cycle between; two devices remove at once, or one twice and one once, or both remove the same device; a device is added; the maker stops straight after the statement; a device is off through a move with an edit not yet published.
  - **Every file as it was:** once every remaining device has applied, and everything has met, every file that is not a conflict file is, on every device, as at the same point of a run with no removal in it in which each pass between a device that had applied and one that had not is left out, and each pass of a device while it was in a fork, the removed device's writes after the removal left out of both runs; and the text of every conflict file of that run is in a conflict file of this one (an extra copy takes the first free name, so the names can differ). A move changes no file, and keeps no less.
  - **No text lost that nobody let go of:** a text is let go of only by an edit made on a device that had not been removed when it made it. Left out of the check, as the limit that property 2 states: a text replaced on a device that had not applied the removal, by a version that the removed device wrote after the statement was made; and a line of the index for a file whose late delete a device took, which a merge then drops (7.4).
  - **No entry in a new channel is signed by a key that does not count under its statement,** and nothing written by a device after it applied a removal can be read with what the removed device holds.
  - **Nothing the removed device wrote after the statement was made is in any file of a device that applied the statement before it took anything,** unless a device that had not yet applied it took it: asked of the texts themselves, with steps in which the removed device writes into channels that only it and a device that is off sync, and into names that no remaining device syncs. (The harness has no relay: "before it took anything" is the condition of property 2, and a test with real processes shows what happens where it does not hold.)
  - **No text is replaced with nothing kept, on a device that takes from a new channel a version whose true history, above what the device had agreed, holds a version that the removed device signed,** that version itself included: asked of the histories the harness keeps, and whoever wrote the text that is replaced.
  - **After any sequence, every device that has applied the last statement holds the same list of devices,** and no statement any device has applied lacks a key that an earlier one of its own removed.
- **The statement:** each rule of 4.2 alone; a removal undone by a later statement made apart; a fork at one number, at a higher one, and two and three changes deep on one side, seen from each side; a statement that is behind; a settlement, applied from each branch, and from a device that had applied neither; that it undoes nothing; a statement that lists this device with a secret that does not open, and the way on from there by `accept`; a statement that does not list this device; applying stops a cycle that is running, and carries in the same transaction; a secret that does not match the commitment; the bounds, the entry's size at every bound together, and the two hundred and fifty-seventh statement refused.
- **Adding:** a record under another statement; a chain of three (the third does not count); a device that signs a hundred records (those counted first stay counted, and no other device's addition is displaced); the sixty-fifth; a record by the key being removed, and one by a key that it had added, that arrive between the prompt and the phrase (the removal is made, the command does not ask again, and each key is in no list).
- **Which phrase a device follows,** in units and with real processes: `accept` in each state of 5.1's table, a device that is alone under a phrase it did not make and one that could not open a change among them; a hand-over under another phrase (taken only where the table says); on a device that is one of several, a hand-over under its own phrase with a change it can apply (taken, after its yes) and one with nothing to apply (it does nothing); `accept` with no terminal is refused; `cordelia phrase` on a device that is one of several leaves them, and each of them shows that it left; `cordelia phrase` on a device that is alone under a phrase; `cordelia init --new-key` forgets what 5.2 says, and no more.
- **Derivation,** with the published vectors: each label; no two kinds collide; the name's length; the ID from the secret; the pair channel from either side; a key of small order and a zero secret refused; the statement key; the commitment.
- **A relay,** with real processes: a stranger with a channel's ID pushes, pulls and asks what it holds; a removed device asks for the new channels; an entry with one signature missing or wrong; a proof replayed on another connection; a channel that a relay does not hold and a proof that fails, answered alike; a relay at its cap, through which a removal is still heard and stored; a change entry larger than the one before in what it says, stored at a full relay (they are the same size on the wire); shown an entry: the same, an earlier one, another at that number, a later one; a channel unused for 90 days goes, and one whose entry a device shows does not; the daily proof of a name that no device syncs; a relay that takes a person's channels from one it works with, and then makes room: the phrase's channel goes last, also where the relay had taken that channel from a device before it took the names from the other relay; a relay that carries both kinds: older channels filled to their cap by a key that is no member displace no new channel, and new channels made without end displace no older one.
- **The change entry,** in units and with real processes: a device answered with a later one applies it in one step, with no state between; one that is two and three changes behind; a device that is not listed reads that it was removed, or is in no list, and cannot open the secret; a relay cannot read either part; an entry signed by another key than the phrase's; an earlier entry shown to a device (nothing is done); two at one number (a fork, and both lists are shown); a maker that never held a generation's secret passes it on; a device that wakes with one relay that lacks the change and one, slower, that has it: it takes nothing and sends nothing before the second answers; with the second out of reach it does both after 30 seconds, and says which relay it has not heard from; what waits to be sent goes to no relay ahead of the show on that connection, and nor does an answer to a relay that asks the device for its entries at connect, an announcement of its channels, or what its queue sends again; nothing that a relay pushes is taken ahead of it; a long pass shows again before each channel; a personal node that meets another directly carries nothing of these channels; a device that is answered with a change and cannot write its database sends nothing and takes nothing, says why, and applies at a later pass.
- **Carrying,** on two stores:
  - applying carries every name it holds in the one transaction, and a cycle that runs at once changes nothing; an entry of an old channel is refused, and what waited for it in the outbox is dropped, once a change is applied;
  - a version by this device (it is carried with its chain); by another device (it is this device's own entry, with the version's chain and a first link for the key that signed it); a carried entry carried again at the next statement (one link more where another key signed it); a delete;
  - **the chain:** a version whose chain holds the folder's text with every newer link signed by a key that counts (taken with no copy), with one newer link signed by a key that does not (the text is kept), and without the folder's text (kept); the first link, and the hundredth; one more behind (kept); a hash that stands twice (the newest link with it decides); a chain that cannot be read is not copied by the entry written over it; an entry with no chain, and one whose chain cannot be read (known to follow nothing);
  - **a late version of the removed device's,** taken by a device that had not heard and carried by it, with and without an edit over it, and one signed at the revision where another device then writes a text the removed device cannot read: every other device keeps its text; a folder that held the removed device's last version takes an edit written over it, and one two further on, with no copy; the removed device signs two versions at one revision, and a folder that holds one keeps its text when it takes an edit over the other;
  - **a merged index:** one whose own source stands in the channel's chain adds no link, and a folder at that source keeps its text where the removed device signed a version in between; one whose sources were written apart puts its own second, and once a link of one chain is left out for standing further on in the other, takes nothing more from that chain (also where the other chain was cut at 100 behind the shared hash);
  - **several entries of one version:** a version held in several entries is written over, and carried, from one of them, and a forged chain in a twin entry is not put behind an honest signer; two entries that are one version (a link for each signer, and known to follow only if each entry shows it);
  - a folder restored from a backup, whose device then writes: the versions it had published before are not known to follow its new one;
  - **sizes:** a text of 60 KB with its name, and a chain of 100 links (it fits, and is carried); one byte more (too large to publish, and no version where another device wrote it); an entry that does not open, one that is not an entry's content, and one in a band it may not be in (each is passed over, counts for the next revision, and is not carried); a record with no version under it (dropped, and the file is published as new);
  - **ties:** a text that beats a delete; a tie held whole, and a tie of which each device holds one side;
  - **sending:** what was carried is not sent where the relay's copy has that version, or a higher one, and what is refused for room there is dropped; two devices that send one name at once at a channel near its cap; the personal channel's list of names;
  - **a carry by command:** `sync carry` of a name from each of two generations that were left, for a name that is synced and for one that is not, and with no name: what keys that count signed is taken and what the removed key signed is not, a file it had deleted comes back, a version below what the new channel holds is not brought in, and one that ties with this device's own entry is not brought in and the command says so; with `--from`, with the phrase, it is; with no terminal, or a yes and no phrase, it is not; run twice, the second takes what a relay that was down held; not after 90 days.
- **A revision:** the renumbering keeps the order of every two revisions that an entry may have; one, two and three statements behind give one result; the next revision in each of its cases, and two devices under two statements that edit one version give one revision; an entry in a band above the statement's counts for nothing. And on stores: a revision in the top half of its band goes to the next band on every device alike, with the record that speaks of it; a remaining device's edit over it keeps its place above it; a device that was behind carries an older version by the same writer, and the newer stays the file on every device with nothing lost; a device two statements behind gives each version the revision that the others gave it; an entry in a band above the statement's, or in the top half of a lower band, is no version; at the top of the statement's own band nothing more is published, and after the next statement it is.
- **Removal,** with real processes: with one device off, which returns with an edit it had not sent; while a relay is down (the command names it, and does not say the machine may be closed); with what the maker carried unsent (the same); cut short after the transaction and restarted; the maker gone for good after a relay holds the change, and before; two removals from two devices, and the settlement; a statement that arrives between the prompt and the phrase; the removed device writing through the removal, on a device that is on and on one that is off, into a name the maker syncs and into one it does not; a device that returns to a relay that lacks the change: it takes what the removed device wrote there, edits one of those files, and when it later applies the change every other device keeps its own text beside what arrives, the edit included (the limit of property 2, shown); a statement that no relay held, shown later to a relay that holds an earlier one (a device that is behind applies it, and one that sees both is in a fork).
- **The two commands,** with real processes: `add-device` and `accept` with no terminal are refused, and each run under a pseudo-terminal is not (the limit of section 5, shown); `add-device` names what it hands over; every device shows the addition until it is cleared; a pair channel is read only within its hour; a folder's first cycle in a channel waits for its first fetch there, so that a file the others hold is not published a second time; two devices that each publish a file into a channel that was still empty at every relay meet as a tie, with the text that loses kept; a command that makes a statement shows its lists from the bytes it signs: a node that hands it other bytes than it described is shown for what it handed.
- **Recovery,** with real processes, with the phrase alone on a clean machine and no device left:
  - what the lost device wrote comes back; the other devices are answered with the change at once, before anything is carried; a device still in the old generation reads that it is not in the change;
  - a device said to be in someone else's hands: the look takes nothing that it signed, and carries what it had written over; a key that such a device added is marked with it, and a record that arrives after the prompt counts for nothing in the look; a name that only a marked device listed is not carried, and a name listed by a key in neither list is not read;
  - the names are listed before any is carried, also by a machine that maps no folder; the names read from the generations before, where the statement lists one device and its own list reached no relay; a recovery from a statement that lists two devices, whose personal channel reached no relay, finds its names in the generation before; the 1,024 names of a recovery;
  - `--from` by the first words of a fingerprint, and with no key named a list of the removed keys that signed; `--from` takes only empty slots without its second yes; it refuses a label that matches two keys, and its second yes for a name with no folder; a carry with the phrase reads a generation that the device never held;
  - a device added since the statement, and lost, is carried from as the statement's devices are; an edit that a remaining device had sent to the generation before, above what was carried, comes in; at the end of the look the command says what each removed key signed that the new channels lack;
  - cut short after some names, and begun again on another machine: what the first had sent comes back by itself, and what the lost device wrote in the files not yet sent comes in by `sync carry --from` with the phrase, and not without it; two devices gone and the first recovery cut short: `--from` with both keys in one run takes the newest of the two in each slot; a third recovery;
  - after the command has ended, a restart sends on and fetches nothing that a removed key signed; a later statement on the new machine carries the names it holds with no folder mapped;
  - a statement made on a remaining device meanwhile is a fork, seen by whichever of the two is answered with the other's, and settled from it; a recovery after a settlement; from a relay that holds only an older statement, and the device that went on sees the fork; two relays that hold entries on two branches at two numbers (a fork); an older change entry shown to a relay that holds a later one is not taken;
  - with two devices left, each added again, and what each wrote since comes back.
- **The upgrade,** with real processes: two devices and a relay on the version before, in step; each takes this version and publishes nothing; the phrase on one; the other added; every file on both, no copy made. The same with one device behind: the copies are where section 10 says. A device left on the version before, upgraded later.
- **The first start** (10.1):
  - a database in the form of the version before, with rows of every older table, a stored report in that version's own bytes, folders that had agreed files, older channels of each type, a queue of things to send and devices trusted, is started on this version. The copy is there, at this schema's version, whole by the store's own check, with every older row and each key file, and with its modes. The records, every older row (each table by name) and the older key files are gone from the node's own. The key, the settings, the mappings, the counters and local history are as they were. Status says "not added yet", its `state` is `attention`, and nothing is published or fetched;
  - with the scope stored on: the notice names what the last report showed, with sync on and with it off; with a report that cannot be read, the date alone; the scope is off afterwards;
  - a second start changes nothing and makes no second copy; a start in a later version does not step again; a first install writes the mark and makes no copy; a database that follows a phrase and has no mark is not stepped;
  - a node that cannot bind its port changes nothing; until the step has succeeded: no cycle, no pass, each changing request refused and turning sync off taken, and status saying why; and it is tried again without a restart;
  - a copy that cannot be made: no step, no older row or key file changed, no mark; a `.partial` left by a start that died is made again; a whole folder with no mark is kept as the earlier one; a step that fails half way leaves nothing of it; a crash after the commit and before the key files are removed: the next start removes them;
  - the guard: a new row in the older table of channels is refused with its words; a relay's start removes it; a relay's database is stepped, keeps every older row, and makes no copy;
  - a database from a later version: refused by the node, which stays up and says so, and by each command that opens it;
  - rule 6's refusal, for each command it names, and each command that still answers; turning sync off against a node of another version;
  - with real processes: a device in the form of the version before is started, a phrase is made there, and its mapped folders are published as a first sync.
- **Before a phrase,** with real processes: a new install with sync on and a folder mapped publishes nothing, and no relay holds a channel of it; after `cordelia phrase` the channel of it that a relay has held longest is the phrase's.
- **One place to look,** with real processes: each line that section 8 gives `cordelia devices`, a device that has applied and not yet sent among them; each colour of the status line, in the state that it is for; each thing in the two lists of the level (10.1), the order among them, and the two five-minute waits.

## 14. What was decided, and what is put off

**Decided, and in this version:**

1. **What a removed device writes before a device hears of its removal may stand on that device** (property 2). That holds for a device that was on, in the moments before it hears. **A device that can reach only relays which the removal has not reached is covered by the same yes as any device that has not heard,** for as long as that lasts. One thing bounds what the command that removes can promise: **its all-clear covers the relays that the device it is run on is set up with,** and relays are set on each device.
   - **What happens.** A device that has not heard of a removal takes what the removed device writes as it takes any device's edit: with nothing kept beside the file, where the edit says that it follows what the device holds. When that device hears, it carries what it holds, and the late text is then the file on every device. Each other device keeps its own text beside the file when it takes it, and likewise when it takes anything that a device wrote over the late text (the chain, 7.3). On the device that took it first, the text it replaced is in its local history.
   - **How long a device can go without hearing.**
     - **One that reaches a relay which holds the change:** the pass that is under way. Devices ask every ten seconds, and show their change entry first.
     - **One that reaches only relays which do not hold the change,** whether it was off or on: for as long as that lasts. Three things bring it about. No device with the change has reached those relays, and no relay with it passes it on: with two relays that pass entries to each other, as the two default relays do, that is one relay cut off from the other and from every device that has the change. Or a relay has lost the phrase's channel and has no room to take it again (2.5). Or something at the same address as the device uses up the address's limits at a relay (2.5), which a removed device that is still in the house can do.
     - In that time the device also sends its own waiting edits to the old channels, where the removed device reads them.
   - **Against the record of 2026-09-30.** There the device that removes is the cut: it publishes again what it holds of the removed device's entries, and nothing later (that record, 4.1). A late edit that another device takes before it has applied the removal ends beside the file as a conflict file, and the file goes back to what the remover published; a late delete is undone. **So for a late edit and a late delete that record is the stricter:** there the late text ends beside the file, where here it is the file, and the honest text is beside it. That record is weaker elsewhere, as its own section 9 says: there a removal is a change of key for each channel, which can wait for one device to make it, and which each other device has to hear of, channel by channel.
   - **The stricter way, which is not taken, and what it costs.** The device that makes the change alone would carry what the removed device wrote, from what it holds, and every other device would carry only its own entries. A late text is then carried by nobody, and ends beside the file. Its costs:
     - until the maker has carried a file whose current version the removed device wrote, the new channel holds an older version of it. On each device that syncs first the file goes back, with its text kept beside it, and returns when the maker's carry arrives: conflict files on every device, for every such file, at every removal;
     - if the maker is lost before its carry is done, everything whose current version the removed device wrote stays behind, though every other device holds it;
     - what a device wrote over a late text is its own entry, and is carried all the same: the promise would be only for a late text that nobody has edited.

     It is not taken, because it brings back waiting for one device, to close a window that is one pass long for a device that is on.
   - **Local history is the way back, for a person who looks.** It holds what each device replaced, for 30 days, within 256 MB. It does not defend against a device of the person's that has been taken over and floods it (the record of 2026-09-30, section 9).
   - **What neither way touches.** For a device that is stolen, the larger window is from the theft to the removal.
2. **Recovery is as section 9 has it:** the person says which devices are gone, keeps the new machine on while it brings back what the relays hold, and adds the rest back by hand. It reaches back 90 days after the last device was on. The other devices are told at once, and stop. A recovery that is cut short: the next one brings back what the first had sent, and `cordelia sync carry --from`, with the phrase, brings the rest. A device that the person still has is not a device until it is added again. And where a device of the person's remains, the removal is made from it, and there is no recovery.
3. **The phrase is typed** to remove, to recover, to settle two changes made apart, to renew, and to bring in what a removed device left behind (7.3). Never to add. A person who has lost it can add devices and can never remove one, short of starting again with a new phrase. And nothing syncs until there is a phrase (5.2).
4. **The upgrade is a new start** (section 10): the phrase on one device, and each other added with the two commands. The relays carry the older channels for one version more, each kind within a cap of its own, so that a device that has not been upgraded is not cut off in the middle. A personal node does nothing of the older kind from this version on.
5. **A relay's room** (2.5): an allowance of 256 new channels an hour for an address; the newest still go first; what nobody has used for 90 days goes. And what is not defended: a full relay, older channels filled and kept by whoever holds their keys, and the limits by address.
6. **What a device no longer does:** it has no inbox, no sealed channel states, no epochs or key rings, no join requests and no owner roles. A relay goes on carrying the older kind of channel, which has them, for one version more (section 10).

**Put off:**

7. **Replacing the phrase** (section 5) is not in this version. Until it is, a phrase that leaks, or is lost, means starting again with a new one, on every device: one makes the new phrase, and each other gets a new key and is added again. A leaked phrase is worse than it reads: its holder reads everything, through every later removal, and nothing shows it. And a phrase makes at most 256 changes.
8. **The lock** (a passphrase on a device's own store) follows in a later version. Its derivation is fixed here (section 11), so that it needs no change to the wire.
9. **A code that the new device shows,** to add it, with the rule that a device adds and removes nothing in its first day, is a later step. Until then a device is added by the two commands of section 6. Both ask a yes at a terminal, which stops a command run by mistake and not a program that runs as the person, and every device shows a new device until someone clears it.
10. **Meeting directly between two of a person's devices,** under the rule of the show (4.6), is a later step. In this version these channels travel only through relays.
11. **A successor channel at a relay,** which takes the standing of the channel it follows (2.5), is a later step.
12. **The operating system's keystore** (section 3) is not in this version. The device's key and the person secret stay where they are.
13. **A command that puts beside each file, from local history, what a version of the removed device's replaced since a date that the person gives,** is noted, and not in this version.

## 15. Where to look for faults

For an outside reviewer: where this design is under most strain, and where a fault would cost most.

- **The time before a device hears** (property 2, 4.6). Everything that a removal promises starts when a device applies it. A device that reaches only relays which lack the change takes what the removed device writes, and sends its own edits where the removed device reads, for as long as that lasts. Look for anything a node sends, serves or takes on a connection ahead of the show there, and for any answer that gives leave and should not.
- **The chain** (7.3). A sequence in which a text is replaced with nothing kept though it was not an ancestor of the version taken, or though a key that does not count signed a version in between; a chain that an entry forges, and what the forger must know to do it; a merge of two chains; the window of 100 links; and the put-back of index lines, which a chain does not show.
- **The renumbering** (2.3). Two revisions whose order it changes; two devices that give one version two revisions, whatever each holds and however far behind it was; a revision that speaks of another and is not moved with it; a name that stays out of reach after a statement; an entry that a device takes in a band it should not; what a device that still counts can do with it.
- **A relay's room** (2.5). A relay that is full takes no new channel. A removed device holds every channel of the generation it was in: it can fill them, and go on proving them, so that their room is never given back; at a relay that is over its cap it pushes out the new generation. Every limit is by address, and a removed device at the same address can use each up. Two caps for the one version that carries both kinds, and tenure by the earlier of two times (2.4), are new.
- **Recovery** (section 9). It cannot know whether the statement it found is the latest. Everything a gone device wrote up to the moment of the look is carried, and a relay keeps nothing older. A gone device can have listed names, and can be shown under a label that is not its own. Look for what a recovery that looks once loses, and for what a device marked as gone can still get in.
- **The phrase** (section 5). It is one secret, typed at a terminal. A copy of it reads everything, through every removal, with no sign, and cannot be shut out short of starting again. It makes at most 256 statements and removes at most 256 keys, and a device that counts can use both up.
- **A program that runs as the person** (section 5, T17). Every yes can be given by an agent with a shell. What is left is that every device shows an addition, and that nothing which asks for the phrase can be done without it. Look for any way to have the phrase sign a list that the person was not shown.
- **Which phrase a device follows** (5.1). Any way that a device which is one of several is moved to another person's devices, and any hand-over taken in a state where the table says it is not.
- **One secret for every name** (section 12). Every device reads every name, a database that is read gives up the person secret, and a pair channel's secret never changes.
- **What stays readable** (4.6, section 12). Every device that ever followed the phrase reads every later statement, and a relay hands the change entry to whoever shows it an earlier one.
- **A folder's first cycle after its first fetch** (section 6): what it holds up, and for how long.
- **A record with no version under it** (4.2): what dropping it loses.
- **Section 13:** a promise in this record with no test, or a test that cannot hold as worded.

## 16. Rules the implementation keeps

- **Applying is one transaction, and the store enforces it:** from that transaction an entry of an old channel is refused, what waits in the outbox for one is dropped, the device's carry is in the new channels of its own store, and the adapter's notes of kept copies are cleared.
- **A relay counts its room by what its entries are counted at,** and not by the database's pages: an entry that replaces one of the same size never tips it over its cap.
- **The answer to an entry shown** counts against the asker's limits, and the two signatures are checked first.
- **Whether a version is known to follow is one rule over a chain** (7.3), in one function. An entry written over another puts that one's link first, by one function, and publishing has no loop that makes an entry say less.
- **Room for what an entry says is kept in every entry** (a chain of 100 links of 32 bytes): the bound on a text and its name is one constant, 60 KB, and the room is what the content's bound leaves beyond it, with a test at every bound together. The local API's publish goes through the same path as the adapter's, and says what it was published over.
- **The renumbering is one function of a revision,** used wherever a version or a record crosses a statement, and the check of an entry's band is one function of a revision and a statement's number. The next revision is one function too: one above the highest, moved as the renumbering moves it where that is in the top half of a lower band, and none where it would be above the statement's band (2.3).
- **Nothing is sent, served or taken on a connection ahead of the show there:** the outbox's timer, the publish path and the queue of things to send again go through it, as the pass does; so do the handlers that answer a relay's request for a device's channels and entries, the announcements at connect, on announce and on the governor's tick, and the handler that takes a push.
- **A relay's room is counted by kind** for the one version that carries both: whether it takes a new channel, and what it drops to make room, each look at one kind. Each kind's room is counted by its own rows, and not by the database's pages, which hold the tables of both. The value that both ends export from a TLS session, for the proof, has a label of its own.
- **When a record of an addition comes to count,** the device reads every channel of its own again from the start, from each relay: an entry of the new device's that arrived before the record was refused and not kept, and has to be given again. (Otherwise two readers that saw the record and the entries in two orders would count the same key and hold different entries.) The same holds for a record refused because its signer did not count yet.
- **A folder's record keeps the signer and the chain of the entry it agreed.** The chain's type sits below the sync adapter, in `cordelia-crypto`, since the local API's publish builds one too. Where there is nothing to read (an entry without its chain, a record without one), the answer to "is it known to follow" is no. The plan is given the keys that count, and every entry of a version. Local history names, for a carried version, the key in its first link, not the carrier.
- **A statement that commits to the secret already applied is refused:** the old channels and the new would be one.
- **Who may add** does not go by the order in which records were seen: a counted key may add where any record kept for it was signed by a device of the statement.
- **Secrets that were left** are kept in the order of their numbers, not of the clock.
- **Names in the personal channel:** a device's word that it has applied a statement is under `applied/<its key>`, a record of an addition under `added/`, a device's word that it has left under `left/<its key>`, and a device's word that it syncs a name under `name/<the name>`, written when it maps the name and deleted when it unmaps it (what 2.5 and 7.1 read as the names the personal channel lists). A word is read as a name only where it is one that this version would itself map, in its one spelling: what another device wrote there is otherwise counted and never shown. The change entry is under `change` in the phrase's channel, and a hand-over under `hand-over` in a pair channel. The hand-over holds the change entry whole, so that the new device can keep it and show it.
- **A show is short after the first on a connection** (2.4, item 5), and the leave it gives a device lasts 10 seconds (4.6): one function gives that leave, and no stream for a channel of the device's own is opened but through it, nor is what comes back taken. A relay asks its memory of the connection before its store: a short show of anything but the entry shown whole there is answered without a look at what is held.
- **A relay counts requests on the streams of these channels,** as it counts the older kind's writes and syncs: 3,000 a minute for a connection (`ENTRY_REQUESTS_PER_PEER_PER_MINUTE`), sized for a device with 256 names (a pull of each every ten seconds, its day's proofs in one burst, its shows and what it pushes), and a breach beyond it.
- **A relay writes that a channel was used at most once an hour,** and never an earlier time than the one it has: a proof, or a show, is otherwise a write for whoever asks.
- **A pull that is refused because the asker has had its bytes for the minute is no breach:** the relay sized the page, and the asker cannot know its room.
- **The address that a connection's streams are counted under is read once,** when the connection is made.
- **One relay never holds up another** once the device is awake: each relay has its pass, and the wake rule is the only thing that couples them.
- **A request is sent only under the change entry that it was built under:** the one way in is given that entry's ID and refuses, at both askings, where the device keeps another; a pass at a relay ends when the kept entry changes, and the next reads the device's channels afresh.
- **A machine that slept wakes:** where the wall clock has run ahead of the clock that cannot go back by more than the leave, every leave is dropped and the device asks every relay first.
- **A change that could not be applied is kept and tried again at every pass,** whatever becomes of the connection it came on, and nothing is sent or taken until it is dealt with.
- **At a relay, the answer to a show is handed while the asker is not yet over its bytes,** so it can take the asker over by one entry and no more; after that a show is refused as "not now", with no breach, until the minute frees. A pull is sized to leave room for one entry of the largest size in the key's allowance and in the address's (`SHOW_ANSWER_ROOM_BYTES`), and only the answer to a show may use that room: a device that pulls at its full rate, or shares its address with one that does, is still told of a removal. (Whoever shows entries of its own from the same address can still use that room up: 2.5, what is not defended.) A whole show that is reset, and so not answered, does not start the device's wait that doubles.
- **A push is answered "held" only for that very entry:** where the relay holds another from that author at that revision in that slot it says so, and the device sends it no more and says so in its status.
- **A pull of a channel that was proved on the connection and is not held is answered as no holding,** and the device then knows that nothing it sent is there.
- **A device goes on past what a relay refuses for room:** what follows the refused entry in a channel is still offered, since a delete, or a replacement that is no larger, makes room.
- **A device stops pulling a channel for the pass where a page does not move its place,** and takes from one relay in a minute no more than a relay may hand a connection.
- **A show that gets no leave is made again after a wait that doubles,** as after a refusal for room.
- **What a command shows as this device is its own reading of the key file,** never the node's word: it refuses where the node names another key. A record of an addition is shown only where it names the applied statement and its adder is a device of that statement or was added by one. Where the maker's own key is not in the applied statement it is shown as an addition, with who added it and when, and its listing is confirmed by a typed answer. What the prompt was shown over is worked out by the command from the entries it holds, not echoed from the node.
- **Everything that comes from the phrase is wiped with it,** and the process that signs cannot be dumped or traced. The wait that follows a change runs in a new process, which never held the phrase. **The phrase is shown only where what the command writes to is a terminal too,** and is cleared from it before the words are typed back. Ctrl-C at a prompt that hides what is typed is read as a key, so that the terminal is always put back.
- **Where a command cannot learn whether the node made what it was handed** (the answer was lost), it asks the node again before it says anything, and where it still cannot know it says so: the words of a new phrase are then to be kept until `cordelia devices` shows which it is.
- **A key typed at `accept` is kept with the row of 5.1 that its yes named.** A hand-over that arrives when the device stands in another row is not taken, and says why. Making a phrase, following one, and leaving one each forget every key typed. A device keeps at most 8 typed keys.
- **The commands of a person's devices refuse a node of another version than their own:** a route of the same name may mean another thing there.
- **A pass, the status and every command are given every relay the device is set up with,** by name, whether or not its name resolves: a relay that cannot be found is one that has not been heard from.
- **A device's store holds one generation.** What it left is dropped in the transaction that applies a statement, after the carry; a carry by command fetches from the relays.
