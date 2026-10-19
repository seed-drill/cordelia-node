# Decision: a relay out of reach

**Date**: 2026-10-19
**Status**: Proposed. Not built. It is the third form of "a relay that stays out of reach". The first two were reviewed and found not sound to build from (section 13). Nothing here is built before this form passes a review of its own.
**Cited as**: "decision 2026-10-19 §4, rule 7". The numbers do not change. A number that is not used stays unused.

Words used throughout:

- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md). **The record of relays** is [`2026-10-17-a-devices-relays-and-connections.md`](2026-10-17-a-devices-relays-and-connections.md), and **the record of recovery** is [`2026-10-17-recovery-and-carrying.md`](2026-10-17-recovery-and-carrying.md).
- **Alpha.12** is 0.2.0-alpha.12: the node as main has it when this record was written (commit 9cf7250), which the next release carries. **This version** is the first that carries what is below.
- Examples say laptop and desktop, relay A and relay B. A is reached; B is the relay out of reach.

---

## 0. What this is

**What was seen, on the first real machines.** A laptop could reach relay A and never relay B. It was in step with the other devices, and yet:

- it never wrote that it had sent what it carried, so every other device said of it "is still sending what it held", for good;
- a change made on it left the command that made it saying "keep this machine on", with no end and no word of what to do.

On a build machine at a site that cannot reach relay B, two more things were seen. The node waits 30 seconds at every start before it syncs. And it says of B "has not answered since this device woke", though B was never off.

**The ruling** (the person's, 8 October): a relay out of reach is acceptable while a device has one connection, and should only warn, **on the condition that no security property rests on it.**

**The line that the condition draws.** Section 2 checks it on main.

- **What a device carried** after a change, and its word that it has sent it (`sent`). Nothing reads that word to take, send, store, count or remove anything. **This half is relaxed:** a second, weaker word says that what the device carried is at the relays it reaches.
- **The change itself, at each relay.** A device that reaches only a relay that lacks a change goes on writing where a device that the change removed can read. That is the narrowing that property 1 of the record of 2026-10-04 names. **This half is not relaxed:** the command never says that the machine may be closed while a relay that it is set up with lacks the change. What changes is that it stops waiting in silence. It says what is so and what to do, and ends with a status that is not 0. Meanwhile the node dials that relay faster, and the status line says so whether the relay is connected or not.

What this form adds to the second: a definition of "out of reach" that the dial pace can meet (rule 2); a faster dial of a relay that lacks a change (rule 3); an end that is not success (rule 8); a status that does not need a connection or sync (rule 11); keys in the weaker word and no names (rule 4); a recovery that waits for the change as the command does (rule 9).

## 1. Terms

Each is used in the rules below only as defined here.

- **A relay** is one relay that the device is set up with, counted once (the record of relays, §1). A name listed as "same relay" is not one. A relay listed with the wrong key is one.
- **The kept entry** is the latest change entry that the device keeps (the record of 2026-10-04, 4.6).
- **A relay holds the change** where, since the device last woke, it has answered a show of the kept entry that it holds it or took it. That is `holds_latest == Some(true)` and `heard_since_woke`, as the node keeps them in memory by the relay's name (`device_entries.rs:2573-2577`). **It lacks the change** otherwise.
- **An attempt** at a relay is a lookup of its name, a dial (a connection made and the handshake with the right key), or a show of the kept entry on an open connection.
- **An attempt fails** where: the name does not resolve; no connection is made; another key answers at the address (`ANOTHER_KEY_ANSWERED`); the connection closes before a show on it is answered ("the relay closed the connection at once" among them); or the show is not answered (the stream is reset, which is how a relay says "not now", or it times out).
- **A relay is reached** while a connection to it is open, and the latest show of the kept entry on that connection was answered. An answer that says whether the relay holds the entry counts: it holds it, took it, has no room for it, holds another, or holds a change that the device does not take. "Show it whole" does not count.
- **A relay is out of reach** from the moment that all of these hold:
  - it has not been reached for five minutes (`OUT_OF_REACH_SECS`, section 10). The five minutes are counted, by the node's own clock (which does not run while the machine sleeps), from the latest of: the device's last wake (the record of 2026-10-04, 4.6; a start is a wake); the moment the kept entry last changed; and the moment it was last reached;
  - at least one attempt at it was begun in those five minutes;
  - every attempt begun in them has failed, and none is in flight.

  **It stays out of reach until** it is reached, the device wakes, or the kept entry changes. So it is a state with a start and an end, and not a window that slides. A relay that is connected and does not answer can be out of reach: "cannot be reached" in what a person reads covers both.
- **The carried word** is the device's entry under `reached/<its key>` in the personal channel (rule 4).
- **The wait after a change** is what `cordelia remove-device`, `cordelia renew` and `cordelia settle` go on to once the change is made: `cordelia change-made <n>`, in a new image of the program (`person_cmd.rs:2182-2224`).

## 2. What main does today

Each claim of the second form about the code was checked again against main. Section 13 lists where it was wrong.

**The word `sent`.**

- **One writer:** `at_relays::say_sent` (`crates/cordelia-api/src/at_relays.rs:697-748`). It writes `"<n> sent"` only where:
  - the device stands applied: not stopped, not in a fork, and following a phrase;
  - no recovery's look is pending (`PERSON_LOOK_PENDING`). That flag stays for good after a look that was interrupted, and after a look that could not fetch the new channels whole (`recover.rs:1291-1307`);
  - its own word is the statement's number alone;
  - nothing that it carried waits at any relay that it is given (`carried_waits_at`, `at_relays.rs:658-679`).
- **Called** only at the end of a whole pass (`device_entries.rs:979-981`), with the relays by key only where every relay, counted once, has an open connection (`every_relay_by_key`, `device_entries.rs:234-243`). A relay with the wrong key has no connection, so it alone keeps `sent` from being written.
- **Readers.** Each decides a sentence and nothing else, but for one, which also decides the end of a wait:
  - `look.rs:1028-1051` fills `applied` and `sent` for `POST /api/v1/devices/list`;
  - `cordelia devices` (`person_cmd.rs:968-992`);
  - the wait after a change (`person_cmd.rs:2315-2336`). It decides a sentence, and the end of the wait;
  - the status level, by `applied` only (`main.rs:1697-1701`);
  - a recovery's judgement that the one device it recovers from was cut short (`recover.rs:572-584`). It is handed on as `--cut-short` and said after the look (`recover_cmd.rs:1868-1946, 2155-2157`). Nothing that the look takes reads it.
- **What reads nothing of it:** taking, sending, storing, counting a device, applying a statement, dropping a secret or a channel, and what a recovery takes. **So no security property rests on `sent`.** What the wait after a change says is the one place that a property names, and that is the other half.

**Four places ask that every relay be connected,** by `every_relay_by_key`:

1. writing `sent`;
2. forgetting what is kept of a relay that the device is no longer set up with (`device_entries.rs:1263-1268`);
3. dropping each message of the device's own that every relay took (`device_entries.rs:1201-1212`; decision 2026-10-09 §2.3);
4. as a count, not by that function: a folder's first cycle waits for every relay, or for 30 seconds (`state.rs:720-735`).

Leaving (`cordelia init --new-key`) waits only for the relays that are connected (`person_cmd.rs:2432-2481`). This record changes only the first, and only by adding a second word beside it.

**The dial pace** (`crates/cordelia-node/src/p2p.rs:3623-3670`). A relay that is not connected is dialled again after a wait that doubles from one tick (10 s). The cap is 30 s (`BACKOFF_BASE_SECS`) while no relay is connected, and 900 s (`BACKOFF_MAX_SECS`) while another is. So with relay A connected, dials of B fail at about 0, 10, 30, 70, 150, 310 and 630 seconds, and then every 900 s.

- Nothing outside the loop can ask that a relay which is not connected be dialled now. The one asking that exists (`DoorAsk::Remake`, `p2p.rs:2882-2892`) closes a connection that is open, and has the relay dialled at the next tick.
- Names are looked up for all relays together: every 300 s while any name resolves, and every 30 s while none does (`p2p.rs:3612-3617`). A name that does not resolve is not dialled; it is listed as unreachable.

**The wake rule** (`device_entries/leave.rs:491-563`). A device wakes at the first pass that finds an open connection after any of three things: the node started, a pass found no open connection, or the machine slept. Until every relay has answered a show, or 30 seconds have gone, it takes nothing and sends nothing. A relay that is never reachable from where the device is costs those 30 seconds at every wake. The device says of it, in `cordelia devices`, "has not answered since this device woke: a change made while it was off may not have reached it" (`person_cmd.rs:1125-1128`). The status says "has not heard from <relay> since it woke: a change made while it was off may not have reached it" (`look.rs:1416-1421`).

**What is kept of each relay.** Kept in memory while the node runs, and lost at a restart:

- whether it holds the kept entry, by the relay's name, across connections (`device_entries.rs:316-342`);
- whether it has answered since the device woke;
- when it was connected (`state.rs:429-438`);
- its tries (`p2p.rs:3623-3636`).

Nothing in the database says which relays hold a change. What the device sent to each relay is in the database, by the relay's key (`at_relays` rows: `sent_to`, `carried_to`).

**The status level.** "a relay does not hold the latest change" is amber only:

- for a relay that is connected and answered that it does not hold it (`holds_latest == false`). A relay that has not answered, or is not connected, is not counted (`main.rs:1706-1709`);
- after five minutes;
- with sync on, a folder mapped and a report (`indicator.rs:458-477`).

**Exit status.** Every command returns through `main`, which gives 0, or 1 for an error (`main.rs:602`). The wait after a change and the end of a recovery return 0 at each of their ends (`person_cmd.rs:2345-2378`, `recover_cmd.rs:2108-2182`).

## 3. Every sentence today that speaks of every relay, each relay, or keeping the machine on

Each is on standard output unless it says otherwise. "Changes" means section 5 gives the new words.

| Where | Today | Its fate |
|---|---|---|
| `person_cmd.rs:2346` (the wait, its first line) | "This machine may be closed only when every relay holds the change and this device has sent what it holds. This command stays until then, and says what is missing. Stopping it stops nothing: the node goes on." | Changes (S1) |
| `person_cmd.rs:2253` | "keep this machine on: no relay is reached yet" | Stays |
| `person_cmd.rs:2259` | "<relay> holds the change" | Stays |
| `person_cmd.rs:2264` | "keep this machine on: <relay> does not hold the change yet" | Stays while the relay is not out of reach. For a relay out of reach it changes (S2) |
| `person_cmd.rs:2275` | "keep this machine on: <relay> is not connected, and what is still to send there is not known until it is" | Stays while the relay is not out of reach. For a relay out of reach it is not said: S2 or S3 is |
| `person_cmd.rs:2285` | "keep this machine on: a relay that this device is set up with is not connected, and what is still to send there is not known until it is" | Stays |
| `person_cmd.rs:2295` | "keep this machine on: <n> of this device's channels still to send to <relay>" | Stays (said only of a relay that is connected) |
| `person_cmd.rs:2308` | "keep this machine on: <N names> still to send (<k> sent)" | Stays |
| `person_cmd.rs:2312` | "<N names> sent", said only while every relay is reached | Stays, and is said too where each relay that is not reached is out of reach |
| `person_cmd.rs:2321` | "keep this machine on: this device has not yet sent every relay what it carried" | Stays while the device's own word is neither `sent` nor the carried word. With the carried word it changes (S4) |
| `person_cmd.rs:2332` | "<device> has applied the change, and is still sending what it held" | Changes for a device whose carried word is read (S5) |
| `person_cmd.rs:2370` | "Every relay holds the change, and this device has sent what it holds: this machine may be closed. `cordelia devices` shows which devices have applied the change." | Stays (end 1 of rule 8) |
| `person_cmd.rs:2210` (the wait could not be started) | "... Keep this machine on until every relay holds the change and nothing is left to send." | Stays: nothing waits in that case, and the advice is true |
| `person_cmd.rs:977` (`cordelia devices`) | "has applied change <n>, and is still sending what it held (if it is lost now, what it had not sent is lost with it; `cordelia sync carry` brings in what it had sent before)" | Changes for a device whose carried word is read (D1) |
| `person_cmd.rs:1126` (`cordelia devices`, a relay) | "has not answered since this device woke: a change made while it was off may not have reached it" | Changes (D2, D3) |
| `person_cmd.rs:1130` | "does not hold the latest change yet" | Stays for a relay that is reached. For one out of reach it changes (D4) |
| `person_cmd.rs:1129` | "holds the latest change" | Stays. A relay out of reach adds when it was last reached (D5) |
| `person_cmd.rs:1087` | "none is reached" | Stays |
| `look.rs:1418` (status) | "has not heard from <relay> since it woke: a change made while it was off may not have reached it" | Changes (T1) |
| `look.rs:1424` (status) | "<relay> does not hold the latest change yet" | Stays for a relay that is reached. For one out of reach it changes (T2) |
| `indicator.rs:472, 476` (the line) | "memory: a relay does not hold the latest change", "memory: <n> relays do not hold the latest change" | Same words, new conditions and a new place (rule 11) |
| `indicator.rs:420` | "memory: no relay for <n> minutes" | Stays |
| `recover_cmd.rs:2310` | "<relay> holds the change." | Goes from the one-shot lines: the wait of rule 9 says it |
| `recover_cmd.rs:2312` | "keep this machine on: <relay> does not hold the change yet." | Goes from the one-shot lines: the wait of rule 9 says what rule 8 says |
| `recover_cmd.rs:2322` | "keep this machine on: <relay> is not connected, and what is still to send there is not known until it is." | As the line above |
| `recover_cmd.rs:2331` | "keep this machine on: no relay is connected, and what is still to send is not known until one is." | Stays |
| `recover_cmd.rs:2349, 2355, 2360, 2366, 2382` | "Nothing is waiting to be sent to a relay that is connected. ...", "keep this machine on: its personal channel ...", "keep this machine on: <N names> still to send", "keep this machine on: <N folders> mapped here ...", "`cordelia devices` shows what this machine has still to send, and when nothing is left." | Stay, said once as today. "Nothing is waiting" is said only where no relay lacks the change, as today |
| `recover_cmd.rs:1914-1946` (cut short) | three sentences: read whole, read in part, held by none | Stay where neither word was found. A fourth is added (R2) |
| `recover_cmd.rs:1993` (the look could not be waited for) | "... Keep this machine on until nothing is left to send." | Stays |
| `main.rs:220, 244` (help of `remove-device`, `renew`) | "Keep this machine on until the command says you can close it." | Changes (H1) |
| `main.rs:311` (help of `devices`) | "- for each relay, whether it has the last change." | Stays |
| `person_cmd.rs:561` (`cordelia phrase`) | "Each relay is shown the change first, before anything else is sent there: `cordelia devices` says which hold it." | Stays |
| `msg_cmd.rs:1343` | "Message <id> from this device may not have reached every relay." | Stays: messages have rules of their own (decision 2026-10-09) |
| `person_cmd.rs` (leaving, `init --new-key`) | "any relay: none is reached", "Could not send it to <relay>: ..." | Stay |

## 4. The rules

### Rule 1. `sent` keeps its meaning and its conditions

Nothing about the word `"<n> sent"` under `applied/` changes: its writer, its conditions, its readers.

- **Why:** a device of alpha.12 reads any other word under `applied/` as no word, and would show a device that had applied a change as one that had not.

### Rule 2. The node keeps, for each relay, whether it is out of reach

As section 1 defines it, in memory, by the relay's name and key together (the record of relays, §1), beside what it keeps of the relay's tries and answers.

- **Kept from:** the dial loop says when an attempt begins and how it ended; the pass says when a show was answered or failed.
- **Since when:** each relay out of reach keeps the moment it was last reached, by the node's own clock, or the moment of the device's last wake where it was not reached since.
- **Reset:** the state is dropped at a wake, at a change of the kept entry, and when the relay is reached. A restart drops it with everything else: the five minutes start again from the start.
- **Why a state and not a window:** the second review showed that a window of one minute is lost as soon as the dial pace grows past a minute (its H1). Once out of reach, a relay stays so until something can have changed.
- **Why five minutes:** a relay that restarts, and a machine that wakes, are each through it in less (parameter-rationale §12.10). The second form's one minute was shorter than a relay's restart.
- **What it costs:** a relay that comes back while it is out of reach is taken for out of reach until the next attempt at it. With rule 3 that is 30 seconds at most for a relay that lacks the change. For one that holds it, it is up to 900 seconds; only the carried word and the status say so meanwhile.

### Rule 3. A relay that lacks the change is dialled at the pace of a node that is cut off

While the device has a change entry to show (it follows a phrase and has not stopped; a device in a fork shows its own), and a relay lacks the change and is not connected:

- **its dials:** the wait after each failure doubles from one tick up to `BACKOFF_BASE_SECS` (30 s), whether or not another relay is connected. That is the pace of a node that has no relay at all (`relay_backoff`, with `another_connected` false for that relay).
- **the lookups:** where such a relay's name does not resolve, names are looked up every `BOOTNODE_RESOLVE_RETRY_SECS` (30 s), as where no name resolves.
- **Once it holds the change** its next wait is as today. The failures that it counted stand.
- **Why:** a relay that lacks a removal is where a device that has not heard goes on writing for the removed device to read (the second review, M3). Today that relay is dialled every 15 minutes while another is connected. And rule 2 needs attempts to be able to say that a relay is out of reach.
- **What it costs:** a relay that is gone for good, and that lacks the latest change, is dialled every 30 seconds for as long as it is in the configuration: about 2,900 failed dials a day, each a few packets. A relay that turns the device's address away (2.5 of the record of 2026-10-04) is asked that often too, and refuses before the handshake. Whether a refused dial counts against the address there is not checked here (section 14).
- **Set aside:**
  - **A dial asked by the command.** There is no such asking (section 2), and the pace gives the same.
  - **A pace bounded in time** (an hour after the change, say). The relay lacks the change for as long as it does, and that is how long it matters.

### Rule 4. The carried word, in a slot of its own

A device writes, in the personal channel of the generation it has applied, under `reached/<its key>` (`PERSONAL_REACHED_PREFIX`), a word that says the weaker thing: what it carried is at the relays it names.

**When it is written.** At the end of a whole pass, where `sent` would be written but for relays out of reach. That is, where all of these hold:

1. every condition of `sent` but the one on connections: the device stands applied; no recovery's look is pending, so never after a look that was interrupted, or that could not fetch the new channels whole; and its own word under `applied/` is the statement's number alone;
2. at least one relay is reached, and nothing that the device carried waits at any relay that is reached (`carried_waits_at`);
3. each other relay is out of reach;
4. `sent` is not written in that pass. Where every relay is connected, `sent` is written, and never this.

**What it says.** A value with four fields, in the content's binary form:

- the statement's number;
- the keys of the relays at which nothing that the device carried waits: by the device's rows of what it sent, which are kept by key, whether or not the relay is reached now. At most 8 (`REACHED_WORD_MAX_RELAYS`), in the order of the configuration;
- how many more such relays there are;
- how many relays it is set up with at which what it carried may still wait.

**No names and no addresses:** a relay is named in a configuration by its address, and every device that ever holds this generation's secret reads this channel, a device removed later among them.

**Rewritten** where any of its fields changes, at most once a pass. It changes only where a relay is reached, or comes to be out of reach, or drops a channel, so it is not rewritten for nothing.

**Deleted** in the transaction that writes `sent`: a delete in its slot.

**Not carried** at the next change, and nor is its delete: `is_its_word_to_carry` (`person.rs:1873-1876`) leaves out `reached/`, as it leaves out `applied/` and `added/`. The next statement's own words are what stand.

- **Why a slot of its own:** see rule 1. A device of alpha.12 stores an entry under a name that it does not know, where its signer counts, and reads nothing of it (`take.rs:188-255, 327-328`).
- **Why keys:** a key is what a relay shows anyone who connects. A reader knows the key of each relay it is set up with that has one in its configuration, and of each it has reached.
- **What it costs:** one entry for each device that has a relay out of reach after a change, a content of 512 bytes, and its delete. And every device of the person learns the keys of the relays to which each other device sent what it carried. For the default relays those keys are in the program already.
- **Set aside:**
  - **The names of the relays out of reach** (the second form). They are addresses, and a reader can do nothing with them but repeat them (the second review, M7). The count says enough: "not to every relay it is set up with".
  - **Changing `sent` to mean this.** See rule 1.

### Rule 5. How the carried word is read

A device reads a carried word only where all of these hold:

- it is the current version of the slot `reached/<key>` among the entries that the key in the name signed, and is not a delete;
- that key counts (the record of 2026-10-04, 4.4);
- its number is the number of the statement that the reader has applied;
- the same device's word under `applied/` carries that number, without ` sent`. Where a device has both words, `sent` counts and this is not read;
- it is well formed. A word that holds more than 8 keys, a key that is not 32 bytes, or a field missing or extra, is no word.

What another key wrote in that slot is not read, as under `applied/` (`look.rs:1011-1025`). A recovery reads it by the same reader, over what it fetched (`recover.rs:572-584`).

### Rule 6. What other devices say of a device whose carried word they read

In place of "is still sending what it held", and of nothing else (D1, S5). A relay is shown:

- by the name that the reader's configuration gives it, where the reader knows its key;
- else, for a default relay, by its name in the program (`FALLBACK_PEERS` against `FALLBACK_PEER_KEYS`);
- else as "the relay whose key is <the key written whole>".

### Rule 7. What the device says of itself

- **In the wait after a change,** where its own word is the carried word under this change, S4 in place of "keep this machine on: this device has not yet sent every relay what it carried".
- **In `cordelia devices`,** its own row stays "this device". The relay lines say which relays are out of reach (rule 12).

### Rule 8. The wait after a change ends in one of three ways

It looks every second, as today, and says each line as it comes (S2 to S5). It ends at the first of these that holds. **None is reached while a relay that the device is set up with lacks the change, but the third, which says so and is not success.**

1. **Done** (status 0), as today: every relay is reached and holds the change, nothing waits to be sent at any relay, and the device's own word says `sent`. It says the line of `person_cmd.rs:2370`, unchanged.
2. **Done, with what was carried at some relays** (status 0):
   - every relay holds the change. A relay out of reach counts where it answered so since the device last woke;
   - the device's own word is the carried word under this change, and that word is at every relay that is reached;
   - nothing waits at any relay that is reached;
   - every other relay is out of reach.

   It says S6, then S7.
3. **Not done** (status 3):
   - something is missing: a relay lacks the change, or no relay is reached;
   - nothing more can move here: nothing waits at any relay that is reached, and the device's own word is `sent` or the carried word under this change at every relay reached; or no relay is reached;
   - each relay that lacks the change, and each relay that is not reached, either is out of reach with an attempt at it begun after the change was applied, or is reached and has not taken the change for five minutes since it was applied (it had no room for it, or holds a change that this device does not take).

   It says S8 for each relay that lacks the change or is out of reach, then S9 where a relay is reached, then S10 or S11, and ends with status 3. **It never says that the machine may be closed.**

While none holds it waits, and says what is missing, as today. With no relay reached and none yet out of reach, that is "keep this machine on: no relay is reached yet", for as long as it lasts.

- **Why status 3:** 1 is what `main` gives for an error, and 2 is what the argument parser gives. A program that runs the command, an agent with a shell among them (property 10 of the record of 2026-10-04), must not read "not done" as done, or as a failure to make the change. The change is made.
- **Why end at all:** the node goes on doing what the command would wait for (showing the change, sending), whether or not the command waits, and the status line goes on saying so (rule 11). A command that never ends is read as one that hung.
- **What it costs:** a person who sees a command end may take the removal as done, whatever its last line said (the second review, H2). Against that: the status is not 0; the last line says what is not done and where to look; and the status line stays amber while it is so (rule 11).
- **Set aside:**
  - **Ending after one minute** (the second form). A relay's restart takes longer.
  - **Advising, in the command's own words, to take a relay out of the configuration.** A relay that is out of reach from here can still serve a device that reaches it, and a removed device at the same address can make a relay look gone (the second review, M1). `cordelia devices` says it, only for a relay gone for good (D4).
  - **"This machine gives it for as long as it is on"** (the second form). Untrue while the address is turned away, or where only other devices reach the relay. S9 says what is true in each case.

### Rule 9. A recovery waits for the change as the wait after a change does

Once a recovery's look has ended, the command says what it says today of the look:

- how much was carried, and which names could not be read;
- each removed key;
- the cut short sentences;
- the one-shot lines on names and folders.

The three lines on relays go from that list (section 3). Then:

- **Where every relay holds the change,** it says "Every relay holds the change." (R1) and ends with status 0, as today.
- **Otherwise** it goes on to the wait of rule 8, for the change only. It says S2 to S3 for each relay as they come, and ends:
  - at R1 and status 0, once every relay holds the change;
  - or at the third end of rule 8 (S8 to S11) and status 3.

  Ends 1 and 2 of rule 8 are not used: a recovery has never said that the machine may be closed, and its lines on names say what is still to send.
- The lines on records not shown, and on each device to add again, are said before the wait: they ask the person to act.
- **Why:** today a recovery prints "keep this machine on: <relay> does not hold the change yet" once and ends with 0. A device that reaches only that relay has not heard that it stopped, and goes on writing where a device that the person said is gone can read (the first review, M9).

### Rule 10. A recovery's judgement of the device it recovers from

Where the statement it recovers from lists one device, a recovery reads that device's words, as today, before its yes.

1. **It wrote `sent`:** as today. Not cut short.
2. **It wrote the carried word** (read by rule 5) and not `sent`, and **one of the keys that the word names is the key of a relay that this machine reached** in this recovery: what it carried is at a relay that the look reads. Not cut short: nothing is said of it, as for `sent`.
3. **It wrote the carried word, and this machine reached none of the relays that it names:**
   - **before the yes,** R2. The look is made once, so the remedy is offered while nothing is made;
   - **after the look,** R3 in place of the sentence that says it was cut short.
4. **Neither word was found:** the three sentences of today, by how the channel was read (whole, in part, held by none).

The command learns, from the node, the key of each relay that it reached. A relay is shown as rule 6 shows it. The look itself is not changed by any of the four: what it takes was never decided by the word.

### Rule 11. The status line

- **"memory: a relay does not hold the latest change"** (or "memory: <n> relays do not hold the latest change"), amber, for each relay that lacks the change for more than five minutes, by the node's own clock:
  - counted from the later of when the device applied the kept entry (or kept it, as answered) and its last wake;
  - **connected or not;**
  - **with sync on or off, and with or without a folder mapped:** wherever the device follows a phrase, as the other amber of a person's devices. It is no longer among the amber of folders;
  - **its place:** after "a device has left" (item 6 of `indicator.rs:316-342`), and before "names carried, not yet sent". A relay that lacks the change for good is amber for good, and must not hide a device added since, which comes before it.
- **"memory: a relay out of reach for <n> minutes"** (or "memory: <n> relays out of reach"), amber, for a relay that is out of reach and holds the change. It is said with sync on, a folder mapped and a report, as "no relay" is, and **last** among the amber: it is the least of them, and one that lasts for good must hide nothing.
- **"memory: no relay for <n> minutes"** stays as it is. Where no relay is connected, it is said and the out-of-reach line is not; "a relay does not hold the latest change" is said all the same.
- **Why:** the second review (H2) showed that once the command has ended nothing standing said that a relay lacks a removal. Not where the relay is not connected; not with sync off; not on a machine that has just recovered and maps nothing.

### Rule 12. `cordelia devices`, of each relay

The relay lines are D2 to D5, by these cases:

- **not heard since the device woke:** D2 while the relay is not out of reach, D3 once it is;
- **lacks the change and out of reach:** D4;
- **holds it and out of reach:** D5.

The other relay lines stay as they are. The line for a relay "same relay" stays out, as today.

### Rule 13. The wake rule: no change to what it does

When the node starts, or reaches a relay after having reached none, or wakes from sleep, it still takes nothing and sends nothing until every relay has answered or 30 seconds have gone. A relay out of reach is no exception. Only the words that name the relay change (T1, D2, D3). Section 6 says why.

### Rule 14. The help

`cordelia remove-device --help` and `cordelia renew --help` say H1 in place of "Keep this machine on until the command says you can close it."

## 5. Every sentence that changes, word for word

`<relay>` is a relay as the device's configuration names it (its address), and as rule 6 names it in a line about another device's word. `<time>` is a time of day as `look.rs` gives one ("14:05"). `<minutes>` is whole minutes. A list of relays is joined with ", " and " and ". **Each is on standard output.** A status is the process's exit status; where none is given, the command goes on.

**The wait after a change** (`cordelia change-made`, from `remove-device`, `renew` and `settle`):

- **S1, its first line:** "This machine may be closed only when every relay holds the change, and this device has sent what it holds to each relay that it can reach. This command stays until then, and says what is missing. Where a relay that lacks the change cannot be reached for five minutes, it says what that means and ends without saying so. Stopping it stops nothing: the node goes on."
- **S2,** for a relay that lacks the change and is out of reach, while something else still moves: "keep this machine on: <relay> does not hold the change yet, and has not been reached from here since <time>"
- **S3,** for a relay that holds the change and is out of reach: "<relay> holds the change, and has not been reached from here since <time>"
- **S4,** where the device's own word is the carried word: "this device has sent what it carried to <relays>, and not to <relay>, which it cannot reach"
- **S5,** of another device whose carried word is read: "<device> has applied the change, and has sent what it held to <relays>, but not to every relay it is set up with"
- **S6,** end 2, for each relay out of reach: "  <relay> holds the change, and has not been reached from here since <time>: what this device carried is not there yet."
- **S7,** end 2, last (status 0): "Every relay holds the change, and this device has sent what it carried to <relays>: this machine may be closed. <relay> is given what it carried when this device next reaches it; until then it is at <relays> alone. `cordelia devices` shows which devices have applied the change."
- **S8,** end 3, for each relay that lacks the change, in the order of the configuration, one of:
  - out of reach: "  <relay> does not hold the change, and has not been reached from here since <time>."
  - reached, no room: "  <relay> is reached, and has not taken the change: it had no room for it at <time> (<it is full | this address is over its allowance of new channels there>)."
  - reached, refused: "  <relay> is reached, and holds a change that this device does not take (<why>): it does not take this one in its place."
  - holds the change and out of reach, where no relay is reached: "  <relay> holds the change, and has not been reached from here since <time>."
- **S9,** end 3, once there is a relay reached: "A device of yours that reaches only <relays> may not have heard of the change. Until it does, it goes on in the channels from before the change, where every device that held their secret can still read what it writes. <relays> take<s> the change from any device that has applied it and reaches <it | them>, this one included, and from a relay that works with <it | them>. While this machine is on it tries <it | each> every 30 seconds."
- **S10,** end 3, last, where a relay is reached (status 3): "The change is not at <relays>: this command ends here without saying that this machine may be closed. `cordelia devices`, here or on a device of yours that reaches <it | them>, says when <it holds | they hold> the latest change."
- **S11,** end 3, last, where no relay is reached (status 3): "No relay that this machine is set up with can be reached from here<, and none is known to hold the change: no other device of yours can hear of it until one does>. This command ends here without saying that this machine may be closed. Keep it on, on a network from which a relay can be reached: `cordelia devices` says what is missing." The part in angle brackets is said where no relay holds the change.

**A recovery:**

- **R1:** "Every relay holds the change."
- **R2,** before the yes, with the lines that say how the personal channel was read: "<device> wrote that it had sent what it carried to <relays>, and not to <k> other relay<s> that it was set up with. This machine has not reached <it | any of them>, and the look of this recovery is made once: what that device carried may be only there. To bring it in by this recovery, answer no, set <relay> up on this machine, and run `cordelia recover` again. Answered yes, it comes in later only by `cordelia sync carry <name> --from <device>`, with the phrase, once <relay> is set up here."
- **R3,** after the look, in place of "never wrote that it had sent what it carried ... was cut short": "The device that this was recovered from, <device>, wrote that it had sent what it carried to <relays>, which this recovery did not read. What it carried that is not here is there: once <it is | they are> set up on this machine, `cordelia sync carry <name> --from <device>` brings it in, with the phrase."
- The wait of rule 9 says S2, S3, S8, S9, S10 and S11 as rule 8 does. Its status is 3 where it ends by them, and 0 where it ends at R1.

**`cordelia devices`:**

- **D1,** of another device whose carried word is read: "has applied change <n>, and has sent what it held to <relays>, but not to <k> other relay<s> that it is set up with, which it could not reach (if it is lost now, what it held is at <relays> alone)"
- **D2,** a relay not heard since the device woke: "  <relay>: has not answered since this device started or woke: a change made while this device was off may be there, and not have reached it"
- **D3,** the same, out of reach: "  <relay>: has not answered since this device started or woke, and has not been reached from here since <time>: a change made while this device was off may be there, and not have reached it"
- **D4,** lacks the change and out of reach: "  <relay>: does not hold the latest change, as far as this device knows, and has not been reached from here since <time>: a device of yours that reaches only it may not have heard of that change. Only if you know that <relay> is gone for good, take it out of the configuration of every device: a relay that cannot be reached from here may still serve a device that reaches it"
- **D5,** holds it and out of reach: "  <relay>: holds the latest change, and has not been reached from here since <time>"

**The status** (`cordelia status`, the lines of `look.rs` `says`):

- **T1:** "has not heard from <relay> since it started or woke: a change made while this device was off may be there, and not have reached it"
- **T2,** a relay that lacks the change and is out of reach: "<relay> does not hold the latest change, and has not been reached since <time>"
- **T3,** a relay that holds it and is out of reach: "<relay> has not been reached since <time>: this device sends through the others"
- The line: "memory: a relay does not hold the latest change", "memory: <n> relays do not hold the latest change" (the words of today), "memory: a relay out of reach for <minutes> minutes", "memory: <n> relays out of reach" (rule 11).

**The help:**

- **H1:** "Keep this machine on until the command says you can close it. Where a relay that lacks the change cannot be reached, the command says so and ends with status 3, without saying that you can."

## 6. The wake rule, and the build machine

**The 30 seconds stay.** A node cannot tell a start after a week off from a start after a minute. Nor can it tell a relay that cannot be reached from this site from one whose connection comes up in five seconds. The wait is one of the narrowings that property 1 names ("a device that wakes asks every relay it is set up with before it takes or sends anything"). So the ruling's condition does not hold for it, and it is not relaxed.

**Set aside: remembering, across starts, that a relay was out of reach at the last stop, and not waiting for it.** That is the case the rule is for. A laptop off for a week, at a site where relay B is blocked, starts with a removal at B only. It would then take from A, and send to A, in the old channels at once, with nothing said. With the wait it does the same 30 seconds later, and its status names B. The wait does not save it. What the third form adds there is the faster dial of B after a change (rule 3, for a device that has applied one), and the words.

**The sentence changes.** "has not answered since this device woke: a change made while it was off may not have reached it" is read as saying that the relay was off. It says the device woke. D2 and T1 say "since this device started or woke", and "while this device was off". Once the relay is out of reach, D3 adds since when. The clause about a change made while the device was off is kept for every relay that has not answered since the device woke, a start included (the first review, M5).

**What it costs, as today:** at a site where a relay cannot be reached, each start, and each return after no relay was reached, waits 30 seconds before it syncs (the record of 2026-10-04, section 12).

## 7. Alpha.12 and this version together

**Nothing on the wire changes.** No stream, answer, entry, statement or relay changes. A relay of either version serves both.

**A device of this version beside one of alpha.12:**

- **The carried word, written by this version.** Alpha.12 stores it where its signer counts and reads nothing of it (`take.rs:188-255`; its names are `name/`, `added/`, `applied/`, `left/`). It shows that device as "is still sending what it held", as today. It does not carry it at its own next change: a device carries only its own words. A recovery made with alpha.12 counts it among the entries that device signed (`recover.rs:362-366`), and judges "cut short" by `sent` alone, as today.
- **Alpha.12 never writes the carried word.** A device of this version shows it as today.
- **A device that goes back from this version to alpha.12** holds its own carried word, and alpha.12 carries it at its next change: alpha.12 leaves out only `added/` and `applied/`. The copy in the new generation has the old statement's number, and rule 5 does not read it. It waits to be sent among what was carried, and is sent.
- **The faster dial, the out-of-reach state, the ends of the wait and the status** are each of the device where they run. A device of alpha.12 dials as today, waits as today and says what it says today.
- **A command and a node of two versions** do not work together: a command that changes anything refuses a node of another version (the record of 2026-10-04, 10.1, rule 6). `cordelia change-made` and `cordelia recover-made` run from the same program as the command that made the change, which has already refused a node of another version.

**What a relay sees of it:**

- the carried word and its delete: one entry of the personal channel each, of a size it cannot tell from any other;
- dials every 30 seconds from a device for which it lacks the change, where today it sees one every 15 minutes.

## 8. What it costs

- **What a device carried is at fewer relays,** where one is out of reach, until that relay is reached or handed it. A relay lost in that time loses it. The carried word says where it is, and a recovery says so before its yes.
- **A command that ends while a relay lacks the change** (rule 8, end 3). A person may close the machine all the same. The status, the last line and the amber line say what is not done.
- **One more entry, and its delete,** in the personal channel for each device that has a relay out of reach after a change.
- **Every device learns the keys of the relays** to which each other device sent what it carried, and how many relays each is set up with.
- **Dials every 30 seconds** of a relay that lacks the change, for as long as it does.
- **A recovery's command can stay** for five minutes and more after its look, where a relay lacks the change. Today it ends at once.
- **The real-process tests of rules 2, 3, 8 and 9 each take more than five minutes:** the five minutes are the protocol's, and are not shortened for a test.

## 9. Set aside, and why

- **Relaxing the change at each relay** (the first form). Property 1 names what the command says as a narrowing.
- **Waiting for ever** (today, and alpha.12). It is what was seen on real machines.
- **One minute** for out of reach, and **one dial made for it** (the second form). A relay's restart takes longer, and no such dial can be asked for (section 2).
- **Names of relays in the carried word** (the second form). Rule 4.
- **The advice to take a relay out of the configuration in the command** (the second form). Rule 8.
- **Skipping the wake wait for a relay that was out of reach.** Section 6.
- **A new meaning for `sent`.** Rule 1.
- **Writing the carried word where no relay is reached.** It would name no relay: then nothing that the device carried is at any relay, which is what having no word says.
- **Status 1 or 2 for "not done".** Rule 8.

## 10. Constants

In `crates/cordelia-core/src/protocol.rs`, each with its line for `docs/specs/parameter-rationale.md`:

- **`OUT_OF_REACH_SECS: u64 = STATUS_AMBER_WAIT_SECS`,** that is 300. Derived. For §12.10:

  > How long a relay that the device is set up with has not been reached, with every attempt at it in that time failed, before it is out of reach (decision 2026-10-19 §1). It is the time after which the status line shows what passes by itself: a relay's restart, and a machine that wakes, are each through it in less. A relay stays out of reach until it is reached, the device wakes, or the change entry it keeps changes. The command after a change ends without success only once each relay that lacks the change has been out of reach for this long since the change.

- **`PERSONAL_REACHED_PREFIX: &str = "reached/"`.** For §12.6, beside the four prefixes of the personal channel:

  > The first part of the name of a device's word that it has sent what it carried to the relays it reaches, where the others are out of reach (decision 2026-10-19 §4, rule 4). The device's key follows it. It is no prefix of another, and none is of it.

- **`REACHED_WORD_MAX_RELAYS: usize = 8`.** Primitive. For §12.6:

  > The most relays that the carried word names by key, and the most that a reader reads from one (decision 2026-10-19, rules 4 and 5). A device is set up with two relays by default; eight is four times that, and keeps the word one content of 512 bytes. A device set up with more names the first eight in the order of its configuration, and says how many more.

**Constants that are used again, with a sentence added to their lines:**

- `BACKOFF_BASE_SECS` (parameter-rationale §3): "It is also the most a relay that lacks the change the device keeps waits to be dialled again, whether or not another relay is connected (decision 2026-10-19, rule 3)."
- `BOOTNODE_RESOLVE_RETRY_SECS`: "It is also how often names are looked up while a relay that lacks the change has a name that does not resolve (decision 2026-10-19, rule 3)."
- `STATUS_AMBER_WAIT_SECS` (§12.10): "a relay that does not hold the latest change, connected or not" in place of "a relay that is connected and does not hold the latest change"; and "It is the time a relay takes to be out of reach (`OUT_OF_REACH_SECS`)."

**Not a protocol constant:** the exit status 3 of "not done". It is the command's, beside `STAYS_COMMAND` in `person_cmd.rs`, as `NOT_AT_EVERY_RELAY_STATUS`. `recover_cmd.rs` uses the same.

**Checks at compile time:** `OUT_OF_REACH_SECS > 2 * WAKE_WAIT_SECS` (a device that wakes has heard from its relays, or given them up, well within it); and that the carried word at its bound is one content of 512 bytes.

## 11. Tests

Each test fails on an assertion if its rule is taken out. A test with real processes is marked so. In those, a relay cannot be reached in one of three ways: its name does not resolve (the `NO_SUCH_NAME` of `person_e2e.rs`); its process is stopped; or it is set up at a port on which nothing listens.

**Rule 2, out of reach** (units, in the module that keeps it, `crates/cordelia-node/src/device_entries/reach.rs`, with a clock that the test moves):

- `a_relay_is_out_of_reach_after_five_minutes_of_failed_attempts`: not at 299 seconds, and at 300.
- `not_while_an_attempt_is_in_flight`, and `not_with_no_attempt_in_the_five_minutes`.
- `a_wake_or_a_new_kept_entry_starts_the_five_minutes_again`, and `being_reached_ends_it_at_once`.
- `a_connected_relay_whose_shows_go_unanswered_is_out_of_reach`.
- `another_key_and_a_name_that_does_not_resolve_are_failed_attempts`.
- `a_same_relay_name_is_never_one`.

**Rule 3, the pace:**

- `p2p.rs`, `a_relay_that_lacks_the_change_is_dialled_at_the_pace_of_a_node_cut_off`: with another relay connected the wait stays at 30 s; once it holds the change, the next wait is 900 s at the cap.
- `p2p.rs`, `names_are_looked_up_every_half_minute_while_a_relay_that_lacks_the_change_does_not_resolve`.
- Real processes, `device_entries_e2e.rs`, `a_relay_that_lacks_the_change_is_dialled_every_half_minute`. A device has relays A and B; B is stopped, and a change is made. B's "last tried" in `cordelia peers` is never more than 40 seconds old while A is connected. B is started again: within 40 seconds it holds the change.

**Rule 4, the carried word** (`at_relays.rs`):

- `the_carried_word_is_written_only_where_sent_would_be_but_for_relays_out_of_reach`. One case for each condition: a look pending; a look interrupted; a device that has stopped; a word with ` sent`; no relay reached; something carried waits at a relay reached; a relay not reached and not out of reach; every relay connected, where `sent` is written and this is not.
- `it_is_rewritten_when_a_field_changes_and_deleted_when_sent_is_written`.
- `it_names_eight_keys_and_counts_the_rest`.
- `person.rs`, `the_carried_word_and_its_delete_are_not_carried`.

**Rule 5, the reader** (`look.rs`):

- `the_carried_word_is_read_only_from_its_own_key_under_the_applied_number`. It is refused where another device signed the slot, where the key does not count, where the number is another, where the device's `applied/` word is of another number, where it holds nine keys, and where it is malformed. Where `sent` is there too, `sent` is what is read.

**Rules 6 to 8, what is said, and the ends** (`person_cmd.rs`, over looks that the test writes):

- `the_wait_never_says_may_be_closed_while_a_relay_lacks_the_change`: over every combination of each relay's state (reached or not, out of reach or not, holds or lacks), the device's own word, and what waits.
- `the_three_ends_of_the_wait_and_their_status`, and `each_line_word_for_word` (S1 to S11, D1 to D5, T1 to T3).

**Real processes, `person_e2e.rs`:**

- `a_change_ends_not_done_where_a_relay_that_lacks_it_cannot_be_reached`. A laptop is set up with a relay that answers and with `NO_SUCH_NAME`, and removes a device. Within five minutes the command does not end, and says S2. After them it says S8, S9 and S10 and ends with status 3. It never says "may be closed". `cordelia status` is then amber with "memory: a relay does not hold the latest change", with sync off and nothing mapped.
- `a_relay_that_comes_back_within_five_minutes_does_not_end_the_wait`. B is stopped at the change, and started again two minutes later. The command ends at end 1, with status 0.
- `a_relay_that_took_the_change_and_cannot_be_reached_ends_at_end_two`. B takes the change and is stopped before what was carried is sent. After five minutes the command says S6 and S7 and ends with status 0. On the desktop, `cordelia devices` says D1 of the laptop. B is started again: the laptop writes `sent`, its carried word is deleted, and the desktop says "has sent what it held".
- `a_relay_whose_name_does_not_resolve_is_waited_for_and_named` (it changes): its line is D2, and T1.

**Real processes, `memory_e2e.rs`:** `a_relay_lost_before_the_names_went_does_not_end_the_wait_after_a_change` (it changes). With its one relay stopped, the command does not end within five minutes. After them it ends with S11 and status 3, and never says "may be closed".

**Rules 9 and 10, a recovery:**

- `recover.rs`, `a_recovery_reads_the_carried_word_of_the_one_device`: the four cases of rule 10.
- `recover_cmd.rs`, `r2_and_r3_word_for_word`.
- Real processes, `recover_e2e.rs`, `a_recovery_says_before_its_yes_where_what_was_carried_is_at_a_relay_it_did_not_reach`. A laptop with relays A and B carries; B is down and A then drops nothing. The laptop writes the carried word naming A. A new machine set up with B alone sees R2 before its yes.
- Real processes, `recover_e2e.rs`, `a_recovery_ends_not_done_where_a_relay_lacks_the_change`. The new machine is set up with A and with `NO_SUCH_NAME`. After the look it waits, says S8 to S10, and ends with status 3. Set up with A alone, it ends at R1 with status 0.

**Rule 11, the level** (`indicator.rs`):

- `a_relay_that_lacks_the_change_is_amber_connected_or_not_with_sync_on_or_off`.
- `its_place_is_after_a_device_that_left`.
- `a_relay_out_of_reach_is_amber_last_and_only_with_folders`.

**Constants** (`protocol.rs`): `OUT_OF_REACH_SECS` is `STATUS_AMBER_WAIT_SECS`; `PERSONAL_REACHED_PREFIX` is no prefix of another, and none is of it; the carried word at its bound fits its content.

**Two versions:** in units, as the record of recovery does (§6). An entry under `reached/` is taken by `take::take`, stored and read as nothing by alpha.12's paths, which this version keeps: the parse of `applied/`, and `record_in`.

## 12. Sentences of other records that this would alter

None is changed until this record is built.

**The record of 2026-10-04:**

- **Property 1, second case:** "says that the machine may be closed only when all of them do". Add: "and, where one that lacks it cannot be reached for five minutes, ends without saying so, with a status that is not 0 (decision 2026-10-19)".
- **4.6, "A device that wakes asks every relay first":** "A relay that was not reached is named in its status: 'has not heard from <relay> since it woke: a change made while it was off may not have reached it'". Becomes T1.
- **4.6, the cost line:** stands.
- **7.1, step 4:** "Then it stays, and shows three things as they come", and "It says that this machine may be closed only when every relay holds the change and this device has sent what it holds. Before that it says which is missing". Add rule 8's three ends.
- **8, the first bullet:** "It has sent what it carried once nothing of that waits at any relay it is set up with, with every one of them connected". Add the carried word (rules 4 and 5).
- **8, `cordelia devices`:** "has applied it and is still sending" (add D1), and "for each relay, whether it holds the latest change entry, and whether this device has heard from it since it woke" (add: whether it is out of reach, and since when).
- **8, the status line:** "a relay that does not hold the latest change". Add: connected or not.
- **9, step 5:** "of this machine, whether each relay holds the change and 'keep this machine on: 12 names still to send'". Becomes rule 9. Also "Where the statement it recovered from lists one device alone, and that device never wrote that it had sent what it carried": add rule 10.
- **10.1, the amber list:** "a relay that has been connected for more than five minutes, by the node's own clock, and does not hold the latest change". Becomes rule 11, and moves to the amber of a person's devices.
- **12:** add the costs of section 8.
- **13, "Removal, with real processes":** "while a relay cannot be found (the command names it, and does not say the machine may be closed)". Add: and ends with status 3 after five minutes.
- **14, item 1:** "its all-clear covers the relays that the device it is run on is set up with". Add: and it is never given while one of them lacks the change.
- **16, "Names in the personal channel":** add `reached/<its key>`.

**The record of relays, §1:** "So while it fails the device never takes every relay for connected: it forgets nothing of that relay, and does not say that it has sent what it carried." Add: "It is out of reach after five minutes, and the carried word may then be written (decision 2026-10-19)."

**`docs/specs/parameter-rationale.md`:** the lines of section 10.

**Not altered:** the record of recovery (its lines before the yes stand, and R2 is said beside them), the record of messages (its own "every relay"), and the record of 2026-09-30.

## 13. The reviews' findings, answered

**The second review** (of the second form), every HIGH and MEDIUM finding:

| Finding | How this form settles it, or why it does not apply on main |
|---|---|
| **H1:** "out of reach" is a window of one minute, used as a state; it cannot be met at a pace of 15 minutes; "dials once for this" is undefined | Out of reach is a state with a start and an end, over five minutes, of attempts (dials, lookups and shows), with none in flight (section 1). A relay that lacks the change is dialled at 30 s (rule 3). No special dial is made |
| **H2:** once the command ends nothing says that a removal is not at a relay; exit status unsaid; the amber is of connected relays only, with folders | The command ends with status 3 and a last line that names the relay (rule 8, S10, S11). "a relay does not hold the latest change" is amber connected or not, sync on or off, and on a machine that maps nothing (rule 11). `cordelia devices` says D4 |
| **M1:** "take it out of the configuration" in the command | Not in the command's own words. In `cordelia devices` only, worded as the review proposed (D4) |
| **M2:** the sentence is not true in each case (address turned away; reachable from others only; after a recovery) | S9 says "may not have heard", names both ways the relay gets the change, says that this machine tries every 30 seconds rather than that it gives it, and points to `cordelia devices` on a device that reaches the relay (S10). After a recovery only this machine has applied, and S9 is still true |
| **M3:** the relay that lacks a removal is dialled every 15 minutes | Rule 3 |
| **M4:** states that are never out of reach: a name that does not resolve, a connected relay that does not answer, reached and lacking, a connection closed at once, another key | Each is a failed attempt (section 1). A reached relay that does not take the change has an end of its own (rule 8, end 3; S8) |
| **M5:** a relay that would have answered can be out of reach (an old failure, a dial in flight, a minute before the change) | Every attempt in five minutes must have failed, none may be in flight, and the five minutes start no earlier than the change of the kept entry (section 1). End 3 also asks for an attempt begun after the change |
| **M6:** rule 8 does not fit how a recovery reads; keys against names; "run again" loops | Rule 10: the word is read before the yes from the personal channel, which step 3 reads, and judged by the keys of the relays this machine reached. A relay is shown by name where the machine knows the key, and by its key written whole otherwise. A personal channel read in part, or not held, is the fourth case, as today. "Run again" is offered only before the yes, when nothing is made |
| **M7:** relay names in the personal channel, read by every holder of the secret | No names; keys of the relays that hold what was carried, and a count (rule 4) |
| **M8:** the out-of-reach amber hides the device notices | It is last among the amber (rule 11). "Out of reach since" is said for every such relay (D3 to D5, T2, T3) |
| **M9:** text elsewhere contradicts the rule | Section 12 lists each sentence. None is changed before this is built |

**The first review** (of the first form), where the second form did not settle a finding:

| Finding | How this form settles it |
|---|---|
| **M1:** "reached" and the times not defined; "not reached" includes "not dialled" | Section 1 defines reached, an attempt, failure and out of reach, and the clock. Rule 3 makes attempts happen |
| **M8:** the reader has no source for a relay's name | Keys, shown by the reader's own names (rule 6) |
| **M9:** a recovery has no wait | Rule 9 |
| **LOW 1:** other places that wait on every relay | Section 2 lists four on main, one more than the second form knew of (messages). None is changed |
| **LOW 2:** the word where every relay is reached | Never written then (rule 4, condition 4) |
| **LOW 4:** the amber's place | Rule 11 |
| **LOW 5:** sentences with no fate | Section 3 |

**Where the second form was wrong about main.** Each was checked on 9cf7250:

- **A relay has no name in a configuration but its address** (`config.rs:100-109`). Names in the word would have been addresses.
- **"Every relay" is every relay counted once** (the record of relays). A relay with the wrong key alone keeps `sent` from being written for good. The second form's "out of reach" did not cover it.
- **Four places ask for every relay, not three.** Dropping one's own messages once every relay took them (decision 2026-10-09 §2.3) came after it.
- **No dial of a relay that is not connected can be asked for.** `DoorAsk::Remake` closes and dials again a connection that is open.
- **A show that is not answered is made again at the next pass** (`device_entries.rs:1355-1359`). So a connected relay that does not answer is not "waited for and named" by any sentence of its own.
- **There are two sentences for a relay not heard since waking:** one in `cordelia devices` and one in the status. The second form quoted one of them.
- **"Woke"** begins at the first pass with an open connection after a start, a pass with none, or sleep (`leave.rs:549-562`). With no relay reached, a device waits with no leave for as long as that lasts, not 30 seconds.
- **Which relays hold the change is in memory, by name,** across connections, and lost at a restart (`device_entries.rs:316, 2573-2576`). The amber counts only connected relays that answered that they lack it (`main.rs:1706-1709`).
- **Names are looked up for all relays together,** every 300 seconds while any resolves (`p2p.rs:3612-3617`). A relay whose name does not resolve was never dialled in any minute.
- **A look that could not fetch the new channels whole** also leaves the look pending for good, so `sent` is never written under that statement (`recover.rs:1291-1307`). The second form named only a look that was interrupted.

## 14. For the review to attack

The weakest points, as this record sees them:

1. **End 2 says "may be closed" with a relay out of reach,** on that relay's answer, given since the device woke, that it holds the change. The answer is kept in memory. A relay that held it and then lost the phrase's channel (2.5 of the record of 2026-10-04) is believed. Is an answer before the relay went out of reach enough, where today a connection is asked for at the moment it is said?
2. **The person who sees a command end.** Status 3 and a last line are what stands between "not done" and a closed laptop. Does any path print S7 or the line of `person_cmd.rs:2370` while a relay lacks the change? In particular: a relay "same relay"; a relay with the wrong key; the kept entry changing during the wait; a relay that answered a show of the change and then a second change was made elsewhere.
3. **Out of reach at a pace of 900 seconds,** for a relay that holds the change. It is out of reach until the next attempt, up to 15 minutes after it came back. Only the carried word and the status rest on it. Check that nothing of the change half does.
4. **A connected relay whose shows fail** counts as out of reach. A removed device at the same address that uses up the address's bytes ("not now") can so make a relay out of reach at will, and end the command at end 3. That gives the removed device nothing it lacks today (the relay lacks the change either way). But it does end a command that today would wait. Attack S9 and S10 against that case.
5. **Rule 3's cost:** a relay gone for good is dialled every 30 seconds for good, until a person takes it out of the configuration. Is the amber of rule 11 enough to make them? And does a dial that a relay turns away before its handshake count against the address there? If it does, rule 3 could bring on the fifteen minutes' refusal of 4.6 that it is meant to shorten. Not checked.
6. **Rule 10, case 2:** a relay the word names was reached by the recovery, so "not cut short". The relay may since have dropped the names' channels, or the device may have written the word, then lost the relay's copy. `sent` has the same staleness over every relay; this has it over fewer.
7. **The carried word is the device's own claim.** As with `sent`, a device that counts can write a false one about itself. No other key's word is read. Can it make a recovery that was cut short pass as whole? It can do the same with `sent` today.
8. **Rule 9 changes a recovery's end** from a print-once to a wait of five minutes and more. Is that a cost a person meets on every recovery with two relays, where one is slow after the change?
9. **Tests of more than five minutes,** with real processes. Is a test that waits on the protocol's own five minutes acceptable in CI, or does it have to be marked to run on demand only, as the stale topology suite is?
10. **Two versions:** a device of alpha.12 beside one of this version says "still sending" of it for good, as today. A recovery made with alpha.12 says "cut short" where this version would not. Both are what alpha.12 says today; neither is worse.
