# Decision: a relay out of reach

**Date**: 2026-10-19
**Status**: Built (2026-10-21). It is the third form of "a relay that stays out of reach", revised three times after its own reviews (section 13). The records of 2026-10-04 and of relays now say what section 12 lists. Where the build differs from what was first written here, the text says what was built: what `adding::leave` forgets (section 1), the order of the relay lines (rule 12, and the status's lines of section 5), the seven days of rule 11, which also run from a relay's latest answer, and three details of section 5 (`<when>` where no relay is reached, a line of sentences in `cordelia devices`, and the minutes of a relay out of reach, rounded up). Its ends were checked over every combination of the classes of each relay, for two and three relays (appendix A); that every state comes to a class rests on section 1 and its event-sequence tests. The first two forms were reviewed and found not sound to build from; this form was built after it passed its review, in five slices, each reviewed.
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
- **The change itself, at each relay.** A device that reaches only a relay that lacks a change goes on writing where a device that the change removed can read. That is the narrowing that property 1 of the record of 2026-10-04 names. **This half is not relaxed:** the command never says that the machine may be closed, and never ends with status 0, while a relay that it is set up with lacks the change. What changes is that it stops waiting in silence. It says what is so and what to do, and ends with status 3. Meanwhile the node dials that relay faster, and the status line says so whether the relay is connected or not.

**How the ruling is kept exact.**

- **The warnings** are the carried word (rule 4), what other devices say of it (rule 6), the second end of the wait (rule 8, end 2), and the amber line of a relay out of reach (rule 11). Each is said only where at least one relay is reached: one connection.
- **No security property rests on a warning.** What guards the change is what each relay is known to hold (section 1), the third end of the wait and its status 3 (rule 8), and the amber line of a relay not known to hold the latest change (rule 11). None of them reads the carried word, or is relaxed by a relay being out of reach.
- **With no relay reached nothing is relaxed:** the wait ends only at end 3, with status 3, and says to keep the machine on.

What this form adds to the second:

- a definition of "out of reach" that the dial pace can meet (section 1, rule 2);
- what a device knows of which relay holds which change, kept across starts (section 1);
- a faster dial of a relay that lacks a change (rule 3);
- an end that is not success (rule 8);
- a status that needs neither a connection nor sync (rule 11);
- keys in the weaker word, and no names (rule 4);
- a recovery that waits for the change as the command does (rule 9).

## 1. Terms

Each is used in the rules below only as defined here.

**Relays and entries**

- **A relay** is one relay that the device is set up with, counted once (the record of relays, §1). A name listed as "same relay" is not one. A relay listed with the wrong key is one.
- **The kept entry** is the latest change entry that the device keeps (the record of 2026-10-04, 4.6).

**What the device knows of which relay holds which change**

- **The answers to a show.** Every answer that the code can give a show of the kept entry is one of three kinds (`device_entries.rs:1445-1497`, `leave.rs:635-679`, `messages.rs:497-520`):
  - **it says that the relay holds the entry:** `Held`, `Taken`;
  - **it says that the relay does not:** `Refused(NoRoom)`, `Refused(OverLimit)`, `Other` (it holds another; to a short show or to a whole one, `device_entries.rs:1468-1477`), and `Another` (it holds another, here it is), whether or not what it hands is an entry;
  - **it says neither:** `Refused(NotSigned)`; `Whole` to a whole show; a reply that is not `EntryShown` ("a show was not answered as one"); a stream that is reset ("not now"), that times out, or that fails; a short show not answered and then a whole one not answered; and a round of shows that runs out (`SHOWS_IN_A_PASS`) with no answer of the first two kinds. **Each of these is a failed attempt** (below).
  - `Whole` to a short show is no answer: the device shows the entry whole, and the answer to that is what counts.
- **The latest answer.** For each relay, the device keeps the latest answer of the first two kinds that the relay gave to a show of the kept entry: the entry's ID, whether it says that the relay holds it or does not, the key that gave it, and the wall-clock time.
  - **Each such answer writes over the one before,** in the transaction that notes it. So a relay that held the entry and then answers "no room" about it no longer holds it (this record's second review, finding 2). An answer of the third kind writes nothing.
  - **Where it is kept:** in the database, in one key of `node_meta` (`person.relays_known`), by the relay's name and key together, as the record of relays finds a relay. So it is kept across starts, wakes and connections. The same key holds the two times that rule 11 needs: **when the kept entry came to be kept** (written when the key first sees an entry ID other than the one it holds), and **when this version first started** on this database.
  - **When it is forgotten:** for a relay that the device is no longer set up with. All of it but when this version first started, wherever the device stops following its phrase: `adding::leave` (`adding.rs:1234-1263`), which `cordelia phrase` on a device of several, `cordelia init --new-key` and a removal of this device go through, removes it. When this version first started is of the database, not of the phrase, and is kept: `cordelia phrase` on a device of several does not move it to now, and so does not give a relay that lacks the change seven days more of amber (rule 11).
  - Today the node keeps that answer in memory only, by name, lost at a restart (`device_entries.rs:316-342, 1639-1644, 2573-2577`).
- **The mark.** A relay's mark is an entry's ID, written in one of three moments, for each relay that the device is set up with then and of which it has no latest answer:
  - **where this device takes a hand-over** (`cordelia accept`, the record of 2026-10-04, section 6): the handed change entry. The mark trusts the relays of the device that added this one, not this device's own: that device kept the entry and showed it to its relays, perhaps not to this one;
  - **where `cordelia phrase` makes statement 1** on this device: its change entry. Statement 1 removes no key and renews nothing, so a relay that lacks it puts nobody in reach of a removed device;
  - **at the first start on this version, where the kept statement is statement 1:** its change entry, for the same reason.

  **There is no mark otherwise:** not at the first start where the kept statement is a later one, not for a relay set up later, not after `cordelia recover`. A latest answer takes the mark's place.
  - **Set aside:** a mark at the first start for any statement that removed no key (a renewal, or a settlement or recovery that removed nobody). The node keeps whether a change removed a key (`person.removed_a_key`) only for the change it applied last, and not what kind of change it was; statement 1 is the one it can know for certain.
- **A relay holds the change** where its latest answer is about the kept entry and says that it holds it, and, for a relay given no key in the configuration, only while the device is connected to it with the key that gave that answer. A relay given no key is found by the address its name resolves to now (`p2p.rs:3768-3779`). Out of reach, its name may name another host, which has never seen the change (this record's third review, finding 3).
- **It lacks the change** where it does not hold it, and either:
  - it has no latest answer and no mark;
  - its latest answer, or its mark, is about an entry other than the kept entry;
  - its latest answer is about the kept entry and says that it does not hold it; or
  - it is a relay given no key, and the device is not connected to it with the key that gave its answer.
- **The third state.** A relay with no latest answer whose mark is the kept entry neither holds nor lacks. Nothing in this record acts on it. That is a relay that has not answered from this site since this device was added, or made its phrase, or first started on this version under statement 1, and no change has been made since.
  - **So the case that was seen ends with that relay lacking the change:** a removal made or applied on alpha.12 that relay B never got, then the upgrade. The kept statement is not statement 1, so B has no mark, and it lacks the change until it answers that it holds it.
- **So in the wait after a change** every relay either holds the change or lacks it: the kept entry is the change just made, which is no relay's mark.

**Attempts**

- **An attempt** at a relay is one of:
  - a dial: a lookup of its name that resolves, a connection made, and the handshake with the right key;
  - a lookup of its name that does not resolve;
  - a show of the kept entry on an open connection.

  **A lookup that resolves is no attempt by itself:** it is part of the dial that follows it.
- **An attempt fails** where:
  - the name does not resolve;
  - no connection is made;
  - another key answers at the address (`ANOTHER_KEY_ANSWERED`);
  - the connection closes before a show on it is answered ("the relay closed the connection at once" among them);
  - or the show gets no answer of the first two kinds above: an answer that says neither is a failed attempt as much as no answer is (this record's third review, finding 1).
- **A relay with the wrong key, at an address where another relay is connected,** is not dialled (`p2p.rs:2690-2696`; the record of relays, §1). **Each tick of the dial loop that passes it over for that reason counts as an attempt at it, begun and failed at that tick:** another key answers at its address. The loop ticks every second.

**Reached, and out of reach**

- **A relay is reached** while a connection to it is open, and the latest show of the kept entry on that connection got an answer of the first two kinds.
- **A relay's reference** is the latest of four moments, by the node's own clock (which does not run while the machine sleeps):
  - the node's start;
  - a sleep that the device woke from (the record of 2026-10-04, 16: the wall clock ran ahead of the node's own clock);
  - the moment the kept entry last changed;
  - the moment this relay was last reached.

  **A wake for any other reason does not move it.** In particular a pass that finds no connection open, which makes the device wake when one opens again (`leave.rs:549-556`), moves no relay's reference: the wake rule still waits for every relay, but a relay's five minutes go on. Otherwise a device whose one reachable relay drops every few minutes would never let another become out of reach (this record's third review, finding 2).
- **A relay becomes out of reach** at the first moment that all of these hold:
  - it has not been reached since its reference, and the reference is five minutes (`OUT_OF_REACH_SECS`, section 10) or more before now;
  - at least one attempt at it was begun after the reference and within the five minutes before now;
  - every attempt begun after the reference has failed, and none is in flight.

  **It stays out of reach until** it is reached, or its reference moves. So it is a state with a start and an end, not a window that slides. A relay that is connected and whose shows get no answer of the first two kinds can be out of reach: "cannot be reached" in what a person reads covers both.
- **A relay refuses the change** where it is reached, and its latest answer to a show of the kept entry is no room, over the allowance, or another change that this device does not take. **It has refused for five minutes** where it has lacked the change for five minutes, and every show answered on it since it last held it, or since the change if it never did, got one of those answers.
- **A relay refuses what waits** where it is reached, holds the change, and something of the device's own waits to be sent there that the relay has refused, for room or for the address's allowance, at each offer for five minutes (the refusal of today's status, `no_room`, kept for that long). A relay full for good, and an address over its allowance of new channels after a change makes every channel new, are the cases.
- **The classes.** Each relay, in the wait after a change, is in one of these, or in none while time can still move it:
  - **OK:** reached, holds the change, and nothing waits there;
  - **STUCK:** reached, holds the change, and refuses what waits;
  - **OUT, holding:** out of reach, and holds the change;
  - **OUT, lacking:** out of reach, and lacks the change;
  - **REFUSING:** reached, lacks the change, and has refused it for five minutes.

  **Every state comes to a class.** A relay in none of them is in one of these, and each ends by itself:
  - not reached and not yet out of reach: each attempt is reached or fails; rule 3 makes one at least every 30 s for a relay that lacks the change, and the dial pace makes one within 900 s for one that holds it. Only the four moments of its reference start its five minutes again, and none of them comes by itself;
  - connected, and its shows get answers of the third kind: each is a failed attempt. A reset or a time-out is shown again at the next pass. "Not signed" or "show it whole" to a whole show starts the wait that doubles after an answer (`device_entries.rs:1360-1375`), so the show is made again at most every ten minutes, and the relay is out of reach within fifteen minutes of its reference;
  - reached and lacking for less than five minutes: the five minutes pass, or it takes the change;
  - reached, holding, and something waits that it has not refused for five minutes: it takes it, or refuses it for five minutes.

  The event-sequence tests of `reach.rs` (section 11) hold each, over the clock and the answers.

**When, and the words**

- **When** (`<when>` below) is a moment that the node noted by the wall clock. It is written as `look.rs` writes a time of day, the hour and the minute in UTC, with " on <the date>" (`YYYY-MM-DD`) after it where it is not today: "14:05 UTC", "23:00 UTC on 2026-10-19". The five minutes themselves are counted by the node's own clock, not by the wall clock.
- **The carried word** is the device's entry under `reached/<its key>` in the personal channel (rule 4).
- **The wait after a change** is what `cordelia remove-device`, `cordelia renew` and `cordelia settle` go on to once the change is made: `cordelia change-made <n>`, in a new image of the program (`person_cmd.rs:2182-2224`).

## 2. What main does today

Each claim of the second form about the code was checked again against main. Section 13 lists where it was wrong.

**The word `sent`.**

- **One writer:** `at_relays::say_sent` (`crates/cordelia-api/src/at_relays.rs:697-748`). It writes `"<n> sent"` only where:
  - the device stands applied: not stopped, not in a fork, and following a phrase;
  - no recovery's look is pending (`PERSON_LOOK_PENDING`). That flag stays after a look that was interrupted, and after a look that could not fetch the new channels whole, until the next statement (`recover.rs:1291-1307`, `person.rs:1623`);
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

**The dial pace** (`crates/cordelia-node/src/p2p.rs:3623-3670`).

- A relay that is not connected is dialled again after a wait that doubles from one tick (10 s). The cap is 30 s (`BACKOFF_BASE_SECS`) while no relay is connected, and 900 s (`BACKOFF_MAX_SECS`) while another is. The wait is set when a dial fails (`RelayTry::failed`), and a later change of the cap does not shorten it.
- So with relay A connected, dials of B fail at about 0, 10, 30, 70, 150, 310 and 630 seconds, and then every 900 s.
- Nothing outside the loop can ask that a relay which is not connected be dialled now. The one asking that exists (`DoorAsk::Remake`, `p2p.rs:2882-2892`) closes a connection that is open, and has the relay dialled at the next tick.
- A relay with the wrong key, at an address where another relay is connected, is not dialled at all (`p2p.rs:2690-2696`).
- Names are looked up for all relays together, in a loop that sleeps 300 s while any name resolves and 30 s while none does (`p2p.rs:3612-3617`). A name that does not resolve is not dialled; it is listed as unreachable.
- A dial that a relay turns away before its handshake does not count against the address there (`p2p.rs:2433-2450, 4180-4191`, as the review read them).

**The wake rule** (`device_entries/leave.rs:491-563`).

- A device wakes at the first pass that finds an open connection after any of three things: the node started, a pass found no open connection, or the machine slept.
- Until every relay has answered a show, or 30 seconds have gone, it takes nothing and sends nothing. A relay that is never reachable from where the device is costs those 30 seconds at every wake.
- What it says of such a relay:
  - in `cordelia devices`: "has not answered since this device woke: a change made while it was off may not have reached it" (`person_cmd.rs:1125-1128`);
  - in the status: "has not heard from <relay> since it woke: a change made while it was off may not have reached it" (`look.rs:1416-1421`).

**What is kept of each relay.** In memory while the node runs, and lost at a restart:

- whether it holds the kept entry, by the relay's name, across connections and wakes (`device_entries.rs:316-342`);
- whether it has answered since the device woke. Any answer counts, "show it whole" among them (`leave.rs:640-666`);
- when it was connected (`state.rs:429-438`);
- its tries (`p2p.rs:3623-3636`).

Nothing in the database says which relays hold a change. What the device sent to each relay is in the database, by the relay's key (`at_relays` rows: `sent_to`, `carried_to`).

**The status level.** "a relay does not hold the latest change" is amber only:

- for a relay that is connected and answered that it does not hold it (`holds_latest == false`). A relay that has not answered, or is not connected, is not counted (`main.rs:1706-1709`);
- after five minutes;
- with sync on, a folder mapped and a report (`indicator.rs:458-477`).

**Exit status.** Every command returns through `main`, which gives 0, or 1 for an error (`main.rs:602`).

- The wait after a change and the end of a recovery return 0 at each of their ends (`person_cmd.rs:2345-2378`, `recover_cmd.rs:2108-2182`). That includes the path where the wait could not be started (`person_cmd.rs:2192-2216`).
- An error during the wait gives 1, though the change was made.

## 3. Every sentence today that speaks of every relay, each relay, or keeping the machine on

Each is on standard output unless it says otherwise. "Changes" means section 5 gives the new words.

| Where | Today | Its fate |
|---|---|---|
| `person_cmd.rs:2346` (the wait, its first line) | "This machine may be closed only when every relay holds the change and this device has sent what it holds. This command stays until then, and says what is missing. Stopping it stops nothing: the node goes on." | Changes (S1) |
| `person_cmd.rs:2253` | "keep this machine on: no relay is reached yet" | Stays |
| `person_cmd.rs:2259` | "<relay> holds the change" | Stays |
| `person_cmd.rs:2264` | "keep this machine on: <relay> does not hold the change yet" | Stays while the relay is not out of reach. For a relay out of reach it changes (S2) |
| `person_cmd.rs:2275` | "keep this machine on: <relay> is not connected, and what is still to send there is not known until it is" | Stays while the relay is not out of reach. For a relay out of reach S2 or S3 is said instead |
| `person_cmd.rs:2285` | "keep this machine on: a relay that this device is set up with is not connected, and what is still to send there is not known until it is" | Stays |
| `person_cmd.rs:2295` | "keep this machine on: <n> of this device's channels still to send to <relay>" | Stays (said only of a relay that is connected) |
| `person_cmd.rs:2308` | "keep this machine on: <N names> still to send (<k> sent)" | Stays |
| `person_cmd.rs:2312` | "<N names> sent", said only while every relay is reached | Stays, and is said too where each relay that is not reached is out of reach |
| `person_cmd.rs:2321` | "keep this machine on: this device has not yet sent every relay what it carried" | Stays while the device's own word is neither `sent` nor the carried word. With the carried word it changes (S4) |
| `person_cmd.rs:2332` | "<device> has applied the change, and is still sending what it held" | Changes for a device whose carried word is read (S5) |
| `person_cmd.rs:2370` | "Every relay holds the change, and this device has sent what it holds: this machine may be closed. `cordelia devices` shows which devices have applied the change." | Stays (end 1 of rule 8) |
| `person_cmd.rs:2210` (the wait could not be started) | "... Keep this machine on until every relay holds the change and nothing is left to send." | Words stay; the status becomes 3 (rule 8) |
| `person_cmd.rs:977` (`cordelia devices`) | "has applied change <n>, and is still sending what it held (if it is lost now, what it had not sent is lost with it; `cordelia sync carry` brings in what it had sent before)" | Changes for a device whose carried word is read (D1) |
| `person_cmd.rs:1126` (`cordelia devices`, a relay) | "has not answered since this device woke: a change made while it was off may not have reached it" | Changes (D2, D3) |
| `person_cmd.rs:1130` | "does not hold the latest change yet" | Stays for a relay that is reached. For one out of reach, D4 |
| `person_cmd.rs:1129` | "holds the latest change" | Stays. For one out of reach, D5 |
| `person_cmd.rs:1131` | "has not said whether it holds the latest change" | Stays: said of a relay in the third state of section 1 |
| `person_cmd.rs:1087` | "none is reached" | Stays |
| `look.rs:1418` (status) | "has not heard from <relay> since it woke: a change made while it was off may not have reached it" | Changes (T1) |
| `look.rs:1424` (status) | "<relay> does not hold the latest change yet" | Stays for a relay that is reached. For one out of reach, T2 |
| `indicator.rs:472, 476` (the line) | "memory: a relay does not hold the latest change", "memory: <n> relays do not hold the latest change" | Changes words, conditions and place (rule 11) |
| `indicator.rs:420` | "memory: no relay for <n> minutes" | Stays |
| `recover_cmd.rs:2310` | "<relay> holds the change." | Goes from the one-shot lines: the wait of rule 9 says it |
| `recover_cmd.rs:2312` | "keep this machine on: <relay> does not hold the change yet." | Goes from the one-shot lines: the wait of rule 9 says S2 or S8 |
| `recover_cmd.rs:2322` | "keep this machine on: <relay> is not connected, and what is still to send there is not known until it is." | As the line above |
| `recover_cmd.rs:2331` | "keep this machine on: no relay is connected, and what is still to send is not known until one is." | Stays |
| `recover_cmd.rs:2349, 2355, 2360, 2366, 2382` | "Nothing is waiting to be sent to a relay that is connected. ...", "keep this machine on: its personal channel ...", "keep this machine on: <N names> still to send", "keep this machine on: <N folders> mapped here ...", "`cordelia devices` shows what this machine has still to send, and when nothing is left." | Stay, said once as today. "Nothing is waiting" is said only where no relay lacks the change, as today |
| `recover_cmd.rs:1914-1946` (cut short) | three sentences: read whole, read in part, held by none | Stay where neither word was found. A fourth is added (R3) |
| `recover_cmd.rs:1993` (the look could not be waited for) | "... Keep this machine on until nothing is left to send." | Words stay; the status becomes 3 (rule 9) |
| `main.rs:220, 244` (help of `remove-device`, `renew`) | "Keep this machine on until the command says you can close it." | Changes (H1), and `settle` is given the same |
| `main.rs` (help of `recover`) | (says nothing of it) | H2 is added |
| `main.rs:311` (help of `devices`) | "- for each relay, whether it has the last change." | Stays |
| `person_cmd.rs:561` (`cordelia phrase`) | "Each relay is shown the change first, before anything else is sent there: `cordelia devices` says which hold it." | Stays |
| `msg_cmd.rs:1343` | "Message <id> from this device may not have reached every relay." | Stays: messages have rules of their own (decision 2026-10-09) |
| `person_cmd.rs` (leaving, `init --new-key`) | "any relay: none is reached", "Could not send it to <relay>: ..." | Stay |

## 4. The rules

### Rule 1. `sent` keeps its meaning and its conditions

Nothing about the word `"<n> sent"` under `applied/` changes: its writer, its conditions, its readers.

- **Why:** a device of alpha.12 reads any other word under `applied/` as no word, and would show a device that had applied a change as one that had not.

### Rule 2. The node keeps, for each relay, what section 1 defines

**In the database:** each relay's latest answer, and its mark (section 1).

- **The latest answer is written** by the pass, in the one transaction that notes the answer, for each answer of the first two kinds that section 1 names. An answer that repeats what is kept writes nothing.
- **The mark is written** at the three moments of section 1, in the transaction of each (taking a hand-over; `cordelia phrase`; the first start on this version under statement 1), and at no other time.

**In memory,** by the relay's name and key together:

- whether it is reached;
- whether it is out of reach, and since when;
- since when it has refused the change;
- the attempts at it: the dial loop says when a dial or a failed lookup begins and how it ended, and the pass says when a show was answered or failed.

The state in memory follows each relay's reference (section 1): it starts again when the reference moves (a start, a sleep, a change of the kept entry, the relay being reached), and at no other wake. A restart drops it with everything else in memory: the five minutes start again from the start.

- **Why a state and not a window:** the second review showed that a window of one minute is lost as soon as the dial pace grows past a minute (its H1). Once out of reach, a relay stays so until something can have changed.
- **Why five minutes:** a relay that restarts, and a machine that wakes, are each through it in less (parameter-rationale §12.10). The second form's one minute was shorter than a relay's restart.
- **Why the latest answer is in the database:** without it, every relay after every start is "not known" to hold anything. A relay that cannot be reached from this site would then lack the change for good, and be amber and dialled every 30 seconds for good, whether or not a change was ever made (this record's first review, finding 5).
- **Why the latest answer, not the last "held":** a relay that held the entry can lose the phrase's channel and have no room to take it again (the record of 2026-10-04, property 4). Its answer then says so, and the device must believe it.
- **Why the mark comes only from those three moments:** at a hand-over the device that added this one kept and showed the entry before; at `cordelia phrase`, and at a first start under statement 1, the entry removes no key and renews nothing, so a relay that lacks it puts nobody in reach of a removed device. At a first start under a later statement the device knows nothing of what its relays got while it ran alpha.12, so it marks nothing (this record's second review, finding 3; the fourth check, finding 3).
- **What it costs:**
  - one key of `node_meta`, of a few hundred bytes, written at each answer that changes what is kept of a relay, and at the three moments of a mark;
  - a relay that comes back while it is out of reach is taken for out of reach until the next attempt at it. With rule 3 that is 30 seconds at most for a relay that lacks the change. For one that holds it, it is up to 900 seconds; only the carried word and the status say so meanwhile.
- **Set aside:**
  - **"Lacks" as "has not answered since the wake"** (this record's first revision). It made a relay that is never reachable from a site lack the change for good, with no change made.
  - **A table of its own, in a schema step.** A node of alpha.12 refuses a database from a later version (the record of 2026-10-04, 10.1), so going back would need a copy. A key of `node_meta` is read by name, and alpha.12 reads none that it does not know (`crates/cordelia-storage/src/meta.rs`).

### Rule 3. A relay that lacks the change is dialled at the pace of a node that is cut off

While the device has a change entry to show (it follows a phrase and has not stopped; a device in a fork shows its own), and a relay lacks the change and is not connected:

- **Its dials:** the wait after each failure doubles from one tick up to `BACKOFF_BASE_SECS` (30 s), whether or not another relay is connected. That is the pace of a node that has no relay at all (`relay_backoff`, with `another_connected` false for that relay).
- **A wait already set is cut:** when a relay comes to lack the change (the kept entry changes, or the node starts with a relay that lacks it), its next dial is set to no later than 30 seconds on, and the lookup loop is woken at once.
- **The lookups:** while such a relay's name does not resolve, names are looked up every `BOOTNODE_RESOLVE_RETRY_SECS` (30 s), as where no name resolves.
- **Once it holds the change** its next wait is as today. The failures that it counted stand.
- **What it does not cover:** a relay with the wrong key at an address where another relay is connected. It is not dialled at all, since a dial there would close a working connection to another relay (the record of relays, §1). Section 1 counts it as failing for as long as that connection is open, so rule 8 can end without a dial.
- **Why:** a relay that lacks a removal is where a device that has not heard goes on writing for the removed device to read (the second review, M3). Today that relay is dialled every 15 minutes while another is connected. And rule 2 needs attempts to be able to say that a relay is out of reach.
- **What it costs:**
  - **A relay gone for good,** after a change it did not take, is dialled every 30 seconds until it is reached or taken out of the configuration: about 2,900 failed dials a day, each a few packets.
  - **A relay that cannot be reached from this site,** after each change made or applied here, is dialled every 30 seconds for good from this machine. This machine cannot learn that it took the change from another device.
  - **A relay in the third state of section 1 is dialled as today.** That is a relay with no answer whose mark is the kept entry: after `cordelia accept` or `cordelia phrase` on this version, or a first start under statement 1, with no change since. A relay of a machine that came by the upgrade under a later statement lacks the change until it answers (section 6), and is dialled so from the first start.
  - **A relay that turns the device's address away** (2.5 of the record of 2026-10-04) is asked that often too. It refuses before the handshake, which does not count against the address there (section 2).
- **Set aside:**
  - **A dial asked by the command.** There is no such asking (section 2), and the pace gives the same.
  - **A pace bounded in time** (an hour after the change, say). The relay lacks the change for as long as it does, and that is how long it matters.

### Rule 4. The carried word, in a slot of its own

A device writes, in the personal channel of the generation it has applied, under `reached/<its key>` (`PERSONAL_REACHED_PREFIX`), a word that says the weaker thing: what it carried is at the relays it names.

**When it is written.** At the end of a whole pass, where `sent` would be written but for relays out of reach. That is, where all of these hold:

1. every condition of `sent` but the one on connections: the device stands applied; no recovery's look is pending, so never after a look that was interrupted, or that could not fetch the new channels whole; and its own word under `applied/` is the statement's number alone;
2. at least one relay is OK (section 1): reached, holds the change, and nothing waits there (`carried_waits_at` among it);
3. each other relay is out of reach, or is reached and refuses what waits (section 1);
4. `sent` is not written in that pass. Where every relay is connected, `sent` is written, and never this.

**What it says.** A value with four fields, in the content's binary form:

1. the statement's number;
2. the keys of the relays at which nothing that the device carried waits: one at least, and at most 8 (`REACHED_WORD_MAX_RELAYS`), in the order of the configuration, each once. This is judged by the device's rows of what it sent, which are kept by key, whether or not the relay is reached now;
3. how many more such relays there are: 0 unless the second field holds 8 keys;
4. how many relays it is set up with are not in the second field, nor counted in the third: those at which something that it carried may still wait. It can be 0, where a relay out of reach took everything before it went (this record's second review, finding 1). **The two fields never overlap,** so a line that reads them never counts a relay twice (this record's third review, finding 4).

**No names and no addresses.** A relay is named in a configuration by its address. Every device that ever holds this generation's secret reads this channel, a device removed later among them.

**Rewritten** where any of its fields changes, at most once a pass. It changes only where a relay is reached, comes to be out of reach, or drops a channel, so it is not rewritten for nothing.

**Deleted** in the transaction that writes `sent`: a delete in its slot.

**Not carried** at the next change, and nor is its delete. `is_its_word_to_carry` (`person.rs:1873-1876`) leaves out `reached/`, as it leaves out `applied/` and `added/`. The next statement's own words are what stand.

- **Why a slot of its own:** see rule 1. A device of alpha.12 stores an entry under a name that it does not know, where its signer counts, and reads nothing of it (`take.rs:188-255, 327-328`).
- **Why keys:** a key is what a relay shows anyone who connects. A reader knows the key of each relay it is set up with that has one in its configuration, and of each it has reached.
- **What it costs:**
  - one entry for each device that has a relay out of reach after a change, and its delete: a content of 256 bytes where the word names up to four keys, as a device's words under `applied/` and `left/` are, and of 512 bytes where it names five or more, as a record of an addition is;
  - every device of the person learns the keys of the relays to which each other device sent what it carried. For the default relays those keys are in the program already.
- **Set aside:**
  - **The names of the relays out of reach** (the second form). They are addresses, and a reader can do nothing with them but repeat them (the second review, M7). The count says enough: "not yet to <k> other relays".
  - **Changing `sent` to mean this.** See rule 1.

### Rule 5. How the carried word is read

A device reads a carried word only where all of these hold:

- it is the current version of the slot `reached/<key>` among the entries that the key in the name signed, and is not a delete;
- that key counts (the record of 2026-10-04, 4.4);
- its number is the number of the statement that the reader has applied;
- the same device's word under `applied/` carries that number, without ` sent`. Where a device has both words, `sent` counts and this is not read;
- it is well formed:
  - four fields, no more;
  - one to 8 keys, each of 32 bytes, none twice;
  - the third field 0 unless there are 8 keys;
  - each count at most 256 (`REACHED_WORD_MAX_COUNT`).

  Any other word is no word.

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

It looks every second, as today, and says each line as it comes (S2 to S5). Its ends are stated over the classes of section 1, and were checked over every combination of those classes, for two and three relays (appendix A). It ends at the first of these that holds.

**Two properties hold, and the model of appendix A checks both:**

- **Safety:** ends 1 and 2 need every relay to hold the change. So the wait never says that the machine may be closed, and never ends with status 0, while a relay lacks the change.
- **Liveness:** in every state in which each relay is in a class, and the device's own word is one that the node will not write over (below), one end holds. Every other state is one that time moves (section 1, rules 2 and 3). That part rests on section 1 and the event-sequence tests of `reach.rs`, not on the model.

**The device's own word** is none, the carried word, or `sent`. **The node will write over it** where `sent` can be written (every relay OK) or the carried word can (rule 4). A word is otherwise as the node leaves it. That covers a recovery's look that stays pending, under which neither is written.

**The node says whether it will write over the word.** Its look (`POST /api/v1/devices/list`) carries `word_to_come`: true where its next whole pass would write `sent` or the carried word by its own conditions (rule 1, rule 4), worked out by the same function that writes them. The command reads that, and never works the conditions out itself: a command and a node that worked them out apart could disagree, and wait on each other for ever (this record's third review, finding 6).

1. **Done** (status 0):
   - every relay is OK;
   - the device's own word is `sent`.

   It says the line of `person_cmd.rs:2370`, unchanged. Against today, "holds" is now what section 1 says, and "reached" needs an answer about the kept entry: an answer of "show it whole" alone no longer counts (this record's first review, finding 10).
2. **Done, with a warning** (status 0):
   - every relay holds the change: each is OK, STUCK, or OUT and holding;
   - at least one relay is OK, so what the device carried is whole at one relay that it reaches;
   - the device's own word is `sent` or the carried word, or the node will not write either (a look pending).

   It says S6 for each relay that is OUT and holding, S6b for each that is STUCK, then S7. `sent` is accepted beside the carried word: a device that wrote `sent` and then lost a relay that holds the change would otherwise have no end (this record's second review, finding 1).
3. **Not done** (status 3), where every relay is in a class, and either:
   - **some relay lacks the change** (it is OUT and lacking, or REFUSING). Nothing is asked of the device's own word then: safety does not need it, and the word may wait on a whole pass (this record's third review, finding 6); or
   - **no relay is OK,** and the node will not write over the device's own word.

   **There is no condition** on what waits at a relay that is not OK. An attempt after the change is not asked apart: a relay is out of reach only after five minutes counted from the change, with an attempt in them (section 1).

   It says S8 for each relay that is not OK, in the order of the configuration. Then S9 where a relay is reached. Then S10 where a relay is reached and some relay lacks the change, S10b where every relay holds it and none is OK but one is reached, or S11 where none is reached. **It never says that the machine may be closed.**

**Every case that the reviews named reaches an end.** Appendix A checks the rest.

| Case | Classes | End |
|---|---|---|
| B down; A reached, takes the change and all that waits | A OK; B OUT, lacking | 3 |
| B took the change and everything carried, then went down before `sent` | A OK; B OUT, holding; the carried word is written, naming A and B | 2 |
| Both took everything; `sent` was written; then B was lost before what came later went to it | A OK; B OUT, holding; the word is `sent` | 2 |
| B's name does not resolve | each lookup is a failed attempt, every 30 s (rule 3); B OUT, lacking | 3 |
| B listed with the wrong key at A's address | each tick that passes B over is a failed attempt (section 1); B OUT, lacking | 3 |
| B connected, and its shows go unanswered ("not now") | each unanswered show is a failed attempt; B OUT, lacking, while connected | 3 |
| A reached and refusing the change (no room, or another change); B out of reach | A REFUSING; B OUT | 3 |
| A alone, reached and refusing the change | A REFUSING | 3 |
| A full for good, or the address over its allowance: A holds the change and refuses what is carried; B OK | A STUCK; B OK | 2 |
| A holds the change and refuses what is carried; no other relay is OK | A STUCK; no relay OK | 3 |
| No relay reached; each out of reach, whether it holds the change or not | no relay OK | 3 |
| Two changes made apart, and A holds the other: A answers "another", and the device is in a fork | A REFUSING after five minutes. The status line is red for the fork meanwhile | 3 |
| B connected, and its shows are answered "not signed", or "show it whole" to the whole entry | each is an answer of the third kind, a failed attempt at every pass (section 1); B OUT, lacking, while connected | 3 |
| A's connection drops and comes back every three minutes; B is down | the wake that each return causes does not move B's reference (section 1); B OUT, lacking, five minutes after the change | 3 |
| B is given no key, answered "took" from one host, and its name now resolves to another, which cannot be reached | B lacks the change while not connected to the key that answered (section 1); B OUT, lacking | 3 |
| A answers with a later change, which the device applies | the kept entry is no longer this command's change: the wait ends at "This device has since applied another change", as today | 3 (below) |

While no end holds, the wait goes on and says what is missing, as today. Each relay comes to a class within five minutes and the time of an attempt, or a show of five minutes' refusals: within fifteen minutes where its whole shows are answered "not signed" or "show it whole" (section 1). The word is written at the next whole pass.

**The statuses after a change is made:**

- **0** only at ends 1 and 2.
- **Any status other than 0, 1 and 2 means that the change was made.** That is 3, and also what a shell gives a wait that is stopped (130 after Ctrl-C) or killed. H1 and H2 say so.
- **3** at end 3. It is also given where the device has since applied another change (`person_cmd.rs:2359`: whether that change is at every relay is the business of the command that made it), where the device no longer stands in its phrase during the wait (it was removed, is in no list, could not open the change, or follows no phrase: it then shows the change to no relay, and no end would hold; the line says why, and that the command does not say that the machine may be closed; a device in a fork still shows its own entry, and goes on), where the wait cannot be started (`person_cmd.rs:2192-2216`), and on any error during the wait (the node stops, or cannot be asked); such an error is printed on standard error first. **3 means: the change is made, and is not known to be at every relay.**
- **1** is given only before the change is known to be made. That includes the case where the node's answer was lost and the command cannot learn whether it made it: the line says so, as today (`person_cmd.rs:1814-1821`).

- **Why status 3:** 1 is what `main` gives for an error, and 2 is what the argument parser gives. A program that runs the command, an agent with a shell among them (property 10 of the record of 2026-10-04), must not read "not done" as done, or as a failure to make the change. The change is made, and is not to be made again.
- **Why end at all:** the node goes on doing what the command would wait for (showing the change, sending), whether or not the command waits, and the status line goes on saying so (rule 11). A command that never ends is read as one that hung.
- **What it costs:** a person who sees a command end may take the removal as done, whatever its last line said (the second review, H2). Against that: the status is not 0; the last line says what is not done and where to look; and the status line stays amber while it is so (rule 11).
- **Set aside:**
  - **Ending after one minute** (the second form). A relay's restart takes longer.
  - **Advising, in the command's own words, to take a relay out of the configuration.** A relay that is out of reach from here can still serve a device that reaches it, and a removed device at the same address can make a relay look gone (the second review, M1). `cordelia devices` says it, only for a relay gone for good (D4).
  - **"This machine gives it for as long as it is on"** (the second form). It is untrue while the address is turned away, or where only other devices reach the relay. S9 says what is true in each case.

### Rule 9. A recovery waits for the change at each relay

Once a recovery's look has ended, the command says what it says today of the look:

- how much was carried, and which names could not be read;
- each removed key;
- the cut-short sentences, or R3;
- the one-shot lines on names and folders;
- the lines on records not shown, and on each device to add again. They ask the person to act, so they come before the wait.

The three lines on relays go from that list (section 3). Then:

- **Where every relay holds the change,** it says R1 and ends with status 0, as today.
- **Otherwise** it says R0, and waits for the change at each relay. It says S2 and S3 as they come, and ends at the first of:
  - **every relay holds the change:** R1, and status 0;
  - **not done for a recovery** (status 3): some relay lacks the change, and each relay that lacks it is OUT and lacking, or REFUSING (section 1). It says S8 for each such relay, then S9 where a relay is reached, then S10 or S11.
- **There is no condition on what waits, nor on the machine's own word.** Its look may stay pending until the next statement (section 2), and then neither `sent` nor the carried word is written. Its one-shot lines have said what is still to send.
- **Both properties hold** over given classes (appendix A): neither end with status 0 holds while a relay lacks the change, and where each relay either holds the change or is OUT and lacking or REFUSING, one end holds.
- **The statuses** are as rule 8 gives them: 0 only where every relay holds the change, and 3 otherwise once the recovery is made. That includes the path where the look cannot be waited for (`recover_cmd.rs:1993-1998`), and an error during the wait.
- **It never says that the machine may be closed,** as today.
- **Why:** today a recovery prints "keep this machine on: <relay> does not hold the change yet" once and ends with 0. A device that reaches only that relay has not heard that it stopped, and goes on writing where a device that the person said is gone can read (the first review, M9).

### Rule 10. A recovery's judgement of the device it recovers from

Where the statement it recovers from lists one device, a recovery reads that device's words before its yes, as today.

1. **It wrote `sent`:** as today. Not cut short.
2. **It wrote the carried word** (read by rule 5) and not `sent`, and **one of the keys that the word names is the key of a relay that this machine read** in this recovery. What it carried is at a relay that the look reads. Not cut short: nothing is said of it, as for `sent`.

**A relay that this machine read** is one at which this recovery read, before its yes, the personal channel of the change it recovers from to its end: what the node says of each relay as "read to its end" (the record of recovery, §3), with the key of the connection that it read on. Section 1's "reached" is not used here: before its yes the machine keeps no change entry, and makes no show (this record's second review, finding 5).
3. **It wrote the carried word, and this machine read none of the relays that it names:**
   - **before the yes,** R2. The look is made once, so the remedy is offered while nothing is made;
   - **after the look,** R3 in place of the sentence that says it was cut short.
4. **Neither word was found:** the three sentences of today, by how the channel was read (whole, in part, held by none).

The command learns, from the node, the key of each relay that it reached, and the key of each relay it is set up with that has one in its configuration. A relay that the word names is shown as rule 6 shows it. R2 and R3 take one of two forms:

- **this machine is set up with that relay and did not read it:** "reach it";
- **it is not set up with it:** set it up, from the configuration of the device named (its `[[network.bootnodes]]`), where that device is at hand.

The look itself is not changed by any of the four: what it takes was never decided by the word.

### Rule 11. The status line

**"memory: a relay not known to hold the latest change"** (or "memory: <n> relays not known to hold the latest change"), amber. Where the node has not yet noted that it keeps the entry it keeps, it came to keep it now.

- **For each relay that lacks the change** (section 1), once it has lacked it for more than five minutes by the node's own clock. The five minutes are counted from the later of when the relay came to lack the change, when the kept entry last changed, the node's start, and a sleep (section 1): a relay that held the change and lost it lacks it from then. A wake after no connection does not restart them (fourth check, finding 2).
- **Connected or not, with sync on or off, and with or without a folder mapped:** wherever the device follows a phrase, as the other amber of a person's devices. It is no longer among the amber of folders.
- **For seven days** (`REMOVAL_NOT_APPLIED_SHOWN_DAYS`), as "a removal not yet applied by every device" is, from the latest of when this device came to keep the entry, when this version first started on it, and that relay's latest answer about the entry. So after the upgrade a removal made on alpha.12 that a relay never got is amber for seven days, however old the removal; and a relay that held the change and says, weeks later, that it has no room for it is amber again, for seven days from its answer, and for as long as it goes on saying so. A relay that gives no answer (one set up later, or one that this site cannot reach) is amber for seven days from the later of the other two times, and then no more. After that it is in `cordelia devices` only (D4).
- **Its place:** after "names carried, not yet sent" (item 7 of `indicator.rs:316-342`), and so after every other amber of a person's devices, and before the amber of folders. A device added since, or one that left, is not hidden by it. "A relay has no room" is hidden by it, as any later amber is by an earlier one; the tooltip says both.
- **A relay in the third state of section 1 is not counted:** it has not been shown to lack the change, and no change has been made since its mark.

**"memory: a relay out of reach for <minutes> minutes"** (or "memory: <n> relays out of reach"), amber.

- For a relay that is out of reach and holds the change, while another relay is reached: the warning of the ruling.
- It is said with sync on, a folder mapped and a report, as "no relay" is.
- It comes **last** among the amber. It is the least of them, and one that lasts for good must hide nothing.

**"memory: no relay for <n> minutes"** stays as it is. Where no relay is connected it is said, and the out-of-reach line is not. "a relay not known to hold the latest change" is said all the same.

- **Why:** the second review (H2) showed that once the command has ended, nothing standing said that a relay lacks a removal. Not where the relay is not connected; not with sync off; not on a machine that has just recovered and maps nothing.
- **Why seven days, and the words "not known to hold":** this record's first review (finding 5). A relay that cannot be reached from a site, after a change, lacks it as far as that machine can ever know. Another device may have given it the change. "Does not hold" would then be untrue, and amber for good would hide what comes after it for good.
- **What it costs:** after seven days a relay that still lacks a removal is amber no more. `cordelia devices` still says so, as it does of a device that has not applied a removal.

### Rule 12. `cordelia devices`, of each relay

The relay lines are D2 to D5, by these cases, the first that holds:

- **lacks the change and out of reach:** D4;
- **holds it and out of reach:** D5;
- **not heard since the device woke:** D2 while the relay is not out of reach, D3 once it is. Out of reach, that is a relay in the third state of section 1, which neither holds nor lacks the change.

D4 and D5 come before what is said of the wake: what a relay is known to hold is kept across starts, and after a start a relay that holds the change and cannot be reached has not answered since the start, yet is D5 (section 11, the end-two test). The build machine of section 6, in the third state, is D2 and then D3. A line of D2 to D4 is sentences: where something of the device's own waits at that relay, how much is said on a line of its own under it, not after it.

The other relay lines stay as they are. The line for a relay "same relay" stays out, as today.

### Rule 13. The wake rule: no change to what it does

When the node starts, or reaches a relay after having reached none, or wakes from sleep, it still takes nothing and sends nothing until every relay has answered or 30 seconds have gone. A relay out of reach is no exception. Only the words that name the relay change (T1, D2, D3). Section 6 says why.

### Rule 14. The help

- `cordelia remove-device --help`, `cordelia renew --help` and `cordelia settle --help` say H1 in place of "Keep this machine on until the command says you can close it." (`settle` says nothing of it today.)
- `cordelia recover --help` adds H2.

## 5. Every sentence that changes, word for word

**Placeholders.**

- `<relay>` is a relay as the device's configuration names it (its address), and as rule 6 names it in a line about another device's word.
- `<when>` is as section 1 defines it. In D2, D3 and T1 it is when the device last woke; where no relay is reached, and so the device has not woken, it is when it came to reach none: its start, a sleep, or the pass that found no connection open. Where the node has said neither, " at <when>" is left out.
- `<since>` is one of two phrases:
  - "has not been reached from here since <when>", where the relay was reached since the latest of the start, a sleep and the change of the kept entry, at the moment it was last reached;
  - "has not answered since <when>", where it was not, at the relay's reference (section 1): the start, the sleep, or the change of the kept entry, whichever was latest. A wake after no connection does not move it (fourth check, finding 7).
  - So a relay reached before a change, and not since, "has not answered since" the change: it has said nothing of the change, and "reached from here since" a moment before the change would read as though it had.
- `<minutes>` is whole minutes. A list of relays is joined with ", " and " and ".
- **`<held>` and `<not yet>` come from two sets that never overlap** (this record's third review, finding 4):
  - of this device's own: `<held>` is each relay at which nothing that it carried waits, by its rows of what it sent, reached or not; `<not yet>` is every other relay;
  - of another device's carried word: `<held>` is the keys of field 2, with "and <m> more" where field 3 is not 0; `<not yet>` is the count of field 4.

  A line says `<not yet>` only where it is not empty, or not 0.

**The subject, and the length.** A line that tells you what to do has "you" as its subject, or is said to you ("keep this machine on", as today). A line that says what the machine does has "this machine" or "this device" as its subject. A sentence says one thing.

**Each is on standard output.** A status is the process's exit status; where none is given, the command goes on.

**The wait after a change** (`cordelia change-made`, from `remove-device`, `renew` and `settle`):

- **S1, its first line:** "You may close this machine once every relay holds the change, and what this device carried is at a relay that it reaches. This command stays until then, and says what is missing. It ends sooner, with status 3, where for five minutes a relay that is not known to hold the change cannot be reached or refuses it, or where no relay that this machine reaches has what this device carried. It then does not say that you may close this machine. Stopping it stops nothing: the node goes on."
- **S2,** for a relay that lacks the change and is out of reach, while the wait goes on: "keep this machine on: <relay> is not known to hold the change yet, and <since>"
- **S3,** for a relay that holds the change and is out of reach: "<relay> holds the change, and <since>"
- **S4,** where the device's own word is the carried word: "this device has sent what it carried to <held>; not yet to <not yet>"
- **S5,** of another device whose carried word is read: "<device> has applied the change, and has sent what it held to <held>; not yet to <not yet> other relay<s>"
- **S6,** end 2, for each relay that is OUT and holding, one of:
  - in `<held>`: "  <relay> holds the change and all that this device carried, and <since>."
  - not in `<held>`: "  <relay> holds the change, and <since>. Some of what this device carried is not there yet."
- **S6b,** end 2, for each relay that is STUCK: "  <relay> holds the change. It has refused for room what this device still has to send there since <when>."
- **S7,** end 2, last (status 0). Its parts, each said only where it is so:
  - "Every relay holds the change. You may close this machine."
  - "All that this device carried is at <held>."
  - "<not yet> <gets | get> the rest when this machine next reaches <it | them>."
  - "What this device writes from now on waits for <each relay OUT or STUCK>."
  - "`cordelia devices` shows which devices have applied the change."
- **S8,** end 3, one line for each relay that is not OK, in the order of the configuration:
  - OUT and lacking: "  <relay> is not known to hold the change, and <since>."
  - REFUSING, no room: "  <relay> is reached, and has not taken the change: it had no room for it at <when> (<it is full | this address is over its allowance of new channels there>)."
  - REFUSING, another change: "  <relay> is reached, and holds a change that this device does not take (<why>). It does not take this one in its place."
  - OUT and holding: "  <relay> holds the change, and <since>."
  - STUCK: S6b.
- **S9,** end 3, once, where a relay is reached. One sentence for each kind of relay that lacks the change, in this order, each said only where there is such a relay:
  - "A device of yours that reaches only <relays that lack the change> may not have heard of the change."
  - "Until it does, it goes on in the channels from before the change, where every device that held their secret can still read what it writes."
  - for relays OUT and lacking: "<relays> take<s> the change from a device that has applied it and reaches <it | them>, this one included, and from a relay that works with <it | them>."
  - for those of them not connected, with a name that resolves: "While this machine is on it dials <it | them> every 30 seconds."
  - for those whose name does not resolve: "It looks <its | their> name<s> up every 30 seconds."
  - for those connected whose shows get no answer of the first two kinds: "It shows <it | them> the change again at most every ten minutes."
  - for a relay with the wrong key at an address where another relay is connected: "It cannot dial <relay> while another relay answers at its address."
  - for relays REFUSING: "<relays> refuse<s> the change. A device that reaches <it | them> hears of it only once <it takes | they take> it, or from another relay."
- **S10,** end 3, last, where a relay is reached and some relay lacks the change (status 3): "The change is not known to be at <relays>. This command ends here, with status 3. It does not say that you may close this machine. `cordelia devices`, here or on a device of yours that reaches <it | them>, says when <it holds | they hold> the latest change."
- **S10b,** end 3, last, where every relay holds the change, none is OK, and one is reached (status 3): "Every relay holds the change. What this device carried is at no relay that this machine reaches: <relays> refuse<s> it for room. This command ends here, with status 3. It does not say that you may close this machine. Keep it on. `cordelia devices` says when what it carried is sent."
- **S11,** end 3, last, where no relay is reached (status 3). Its parts, the second said only where no relay holds the change:
  - "No relay can be reached from here."
  - "None is known to hold the change. No other device of yours can hear of it until one does."
  - "This command ends here, with status 3. It does not say that you may close this machine. Keep it on, on a network from which a relay can be reached. `cordelia devices` says what is missing."
- **The wait could not be started** (`person_cmd.rs:2210`): its words stay, and the status is 3.
- **An error during the wait:** "The change is made (change <n>). This command could not go on: <the error>. Do not make the change again. `cordelia devices` shows whether each relay holds it." On standard error, with status 3.

**A recovery:**

- **R0,** where a relay does not hold the change when the look has ended: "This command stays until every relay holds the change. It ends sooner, with status 3, once each relay that is not known to hold it cannot be reached, or refuses it, for five minutes. Stopping it stops nothing: the node goes on, and the recovery stays made."
- **R1:** "Every relay holds the change."
- **R2,** before the yes, with the lines that say how the personal channel was read. It has a first part, and one of two endings.
  - **The first part:** "<device> wrote that it had sent what it carried to <held>." Then, where `<not yet>` is not 0: "It had not yet sent it to <not yet> other relay<s> that it was set up with." Then: "This machine has read none of <them | it>. The look of this recovery is made once, so what that device carried may be only there."
  - **Where this machine is set up with a relay named and did not read it:** "To bring it in by this recovery, answer no. Make sure this machine can reach <relay>, and run `cordelia recover` again."
  - **Where it is not:** "To bring it in by this recovery, answer no. On this machine, set up the relay whose key is <key>: the configuration of that device (its `[[network.bootnodes]]`) names it. Then run `cordelia recover` again."
  - **Where it is not, and this machine is set up with relays that it is given no key for and did not reach**, one of which may be that relay: "To bring it in by this recovery, answer no. Make sure this machine can reach <those relays>: the relay whose key is <key> may be <that one | one of them>. If it is not, set it up on this machine: the configuration of that device (its `[[network.bootnodes]]`) names it. Then run `cordelia recover` again."
  - **Both endings go on:** "If you answer yes, it comes in later only by `cordelia sync carry <name> --from <device>`, with the phrase, once this machine reaches <relay | that relay>."
- **R3,** after the look, in place of "never wrote that it had sent what it carried ... was cut short": "The device that this was recovered from, <device>, wrote that it had sent what it carried to <held>. This recovery did not read <it | them>. What it carried that is not here is there. Once this machine reaches <it | them>, `cordelia sync carry <name> --from <device>` brings it in, with the phrase."
- **The wait of rule 9** says S2, S3, S8, S9, S10 and S11 as rule 8 does. Its status is 3 where it ends by them, and 0 where it ends at R1.

**`cordelia devices`:**

- **D1,** of another device whose carried word is read: "has applied change <n>, and has sent what it held to <held>". Then, where `<not yet>` is not 0: "; not yet to <not yet> other relay<s> that it is set up with (if it is lost now, what it held is at <held> alone)".
- **D2,** a relay not heard since the device woke: "  <relay>: has not answered since this device started or woke at <when>. A change made while this device was off may be there, and not have reached it."
- **D3,** the same, out of reach: "  <relay>: has not answered since this device started or woke at <when>, and cannot be reached from here. A change made while this device was off may be there, and not have reached it."
- **D4,** lacks the change and out of reach: "  <relay>: is not known to hold the latest change, and <since>. A device of yours that reaches only it may not have heard of that change. If you know that <relay> is gone for good, take it out of the configuration of every device. Do not do so only because this machine cannot reach it: it may still serve a device that does."
- **D5,** holds it and out of reach: "  <relay>: holds the latest change (as it said at <when>), and <since>"

**The status** (`cordelia status`, the lines of `look.rs` `says`):

- **T1:** "has not heard from <relay> since it started or woke at <when>: a change made while this device was off may be there, and not have reached it". T2 and T3 come before it, as D4 and D5 come before D2 (rule 12); a relay in the third state that is out of reach is T1.
- **T2,** a relay that lacks the change and is out of reach: "<relay> is not known to hold the latest change, and <since>"
- **T3,** a relay that holds it and is out of reach: "<relay> <since>: this device sends through the others"
- **The line:**
  - "memory: a relay not known to hold the latest change", or "memory: <n> relays not known to hold the latest change";
  - "memory: a relay out of reach for <minutes> minutes" (rounded up, so never 0: "1 minute" for one), or "memory: <n> relays out of reach" (rule 11). The minutes are counted from when it came to be out of reach.

**The help:**

- **H1** (`remove-device`, `renew`, `settle`): "Keep this machine on until the command says you can close it. Where a relay that is not known to hold the change cannot be reached, or refuses it, the command says so and ends with status 3, without saying that you can. Any status other than 0, 1 and 2 means that the change is made: do not make it again."
- **H2** (`recover`): "After the look the command waits for every relay to hold the change. Where one that is not known to hold it cannot be reached, or refuses it, the command says so and ends with status 3. Any status other than 0, 1 and 2 means that the recovery is made: do not run it again. Keep this machine on."

## 6. The wake rule, and the build machine

**The 30 seconds stay.** A node cannot tell a start after a week off from a start after a minute. Nor can it tell a relay that cannot be reached from this site from one whose connection comes up in five seconds. The wait is one of the narrowings that property 1 names ("a device that wakes asks every relay it is set up with before it takes or sends anything"). So the ruling's condition does not hold for it, and it is not relaxed.

**Set aside: remembering, across starts, that a relay was out of reach at the last stop, and not waiting for it.** That is the case the rule is for.

- A laptop off for a week, at a site where relay B is blocked, starts with a removal at B only.
- Without the wait, it would take from A, and send to A, in the old channels at once, with nothing said.
- With the wait it does the same 30 seconds later, and its status names B.

The wait does not save it there. What the third form adds there is the faster dial of B after a change (rule 3), and the words.

**The build machine, before any change and after one.**

- **Added on this version, or its phrase made here, or first started on this version under statement 1, with no change since:** B is in the third state of section 1 (its mark is the kept entry). It is not dialled faster, not amber, and its line is D2, then D3.
- **Upgraded from alpha.12 under a statement after statement 1, or after a change made or applied here:** B lacks the change, as far as this machine can know: it has no answer about the entry kept. It is dialled every 30 seconds, and is amber for seven days (rules 3 and 11). For a machine that came by the upgrade that holds until B answers from it, which at such a site is never. The way out is to take B out of the configuration of that one machine, where it is of no use. This is not D4's case: B is not gone, it is only out of this site's reach, and D4's advice to take a relay out of every device is for a relay gone for good.

**The sentence changes.** "has not answered since this device woke: a change made while it was off may not have reached it" is read as saying that the relay was off. It says the device woke.

- D2 and T1 say "since this device started or woke at <when>", and "while this device was off".
- Once the relay is out of reach, D3 says so.
- The clause about a change made while the device was off is kept for every relay that has not answered since the device woke, a start included (the first review, M5).

**What it costs, as today:** at a site where a relay cannot be reached, each start, and each return after no relay was reached, waits 30 seconds before it syncs (the record of 2026-10-04, section 12).

## 7. Alpha.12 and this version together

**Nothing on the wire changes.** No stream, answer, entry, statement or relay changes. A relay of either version serves both.

**A device of this version beside one of alpha.12:**

- **The carried word, written by this version.** Alpha.12 stores it where its signer counts and reads nothing of it (`take.rs:188-255`; its names are `name/`, `added/`, `applied/`, `left/`). It shows that device as "is still sending what it held", as today. It does not carry it at its own next change: a device carries only its own words. A recovery made with alpha.12 counts it among the entries that device signed (`recover.rs:362-366`), and judges "cut short" by `sent` alone, as today.
- **Alpha.12 never writes the carried word.** A device of this version shows it as today.
- **A device that goes back from this version to alpha.12.**
  - Its database opens there: no schema step is added, and the key `person.relays_known` is not read.
  - It holds its own carried word, and alpha.12 carries it at its next change: alpha.12 leaves out only `added/` and `applied/`. The copy in the new generation has the old statement's number, and rule 5 does not read it. It waits to be sent among what was carried, and is sent.
  - Brought forward again, what it knows of each relay is as it last wrote it. An answer given meanwhile is not there, so a relay may lack the change until it answers again.
  - Alpha.12's `cordelia phrase` and `cordelia init --new-key` do not remove `person.relays_known`. A device that left its phrase on alpha.12 and is brought forward again holds answers about entries of the phrase it left. No such entry is the one it keeps, so each such answer reads as "lacks", which errs the safe way; the next answer writes over it (this record's second review, finding 9).
- **The faster dial, the state of each relay, the ends of the wait and the status** are each of the device where they run. A device of alpha.12 dials as today, waits as today and says what it says today.
- **A command and a node of two versions** do not work together: a command that changes anything refuses a node of another version (the record of 2026-10-04, 10.1, rule 6). `cordelia change-made` and `cordelia recover-made` run from the same program as the command that made the change, which has already refused a node of another version.

**What a relay sees of it:**

- the carried word and its delete: one entry of the personal channel each. A word that names up to four keys, and every delete, is a content of 256 bytes, as a device's words under `applied/` and `left/` are; a word that names five keys or more is of 512 bytes, as a record of an addition is. So a relay cannot tell it by its size from every other entry there, only from those of the other size. It is not padded to 512: for a device set up with the two default relays it would then stand beside the records of additions and apart from every word of a device, where at 256 it stands among them;
- dials every 30 seconds from a device for which it lacks a change, where today it sees one every 15 minutes.

## 8. What it costs

- **What a device carried is at fewer relays,** where one is out of reach, until that relay is reached or handed it. A relay lost in that time loses it. The carried word says where it is, and a recovery says so before its yes.
- **A command that ends while a relay lacks the change** (rule 8, end 3). A person may close the machine all the same. The status, the last line and the amber line say what is not done.
- **One more entry, and its delete,** in the personal channel for each device that has a relay out of reach after a change.
- **One key of `node_meta`,** of a few hundred bytes, written at each answer that changes what is kept of a relay: after a change, once or twice for each relay.
- **Every device learns the keys of the relays** to which each other device sent what it carried, and how many relays each is set up with.
- **Dials every 30 seconds** of a relay that lacks a change, for as long as it does as far as this machine knows. That can be for good at a site that cannot reach it, and it is so from the first start on this version, under a statement after statement 1, for every relay that does not answer from there.
- **After the upgrade under a statement after statement 1, every relay lacks the change** until it answers a show from this device. A relay that answers within the wake is never amber; one that does not is amber for seven days (rule 11).
- **A wait that ends with status 0 though a relay refuses what is carried** (end 2, a relay STUCK), where another relay holds it whole. The status line says "a relay has no room" for as long as the refusal stands.
- **The amber of a relay not known to hold the latest change lasts seven days,** and is then in `cordelia devices` only.
- **A recovery's command can stay** for five minutes and more after its look, where a relay lacks the change. Today it ends at once.
- **Real-process tests of more than five minutes.** They are marked so that `cargo test --all` passes them over, and a CI job of their own runs them on every pull request, beside the others (section 11).

## 9. Set aside, and why

- **Relaxing the change at each relay** (the first form). Property 1 names what the command says as a narrowing.
- **Waiting for ever** (today, and alpha.12). It is what was seen on real machines.
- **One minute** for out of reach, and **one dial made for it** (the second form). A relay's restart takes longer, and no such dial can be asked for (section 2).
- **Names of relays in the carried word** (the second form). Rule 4.
- **The advice to take a relay out of the configuration in the command** (the second form). Rule 8.
- **Skipping the wake wait for a relay that was out of reach.** Section 6.
- **A new meaning for `sent`.** Rule 1.
- **Writing the carried word where no relay is reached.** It would name no relay. Then nothing that the device carried is at any relay, which is what having no word says.
- **Status 1 or 2 for "not done".** Rule 8.
- **"Lacks" as "not heard since the wake"** (this record's first revision), and **"holds" in memory only.** Rule 2.
- **A schema step for what each relay is known to hold.** Rule 2.
- **The amber of a relay not known to hold the change, for good.** At a site that cannot reach a relay it would be amber after every change, and hide what comes after it, for good (rule 11).
- **A mark at the first entry a device keeps whatever it is, or at a first start on this version under a later statement** (this record's first revision). It can be untrue: a removal made on alpha.12 that a relay never got would have been its mark, and nothing would have said that the relay lacks it (this record's second review, finding 3).
- **"Known to hold" as the last "held", which a refusal does not clear** (this record's first revision). A relay that lost the phrase's channel would have counted as holding the change (this record's second review, finding 2).

## 10. Constants

In `crates/cordelia-core/src/protocol.rs`, each with its line for `docs/specs/parameter-rationale.md`:

- **`OUT_OF_REACH_SECS: u64 = STATUS_AMBER_WAIT_SECS`,** that is 300. Derived. For §12.10:

  > How long a relay that the device is set up with has not been reached, with every attempt at it in that time failed, before it is out of reach (decision 2026-10-19 §1). It is the time after which the status line shows what passes by itself: a relay's restart, and a machine that wakes, are each through it in less. A relay stays out of reach until it is reached, or until its reference moves: a start, a sleep, or a change of the change entry the device keeps. A wake for any other reason does not move it. The command after a change ends without success only once each relay that lacks the change has been out of reach for this long since the change, or has refused the change for this long.

- **`PERSONAL_REACHED_PREFIX: &str = "reached/"`.** For §12.6, beside the four prefixes of the personal channel:

  > The first part of the name of a device's word that it has sent what it carried to the relays it reaches, where the others are out of reach (decision 2026-10-19 §4, rule 4). The device's key follows it. It is no prefix of another, and none is of it.

- **`REACHED_WORD_MAX_RELAYS: usize = 8`.** Primitive. For §12.6:

  > The most relays that the carried word names by key, and the most that a reader reads from one (decision 2026-10-19, rules 4 and 5). A device is set up with two relays by default; eight is four times that, and keeps the word one content of 512 bytes. A device set up with more names the first eight in the order of its configuration, and says how many more.

- **`REACHED_WORD_MAX_COUNT: u64 = 256`.** Primitive. For §12.6:

  > The most that either count of the carried word may say (decision 2026-10-19, rule 5): how many more relays hold what a device carried, and at how many it may still wait. A word written by another device is read only within it, so that no line says a number that no configuration holds.

**Constants that are used again, with a sentence added to their lines:**

- `BACKOFF_BASE_SECS` (parameter-rationale §3): "It is also the most that a relay that lacks the change the device keeps waits to be dialled again, whether or not another relay is connected; a longer wait already set is cut to it when the relay comes to lack the change (decision 2026-10-19, rule 3)."
- `BOOTNODE_RESOLVE_RETRY_SECS`: "It is also how often names are looked up while a relay that lacks the change has a name that does not resolve (decision 2026-10-19, rule 3)."
- `STATUS_AMBER_WAIT_SECS` (§12.10): "a relay that is not known to hold the latest change, connected or not, counted from the later of the change of the kept entry, the node's start and a sleep, and not from a wake after no connection", in place of "a relay that is connected and does not hold the latest change". And: "It is the time a relay takes to be out of reach (`OUT_OF_REACH_SECS`)."
- `REMOVAL_NOT_APPLIED_SHOWN_DAYS` (§12.10): "A relay not known to hold the latest change is shown for as long (decision 2026-10-19, rule 11)."

**Not a protocol constant:** the exit status 3. It is the command's, beside `STAYS_COMMAND` in `person_cmd.rs`, as `NOT_AT_EVERY_RELAY_STATUS`. `recover_cmd.rs` uses the same.

**Checks at compile time:**

- `OUT_OF_REACH_SECS > 2 * WAKE_WAIT_SECS`: a device that wakes has heard from its relays, or given them up, well within it;
- `OUT_OF_REACH_SECS > BOOTNODE_RESOLVE_RETRY_SECS` and `OUT_OF_REACH_SECS > BACKOFF_BASE_SECS`: a relay that lacks the change has an attempt in its five minutes;
- the carried word at its bound is one content of 512 bytes.

## 11. Tests

Each test fails on an assertion if its rule is taken out.

**Real-process tests.**

- In those, a relay cannot be reached in one of four ways:
  - its name does not resolve (the `NO_SUCH_NAME` of `person_e2e.rs`);
  - its process is stopped;
  - it is set up at a port on which nothing listens;
  - it is a second relay set up at the address of the first, with another key.
- Those that wait for the five minutes are marked `#[ignore]` with the reason. A CI job of their own (`ci.yml`, "out of reach") runs them with `--ignored` on every pull request, beside the others, so that the job that runs `cargo test --all` is not made longer.
- **That job must be required for a merge into main.** Which checks are required is set in the repository's settings on GitHub, not in the repository, so this record cannot make it so: it is an act for whoever builds this (section 12).

**Section 1 and rule 2, what is known of each relay** (units, in the module that keeps it, `crates/cordelia-node/src/device_entries/reach.rs`, with a clock that the test moves, and in `at_relays.rs` for what is stored):

- **Out of reach:**
  - `a_relay_is_out_of_reach_after_five_minutes_of_failed_attempts`: not at 299 seconds, and at 300;
  - `not_while_an_attempt_is_in_flight`;
  - `not_with_no_attempt_in_the_five_minutes`;
  - `a_lookup_that_resolves_is_no_attempt` (first review, finding 3);
  - `a_new_kept_entry_starts_the_five_minutes_again`;
  - `being_reached_ends_it_at_once`;
  - `a_connected_relay_whose_shows_go_unanswered_is_out_of_reach`;
  - `another_key_and_a_name_that_does_not_resolve_are_failed_attempts`;
  - `each_answer_of_the_third_kind_is_a_failed_attempt`: "not signed", "show it whole" to a whole show, a reply that is not `EntryShown`, a reset, a time-out, and a round that runs out, on a connection that stays open: the relay is out of reach. A reset or a time-out is shown again at each pass; "not signed" and "show it whole" to a whole show at the pace of the wait that doubles, so out of reach comes within fifteen minutes (third review, finding 1; fourth check, finding 4);
  - `whole_to_a_short_show_is_no_answer`: the whole show that follows is what counts;
  - `a_wake_after_no_connection_does_not_move_another_relays_reference`: B down; A drops and comes back every three minutes; B is out of reach five minutes after the change (third review, finding 2);
  - `a_start_a_sleep_a_new_kept_entry_and_being_reached_each_move_the_reference`;
  - `an_attempt_must_be_in_the_last_five_minutes_and_after_the_reference`: a relay whose first attempt after the reference comes at minute nine becomes out of reach at minute nine (third review, finding 7);
  - `a_relay_with_the_wrong_key_where_another_is_connected_is_out_of_reach_with_no_dial` (first review, finding 2), with an attempt counted at each tick that passes it over (second review, finding 6);
  - `a_same_relay_name_is_never_one`;
  - `a_relay_that_held_and_then_refuses_is_refusing_five_minutes_on`: it answers `Taken`, then `NoRoom` at every show; five minutes after its first `NoRoom` it is REFUSING, and the wait ends at end 3 (fourth check, finding 1).
- **Every state comes to a class** (third review, findings 1 and 2; event sequences over the clock and the answers, in `reach.rs`): `every_unclassed_state_ends_in_a_class`. From each kind of state that section 1 lists as in no class, a sequence of answers, failed attempts and clock steps that the node can meet is run, and the relay is in a class within five minutes and the time of an attempt, or within fifteen where its whole shows are answered "not signed" or "show it whole". A relay that held the change and then answers "no room" at every show is REFUSING five minutes after it came to lack it (fourth check, finding 1). The enumeration over the classifier's inputs cannot show this: it takes the classes as given.
- **The latest answer, and the mark:**
  - `the_latest_answer_writes_over_the_one_before`: "held" then "no room" about the same entry is "lacks", and so are "over the allowance" and "another"; "no room" then "took" is "holds" (second review, finding 2);
  - `show_whole_not_signed_a_reset_and_a_time_out_write_nothing` (first review, finding 10);
  - `what_is_kept_survives_a_restart_and_goes_with_the_relay`;
  - `adding_leave_forgets_it`: the key is in the list that `adding::leave` removes, and `cordelia phrase` on a device of several, `cordelia init --new-key` and a removal of this device each leave nothing of it (second review, finding 8);
  - `the_mark_is_written_only_at_its_three_moments`: none at the first start on this version under a later statement, none for a relay set up later, none after `cordelia recover` (second review, finding 3; fourth check, finding 3);
  - `a_removal_made_on_alpha_12_leaves_a_relay_that_never_answers_lacking_after_the_upgrade`: a database in alpha.12's form, whose kept entry is a removal, is started on this version with one relay that answers and one that does not. The second lacks the change and is amber; the first holds it after its answer (second review, finding 3);
  - `a_relay_in_the_third_state_neither_holds_nor_lacks` (first review, finding 5);
  - `the_mark_is_written_at_phrase_and_at_a_first_start_under_statement_1` (third review, finding 5);
  - `a_relay_given_no_key_holds_only_while_connected_to_the_key_that_answered`: it answered "took" from one key; its name now resolves to an address where nothing answers; it lacks the change, and the wait ends at end 3, not end 2. Connected again to the same key, it holds; to another key, it lacks until that key answers (third review, finding 3);
  - `the_two_times_are_kept`: when the kept entry came to be kept, and when this version first started (third review, finding 9).

**Rule 3, the pace:**

- `p2p.rs`, `a_relay_that_lacks_the_change_is_dialled_at_the_pace_of_a_node_cut_off`. With another relay connected the wait stays at 30 s. Once it holds the change, the next wait is 900 s at the cap. A relay in the third state is dialled as today.
- `p2p.rs`, `a_wait_already_set_is_cut_when_the_relay_comes_to_lack_the_change`: a next try 900 s ahead becomes 30 s ahead, and the lookup loop wakes (finding 4).
- `p2p.rs`, `names_are_looked_up_every_half_minute_while_a_relay_that_lacks_the_change_does_not_resolve`.
- **Real processes,** `device_entries_e2e.rs`, `a_relay_that_lacks_the_change_is_dialled_every_half_minute` (ignored: it runs eleven minutes).
  - A device has relays A and B. B is stopped, and stays down for ten minutes, so that its wait is at the cap.
  - A change is made. Within 40 seconds, and then never more than 40 seconds apart while A is connected, B's "last tried" in `cordelia peers` moves.
  - B is started again: within 40 seconds it holds the change.
- **Real processes,** `devices_e2e.rs`, `a_relay_unreachable_from_here_is_dialled_as_today_until_a_change` (ignored: about seven minutes).
  - A device is set up with A and with `NO_SUCH_NAME`, and is added from another.
  - For six minutes no amber of a relay not known to hold the change is shown, and B is looked up at the pace of today.
  - Then a change is made on the other device. Within five minutes and a half, the amber is shown here, with sync off and nothing mapped.

**Rule 4, the carried word** (`at_relays.rs`):

- `the_carried_word_is_written_only_where_sent_would_be_but_for_relays_out_of_reach`. One case for each condition: a look pending; a look interrupted; a device that has stopped; a word with ` sent`; no relay reached; something carried waits at a relay reached; a relay not reached and not out of reach; every relay connected, where `sent` is written and this is not.
- `it_is_rewritten_when_a_field_changes_and_deleted_when_sent_is_written`.
- `it_names_eight_keys_and_counts_the_rest`.
- `person.rs`, `the_carried_word_and_its_delete_are_not_carried`.

**Rule 5, the reader** (`look.rs`):

- `the_carried_word_is_read_only_from_its_own_key_under_the_applied_number`. It is refused where:
  - another device signed the slot;
  - the key does not count;
  - the number is another;
  - the device's `applied/` word is of another number;
  - it holds nine keys, no key, or one key twice;
  - the third field is not 0 with fewer than eight keys;
  - a count is over 256;
  - it is malformed.

  Where `sent` is there too, `sent` is what is read (first review, finding 11). A fourth field of 0 is read: a relay out of reach that took everything is named in field 2, not counted in field 4 (third review, finding 4).

**Rules 6 to 8, what is said, and the ends** (`person_cmd.rs`):

- `the_wait_never_says_may_be_closed_or_ends_with_0_while_a_relay_lacks_the_change`. It runs over every combination, as the node can give them, of:
  - each relay's state (reached or not, out of reach or not, holds, lacks, refuses);
  - the device's own word;
  - what waits.

  The looks are built by the node's own function from a store and the state of each relay, not written by the test: so "no room" never comes with "nothing waits" unless the node gives that (first review, finding 1).
- `the_ends_are_safe_and_live_over_every_state` (second review, finding 8): the enumeration of appendix A, in Rust, over the node's own function that puts a relay in its class and its own test of each end, for two and three relays. Safety: no end with status 0 while a relay lacks the change. Liveness: in every state that time does not move, one end holds. The same for a recovery's wait. Taking out `sent` from end 2, or STUCK from it, makes it fail.
- `a_relay_is_named_three_ways` (rule 6): by the reader's configuration, by a default relay's name, and by its key (second review, finding 8).
- `each_relay_line_by_its_case` (rule 12): D2 to D5 and the lines of today, one case each (second review, finding 8).
- `each_case_of_the_table_of_rule_8_reaches_its_end`: every row, with its status.
- `the_statuses`: 0 only at ends 1 and 2; 3 at end 3, where the wait cannot be started, on an error in the wait, and where another change was applied (first review, finding 7).
- `end_three_does_not_wait_on_the_word_where_a_relay_lacks_the_change`, and `the_command_reads_word_to_come_from_the_node` (third review, finding 6).
- `held_and_not_yet_never_overlap`: S4 to S7, D1, R2 and R3 over words and rows in which a relay out of reach took everything (third review, finding 4).
- `each_line_word_for_word`: S1 to S11, D1 to D5, T1 to T3, R0 to R3, H1 and H2, `<since>` in both forms, and `<when>` with and without its date (finding 8).

**Real processes, `person_e2e.rs`:**

- `a_change_ends_not_done_where_a_relay_that_lacks_it_cannot_be_reached` (ignored).
  - A laptop is set up with a relay that answers and with `NO_SUCH_NAME`, and removes a device.
  - Within five minutes the command does not end, and says S2. After them it says S8, S9 and S10, and ends with status 3. It never says "may be closed".
  - `cordelia status` is then amber with "memory: a relay not known to hold the latest change", with sync off and nothing mapped.
- `a_change_ends_not_done_where_the_relay_it_reaches_refuses_it` (ignored; finding 1).
  - Relay A is started with a small cap and filled with channels that the test signs. It is then set up on the laptop, which never showed it its change entry before. Relay B is `NO_SUCH_NAME`.
  - A device is removed. A refuses the change for room, and B is out of reach.
  - After five minutes the command says S8 for both, S9 and S10, and ends with status 3, though what was carried waits at A.
  - The same with A alone ends the same way.
- `a_change_ends_not_done_where_the_other_relay_has_the_wrong_key_at_the_same_address` (ignored; finding 2). The laptop is set up with one relay of the test's under two names, one with another key. The command ends at end 3, with S9's words for a relay that cannot be dialled.
- `a_relay_that_comes_back_within_five_minutes_does_not_end_the_wait` (ignored: more than two minutes; third review, finding 10). B is stopped at the change, and started again two minutes later. The command ends at end 1, with status 0.
- `a_relay_that_holds_the_change_and_cannot_be_reached_ends_at_end_two` (ignored; second review, findings 1 and 8). It does not depend on stopping B inside a window:
  - A and B take the change and all that was carried, and the laptop writes `sent`.
  - B is stopped, and a memory file is then edited on the laptop: A takes it, and it waits for B.
  - After five minutes the command says S6 (B holds "all that this device carried") and S7 ("All that this device carried is at A and B", and "What this device writes from now on waits for B"), and ends with status 0 (third review, findings 4 and 10).
  - The laptop's node is restarted: `cordelia devices` there says D5 of B, from what is kept across the restart.
- `the_carried_word_counts_a_relay_out_of_reach_that_took_everything` (`at_relays.rs`, units; second review, finding 1). B took what was carried and then went out of reach before `sent`: the word names A and B, its fourth field is 0, and the reader reads it. The desktop's D1 is then tested in `look.rs` over that word.
- `a_relay_that_holds_the_change_and_refuses_what_is_carried_ends_at_end_two` (ignored; second review, finding 4). Relay A holds the phrase's channel and is then filled to its cap with channels that the test signs; B answers. After a removal A takes the change and refuses the new channels for room. After five minutes the command says S6b and S7, and ends with status 0. With B stopped too, it ends with S10b, or S11, and status 3.
- `the_wait_that_cannot_start_ends_with_3` (finding 7): the program is moved away after the change is made, so that it cannot be run again.
- `a_relay_whose_name_does_not_resolve_is_waited_for_and_named` (it changes): its line is D2, and T1.

**Real processes, `memory_e2e.rs`:** `a_relay_lost_before_the_names_went_does_not_end_the_wait_after_a_change` (it changes, and is ignored). With its one relay stopped, the command does not end within five minutes. After them it ends with S8 ("holds the change"), S11 without the part in angle brackets, and status 3. It never says "may be closed".

**Rules 9 and 10, a recovery:**

- `recover.rs`, `a_recovery_reads_the_carried_word_of_the_one_device`: the four cases of rule 10.
- `recover_cmd.rs`, `r0_to_r3_word_for_word`, with both endings of R2.
- `recover_cmd.rs`, `a_recovery_whose_look_stays_pending_ends_at_3` (finding 6). The look reports that the new channels were not read whole, so the look stays pending. One relay is out of reach. The wait ends with status 3.
- **Real processes,** `recover_e2e.rs`, `a_recovery_says_before_its_yes_where_what_was_carried_is_at_a_relay_it_did_not_reach` (ignored).
  - A laptop with relays A and B carries. B is down, and the laptop writes the carried word naming A.
  - A new machine set up with B alone sees R2 with the second ending before its yes.
  - Set up with A and B where A is down, it sees R2 with the first ending.
- **Real processes,** `recover_e2e.rs`, `a_recovery_ends_not_done_where_a_relay_lacks_the_change` (ignored). The new machine is set up with A and with `NO_SUCH_NAME`. After the look it says R0, waits, says S8 to S10, and ends with status 3. Set up with A alone, it ends at R1 with status 0.

**Rule 11, the level** (`indicator.rs`; where a test needs what the node puts in its look, beside it: the third state in `main.rs`, over the look as `cordelia status` reads it, and the wake after no connection in `device_entries_e2e.rs`, over the node's own clock):

- `a_relay_that_lacks_the_change_is_amber_connected_or_not_with_sync_on_or_off`.
- `for_seven_days_and_then_not`.
- `a_relay_in_the_third_state_is_not_amber` (finding 5).
- `its_place_is_after_names_carried`.
- `a_wake_after_no_connection_does_not_restart_the_ambers_five_minutes`: B lacks the change; A drops and comes back every three minutes; the line is amber five minutes after the change (fourth check, finding 2).
- `a_relay_out_of_reach_is_amber_last_only_with_folders_and_only_with_one_reached`.

**Constants** (`protocol.rs`):

- `OUT_OF_REACH_SECS` is `STATUS_AMBER_WAIT_SECS`;
- `PERSONAL_REACHED_PREFIX` is no prefix of another, and none is of it;
- the carried word at its bound fits its content;
- the checks at compile time of section 10.

**Two versions:** in units, as the record of recovery does (§6).

- An entry under `reached/` is taken by `take::take`, stored, and read as nothing by alpha.12's paths, which this version keeps: the parse of `applied/`, and `record_in`.
- A database written by this version opens at alpha.12's schema version.

## 12. Sentences of other records that this would alter

Each is changed in the build of this record.

**The record of 2026-10-04:**

- **Property 1, second case:** "says that the machine may be closed only when all of them do". Add: "and, where one that is not known to hold it cannot be reached, or refuses it, for five minutes, ends without saying so, with status 3 (decision 2026-10-19)".
- **4.6, "A device that wakes asks every relay first":** "A relay that was not reached is named in its status: 'has not heard from <relay> since it woke: a change made while it was off may not have reached it'". Becomes T1.
- **4.6, the cost line:** stands.
- **7.1, step 4:**
  - "Then it stays, and shows three things as they come";
  - "It says that this machine may be closed only when every relay holds the change and this device has sent what it holds. Before that it says which is missing".

  Add rule 8's three ends, and its statuses.
- **8, the first bullet:** "It has sent what it carried once nothing of that waits at any relay it is set up with, with every one of them connected". Add the carried word (rules 4 and 5).
- **8, `cordelia devices`:**
  - "has applied it and is still sending": add D1;
  - "for each relay, whether it holds the latest change entry, and whether this device has heard from it since it woke": add whether it is out of reach, and since when, and that what it is known to hold is kept across starts.
- **8, the status line:** "a relay that does not hold the latest change". Becomes "a relay not known to hold the latest change, connected or not, for seven days".
- **9, step 5:**
  - "of this machine, whether each relay holds the change and 'keep this machine on: 12 names still to send'": becomes rule 9;
  - "Where the statement it recovered from lists one device alone, and that device never wrote that it had sent what it carried": add rule 10.
- **10.1, the amber list:** "a relay that has been connected for more than five minutes, by the node's own clock, and does not hold the latest change". Becomes rule 11, and moves to the amber of a person's devices.
- **12:** add the costs of section 8.
- **13, "Removal, with real processes":** "while a relay cannot be found (the command names it, and does not say the machine may be closed)". Add: "and ends with status 3 after five minutes".
- **14, item 1:** "its all-clear covers the relays that the device it is run on is set up with". Add: "and it is never given while one of them is not known to hold the change".
- **16, "Names in the personal channel":** add `reached/<its key>`.

**The record of relays, §1:** "So while it fails the device never takes every relay for connected: it forgets nothing of that relay, and does not say that it has sent what it carried." Add: "It is out of reach after five minutes, though it is not dialled, and the carried word may then be written (decision 2026-10-19)."

**`docs/specs/parameter-rationale.md`:** the lines of section 10.

**`.github/workflows/ci.yml`:** the job "out of reach" of section 11. **The repository's settings on GitHub** (not in the repository): that job made a check required for a merge into main.

**Not altered:** the record of recovery (its lines before the yes stand, and R2 is said beside them), the record of messages (its own "every relay"), and the record of 2026-09-30.

## 13. The reviews' findings, answered

**This record's first review** (of the first revision of this form, 60a7345):

| Finding | How this revision settles it | The test that shows it |
|---|---|---|
| **1 HIGH:** end 3 cannot end where a relay is reached and refuses the change: what was carried waits there, and the carried word is never written | End 3's (d) asks only of relays that are reached and hold the change. Nothing is asked of a relay that refuses it, nor of the own word otherwise. The table of rule 8 shows each case reaching an end | `a_change_ends_not_done_where_the_relay_it_reaches_refuses_it` (real processes, both forms). `the_wait_never_says_may_be_closed_or_ends_with_0_while_a_relay_lacks_the_change` takes its looks from the node's own function |
| **2 MEDIUM:** a relay with the wrong key at an address another relay uses is never dialled, so it is never out of reach | Section 1: while that connection is open it counts as an attempt at that relay that has failed. Rule 3 and S9 say that it is not dialled | `a_relay_with_the_wrong_key_where_another_is_connected_is_out_of_reach_with_no_dial`; `a_change_ends_not_done_where_the_other_relay_has_the_wrong_key_at_the_same_address` |
| **3 MEDIUM:** a lookup that resolves is an attempt that did not fail | Section 1: a lookup that resolves is part of the dial that follows it, and no attempt by itself. A lookup that does not resolve is a failed attempt | `a_lookup_that_resolves_is_no_attempt` |
| **4 MEDIUM:** rule 3 does not cut a wait already set, nor wake the lookups | Rule 3: when a relay comes to lack the change its next dial is set to no later than 30 s on, and the lookup loop is woken. Compile-time checks that a lacking relay has an attempt in five minutes | `a_wait_already_set_is_cut_when_the_relay_comes_to_lack_the_change`; real processes, `a_relay_that_lacks_the_change_is_dialled_every_half_minute`, with B down ten minutes before the change |
| **5 MEDIUM:** "lacks" meant "not heard since the wake": amber and dials every 30 s for good at a site, with no change made; D5, T3, S3 and end 2 unreachable after a restart | The latest answer is kept in the database. A relay lacks the change where it has no answer and no mark, where its answer or mark is about another entry than the kept one, or where it answered that it lacks it (as revised after the second review). A relay never known to hold one, with no change since, is in a third state that nothing acts on. The line says "not known to hold", for seven days, after the amber of devices. **Chosen:** both of the review's ways together, since the second needs the first to survive a start. A key of `node_meta`, not a schema step, so that alpha.12 still opens the database | `a_relay_in_the_third_state_neither_holds_nor_lacks`; `the_mark_is_written_only_at_its_three_moments` (the mark of this revision: see the second review's finding 3); `what_is_kept_survives_a_restart_and_goes_with_the_relay`; real processes, `a_relay_unreachable_from_here_is_dialled_as_today_until_a_change`, and the restart in `..._ends_at_end_two` (D5 after a restart) |
| **6 MEDIUM:** a recovery whose look stays pending waits for ever; "for the change only" undefined | Rule 9 states its end: each relay that lacks the change is out of reach, with an attempt after the change, or has refused it for five minutes. There is no condition on what waits or on the own word | `a_recovery_whose_look_stays_pending_ends_at_3`; real processes, `a_recovery_ends_not_done_where_a_relay_lacks_the_change` |
| **7 LOW/MEDIUM:** the wait that cannot start returns 0; an error in the wait returns 1, though the change was made | Both give 3, with the error on standard error. 1 is given only before the change is known to be made. Rule 9 does the same for a recovery | `the_statuses`; real processes, `the_wait_that_cannot_start_ends_with_3` |
| **8 LOW:** "since <time>" is untrue or ambiguous; S8 says "does not hold"; S9's 30 seconds untrue of a connected relay and of the wrong-key relay | `<since>` has two forms; `<when>` has a date where it is not today, and is the wall-clock time noted. S8, S2, T2 and D4 say "not known to hold". S9 says 30 s only of relays not connected, and says that a wrong-key relay cannot be dialled | `each_line_word_for_word` |
| **9 LOW:** R2 and R3 cannot be followed in the case they are for | Two endings: "make sure this machine can reach <relay>" where it is set up here, and "set up the relay of that device's configuration whose key is <key>" where not | `r0_to_r3_word_for_word`; real processes, `a_recovery_says_before_its_yes...`, both endings |
| **10 LOW:** "holds" in memory survives a wake, and "heard" is set by any answer | The latest answer is written only by the answers of the first two kinds about the kept entry; "show it whole", "not signed", a reset and a time-out write nothing. "Reached" needs an answer that says whether it holds it. End 1 uses both | `show_whole_not_signed_a_reset_and_a_time_out_write_nothing` |
| **11 LOW:** the reader's bounds on the carried word | Rule 5: one to 8 keys, none twice; the third field 0 unless 8 keys; each count at most 256 (`REACHED_WORD_MAX_COUNT`). (The floor of 1 on the fourth field was dropped after the third review, finding 4: field 4 no longer overlaps field 2.) | `the_carried_word_is_read_only_from_its_own_key_under_the_applied_number` |
| **12 LOW:** help of `settle` and `recover`; no "stopping it" line in the recovery's wait; a script may run a recovery again on 3 | H1 for `settle` too; H2 for `recover`, which says that 3 means the recovery is made; R0 has "Stopping it stops nothing" | `each_line_word_for_word` |
| **13 LOW:** missing tests; six long tests in `cargo test --all` | The tests of findings 2, 4, 5 and 7 are added. Tests that wait the five minutes are `#[ignore]`d, and run in a CI job of their own on every pull request | Section 11 |
| **Not of this record:** a relay given no key is "same relay" wherever one connection answers for it, so end 1 can say "may be closed" without the relay that its name really names | **Settled** in the record of relays, §1, since this record: a relay given no key is never taken for another relay. At another relay's address it stays a relay of its own, with no connection, and is out of reach after five minutes, so the wait ends at end 3 | `a_relay_given_no_key_at_another_relays_address_is_a_relay_of_its_own`; `a_relay_given_no_key_at_another_relays_address_is_passed_over_and_comes_to_be_out_of_reach`; real processes, `a_relay_given_no_key_at_another_relays_address_is_counted_as_its_own` |

**This record's third review** (of the third revision, 197db5e). The model reproduced; its faults were in what the model took as given. Section 1 was settled first, and event-sequence tests named. **The model checks only the ends over given classes.** Mediums 1 to 3 below rest on the event-sequence tests of `reach.rs` and on the keyless test alone, not on the model (fourth check, finding 5).

| Finding | How this revision settles it | The test that shows it |
|---|---|---|
| **1 MEDIUM:** a relay whose shows get "not signed", or "show it whole" to the whole entry, is in no class for ever | Section 1 lists every answer the code can give, in three kinds. Every answer of the third kind (it says neither) is a failed attempt: "not signed", "show it whole" to a whole show, a reply that is not `EntryShown`, a reset, a time-out, a failure, and a round that runs out. Section 1 then lists each kind of state in no class and what ends it. The model does not show this: it checks only the ends over given classes (fourth check, finding 5) | `each_answer_of_the_third_kind_is_a_failed_attempt`; `whole_to_a_short_show_is_no_answer`; `every_unclassed_state_ends_in_a_class` (event sequences, `reach.rs`) |
| **2 MEDIUM:** the five minutes restart at every wake, and a pass with no connection causes one | A relay's reference moves only at a start, a sleep, a change of the kept entry, or that relay being reached. A wake after no connection still makes the wake rule wait, but moves no reference; nor does it restart the amber's five minutes (rule 11). The model cannot see time; only the event-sequence tests show this | `a_wake_after_no_connection_does_not_move_another_relays_reference`; `a_start_a_sleep_a_new_kept_entry_and_being_reached_each_move_the_reference` |
| **3 MEDIUM:** for a relay given no key, a stored answer outlives the host its name named | Such a relay holds the change only while the device is connected to it with the key that gave the answer; otherwise it lacks it. The model's check of a keyless relay restates the rule, and does not show it: nothing in the model stands for the host a name now names (fourth check, finding 5) | `a_relay_given_no_key_holds_only_while_connected_to_the_key_that_answered` |
| **4 LOW-MEDIUM:** sentences untrue where field 2 and field 4 overlap; S1, R0, S7; the subject | Field 4 now counts only relays not in field 2 (it can be 0). Every line takes `<held>` and `<not yet>` from two sets that never overlap. S6 and S7 say what is so on the `sent` path. S1 names the end where no relay that this machine reaches has what was carried. R0 says "cannot be reached, or refuses it, for five minutes". A subject rule: "you" where the line tells you what to do. Sentences are split to say one thing each. Section 6 and D4 now name their two different cases | `held_and_not_yet_never_overlap`; `each_line_word_for_word`; the end-two test's lines on the `sent` path |
| **5 LOW:** "as today" before any change is false for most machines | The mark is also written at `cordelia phrase` and at the first start on this version where the kept statement is statement 1: both remove no key and renew nothing. Rule 3 and rule 11 now say "a relay in the third state" rather than "before any change". Not taken: a mark at the first start for any statement that removed no key, since the node does not keep what kind of change a statement was | `the_mark_is_written_at_phrase_and_at_a_first_start_under_statement_1` |
| **6 LOW:** end 3 waits on the carried word, which needs a whole pass, and the command would work out the node's conditions | End 3 asks nothing of the word where a relay lacks the change. Where none does, the node's look says `word_to_come`, worked out by the function that writes the word; the command never works it out | `end_three_does_not_wait_on_the_word_where_a_relay_lacks_the_change`; `the_command_reads_word_to_come_from_the_node`; the model checks that end 3 holds wherever every relay is in a class and one lacks the change |
| **7 LOW:** "an attempt begun in those five minutes" reads two ways | Section 1: at least one attempt begun after the reference and within the five minutes before now | `an_attempt_must_be_in_the_last_five_minutes_and_after_the_reference` |
| **8 LOW:** the mark trusts the adder's relays | Section 1 says so | none: it is a statement of what the mark means |
| **9 LOW:** a stopped wait exits 130; the two times rule 11 needs are not stored | Any status other than 0, 1 and 2 means the change was made, in rule 8, H1 and H2. The two times (when the kept entry came to be kept, when this version first started) are named in section 1, in the same key | `the_statuses`; `the_two_times_are_kept` |
| **10 LOW:** tests | Event-sequence tests in `reach.rs` for findings 1, 2 and 7, and for every unclassed state; a test for the keyless relay; the `sent` path's lines in the end-two test. The two-minute test is `#[ignore]`d with the others | section 11 |
| **Not of this record:** a relay given no key counts as "same relay" wherever one connection answers for it | **Settled** in the record of relays, §1, as above: only the same key makes two names one relay. Finding 3's rule still holds of a relay given no key at an address of its own | as above |

**This record's second review** (of the second revision, 263ade8). Before these rules were written down again, a model of the ends was built and run (appendix A).

| Finding | How this revision settles it | The test that shows it |
|---|---|---|
| **1 HIGH:** the wait never ends once `sent` is written and a relay that holds the change is lost; nor where a relay out of reach took everything (the word's fourth field would be 0) | End 2 accepts `sent` beside the carried word, or a word that the node will not write. The fourth field counted relays out of reach or refusing what waits. (Revised after the third review, finding 4: it now counts only relays not named in field 2, and can be 0.) The model finds an end in every state that time does not move | `the_ends_are_safe_and_live_over_every_state`; `a_relay_that_holds_the_change_and_cannot_be_reached_ends_at_end_two` (the `sent` path, with no window to hit); `the_carried_word_counts_a_relay_out_of_reach_that_took_everything` |
| **2 HIGH:** a later refusal never clears "holds", so end 1 can give 0 while a relay lacks the change | "Holds" is the latest answer about the kept entry's ID; "no room", "over the allowance" or "another" about that ID writes over "held", in the same transaction (section 1, rule 2) | `the_latest_answer_writes_over_the_one_before`; the model's safety check |
| **3 MEDIUM:** the mark cannot be worked out, and at the first start it hides a removal made on alpha.12 | The mark is written only where this device takes a hand-over, as the handed entry, for each relay with no answer yet. There is no mark otherwise: not at the first start on this version, not for a relay set up later. So the case that was seen ends with that relay lacking the change, amber for seven days from the upgrade. (Widened after the third review: also at `cordelia phrase` and at a first start under statement 1, section 1.) | `the_mark_is_written_only_at_its_three_moments`; `a_removal_made_on_alpha_12_leaves_a_relay_that_never_answers_lacking_after_the_upgrade` |
| **4 MEDIUM:** no end where a relay holds the change and refuses what is carried for room | A class of its own, STUCK. End 2 takes it where another relay is OK (with S6b); end 3 where none is (S10b). The rule 4 word is written beside it, and counts it | the model; `a_relay_that_holds_the_change_and_refuses_what_is_carried_ends_at_end_two`, both ways |
| **5 MEDIUM:** "a relay that this machine reached in this recovery" is undefined | Rule 10: a relay at which the recovery read the personal channel to its end before its yes, by the key of that connection. No show is needed | `a_recovery_reads_the_carried_word_of_the_one_device`; the real-process test of R2, both endings |
| **6 LOW:** a wrong-key relay's failed attempt had no start | Each tick of the dial loop that passes it over is an attempt begun and failed at that tick. End 3 no longer asks for an attempt after the change apart: out of reach counts its five minutes from the change | `..._wrong_key_where_another_is_connected_is_out_of_reach_with_no_dial`; `a_change_ends_not_done_where_the_other_relay_has_the_wrong_key_at_the_same_address` |
| **7 LOW:** sentences | S9 is split, one short sentence for each kind of relay: dialled, looked up, shown, cannot be dialled, refusing. S1 says "without saying that this machine may be closed", and names a relay that refuses. R0 names each relay that lacks the change. S2 says "while the wait goes on". Lines keep "this machine" as subject, as the commands of today do | `each_line_word_for_word` |
| **8 LOW:** tests | A test of liveness (the model in Rust); a refusal that clears "holds"; what `adding::leave` forgets; rule 6's three namings; rule 12's choice of line. The end-two test now goes by `sent` and needs no window. Whether the long job is required for a merge is a setting of the repository on GitHub: section 11 and section 12 say so, and name it as an act for whoever builds this | section 11 |
| **9 LOW:** going back to alpha.12 and forward again keeps what was known under another phrase | Section 7 says so: no such answer is about the kept entry, so each reads as "lacks", and the next answer writes over it | `adding_leave_forgets_it` (this version's side); none for alpha.12's, which is not changed |

**The second review** (of the second form), every HIGH and MEDIUM finding:

| Finding | How this form settles it, or why it does not apply on main |
|---|---|
| **H1:** "out of reach" is a window of one minute, used as a state; it cannot be met at a pace of 15 minutes; "dials once for this" is undefined | Out of reach is a state with a start and an end, over five minutes of attempts (dials, failed lookups and shows), with none in flight (section 1). A relay that lacks the change is dialled at 30 s, and a wait already set is cut (rule 3). No special dial is made |
| **H2:** once the command ends nothing says that a removal is not at a relay; exit status unsaid; the amber is of connected relays only, with folders | The command ends with status 3 and a last line that names the relay (rule 8, S10, S11). "a relay not known to hold the latest change" is amber connected or not, sync on or off, and on a machine that maps nothing (rule 11). `cordelia devices` says D4 |
| **M1:** "take it out of the configuration" in the command | Not in the command's own words. In `cordelia devices` only, worded as the review proposed (D4) |
| **M2:** the sentence is not true in each case (address turned away; reachable from others only; after a recovery) | S9 says "may not have heard", names both ways the relay gets the change, says what this machine does (dials, or shows) rather than that it gives it, and points to `cordelia devices` on a device that reaches the relay (S10). After a recovery only this machine has applied, and S9 is still true |
| **M3:** the relay that lacks a removal is dialled every 15 minutes | Rule 3 |
| **M4:** states that are never out of reach: a name that does not resolve, a connected relay that does not answer, reached and lacking, a connection closed at once, another key | Each is a failed attempt (section 1), and a wrong-key relay that is not dialled counts as failing. A reached relay that refuses the change has its own case of end 3, with no condition on what waits there (rule 8) |
| **M5:** a relay that would have answered can be out of reach (an old failure, a dial in flight, a minute before the change) | Every attempt in five minutes must have failed, none may be in flight, and the five minutes start no earlier than the change of the kept entry (section 1). End 3 also asks for an attempt begun after the change |
| **M6:** rule 8 does not fit how a recovery reads; keys against names; "run again" loops | Rule 10: the word is read before the yes from the personal channel, which step 3 reads, and judged by the keys of the relays this machine reached. R2 and R3 have one ending where the relay is set up here and another where it is not. A personal channel read in part, or not held, is the fourth case, as today. "Run again" is offered only before the yes, when nothing is made |
| **M7:** relay names in the personal channel, read by every holder of the secret | No names; keys of the relays that hold what was carried, and two bounded counts (rules 4, 5) |
| **M8:** the out-of-reach amber hides the device notices | It is last among the amber. The amber of a relay not known to hold the change comes after every amber of devices (rule 11) |
| **M9:** text elsewhere contradicts the rule | Section 12 lists each sentence. None is changed before this is built |

**The first review** (of the first form), where the second form did not settle a finding:

| Finding | How this form settles it |
|---|---|
| **M1:** "reached" and the times not defined; "not reached" includes "not dialled" | Section 1 defines reached, an attempt, failure, out of reach, and the clocks. Rule 3 makes attempts happen |
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
- **A look that could not fetch the new channels whole** also leaves the look pending until the next statement, so `sent` is never written under that statement (`recover.rs:1291-1307`). The second form named only a look that was interrupted.

## 14. For the review to attack

The weakest points, as this record sees them:

1. **The model is only as true as its classes.** Appendix A checks the ends over the classes of section 1, and nothing else. It carries a relay that is connected and not reached, and a relay given no key, but checks neither: taking either out still passes. It does not see time. That every state not in a class comes to one is argued in section 1, case by case, and held by event-sequence tests over the clock and the answers in `reach.rs`, not by the enumeration. A kind of answer or event that section 1 does not list would escape both: attack the list of answers against `device_entries.rs` and `leave.rs` as they will be when this is built.
2. **The latest answer is kept across starts.**
   - End 2 says "may be closed" with a relay out of reach, on an answer kept in the database. That answer can only have been given after the change, since the kept entry is the change.
   - A relay that answered so and then lost its store, or a hostile relay that lied, is believed until it answers otherwise. One that answers "no room" about the entry is believed at once.
   - Is that weaker than end 1, which believes the same answer from a relay that is connected?
3. **The mark.** A relay with no answer, whose mark is the kept entry, is acted on by nothing until a change. It is written at a hand-over, at `cordelia phrase`, and at a first start under statement 1. A device added on this version while relay B was unreachable from its site has B in that state.
   - If B lacks the statement that this device was added under, and some other device reaches only B, nothing here says so. Today nothing does either.
   - The device that added it kept and showed that entry, but perhaps never to B.
4. **End 2 with a relay STUCK.** Status 0 is given while a relay holds the change and refuses what this device carried, since another relay holds it whole. Only the carried half rests on that; check that nothing of the change half does.
5. **The person who sees a command end.** Status 3 and a last line are what stands between "not done" and a closed laptop.
   - Does any path print S7 or the line of `person_cmd.rs:2370` while a relay lacks the change?
   - In particular: a relay "same relay" (the review's note, since settled in the record of relays: only the same key makes one); the kept entry changing during the wait; an answer of "held" noted for an entry that the device kept a moment before.
6. **Seven days of amber.** After them a relay that lacks a removal is said only in `cordelia devices`. At a site that can never reach B, that is the right end. Elsewhere it is a removal that may still not be at B, and no line says so.
7. **Out of reach at a pace of 900 seconds,** for a relay that holds the change. It is out of reach until the next attempt, up to 15 minutes after it came back. Only the carried word and the status rest on it. Check that nothing of the change half does.
8. **A connected relay whose shows fail** counts as out of reach. A removed device at the same address that uses up the address's bytes ("not now") can so make a relay out of reach at will, and end a command at end 3. That gives it nothing it lacks today (the relay lacks the change either way), and the status is 3. But it ends a command that today would wait.
9. **Rule 3 at a site that never reaches B:** every 30 seconds, for good, after each change, and from the upgrade on for a machine that came by it under a statement after statement 1. Is a failed dial every 30 seconds an acceptable cost on a machine that will never reach B, where the person's only way out is to take B out of that machine's configuration?
10. **Rule 10, case 2:** a relay that the word names was read by the recovery, so it is "not cut short". The relay may since have dropped the names' channels. `sent` has the same staleness over every relay; this has it over fewer.
11. **The carried word is the device's own claim.** As with `sent`, a device that counts can write a false one about itself. No other key's word is read. Can it make a recovery that was cut short pass as whole? It can do the same with `sent` today.
12. **Rule 9 changes a recovery's end** from a print-once to a wait of five minutes and more, where a relay is slow after the change.
13. **Long tests in a job of their own.** If that job is not made required for a merge, which only the repository's settings can do, the rules it holds can break unseen.
14. **Two versions.** A device of alpha.12 beside one of this version says "still sending" of it for good, as today. A recovery made with alpha.12 says "cut short" where this version would not. A device brought forward again after a time on alpha.12 has stale knowledge of which relay holds what, and errs toward "lacks". None of this is worse than alpha.12 alone.


## Appendix A. The model of the ends

Before rules 4, 8 and 9 were written down, their ends were checked by the script below, over every combination of the classes of each relay. It was extended after this record's third review. It checks only the ends over given classes (below).

**What it enumerates.** For each relay:

- whether it is given a key in the configuration;
- whether a connection to it is open;
- whether it is reached (only on an open connection);
- whether it is out of reach (never with reached; it may be with an open connection, whose shows get no answer of the first two kinds);
- the latest answer about the kept entry: none, held, took, no room, over the allowance, another (a relay that is reached has one);
- what waits there: nothing, something that moves, or something refused for five minutes (known only of a relay that is reached);
- whether it has refused the change for five minutes (only of a relay that is reached and lacks it).

A relay given no key holds the change only while connected. That is 96 states of one relay. With them it enumerates the device's own word (none, the carried word, `sent`) and whether a recovery's look is pending, under which no word is written.

**What it checks.**

- **Safety:** no end with status 0 (end 1, end 2, and R1 of a recovery) holds while a relay lacks the change, nor while a relay given no key is not connected; end 2 holds only where a relay is reached; end 3 never holds beside an end with status 0.
- **Liveness:** in every state in which each relay is in a class of section 1 and the node will not write over the device's word, one end holds. Wherever each relay is in a class and one lacks the change, end 3 holds, whatever the word. For a recovery's wait: wherever each relay holds the change, or is OUT and lacking, or REFUSING, one of its ends holds.

**What it cannot see:** time. That a state in no class comes to one is in section 1, and in the event-sequence tests of `reach.rs` (section 11).

**The result,** with Python 3, `python3 -I ends.py`:

```
2 relays: 96 relay states, 36864 states, 9744 that time does not move: both hold
3 relays: 96 relay states, 3538944 states, 489120 that time does not move: both hold
```

**What it checks, and what it does not.** It checks only the ends over given classes. It does not check that the node puts a relay in the right class, that a state in no class comes to one, or that a relay given no key names the host it did. So the third review's mediums 1 to 3 rest on the event-sequence tests of `reach.rs` and on the keyless test (section 11) alone, not on this model. Taking out the connected relay that is not reached, or the rule for a relay given no key together with its check, still passes (fourth check, finding 5).

**Where it has teeth.**

- The ends of this record's second revision (263ade8) leave 216 states of two relays with no end (the second review's findings 1 and 4).
- With end 3 asking for the word where a relay lacks the change, the check that end 3 holds there fails (the third review's finding 6).

The test `the_ends_are_safe_and_live_over_every_state` (section 11) is this check in Rust, over the node's own functions.

```python
"""The ends of the wait after a change, and of a recovery's wait
(decision 2026-10-19, rules 4, 8 and 9), over every state the node keeps.
Checks SAFETY (no end with status 0 while a relay lacks the change) and
LIVENESS (in every state that time does not move, some end holds)."""
from itertools import product

ANSWERS = ["none", "held", "took", "noroom", "over", "another"]
WAITS = ["nothing", "moving", "stuck"]   # stuck: refused for room or allowance for 5 min

def relays():
    for keyed, connected, reached, out, answer, waits, refused_long in product(
            [True, False], [True, False], [True, False], [True, False],
            ANSWERS, WAITS, [True, False]):
        if reached and not connected: continue            # reached is on an open connection
        if reached and out: continue                      # out of reach is not reached
        if reached and answer == "none": continue         # reached needs an answer that says
        if not reached and (waits != "nothing" or refused_long): continue  # known only while reached
        # a relay given no key holds only while connected to the key that gave the answer
        holds = answer in ("held", "took") and (keyed or connected)
        if holds and refused_long: continue               # "refused" is of a relay that lacks it
        # connected, not reached: its shows get no answer that says (not signed,
        # whole to a whole show, a reset): failed attempts, so it may be out of reach
        yield dict(keyed=keyed, connected=connected, reached=reached, out=out,
                   answer=answer, waits=waits, refused_long=refused_long, holds=holds)

def cls(r):
    if r["reached"] and r["holds"]:
        return {"nothing": "OK", "stuck": "STUCK", "moving": None}[r["waits"]]
    if r["reached"]:
        return "REF" if r["refused_long"] else None
    if r["out"]:
        return "OUTH" if r["holds"] else "OUTL"
    return None                                            # not reached, not yet out of reach

def can_sent(rs, word, pending):
    return not pending and word != "sent" and all(cls(r) == "OK" for r in rs)

def can_carried(rs, word, pending):   # the node reports this; the command does not work it out
    c = [cls(r) for r in rs]
    return (not pending and word == "none" and "OK" in c
            and all(x in ("OK", "STUCK", "OUTH", "OUTL") for x in c)
            and not all(x == "OK" for x in c))

def word_settled(rs, word, pending):
    return not can_sent(rs, word, pending) and not can_carried(rs, word, pending)

def lacks(r): return not r["holds"]

def end1(rs, word, pending):
    return all(cls(r) == "OK" for r in rs) and word == "sent"

def end2(rs, word, pending):
    c = [cls(r) for r in rs]
    return (all(x in ("OK", "STUCK", "OUTH") for x in c) and "OK" in c
            and word_settled(rs, word, pending))

def end3(rs, word, pending):
    c = [cls(r) for r in rs]
    if any(x is None for x in c): return False
    if any(lacks(r) for r in rs): return True             # no clause on the word here
    return "OK" not in c and word_settled(rs, word, pending)

def rec_done(rs): return all(r["holds"] for r in rs)
def rec_not_done(rs):
    return (any(lacks(r) for r in rs)
            and all(cls(r) in ("OUTL", "REF") for r in rs if lacks(r)))
def rec_stable(rs):
    return all(r["holds"] or cls(r) in ("OUTL", "REF") for r in rs)

for n in (2, 3):
    R = list(relays())
    states = settled = 0
    for rs in product(R, repeat=n):
        for word, pending in product(["none", "carried", "sent"], [False, True]):
            if pending and word != "none": continue
            states += 1
            e1, e2, e3 = end1(rs, word, pending), end2(rs, word, pending), end3(rs, word, pending)
            assert not ((e1 or e2) and any(lacks(r) for r in rs)), rs          # SAFETY
            assert not e2 or any(r["reached"] for r in rs)                     # one connection
            # a relay given no key and not connected may now name another host
            assert not ((e1 or e2) and any(not r["keyed"] and not r["connected"] for r in rs))
            assert not (e3 and (e1 or e2)), (rs, word)
            if all(cls(r) is not None for r in rs) and word_settled(rs, word, pending):
                settled += 1
                assert e1 or e2 or e3, ("LIVENESS", rs, word, pending)
            if all(cls(r) is not None for r in rs) and any(lacks(r) for r in rs):
                assert e3, ("end 3 waits on the word", rs, word)               # finding 6
            assert not (rec_done(rs) and any(lacks(r) for r in rs))
            if rec_stable(rs):
                assert rec_done(rs) or rec_not_done(rs), rs
    print(f"{n} relays: {len(R)} relay states, {states} states, {settled} that time does not move: both hold")
```
