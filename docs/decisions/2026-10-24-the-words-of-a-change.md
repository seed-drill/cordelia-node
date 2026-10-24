# Decision: the words of a change

**Date**: 2026-10-24
**Status**: Proposed. Not built. Revised once after its review (section 8).
**Cited as**: "decision 2026-10-24, rule 3". The numbers do not change. A number that is not used stays unused.

Words used throughout:

- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md). **The record of reach** is [`2026-10-19-a-relay-out-of-reach.md`](2026-10-19-a-relay-out-of-reach.md).
- **A change** is a statement and its change entry, as the record of 2026-10-04 says (section 4). **The kept entry** is the latest change entry that the device keeps (its 4.6). **The wait** is the wait after a change (the record of reach, §1), and the wait of a recovery (its rule 9).
- **Main** is the tree of 0.2.0-alpha.16 (commit 6a9874d). Every file and line below is of main.
- Examples say laptop and desktop, relay1 and relay2. relay2 is the one that cannot be reached.

---

## 0. What this is

Two machines of one person, with two relays, were tested by hand. A firewall rule kept the laptop from relay2. Every change was made and every end was right. The words were hard to follow. Seven things were found:

1. the question that a device added since the last change is asked before it makes a change (the `stays` question);
2. a relay named by its address in one line, where every other line names it as it is configured;
3. no time on any line of the wait;
4. the label of `cordelia status` said twice;
5. "has not answered since" a time at which the relay had already gone quiet;
6. "a relay out of reach" never shown;
7. the "Could not fetch" line at the start of a change, which names no relay, and says nothing of what a change made after it can do.

**This record changes words, and what is shown.** It changes nothing that a change does: no step, no end, no status, no rule of the record of reach. Item 6 was checked first in case it was a fault (section 2). It is not: the code does what the record of reach says, and a release note says something else.

**The project's rule for words a person reads,** which every new line here keeps: plain, short, active, with "you" as the subject where it tells you to do something; say what each answer does; no word that the person has to look up.

## 1. Placeholders

- `<relay>` is a relay as the device's configuration names it (`[[network.bootnodes]]`), never the address it was reached at.
- `<when>` is as the record of reach, §1, writes a moment: "14:05 UTC", or "23:00 UTC on 2026-10-19" where it is not today.
- `<time>` is the time at which a line is said, in UTC, with seconds: "10:53:12". The wait says once that its times are UTC (rule 3).
- `<device>` is a device as `named` writes it (`person_cmd.rs:276`): the four words of its key's fingerprint, then its label in quotes, `(abc def ghi jkl) "laptop"`. A label comes after the words, quoted, so that it cannot pass for words that the command says itself (`person_cmd.rs:270-275`). That stays.
- A list of relays is joined with ", " and " and ". `<it | them>` and the like follow the count.

## 2. Item 6 first: is it a fault?

**What was seen.** In two runs, `cordelia status` and `cordelia devices` said "a relay not known to hold the latest change" and "relay2 ... is not known to hold the latest change, and has not answered since ...". Neither said "a relay out of reach". In the first run relay2 was blocked for about fifteen minutes, past the five minutes. The release notes of 0.2.0-alpha.14 say that while another relay is reached, the status "also says 'a relay out of reach'".

**What the record of reach says.** The line "memory: a relay out of reach for <minutes> minutes" is said "for a relay that is out of reach **and holds the change**, while another relay is reached: the warning of the ruling" (rule 11). A relay that is out of reach and **lacks** the change is not a warning: it is the half of the ruling that is not relaxed, and the line for it is "a relay not known to hold the latest change" (rule 11), with T2 in the status and D4 in `cordelia devices` (§5).

**What the code does.** It keeps the record.

- `main.rs:1836-1839` fills the list that the line reads with each relay whose class is `out_holding`, and no other:
  `out_of_reach_secs: list("relays").filter(|relay| relay["reach"]["class"] == "out_holding")`.
- `indicator.rs:645-666` says "memory: a relay out of reach for <m> minutes" from that list, only while `one_reached`, and only with sync on, a folder mapped and a report.
- A relay that lacks the change goes to `not_known_to_hold` (`main.rs:1826-1834`), and `indicator.rs:606-621` says "memory: a relay not known to hold the latest change" for it.
- `person_cmd.rs:1354-1364` (D4) and `look.rs:1726-1731` (T2) are said only where the relay **is** out of reach: `out` is `Some` only where `out_of_reach_since` is set for the kept entry (`person_cmd.rs:1349`, `look.rs:1708-1712`). The person saw D4's words, so the node had found relay2 out of reach.

In both runs relay2 was blocked before the change was made (item 5: it last answered at about 10:48, and the change was made at 10:53). So it lacked the change, was OUT and lacking, and was said as the record says.

**Finding: the words, not a fault.** Two sets of words are wrong:

1. **The release notes of alpha.14.** "While another relay is reached, it also says 'a relay out of reach'" is untrue of the case that matters most, a relay that lacks the change. They should have said: "A relay that holds the change and cannot be reached is shown as 'a relay out of reach'. One that lacks the change is shown as 'not known to hold the latest change'."
2. **The record of reach's own lines for a relay out of reach.** D4, T2, S2 and S8 (a relay that lacks the change), and D5, T3, S3, S6 and S8 (one that holds it), say "has not answered since <when>", or nothing of reach at all. None says that the relay cannot be reached, though the node knows it, and each line is said only because it cannot be. A person reads "has not answered" as a relay that is slow, not one that this machine cannot reach. Rule 7 fixes these words.

**Where a person learns it before any change.** With no change made, sync off or no folder mapped (just after a recovery, say), the status line's "a relay out of reach" is not said (`indicator.rs:623-625`: it is among the amber of folders). T3 and D5 are then the only words, and rule 7 makes them say "cannot be reached from here".

Nothing that a change does, or that the status counts, changes.

## 3. The rules

Each item gives what the person sees today, quoted from the code, what is wrong, the new words, and the rule.

### Rule 1. The question to a device added since the last change

**Today.** `cordelia renew` and `cordelia remove-device` on a device that is not in the last change, and `cordelia settle` on a device that neither change lists (`person_cmd.rs:2167-2171`, `2122-2124`), call `own_listing` (`person_cmd.rs:2247-2256`), whose words are in `own_addition` (`person_cmd.rs:2273-2280`):

> This device is not in the last change: it was added since, as `<device>`, from `<device>` at 2026-10-08 13:43 UTC.
> The device that makes a change is always among its devices: this change lists it under that label.
>   Type \`stays\` to list this device, or anything else to stop:

Anything but `stays` ends with "That was not \`stays\`. Nothing was done." (`person_cmd.rs:2253`).

**What is wrong.**

- It never says what a change is. To a person a change is something they did, not a signed list of their devices.
- "added since", "this change" and "that label" leave the reader to work out which change and which label.
- `stays` names no action, and is the answer word of another question ("Type \`stays\` or \`removed\`", `person_cmd.rs:1841`) about another device.
- It does not say what each answer does, or that stopping changes nothing.

**The new words** (`cordelia renew`, `cordelia remove-device`):

> A change is the list of your devices that your recovery phrase signs.
> Your last change (change `<last>`, made on `<maker>`) was signed before this machine was added, so it does not list this machine. `<adder>` added this machine at `<added at>`, as `<this>`.
> This command makes change `<new>`. The machine that makes a change is always in it, so change `<new>` will list this machine as `<this>`.
>   Type \`list\` to list this machine and go on. Anything else stops here, and nothing is changed:

**`cordelia settle`** says the same, with its second and third sentences so:

> Neither change `<a>` nor change `<b>` lists this machine: both were signed before it was added. `<adder>` added this machine at `<added at>`, as `<this>`.
> This command makes change `<new>`, which settles the two. The machine that makes a change is always in it, so change `<new>` will list this machine as `<this>`.

**Any answer but `list`:** "You did not type \`list\`. Nothing was changed." **The input ends:** "The input ended before you typed an answer. Nothing was changed." Both with status 1, as today.

**Why `list`, and not `add`.** The person suggested `add`. `list` is chosen because:

- the sentence it answers says "to list this machine", and the change does that and nothing more;
- the machine is already added: `add` reads as `cordelia add-device`, an act that is done;
- the same command keeps `stays` to mean "list it" of other devices, and `list` says that act in plain words.

A person who types another word, `add` or `stays` among them, only stops the command, with nothing changed: either word fails safe.

Placeholders:

- `<last>` is the number of the statement this device has applied (`handed.applied.statement.number`); `<maker>` is the device that made it, as `lists_shown` writes its "made on" (`person_cmd.rs:2290`).
- `<a>` and `<b>` are the numbers of the change this device had applied and the change made apart, in that order.
- `<adder>`, `<added at>` and `<this>` are what `own_addition` writes today: the adder, the time of the addition (`time_of`, "2026-10-08 13:43 UTC"), and this device as its addition record names it.
- `<new>` is the number of the statement that `prepare_change` or `prepare_settlement` will make: one above `<last>` for a renewal or a removal, and one above the higher of `<a>` and `<b>` for a settlement (the record of 2026-10-04, 4.5).

**Rule 1.**

1. `own_listing` says the words above, and goes on only where `list` is typed.
2. `<new>` is the number that "The change that the recovery phrase will sign (change N)" shows next (`person_cmd.rs:1971-1974`). A unit test holds the two equal for a renewal, a removal and a settlement.
3. The other question, "Type \`stays\` or \`removed\`" about another device (`person_cmd.rs:1841`), is not changed here.

### Rule 2. A relay is named as it is configured, in every line

**Today.**

- The wait says, for each relay that is connected and has channels of this device to send to (`person_cmd.rs:2555-2562`): "keep this machine on: 1 of this device's channels still to send to `<address>`:9474". It reads `text(waits, "relay")`: the address the relay was reached at (`commands.rs:303-316`, `"relay": address`). The row also carries `"name"`, the relay as configured, where the relay answers with a configured key; for a relay given no key, `name` is null (`commands.rs:284-293`).
- `cordelia init --new-key` does the same in "Could not send it to <relay>" (`person_cmd.rs:2731-2733`, `2748`).
- `cordelia devices` lists a row that it can match to no relay by its address: "  `<address>`: `<n>` of this device's channels still to send there" (`person_cmd.rs:1288-1293`).

**What is wrong.** Every other line names the relay as configured (relay2). These read as a third relay, and put an address on the screen.

**The new words.** The same lines, with `<relay>` as section 1 defines it:

> keep this machine on: `<n>` of this device's channels still to send to `<relay>`

> Could not send it to `<relay>`: the devices that this one leaves may not be told that it left.

And in `cordelia devices`, for a row that it still matches to no relay: "  a relay that this device is connected to and that no line above names: `<n>` of this device's channels still to send there".

**Rule 2.**

1. Each row of `waiting` names the relay as configured, a relay given no key among them. **This needs data the node does not hand today.** `relays_reached` (`commands.rs:271-278`) gives each relay connection's address and key, and `RelaySnapshot` (`state.rs:1583-1601`) gives each configured relay's host, key and state; neither says which connection is which configured relay's own. The dial loop (`p2p.rs`) knows it, since it dials each configured host: it is to say, for each connection that it made, the configured host it made it to, and `waiting` takes the name from there.
2. A line of the wait, of `cordelia init --new-key`, of a recovery or of `cordelia devices` never prints the `relay` field of a row. Where a row has no name, which a personal node that dials only its configured relays never makes, the line says it as above.
3. `cordelia devices` matches a row to a relay by name, and then by the addresses a name resolves to (`person_cmd.rs:1220-1250`). That matching stays.

### Rule 3. Each line of the wait carries its time

**Today.** The wait says its first line, then each line as it comes, once, while its words stay the same (`person_cmd.rs:2632-2670`: a line of this look that was not in the last look is said). No line has a time. A wait of five minutes in which nothing changes prints nothing for five minutes.

**What is wrong.** You cannot see that the command is alive, or when anything last moved.

**The new words.**

- S1, the first line of the wait after a change, and R0, the first line of a recovery's wait, each end with one sentence more: "Each line below starts with the time it was said, in UTC."
- Each line of the wait after the first starts with its time, two spaces in, two spaces after:

  > `  10:53:12  relay1 holds the change`

- Where no line has been said for 60 seconds, the wait says:

  > `  <time>  still waiting: no new line since <time>`

  where the second `<time>` is the time of the last line that was not this one. It is said again 60 seconds after the last line of any kind, so once a minute while no line comes.
- Each end begins with a line of its own, before the lines it says today: `  <time>  The wait has ended.` The lines of the end (end 1's line, S6 to S11, R1) are said under it as today, with no time.

**Rule 3.**

1. **What is a new line** stays as today: a line of this look that was not in the last look, judged by its words without the time. A line is never said twice because its time changed. A line that drops out of the look says nothing, as today; that is why the line says "no new line", and not "nothing has changed".
2. **The clock.** The time is read from the clock that the wait is given: the wall clock (`chrono::Utc::now()`) when it runs, and a clock that the test moves in its tests, as the tests of `reach.rs` move theirs. It is written `%H:%M:%S`, in UTC.
3. The same holds in the wait of a recovery (the record of reach, rule 9; `recover_cmd.rs`), R0 among it.
4. Nothing of what the wait decides reads a time it prints.

### Rule 4. The count while a relay is waited out

**Today.** While a relay is not reached and not yet out of reach, the wait says "keep this machine on: relay2 does not hold the change yet" or "keep this machine on: relay2 is not connected, and what is still to send there is not known until it is" (`person_cmd.rs:2523`, `2536-2539`), once. It does not say that the command will stop waiting for it, or when.

**What is wrong.** The five minutes of the record of reach are invisible. The person wants "relay2 unreachable for 3 of 5 minutes".

**The new words.** For each relay that is not reached and not out of reach, once each minute counted, from minute 1 to minute 4:

> `  <time>  <relay> has not been reached for <m> of the 5 minutes that this command waits for it`

From minute 5, while it is still not out of reach:

> `  <time>  <relay> has not been reached for <m> minutes. This command stops waiting for it once this machine has tried it again and failed.`

That sentence is true whether an attempt is in flight or none was made in the last five minutes, the two cases in which a relay is not yet out of reach after five minutes (the record of reach, §1).

For a relay that is reached and refuses the change, once each minute counted, from minute 1 to minute 4:

> `  <time>  <relay> has refused the change for <m> of the 5 minutes that this command waits for it`

**Rule 4.**

1. `<m>` is whole minutes, rounded down, from the relay's reference (the record of reach, §1, as the look gives it: `reach.reference`), or from when it came to refuse. At minute 0 nothing is said.
2. It is said only while the relay is in no class (the record of reach, §1). Once it is out of reach, S2 or S3 says so instead.
3. The line is new each minute, so rule 3 says it once each minute, with its time.
4. The count is a word to the person. The five minutes that end the wait are counted by the node's own clock, as today, and the count may read 5 a few seconds before or after the node finds the relay out of reach.

### Rule 5. `cordelia status` says its label once

**Today.** `main.rs:1526`:

> `  Memory:    memory: a relay not known to hold the latest change`

`summary` is the status line's own words (`indicator.rs:700-711`), which begin with "memory".

**The new words.**

> `  Memory:    a relay not known to hold the latest change`

and so for every line: "Memory:    not syncing: two changes made apart", "Memory:    sync error", "Memory:    node stopped".

**Rule 5.**

1. The plain `cordelia status` takes the first word "memory" off the summary as `Holds::detail` does (`indicator.rs:297-307`: the prefix "memory: ", else "memory "), by the same function.
2. The line itself (`--line`), the bar (`--waybar`) and `--json` keep their words.

### Rule 6. "Since" says since what

**Today.** `<since>` (`look.rs:1662-1669`; the record of reach, §5) is "has not been reached from here since <when>" where the relay was reached after its reference, and otherwise "has not answered since <when>", where `<when>` is the reference: the start, a sleep or the change, whichever was latest. In the test the relay last answered at about 10:48; the change was made at 10:53; the line said "has not answered since 10:53 UTC".

**What is wrong.** The time is not when the relay went quiet. A person reads "since 10:53" as "it answered until 10:53".

**The new words.** `<since>` is one of:

- "has not been reached since `<when>`", where the relay was reached after its reference ("from here" goes: every line that says `<since>` now says "cannot be reached from here" first, rule 7);
- "has not answered since this device applied the change at `<when>`", where the reference is the change of the kept entry. On the device that made the change that is when it made it; on another, when the change came to it;
- "has not answered since this device started at `<when>`", where it is the node's start;
- "has not answered since this device woke from sleep at `<when>`", where it is a sleep.

Then, in the last three, where the relay was reached before the reference since the node started: " (it was last reached at `<when>`)".

So the test's line reads: "has not answered since this device applied the change at 10:53 UTC (it was last reached at 10:48 UTC)".

**Rule 6.**

1. The look says which moment a relay's reference is: a field `reference_by` of `ReachLook` (`look.rs:300-340`), one of `start`, `sleep`, `change` and `reached`, put by the module that moves the reference (`device_entries/reach.rs`). It is shown, and nothing decides by it.
2. "it was last reached at" uses `last_reached` (`look.rs:318-319`), kept since the node started, as today.
3. `<since>` is written in one place (`look::since`), and every line that says it (S2, S3, S6, S8, D4, D5, T2, T3) takes it from there, as today.

### Rule 7. A relay out of reach says that it cannot be reached

Section 2 found item 6 to be the words. **Today:**

- D4 (`person_cmd.rs:1355-1363`): "  relay2: is not known to hold the latest change, and has not answered since 10:53 UTC. A device of yours that reaches only it may not have heard of that change. If you know that relay2 is gone for good, ..."
- D5 (`person_cmd.rs:1365-1370`): "  relay2: holds the latest change (as it said at 10:40 UTC), and has not answered since 10:53 UTC"
- T2 (`look.rs:1726-1731`): "relay2 is not known to hold the latest change, and has not answered since 10:53 UTC"
- T3 (`look.rs:1732-1737`): "relay2 has not answered since 10:53 UTC: this device sends through the others"
- S2 and S3 (`person_cmd/wait.rs:452-461`): "keep this machine on: relay2 is not known to hold the change yet, and has not answered since 10:53 UTC"; "relay2 holds the change, and has not answered since 10:53 UTC"
- S6 and S8 (`person_cmd/wait.rs`; the record of reach, §5): "  relay2 holds the change and all that this device carried, and ..."; "  relay2 is not known to hold the change, and ..."; "  relay2 holds the change, and ..."
- The status line (`indicator.rs:611-621`): "memory: a relay not known to hold the latest change".

**What is wrong.** None says that the relay cannot be reached, though each is said only because it cannot.

**The new words** (`<since>` as rule 6):

- **D4:** "  `<relay>`: cannot be reached from here, and is not known to hold the latest change: it `<since>`. A device of yours that reaches only it may not have heard of that change. If you know that `<relay>` is gone for good, take it out of the configuration of every device. Do not do so only because this machine cannot reach it: it may still serve a device that does."
- **D5:** "  `<relay>`: cannot be reached from here, and holds the latest change (as it said at `<when>`): it `<since>`"
- **T2:** "`<relay>` cannot be reached from here, and is not known to hold the latest change: it `<since>`"
- **T3:** "`<relay>` cannot be reached from here: it `<since>`. It holds the latest change, and this device sends through the others"
- **S2:** "keep this machine on: `<relay>` cannot be reached from here, and is not known to hold the change yet: it `<since>`"
- **S3:** "`<relay>` holds the change, and cannot be reached from here: it `<since>`"
- **S6,** in `<held>`: "  `<relay>` holds the change and all that this device carried, and cannot be reached from here: it `<since>`." Not in `<held>`: "  `<relay>` holds the change, and cannot be reached from here: it `<since>`. Some of what this device carried is not there yet."
- **S8, OUT and lacking:** "  `<relay>` cannot be reached from here, and is not known to hold the change: it `<since>`."
- **S8, OUT and holding:** "  `<relay>` holds the change, and cannot be reached from here: it `<since>`."
- **The status line,** where every relay it counts is out of reach: "memory: a relay out of reach, not known to hold the latest change", or "memory: `<n>` relays out of reach, not known to hold the latest change". Where some are out of reach and some not: "memory: `<n>` relays not known to hold the latest change, `<k>` out of reach". Otherwise as today.

**Rule 7.**

1. The lines above take the place of D4, D5, T2, T3, S2, S3, S6, S8 and the line of the record of reach, §5. When each is said does not change.
2. The status line's count, place, five minutes and seven days do not change (the record of reach, rule 11). What it reads of each relay counted gains whether it is out of reach: `NotKnown` (`indicator.rs:253-262`) gains `out_of_reach`, from `reach.class == "out_lacking"`.
3. "memory: a relay out of reach for <minutes> minutes" stays as it is, for a relay that holds the change.
4. The notes of the release that carries this say, once, that the notes of alpha.14 were wrong in this, with the sentence of section 2.

### Rule 8. The start of a change says, by relay, what it could not ask and could not read

**Today.** Before its questions, a change says each line of `could_not_fetch` (`person_cmd.rs:1963-1965`), from `not_fetched` (`commands.rs:994-1021`) and `change_prepare` (`commands.rs:1119-1127`):

> Could not fetch: the fetch ended before every channel was read to its end at every relay: a relay gave no leave or stopped answering, or holds more of a channel than one pass takes.

and "Could not fetch: <relay> did not answer." for a relay that has not answered since the node woke. That second line is said in a fork too (`commands.rs:1120-1123`).

**What the fetch does at each relay.** A whole pass takes each open connection (`device_entries.rs:554-558`). At each it first **shows the kept entry**; only an answer that the relay holds it (`Held`, `Taken`) gives leave, and only with leave does it go on to **read** the device's own channels (`turn`, `device_entries.rs:1281-1302`). The change entry is not in any channel that a device reads: it is the one entry of the phrase's channel (the record of 2026-10-04, 2.2), and a device learns of another change only by the answer to its show (4.6). The personal channel holds `name/`, `added/`, `applied/` and `left/`, not the change.

So the two steps put two different things at risk:

- **A relay not asked** (its show got no answer that it holds the kept entry) may hold another change, which this machine has not seen. Rule 9 is about that.
- **A relay asked, and not read** (it holds the kept entry, but a channel of the device's own was not read to its end there) holds no other change. What it may hold that this machine has not seen:
  - in the personal channel: **a device added through that relay since the last change.** Its record of addition is not known here, so this change does not list it, and it has to be added again (the record of 2026-10-04, section 6);
  - in a name's channel: what was last written in that name, so the folders here may not hold it.

**What is wrong.**

- The first line names no relay.
- "gave no leave" names a rule of the code, not anything a person knows.
- **A relay that is not connected is named by nothing** where it answered once since the node woke. A pass reads only the relays with an open connection, and a pass is short only where a relay it reached was not read to its end. So a relay that dropped after the wake leaves the pass whole, and `heard_since_woke` is true: nothing at all is said.
- Neither line says what is at risk.
- The review behind the first form of this record took `fetched_from` to say which relays were read. It does not: it is noted only for a name's channel and the messages channel (`device_entries.rs:2096-2101`), and is kept since the node started, not by pass (`state.rs:715-725`).

**Two notes, by relay.** For the fetch of a change (`fetch`, `commands.rs:931-958`), the node notes for each relay that the device is set up with, over every whole pass that began after the asking:

- **ASKED:** a show of the kept entry in such a pass got an answer that the relay holds it (`Held` or `Taken`: the answers that give leave). The wake rule's withholding of leave does not take this away: what is noted is the answer.
- **READ:** such a pass read every channel of the device's own to its end there, the messages channel excepted. That is what `read_all` counts today (`device_entries.rs:2061-2101`): a channel whose proof was not answered, or whose pull did not catch up, is not read; the messages channel is not counted.

**Why every channel, and not the personal channel alone.** `read_all` already counts every channel but messages, so the note is the measure the code has, kept by relay. And step 1 of the record of 2026-10-04, 7.1, is there "to make the folders here as current as they can be made": a name's channel read only in part is what today's first line warns of. Counting the personal channel alone would drop that warning.

**The precise rules of the notes.**

1. A relay is ASKED, or READ, where **any** whole pass that began after the asking did so. A relay that one pass missed and the next read is read.
2. **The kept entry** is the one kept when `fetch` returns. A pass that began under an earlier kept entry (the device applied a later change that a relay answered with, and `ask_whole` began another pass) does not count toward either note.
3. **The reason** that a relay is not ASKED, or not READ, is taken from the last such pass that began after the asking, under that kept entry. Where no such pass began at all within the two minutes, the reason is "it was not reached in the two minutes".
4. Each pass's reason for each relay is the first of the lists below that holds in that pass.

**The new words.** One line for each relay that is not ASKED:

> `  Could not ask <relay> for your latest change: <why>. <advice>`

`<why>` and `<advice>`:

1. no connection to it was open at the start of the pass: "this machine cannot reach it now". "Make sure this machine can reach it, and run this command again."
2. a turn of an earlier pass was still running there (`try_lock`, `device_entries.rs:1286-1288`): "an earlier pass was still reading it". "Wait a minute, and run this command again."
3. its show got an answer of the third kind of the record of reach, §1 (none, a reset, a time-out, "not signed", a round that ran out): "it did not answer". "Wait a minute, and run this command again."
4. it answered that it has no room for the change, or that the address is over its allowance: "it had no room for it". "\`cordelia devices\` says more."
5. it answered with another change that this machine does not take: "it holds a change that this machine does not take". "\`cordelia devices\` says what it holds."
6. no pass began: "it was not reached in the two minutes". "Wait a minute, and run this command again."

Then, one line for each relay that is ASKED and not READ:

> `  Could not read everything at <relay>: <why>. <what>. <advice>`

`<why>` and `<advice>`:

1. the wake rule withheld leave (the device had just started or woken, and was waiting for its other relays): "this machine had just started or woken, and was still waiting for its other relays". "Wait a minute, and run this command again."
2. a proof or a pull there failed, timed out or was reset: "it stopped answering". "Wait a minute, and run this command again."
3. a pull did not catch up before the passes ran out: "it holds more than this command reads in two minutes". "Run this command again: it reads on from where it stopped."

`<what>` says what was not read, one or both, in this order:

- the personal channel: "A device of yours added through it since your last change may not be known here: if so, this change does not list it, and you add it again";
- names' channels: "The folders here may not hold what was last written in `<n>` name`<s>` there".

Where no relay was reached in any pass: "  Could not ask any relay for your latest change: this machine cannot reach one now." Rule 9 follows.

The sync cycle's lines stay, in plain words: "  The folders here may not yet hold everything that was read: the sync cycle stopped before its end." or "... the sync cycle did not end within 2 minutes."

**In a fork** (`cordelia settle`, which `change_prepare` takes only in a fork, `commands.rs:1101-1107`). A device in a fork reads nothing, and goes on showing each relay the entry it had applied (the record of 2026-10-04, 4.5). So:

- **ASKED** in a fork is: the show got an answer of the first two kinds of the record of reach, §1, about one of the two changes the device holds: the relay holds the entry the device applied, or answers with the change made apart.
- One line for each relay that is not so asked: `  Could not ask <relay> which change it holds: <why>. <advice>`, with `<why>` and `<advice>` as above; and, for an answer with a third change, "it holds a change that is neither of the two".
- **READ** is not noted, and no line of reading is said: a device in a fork reads nothing, which is no failure of the fetch (`not_fetched`, `commands.rs:998`).
- This takes the place of today's "Could not fetch: <relay> did not answer" in a fork, and says more: no relay that today's line names goes unnamed.

**Rule 8.**

1. The node keeps the two notes above, by pass and by relay, with each pass's reason, in memory beside `whole_pass_was_short`. `fetched_from` is not used for them.
2. `fetch` hands back, by configured name, each relay that is not ASKED and each that is ASKED and not READ, each with its reason and what was not read. `change_prepare` hands them as a list, and the cycle's lines apart. The command says the lines above.
3. What the fetch does, and that a change goes on whatever it could not ask or read, do not change (the record of 2026-10-04, 7.1, step 1).

### Rule 9. What a change made without asking every relay can do

**Today.** Nothing is said. An independent review found that a change made after a fetch that did not ask every relay is by design, and can be put right, but:

- relay2 may hold a change made on another device, which this machine has not seen;
- the change made here starts from the last change this machine applied, and is made apart from that one: a fork (the record of 2026-10-04, 4.5);
- until `cordelia settle`, a device that the other change removed may still be listed in the change made here. A removed device that has not yet applied its own removal may apply this change, and read what is written under it. One that has applied its removal takes no change entry (`device_entries.rs:1019-1024`), so does not.

**This is one way a change comes to be made apart, not the only one.** Two devices can each make a change before they have met, with every relay asked by both (4.5); a change can reach a relay after the fetch, while you answer the questions, and that relay then be lost; a recovery can be made from an old state (section 9). So the words below never say, or let a person read, that a change made after every relay was asked cannot be made apart. Where every relay was asked, this rule says nothing; the line that follows every change, "two changes made apart have to be settled with the phrase" (`person_cmd.rs:2040-2044`), stays.

**The new words.** Where rule 8 named a relay that is not ASKED, after rule 8's lines and before any question:

> This change is made from what `<asked>` hold`<s>`. `<not asked>` may hold a change made on another device of yours, which this machine has not seen. If it does, this change and that one are made apart, and you settle them with \`cordelia settle\` and your recovery phrase, on a device that has seen both. Until you do, a device that the other change removed may still be listed in this one, and may read what your devices write after it.
> To ask `<not asked>` first, answer no when you are asked to make this change, and follow the advice above. Then run this command again.

Where no relay was asked, the first sentence is: "This change is made from what this machine holds: no relay was asked for your latest change."

**In a fork** (`cordelia settle`), in place of the paragraph above, where a relay is not asked:

> This settlement is made from the two changes this machine holds. `<not asked>` may hold a third change, made on another device of yours, which this machine has not seen. If it does, this settlement and that change are made apart, and you settle again. Until you do, a device that the third change removed may still be listed in this one, and may read what your devices write after it.
> To ask `<not asked>` first, answer no when you are asked to make this change, and follow the advice above. Then run this command again.

And just before "Make this change?" (`person_cmd.rs:1992`), in both:

> This change is made without asking `<not asked>`.

**Rule 9.**

1. The words are said only where rule 8 named a relay that is not ASKED, in a renewal, a removal and a settlement. A relay that is ASKED and not READ is not in `<not asked>`: it holds the kept entry, and so no other change.
2. `<asked>` is each relay that is ASKED; `<not asked>` each that is not.
3. Nothing is asked that is not asked today: the yes stays the one place to stop.

### Rule 10. The two records say it too

The sentences of section 5 for the record of 2026-10-04 describe the design as it is: they are added when this record is accepted, whether or not the words above are built yet.

## 4. Tests

**Tests of today's words that change.** A test that finds a line with `contains` passes the times of rule 3 unchanged; one that matches a whole line, or its start, changes.

| Test | Asserts today | Asserts after |
|---|---|---|
| `person_e2e.rs:1575`, `1590`, `3842`, `3856`, `3948` | "Type \`stays\` to list this device", typed `stays` | "Type \`list\` to list this machine", typed `list` |
| `person_e2e.rs:382` | "Could not fetch: NO_SUCH_NAME did not answer." | "Could not ask NO_SUCH_NAME for your latest change: this machine cannot reach it now." |
| `person_e2e.rs:2981` | a fetch that read everything says no "Could not fetch" | no "Could not ask" and no "Could not read" |
| `person_e2e.rs:1103` | S1 | S1 with its sentence on times |
| `person_e2e.rs:5436`, `5439`, `5464`, `5561`, `5601` | S2, S8 and D4 as today | S2, S8 and D4 of rule 7, with `<since>` of rule 6 |
| `recover_e2e.rs:2327`, `2330` | S2, S8 | S2, S8 of rule 7; R0 with its sentence on times |
| `memory_e2e.rs:1024` | S8 "is not known to hold the change, and has not been reached from here since" | rule 7's S8 |
| `devices_e2e.rs:4576` | the line "memory: a relay not known to hold the latest change" | the line of rule 7 once the relay is out of reach, and today's line before |
| `first_start_e2e.rs:1796` | "Memory:    memory: 1 folder stopped syncing" | "Memory:    1 folder stopped syncing" |
| units: `person_cmd.rs` (the wait's lines, `3742-3833`; D4 and D5, `4337`, `4428`), `person_cmd/wait.rs`, `look.rs:3239` (T2, T3), `recover_cmd.rs:5845-6111`, `commands.rs:2165` (`not_fetched`), `main.rs:6913` and the status tests, `indicator.rs` (the line of a relay not known) | today's words | the new words |

The tests that answer "Type \`stays\` or \`removed\`" (`common/mod.rs:1499-1502`, and every `renews(.., &["stays"], ..)`) do not change.

**New tests.** Each fails on an assertion if its rule is taken out.

- **Rule 1.** `person_e2e.rs`, `a_device_added_since_the_last_change_is_asked_to_list_itself`: a device added after change 2 runs `cordelia renew`; the prompt says "A change is the list of your devices", "Your last change (change 2, made on", the adder, "This command makes change 3", and "Type \`list\`"; typing `stays` stops with "You did not type \`list\`. Nothing was changed." and `cordelia devices` still shows change 2; typing `list` goes on, and "The change that the recovery phrase will sign (change 3)" follows. A unit test in `person_cmd.rs` holds `<new>` equal to the number signed, for a renewal, a removal and a settlement.
- **Rule 2.** `p2p.rs`, `each_connection_says_the_configured_relay_it_was_made_to`. `commands.rs`, `a_relay_given_no_key_is_named_in_its_row_as_configured`. `person_e2e.rs`, `the_wait_names_a_relay_as_configured`: the device is set up with a relay by a name that resolves to its address (`localhost:<port>`), something waits there, and the wait's line says `localhost:<port>` and never `127.0.0.1:<port>`.
- **Rule 3.** `person_cmd.rs`, with a clock that the test moves: `each_line_of_the_wait_starts_with_its_time_and_is_said_once` (two looks with the same lines at different times say each line once; every line after the first matches `^  \d\d:\d\d:\d\d  `); `still_waiting_is_said_after_a_minute_with_no_new_line` (nothing at 59 seconds, the line at 60 naming the last line's time, again at 120 naming the same time); `each_end_begins_with_the_wait_has_ended`. The same in `recover_cmd.rs` for R0 and the recovery's wait.
- **Rule 4.** `person_cmd.rs`, `the_count_of_a_relay_waited_out`: a relay not reached, its reference 30 seconds ago, gives no count; at 3 minutes and 10 seconds, "has not been reached for 3 of the 5 minutes"; at 6 minutes and in no class, "for 6 minutes. This command stops waiting for it once this machine has tried it again and failed."; out of reach, no count. The same for a relay that refuses.
- **Rule 5.** `main.rs`, `the_plain_status_says_memory_once`: for each summary of `indicator.rs`, the plain status line starts "  Memory:    " and does not contain "memory" right after it; `--line` keeps "memory: ".
- **Rule 6.** `look.rs`, `since_says_since_what`: one case for each `reference_by`, with and without `last_reached`; the case of the test reads "has not answered since this device applied the change at 10:53 UTC (it was last reached at 10:48 UTC)". `reach.rs`, `the_reference_says_which_moment_it_is`.
- **Rule 7.** `look.rs` and `person_cmd.rs`: D4, D5, T2 and T3 each contain "cannot be reached from here"; `person_cmd/wait.rs`: S2, S3, S6 (both forms) and S8 (both forms) each contain it. `indicator.rs`, `the_line_says_out_of_reach_where_every_relay_it_counts_is`: two relays out of reach and lacking give "memory: 2 relays out of reach, not known to hold the latest change"; one of each gives "..., 1 out of reach"; a relay that holds and is out of reach still gives "a relay out of reach for <m> minutes", last. The ignored real-process test `a_change_ends_not_done_where_a_relay_that_lacks_it_cannot_be_reached` (`person_e2e.rs:5405`) asserts rule 7's S8 and D4.
- **Rule 8,** units in `device_entries.rs` and `commands.rs`:
  - `a_whole_pass_notes_asked_and_read_by_relay`: `Held` with every channel caught up is ASKED and READ; `Held` then a pull that times out is ASKED and not READ; no answer is neither.
  - `a_relay_read_by_any_pass_after_the_asking_is_read`: the first pass misses it, the second reads it.
  - `a_pass_under_an_earlier_kept_entry_does_not_count`: a relay answers with a later change; the passes before it are not counted.
  - `the_reason_is_the_last_passes`: one case for each `<why>` of both lists, among them "an earlier pass was still reading it", and **a relay not connected that answered since the wake**, which today is named by nothing.
  - `what_was_not_read_is_said`: the personal channel alone, names alone, both.
  - `in_a_fork_a_relay_not_asked_is_named_and_no_reading_is_said`.
- **Rule 8,** real processes, `person_e2e.rs`: the test at 382 with the new line; and `a_relay_stopped_after_the_wake_is_named`, in which relay2 is stopped after the device has woken, and **the test waits until `cordelia peers` shows relay2 not connected** before it runs `cordelia renew`. A stopped relay's connection stays open for up to `QUIC_MAX_IDLE_TIMEOUT_SECS` (60 s), and a pass in that time gives "it did not answer". It then asserts "Could not ask relay2 for your latest change: this machine cannot reach it now."
- **Rule 9.** `person_e2e.rs`, `a_change_made_without_asking_a_relay_says_what_it_can_do`: with one relay not asked, "This change is made from what" names the other, "may hold a change made on another device of yours" and "To ask" name the relay not asked, and "This change is made without asking" comes before "Make this change?"; with every relay asked, none of these is said, and "two changes made apart have to be settled with the phrase" still is. A unit test: a relay ASKED and not READ is not in `<not asked>`. And `a_settlement_names_a_relay_not_asked_and_a_third_change`: a device in a fork, relay2 not connected, `cordelia settle` says "Could not ask relay2 which change it holds" and "may hold a third change".

## 5. Sentences of other records that change

**The record of 2026-10-04.**

- **Property 5, its limit** (section 1). After "... until the two are settled (section 9).", add: "The same holds of any two changes made apart (4.5): until they are settled, a device that one of them removed may still be listed in the other, and may read what is written under it. A recovery from an old state is one way they come about; two changes made on two devices before they meet is another; and a change made after a fetch that did not ask every relay for its latest change is a third (7.1, step 1)."
- **7.1, step 1.** "It says what it could not fetch." becomes: "It names each relay that it could not ask for its latest change, and each that it asked but could not read to the end, and says why and what is at risk (decision 2026-10-24, rule 8). A relay not asked may hold a change made apart from this one; until the two are settled, a device that that change removed may still be listed in this one, and may read what is written under it: the command says so before its questions (decision 2026-10-24, rule 9). A relay asked and not read holds no other change, but may hold a device added through it since the last change, which this one then does not list."

**The record of reach.**

- **§3, the row of `person_cmd.rs:2295`.** "Stays (said only of a relay that is connected)" becomes "Its words stay; the relay is named as configured (decision 2026-10-24, rule 2)".
- **§5, `<since>`.** Its two phrases become the four of decision 2026-10-24, rule 6. The sentence "So a relay reached before a change, and not since, 'has not answered since' the change" becomes "So a relay reached before a change, and not since, 'has not answered since this device applied the change at <when>', and says when it was last reached."
- **§5, S1, and R0.** One sentence is added at the end of each: "Each line below starts with the time it was said, in UTC." (decision 2026-10-24, rule 3).
- **§5, D4, D5, T2, T3, S2, S3, S6 and S8.** Each becomes its words in decision 2026-10-24, rule 7.
- **§5, the line.** Its first form gains the forms "memory: a relay out of reach, not known to hold the latest change", "memory: <n> relays out of reach, not known to hold the latest change" and "memory: <n> relays not known to hold the latest change, <k> out of reach".
- **Rule 11.** After "For a relay that is out of reach and holds the change, while another relay is reached: the warning of the ruling.", add: "It is never said of a relay that lacks the change: that relay is counted by the line above, which says that it is out of reach (decision 2026-10-24, rule 7)."

**`docs/specs/channels-api.md:1120`** (`POST /api/v1/change/prepare`). "and what it could not fetch" becomes "each relay it could not ask for its latest change and each it could not read to the end, by configured name, with why and what was not read, and whether the sync cycle went to its end".

## 6. Set aside, and why

- **Times in the person's own zone.** Every other time the node shows is UTC (the record of reach, §1). Two zones on one screen would be worse than one.
- **Naming relay2 in the status line.** A relay is named by its address in a configuration, and the line is shown on a bar and read by programs. `cordelia status` and `cordelia devices` name it.
- **Holding a change back until every relay is asked.** A removal must never wait on a relay (the record of 2026-10-04, 7.1, step 1). The person is told, and the yes is where to stop.
- **A new word for the answer to "Type \`stays\` or \`removed\`".** It was not found hard to follow, and changing it changes every test that makes a change. It can follow.
- **A date in words ("8 October")**, as the person wrote it. Every other date the commands show is written 2026-10-08.
- **"Read" as the personal channel alone** (the first form of this record). It drops today's warning of memory not fetched (rule 8, why every channel).
- **The fork warning for every change,** whatever was asked. Most changes are made with every relay asked, and a warning said every time is read by nobody. The line that follows every change already says that two changes made apart are settled with the phrase.

## 7. What it costs

- One field in the look of each relay (`reference_by`), and one in what the status reads (`out_of_reach`).
- From the dial loop, for each connection, the configured relay it was made to (rule 2.1).
- Two notes by pass and by relay, with a reason, in memory; and a list in place of strings in `change_prepare`'s answer. The command and the node of one version only work together (the record of 2026-10-04, 10.1, rule 6), so no older reader is broken.
- One line a minute in a wait where no line comes.
- The tests of section 4.

## 8. The review, and what became of each finding

The first form (commit bb91d29) had one independent review: one high, five medium and eight low findings. Each was taken at its least change.

| # | Level | Finding | Settled |
|---|---|---|---|
| 1 | high | Rules 8 and 9 measured the personal channel, which does not hold the change; a relay that holds the kept entry was warned of as a fork | Two notes by relay, ASKED (an answer that it holds the kept entry) and READ (every own channel read to its end); rule 9 goes by ASKED, rule 8's reading lines by READ; what an unread personal channel puts at risk is said (a device added through that relay); the "Today" text and §5's sentence for 7.1 corrected (rule 8, rule 9, section 5) |
| 2 | medium | The fork warning overclaimed, and "can read" was untrue of a removed device that applied its removal | The limit is written for any change made apart, an unread relay one cause of three; "may still be listed, and may read"; the warning never says that asking every relay rules a fork out, and today's line after every change stays (rule 9, section 5) |
| 3 | medium | A settlement said none of rule 8's lines, and lost today's "did not answer" | In a fork each relay not asked which change it holds is named, and rule 9's words are said for a third change; no relay that today's line names goes unnamed (rule 8, in a fork; rule 9) |
| 4 | medium | Rule 8 dropped today's warning that memory was not fetched | "Read" is every own channel but messages, as `read_all` counts; the reason is given; names not read are said (rule 8) |
| 5 | medium | The note by pass was not defined well enough | Read by any pass begun after the asking; the reason from the last such pass; the kept entry as when `fetch` returns; "an earlier pass was still reading it" and "not reached in the two minutes" added (rule 8) |
| 6 | medium | Rule 7 fixed only the lines of a relay that lacks the change | D5, T3, S3, S6 and S8 (holding) say "cannot be reached from here" too; section 2 says where a person learns it before any change (rule 7, section 2) |
| 7 | low | Rule 9's advice was wrong for some reasons | Advice by reason, in rule 8's lines; rule 9 points to it |
| 8 | low | Rule 2.1 rested on data the node does not hand, and `cordelia devices` kept one address line | The data is named, its source (the dial loop) and its cost; the line of `cordelia devices` is reworded (rule 2, section 7) |
| 9 | low | "Still waiting" was ambiguous, could be untrue, and its clock was fixed | "no new line since" the last line that was not a notice; a dropped line is no new line, as today; the clock is given to the wait (rule 3) |
| 10 | low | The count said "0 of 5", and "still trying" could be untrue | The count starts at minute 1; after five minutes one sentence true in both cases (rule 4) |
| 11 | low | "since the change at" misled on a device that applied a change made elsewhere | "since this device applied the change at" (rule 6) |
| 12 | low | The answer word `add` | `list`, with the reason (rule 1) |
| 13 | low | Rule 8's real-process test would be flaky | It waits until the relay shows as not connected (section 4) |
| 14 | low | R0 had no sentence on times; a time on S8's first line set it apart | R0 gets the sentence; each end begins with a timed line of its own, and its lines have none (rule 3) |
