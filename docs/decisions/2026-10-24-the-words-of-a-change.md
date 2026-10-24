# Decision: the words of a change

**Date**: 2026-10-24
**Status**: Proposed. Not built.
**Cited as**: "decision 2026-10-24, rule 3". The numbers do not change. A number that is not used stays unused.

Words used throughout:

- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md). **The record of reach** is [`2026-10-19-a-relay-out-of-reach.md`](2026-10-19-a-relay-out-of-reach.md).
- **A change** is a statement and its change entry, as the record of 2026-10-04 says (section 4). **The wait** is the wait after a change (the record of reach, §1), and the wait of a recovery (its rule 9).
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
- `<time>` is the wall-clock time at which a line is said, in UTC, with seconds: "10:53:12". The wait says once that its times are UTC (rule 3).
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
2. **The record of reach's own lines for a relay that lacks the change.** D4, T2, S2 and S8 (OUT and lacking) say "is not known to hold the latest change, and has not answered since <when>". None says that the relay cannot be reached, though the node knows it and the relay is in that line only because it cannot be. A person reads "has not answered" as a relay that is slow, not one that this machine cannot reach. Rule 7 fixes these words.

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
>   Type \`add\` to list this machine and go on. Anything else stops here, and nothing is changed:

**`cordelia settle`** says the same, with its second and third sentences so:

> Neither change `<a>` nor change `<b>` lists this machine: both were signed before it was added. `<adder>` added this machine at `<added at>`, as `<this>`.
> This command makes change `<new>`, which settles the two. The machine that makes a change is always in it, so change `<new>` will list this machine as `<this>`.

**Any answer but `add`:** "You did not type \`add\`. Nothing was changed." **The input ends:** "The input ended before you typed an answer. Nothing was changed." Both with status 1, as today.

Placeholders:

- `<last>` is the number of the statement this device has applied (`handed.applied.statement.number`); `<maker>` is the device that made it, as `lists_shown` writes its "made on" (`person_cmd.rs:2290`).
- `<a>` and `<b>` are the numbers of the change this device had applied and the change made apart, in that order.
- `<adder>`, `<added at>` and `<this>` are what `own_addition` writes today: the adder, the time of the addition (`time_of`, "2026-10-08 13:43 UTC"), and this device as its addition record names it.
- `<new>` is the number of the statement that `prepare_change` or `prepare_settlement` will make: one above `<last>` for a renewal or a removal, and one above the higher of `<a>` and `<b>` for a settlement (the record of 2026-10-04, 4.5).

**Rule 1.**

1. `own_listing` says the words above, and goes on only where `add` is typed.
2. `<new>` is the number that "The change that the recovery phrase will sign (change N)" shows next (`person_cmd.rs:1971-1974`). A unit test holds the two equal for a renewal, a removal and a settlement.
3. The other question, "Type \`stays\` or \`removed\`" about another device (`person_cmd.rs:1841`), is not changed here.

### Rule 2. A relay is named as it is configured, in every line

**Today.** The wait says, for each relay that is connected and has channels of this device to send to (`person_cmd.rs:2555-2562`):

> keep this machine on: 1 of this device's channels still to send to `<address>`:9474

It reads `text(waits, "relay")`: the address the relay was reached at (`commands.rs:303-316`, `"relay": address`). The row also carries `"name"`, the relay as configured, where the relay answers with a configured key; for a relay given no key, `name` is null (`commands.rs:284-293`). `cordelia init --new-key` does the same in "Could not send it to <relay>" (`person_cmd.rs:2731-2733`, `2748`).

**What is wrong.** Every other line names the relay as configured (relay2). This one reads as a third relay, and puts an address on the screen.

**The new words.** The same lines, with `<relay>` as section 1 defines it:

> keep this machine on: `<n>` of this device's channels still to send to `<relay>`

> Could not send it to `<relay>`: the devices that this one leaves may not be told that it left.

**Rule 2.**

1. Each row of `waiting` names the relay as configured. The node fills `name` for a relay given no key too: by the configured relay whose connection the row is (the node's list of its relays, `state.relays`, names the host it dialled, and which connection is its own).
2. A line of the wait, of `cordelia init --new-key` or of a recovery never prints the `relay` field of a row. Where a row has no name, which a personal node that dials only its configured relays never makes, the line says "a relay that this device is connected to".
3. `cordelia devices` matches a row to a relay by name, and then by the addresses a name resolves to (`person_cmd.rs:1220-1250`). That matching stays, and is used by nothing new.

### Rule 3. Each line of the wait carries its time

**Today.** The wait says its first line, then each line as it comes, once, while its words stay the same (`person_cmd.rs:2632-2670`: `if !said.contains(line)`). No line has a time. A wait of five minutes in which nothing changes prints nothing for five minutes.

**What is wrong.** You cannot see that the command is alive, or when anything last moved.

**The new words.**

- S1, the first line, ends with one sentence more: "Each line below starts with the time it was said, in UTC."
- Each line of the wait after the first starts with its time, two spaces in, two spaces after:

  > `  10:53:12  relay1 holds the change`

- Where no line has been said for 60 seconds, the wait says:

  > `  <time>  still waiting: nothing has changed since <time of the last line>`

  It says it again 60 seconds after the last line of any kind, so once a minute while nothing moves.
- The first line of each end (end 1's line, S6, S6b or S8's first line, R1) starts with its time too. The lines under it do not.

**Rule 3.**

1. Whether a line is new is judged by its words without the time, as today. A line is never said twice because its time changed.
2. The time is the wall clock at the moment the line is said, in UTC (`chrono::Utc::now()`, `%H:%M:%S`).
3. The same holds in the wait of a recovery (the record of reach, rule 9; `recover_cmd.rs`).
4. Nothing of what the wait decides reads a time it prints.

### Rule 4. The count while a relay is waited out

**Today.** While a relay is not reached and not yet out of reach, the wait says "keep this machine on: relay2 does not hold the change yet" or "keep this machine on: relay2 is not connected, and what is still to send there is not known until it is" (`person_cmd.rs:2523`, `2536-2539`), once. It does not say that the command will stop waiting for it, or when.

**What is wrong.** The five minutes of the record of reach are invisible. The person wants "relay2 unreachable for 3 of 5 minutes".

**The new words.** For each relay that is not reached and not out of reach, once each minute counted:

> `  <time>  <relay> has not been reached for <m> of the 5 minutes that this command waits for it`

After five minutes, while it is still not out of reach (an attempt is in flight, or none was made in the last five minutes; the record of reach, §1):

> `  <time>  <relay> has not been reached for <m> minutes. This machine is still trying it.`

For a relay that is reached and refuses the change, once each minute counted:

> `  <time>  <relay> has refused the change for <m> of the 5 minutes that this command waits for it`

**Rule 4.**

1. `<m>` is whole minutes, rounded down, from the relay's reference (the record of reach, §1, as the look gives it: `reach.reference`), or from when it came to refuse.
2. It is said only while the relay is in no class (the record of reach, §1). Once it is out of reach, S2 or S3 says so instead.
3. The line is new each minute, so rule 3 says it once each minute, with its time; the "still waiting" line of rule 3 is then not needed for it.
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

- "has not been reached from here since `<when>`", where the relay was reached after its reference (as today);
- "has not answered since the change at `<when>`", where the reference is the change of the kept entry;
- "has not answered since this device started at `<when>`", where it is the node's start;
- "has not answered since this device woke from sleep at `<when>`", where it is a sleep.

Then, in the last three, where the relay was reached before the reference since the node started: " (it was last reached at `<when>`)".

So the test's line reads: "has not answered since the change at 10:53 UTC (it was last reached at 10:48 UTC)".

**Rule 6.**

1. The look says which moment a relay's reference is: a field `reference_by` of `ReachLook` (`look.rs:300-340`), one of `start`, `sleep`, `change` and `reached`, put by the module that moves the reference (`device_entries/reach.rs`). It is shown, and nothing decides by it.
2. "it was last reached at" uses `last_reached` (`look.rs:318-319`), kept since the node started, as today.
3. `<since>` is written in one place (`look::since`), and every line that says it (S2, S3, S6, S8, D4, D5, T2, T3) takes it from there, as today.

### Rule 7. A relay that lacks the change and cannot be reached says so

Section 2 found this item to be the words. **Today:**

- D4 (`person_cmd.rs:1355-1363`): "  relay2: is not known to hold the latest change, and has not answered since 10:53 UTC. A device of yours that reaches only it may not have heard of that change. If you know that relay2 is gone for good, ..."
- T2 (`look.rs:1726-1731`): "relay2 is not known to hold the latest change, and has not answered since 10:53 UTC"
- S2 (`person_cmd/wait.rs:456-459`): "keep this machine on: relay2 is not known to hold the change yet, and has not answered since 10:53 UTC"
- S8, OUT and lacking (the record of reach, §5): "  relay2 is not known to hold the change, and has not answered since 10:53 UTC."
- The status line (`indicator.rs:611-621`): "memory: a relay not known to hold the latest change".

**What is wrong.** None says that the relay cannot be reached, though each is said only because it cannot.

**The new words** (`<since>` as rule 6):

- **D4:** "  `<relay>`: cannot be reached from here, and is not known to hold the latest change: it `<since>`. A device of yours that reaches only it may not have heard of that change. If you know that `<relay>` is gone for good, take it out of the configuration of every device. Do not do so only because this machine cannot reach it: it may still serve a device that does."
- **T2:** "`<relay>` cannot be reached from here, and is not known to hold the latest change: it `<since>`"
- **S2:** "keep this machine on: `<relay>` cannot be reached from here, and is not known to hold the change yet: it `<since>`"
- **S8, OUT and lacking:** "  `<relay>` cannot be reached from here, and is not known to hold the change: it `<since>`."
- **The status line,** where every relay it counts is out of reach: "memory: a relay out of reach, not known to hold the latest change", or "memory: `<n>` relays out of reach, not known to hold the latest change". Where some are out of reach and some not: "memory: `<n>` relays not known to hold the latest change, `<k>` out of reach". Otherwise as today.

**Rule 7.**

1. The lines above take the place of D4, T2, S2, S8 (OUT and lacking) and the line of the record of reach, §5. When each is said does not change.
2. The status line's count, place, five minutes and seven days do not change (the record of reach, rule 11). What it reads of each relay counted gains whether it is out of reach: `NotKnown` (`indicator.rs:253-262`) gains `out_of_reach`, from `reach.class == "out_lacking"`.
3. "memory: a relay out of reach for <minutes> minutes" stays as it is, for a relay that holds the change.
4. The notes of the release that carries this say, once, that the notes of alpha.14 were wrong in this, with the sentence of section 2.

### Rule 8. The start of a change names each relay that was not read

**Today.** Before its questions, a change says each line of `could_not_fetch` (`person_cmd.rs:1963-1965`), from `not_fetched` (`commands.rs:994-1021`) and `change_prepare` (`commands.rs:1119-1127`):

> Could not fetch: the fetch ended before every channel was read to its end at every relay: a relay gave no leave or stopped answering, or holds more of a channel than one pass takes.

and "Could not fetch: <relay> did not answer." for a relay that has not answered since the node woke.

**What is wrong.**

- The first line names no relay.
- "gave no leave" names a rule of the code (the wake rule's leave, `device_entries/leave.rs`), not anything a person knows.
- **A relay that is not connected is named by nothing** where it answered once since the node woke. A pass reads only the relays with an open connection (`device_entries.rs:554-558`), and a pass is short only where a relay it reached was not read to its end (`device_entries.rs:2096-2101`, `586-593`). So a relay that dropped after the wake leaves the pass whole, and `heard_since_woke` is true: nothing at all is said.
- The review behind this record took `fetched_from` to say which relays were read. It does not, for this: `fetched_from` is noted only for a name's channel and the messages channel (`device_entries.rs:2096-2101`: `Kind::Name(_) | Kind::Messages`), never for the personal channel, which holds the change; and it is kept since the node started, not by pass (`state.rs:715-725`).

**The new words.** One line for each relay that the device is set up with and that this fetch did not read:

> `  Could not read <relay>: <why>.`

`<why>` is the first of these that holds:

1. "this machine cannot reach it now": no connection was open to it during the fetch;
2. "this machine had just started or woken, and was still waiting for its relays": the pass took nothing under the wake rule;
3. "it stopped answering before this machine had read everything it holds": a stream to it failed, timed out or was reset;
4. "it holds more than this command reads in two minutes": a channel there was read only in part when the passes ran out;
5. "it was not read in the two minutes": anything else.

Where no relay was reached: "  Could not read any relay: this machine cannot reach one now."

The sync cycle's lines stay, in plain words: "  The folders here may not yet hold everything that was read: the sync cycle stopped before its end." or "... the sync cycle did not end within 2 minutes."

**Rule 8.**

1. **What "read" means:** a relay was read where a whole pass that began after the asking pulled the personal channel of the generation this device has applied to its end there, or the relay answered that it holds none of it. The node notes this for each whole pass and each relay, with the reason where it was not (a note of its own, beside `whole_pass_was_short`; `fetched_from` is not used for it). `fetch` (`commands.rs:931-958`) hands back the relays that no such pass read, by their configured names, each with its reason.
2. `change_prepare` hands `could_not_fetch` as a list of `{ "relay": <name>, "why": <reason> }`, and the cycle's lines apart. The command says the lines above.
3. A device in a fork reads nothing, as today, and says none of these lines: it is settling, and rule 9 says what it needs.
4. What the fetch does, and that a change goes on whatever it could not read, do not change (the record of 2026-10-04, 7.1, step 1).

### Rule 9. What a change made without reading every relay can do

**Today.** Nothing is said. An independent review found that a change made after a fetch that did not read every relay is by design, and can be put right, but:

- relay2 may hold a change that another device made through it, which this machine has not seen;
- the change made here then starts from the last change this machine applied, and is made apart from that one: a fork (the record of 2026-10-04, 4.5);
- until `cordelia settle`, a device that the other change removed is listed in the change made here. It applies it, and reads what is written under it.

**The new words.** Where rule 8 named at least one relay, after its lines and before any question:

> This change is made from what `<read>` hold`<s>`. `<not read>` may hold a change that another device of yours made, which this machine has not seen. If so, this change and that one are made apart, and you settle them with \`cordelia settle\` and your recovery phrase, on a device that has seen both. Until you do, a device that the other change removed is still listed in this one, and can read what your devices write after it.
> To read `<not read>` first, answer no when you are asked to make this change, make sure this machine can reach `<it | them>`, and run this command again.

Where no relay was read, the first sentence is: "This change is made from what this machine holds: no relay was read."

And just before "Make this change?" (`person_cmd.rs:1992`):

> This change is made without reading `<not read>`.

**Rule 9.**

1. The words are said only where rule 8 named a relay, in a renewal, a removal and a settlement alike.
2. `<read>` is each relay that the fetch read; `<not read>` each that it did not.
3. Nothing is asked that is not asked today: the yes stays the one place to stop.

### Rule 10. The two records say it too

The review's sentence for the record of 2026-10-04 is section 5. It describes the design as it is: it is added when this record is accepted, whether or not the words above are built yet.

## 4. Tests

**Tests of today's words that change.** A test that finds a line with `contains` passes the times of rule 3 unchanged; one that matches a whole line, or its start, changes.

| Test | Asserts today | Asserts after |
|---|---|---|
| `person_e2e.rs:1575`, `1590`, `3842`, `3856`, `3948` | "Type \`stays\` to list this device", typed `stays` | "Type \`add\` to list this machine", typed `add` |
| `person_e2e.rs:382` | "Could not fetch: NO_SUCH_NAME did not answer." | "Could not read NO_SUCH_NAME: this machine cannot reach it now." |
| `person_e2e.rs:2981` | a fetch that read everything says no "Could not fetch" | no "Could not read" |
| `person_e2e.rs:1103` | S1 | S1 with its sentence on times |
| `person_e2e.rs:5436`, `5439`, `5464`, `5561`, `5601` | S2, S8 and D4 as today | S2, S8 and D4 of rule 7, with `<since>` of rule 6 |
| `recover_e2e.rs:2327`, `2330` | S2, S8 | S2, S8 of rule 7 |
| `memory_e2e.rs:1024` | S8 "is not known to hold the change, and has not been reached from here since" | rule 7's S8 |
| `devices_e2e.rs:4576` | the line "memory: a relay not known to hold the latest change" | the line of rule 7 once the relay is out of reach, and today's line before |
| `first_start_e2e.rs:1796` | "Memory:    memory: 1 folder stopped syncing" | "Memory:    1 folder stopped syncing" |
| units: `person_cmd.rs` (the wait's lines, `3742-3833`; D4, `4337`, `4428`), `person_cmd/wait.rs`, `look.rs:3239` (T2), `recover_cmd.rs:5845-6111`, `commands.rs:2165` (`not_fetched`), `main.rs:6913` and the status tests, `indicator.rs` (the line of a relay not known) | today's words | the new words |

The tests that answer "Type \`stays\` or \`removed\`" (`common/mod.rs:1499-1502`, and every `renews(.., &["stays"], ..)`) do not change.

**New tests.** Each fails on an assertion if its rule is taken out.

- **Rule 1.** `person_e2e.rs`, `a_device_added_since_the_last_change_is_asked_to_add_itself`: a device added after change 2 runs `cordelia renew`; the prompt says "A change is the list of your devices", "Your last change (change 2, made on", the adder, "This command makes change 3", and "Type \`add\`"; typing `stays` stops with "You did not type \`add\`. Nothing was changed." and `cordelia devices` still shows change 2; typing `add` goes on, and "The change that the recovery phrase will sign (change 3)" follows. A unit test in `person_cmd.rs` holds `<new>` equal to the number signed, for a renewal, a removal and a settlement.
- **Rule 2.** `commands.rs`, `a_relay_given_no_key_is_named_in_its_row_as_configured`. `person_e2e.rs`, `the_wait_names_a_relay_as_configured`: the device is set up with a relay by a name that resolves to its address (`localhost:<port>`), something waits there, and the wait's line says `localhost:<port>` and never `127.0.0.1:<port>`.
- **Rule 3.** `person_cmd.rs`, `each_line_of_the_wait_starts_with_its_time_and_is_said_once`: two looks with the same lines at different times say each line once; every line after the first matches `^  \d\d:\d\d:\d\d  `. `still_waiting_is_said_after_a_minute_of_nothing`: with a clock that the test moves, nothing at 59 seconds, the line at 60, and again at 120.
- **Rule 4.** `person_cmd.rs`, `the_count_of_a_relay_waited_out`: a relay not reached, its reference 3 minutes and 10 seconds ago, gives "has not been reached for 3 of the 5 minutes"; at 6 minutes and in no class, "for 6 minutes. This machine is still trying it."; out of reach, no count. The same for a relay that refuses.
- **Rule 5.** `main.rs`, `the_plain_status_says_memory_once`: for each summary of `indicator.rs`, the plain status line starts "  Memory:    " and does not contain "memory" right after it; `--line` keeps "memory: ".
- **Rule 6.** `look.rs`, `since_says_since_what`: one case for each `reference_by`, with and without `last_reached`; the case of the test reads "has not answered since the change at 10:53 UTC (it was last reached at 10:48 UTC)". `reach.rs`, `the_reference_says_which_moment_it_is`.
- **Rule 7.** `look.rs` and `person_cmd.rs`, D4 and T2 contain "cannot be reached from here"; `indicator.rs`, `the_line_says_out_of_reach_where_every_relay_it_counts_is`: two relays out of reach and lacking give "memory: 2 relays out of reach, not known to hold the latest change"; one of each gives "..., 1 out of reach"; a relay that holds and is out of reach still gives "a relay out of reach for <m> minutes", last. The ignored real-process test `a_change_ends_not_done_where_a_relay_that_lacks_it_cannot_be_reached` (`person_e2e.rs:5405`) asserts rule 7's S8 and D4.
- **Rule 8.** `commands.rs`, `could_not_fetch_names_each_relay_not_read`: one case for each `<why>`, among them **a relay not connected that answered since the wake**, which today is named by nothing. `device_entries.rs`, `a_whole_pass_notes_which_relays_read_the_personal_channel_to_its_end`. `person_e2e.rs`: the existing test at 382 with the new line, and one where relay2 is stopped after the device has woken, which says "Could not read relay2: this machine cannot reach it now."
- **Rule 9.** `person_e2e.rs`, `a_change_made_without_reading_a_relay_says_what_it_can_do`: with one relay not read, "This change is made from what" names the other, "may hold a change that another device of yours made" and "To read" name the relay not read, and "This change is made without reading" comes before "Make this change?"; with every relay read, none of these is said.

## 5. Sentences of other records that change

**The record of 2026-10-04.**

- **Property 5, its limit** (section 1). After "... until the two are settled (section 9).", add: "A second limit is a change made after a fetch that did not read every relay (7.1, step 1): it can be made apart from a change held only at a relay not read, and until the two are settled, a device removed by that change is listed in the new one, and reads what is written under it."
- **7.1, step 1.** "It says what it could not fetch." becomes: "It names each relay that it could not read, and why. A change made after such a fetch can be made apart from a change that a relay not read holds, and until the two are settled a device removed by that change is listed in this one, and reads what is written under it: the command says so before its questions (decision 2026-10-24, rules 8 and 9)."

**The record of reach.**

- **§3, the row of `person_cmd.rs:2295`.** "Stays (said only of a relay that is connected)" becomes "Its words stay; the relay is named as configured (decision 2026-10-24, rule 2)".
- **§5, `<since>`.** Its two phrases become the four of decision 2026-10-24, rule 6. The sentence "So a relay reached before a change, and not since, 'has not answered since' the change" becomes "So a relay reached before a change, and not since, 'has not answered since the change at <when>', and says when it was last reached."
- **§5, S1.** One sentence is added at its end: "Each line below starts with the time it was said, in UTC." (decision 2026-10-24, rule 3).
- **§5, S2, S8 (OUT and lacking), D4 and T2.** Each becomes its words in decision 2026-10-24, rule 7.
- **§5, the line.** Its first form gains the forms "memory: a relay out of reach, not known to hold the latest change", "memory: <n> relays out of reach, not known to hold the latest change" and "memory: <n> relays not known to hold the latest change, <k> out of reach".
- **Rule 11.** After "For a relay that is out of reach and holds the change, while another relay is reached: the warning of the ruling.", add: "It is never said of a relay that lacks the change: that relay is counted by the line above, which says that it is out of reach (decision 2026-10-24, rule 7)."

**`docs/specs/channels-api.md:1120`** (`POST /api/v1/change/prepare`). "and what it could not fetch" becomes "each relay it could not read, by its configured name, with why, and whether the sync cycle went to its end".

## 6. Set aside, and why

- **Times in the person's own zone.** Every other time the node shows is UTC (the record of reach, §1). Two zones on one screen would be worse than one.
- **Naming relay2 in the status line.** A relay is named by its address in a configuration, and the line is shown on a bar and read by programs. `cordelia status` and `cordelia devices` name it.
- **Holding a change back until every relay is read.** A removal must never wait on a relay (the record of 2026-10-04, 7.1, step 1). The person is told, and the yes is where to stop.
- **A new word for the answer to "Type \`stays\` or \`removed\`".** It was not found hard to follow, and changing it changes every test that makes a change. It can follow.
- **A date in words ("8 October")**, as the person wrote it. Every other date the commands show is written 2026-10-08.

## 7. What it costs

- One field in the look of each relay (`reference_by`), and one in what the status reads (`out_of_reach`).
- A note by pass and by relay of whether the personal channel was read to its end, in memory, and a list in place of strings in `change_prepare`'s answer. The command and the node of one version only work together (the record of 2026-10-04, 10.1, rule 6), so no older reader is broken.
- One line a minute in a wait where nothing moves.
- The tests of section 4.
