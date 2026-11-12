# Decision: plain words in the command line

**Date**: 2026-11-11
**Status**: Proposed. The owner asked for plain words, and chose "reset", on 11 November; on 12 November, that `label` stays. Revised after a review on 12 November. Section 3's recovery questions wait for the owner. Not built: the slices of section 6 build it.
**Cited as**: "decision 2026-11-11 (plain words), rule 3".

## 0. Why

The owner, after clearing the warning `Shared: 1 shared channel not made anew since a removal: make each anew once with cordelia shared anew <name>`: "the language we use is very hard to understand still ... It feels like it could be much simpler".

The cause: the records' own terms leaked into what a person reads. Key, labelled, made anew, applied change 4, holds, sealed, a removal, the six or four words: each is exact in a record, and hard at a prompt. The "say less" pass (#338) cut how much is said. This pass changes the words.

## 1. The rules

**Rule 1. Use everyday words a person already knows.** Device, not key. The name you gave it, not its label. Up to date, not "applied change 4". Reset, not made anew. Section 2 gives each word.

**Rule 2. Name the thing.** Say the channel and the device by their names ("old laptop"), not by a count. Where a line would count several, name a few, then "and 3 more". "Name" means three things here (a device's, a channel's, a memory name): for a device, say "the name you gave it".

**Rule 3. Say what is wrong in plain terms, then give one command.** For example: `design-review: old laptop can still read new messages there. To stop that: cordelia shared reset design-review`.

**Rule 4. Fingerprint words, change numbers, relays' addresses and counts show only with `-v`, but where a person checks them or chooses by them.** The words stay:

- in the six-word check before you trust a device;
- wherever you decide about a device: `remove-device`, `renew`, `settle`, `recover`, `sync carry --from`, and each question about a device added since. A name can be forged, and the words are the check;
- where two devices, or two channels, have one name;
- where they are a thing's only name: a device with no name from you, and a relay's address in a line that warns of that relay.

Only the list in `cordelia devices` shows the name alone. Where one line tells you to check a number or words, the line it points to shows them. A command that moves a fact behind `-v` gets a `-v`: `devices`, `add-device`, `accept`, `remove-device`, `renew`, `settle`, `recover`, `sync carry`, `share`, `shared reset`, `shared move` and `label`.

**Rule 5. A question asks about one named thing, and a habitual yes never does the unsafe thing.** `Keep "old laptop" in design-review? Type keep or out.` The answer names the act, so a reflex "yes" keeps no one (threat model T23). Where yes or no is safe, the question asks yes or no. No answer is suggested.

**Rule 6. Nothing a person must know is lost.** A limit (a reader you cannot see), a risk, or what a yes does stays. If plain words would hide a fact, keep the fact and say it simply.

## 2. The glossary

The old term may stay in code, in the records' rule text, in `--json` field names and machine values, and in the node's log. It goes from every line a person reads.

| Old | Plain |
|---|---|
| key (a device) | device; the string `cordelia id` prints is the device ID |
| label, labelled, no label of yours | the name you gave it, named by you, no name from you |
| make anew, made anew | reset; it makes the new channel |
| not clean | not reset since you removed (the device) |
| has applied change N, has sent what it held | up to date |
| change N, the last change | the last change to your devices; its number: rule 4 |
| holds, held (a device or relay) | has, keeps |
| held up (the node) | the node cannot go on: (why) |
| a hold (of agents) | your agents wait for you; paused |
| sealed to | is for (those devices) |
| a removal, since a removal | removing (the device), since you removed (the device) |
| six words, four words | fingerprint words: rule 4 |
| the phrase's words | the recovery phrase fingerprint |
| hand, hands over, handed | share, send |
| taken, nothing was taken | received, copied in, nothing (more) was copied in |
| carry, carried | copy over; name `sync carry` where it is the command to run |
| follows (a phrase) | is under (a recovery phrase); never "has": no device stores the phrase |
| follows (a change) | is on |
| made apart | made separately, neither knowing of the other |
| set aside | put aside |
| past a bound | pushed off your list of 16 shared channels |
| generation | before the change of (its date) |
| let go | removed from this device |
| cleared (a notice) | marked seen |
| statement, slot, revision, chain, change entry, the personal channel, the look, a word (of a device, of the phrase) | never shown; say what it means for you |

A relay's key in the configuration stays "key": it is the setting's name. So do `--new-key` and "wrong key".

## 3. The renames

- **`cordelia shared anew` becomes `cordelia shared reset`.** `anew` stays as a hidden alias until the oldest version still in use prints `reset`. The local API's route (`/api/v1/shared/anew`) does not change.
- **The typed answers `keep`, `out` and `out for the rest` stay** (rule 5). Only the question around them changes.
- **`label` stays `label`** (the owner, 12 November). No other command or flag is renamed.
- **Proposed, for the owner's word: `recover` asks two questions of each device in place of `have`, `lost` or `hands`.** First `Could someone else have "laptop" now? If you are not sure, type yes.` Yes is `hands`: it is removed, and nothing it wrote comes back now (`sync carry --from` can copy it in later, and says what that means). If no: `Do you still have "laptop"?` Yes is `have`, no is `lost`. Asked in this order, a reflex yes takes the safe side (rule 5). Both `lost` and `hands` remove the device; the answer decides whether what it wrote comes back (decision 2026-10-04 §9). The three old answers still work as aliases.

## 4. How the records change

Records' wording is checked by tests (CLAUDE.md, engineering rule 5). **When a line changes, the record's quoted line changes in the same commit,** and so does each test that quotes it. The rule text around the quote may keep its old terms. A record that quotes a line no test checks changes too, so that it stays true. Each record that changes adds to its Status line: "Its quoted lines amended by decision 2026-11-11 (plain words)." README, TESTING and the threat model change in the same slice where they quote a changed line. So do what quotes the words outside this repository: the panels (such as "holds the latest change" and "This device's key"), the site, and the Claude skill (such as "give the person the key" and "held up").

## 5. `--json`

**Field names do not change:** the panels read them. Machine values do not change either (`what`, `state`, `level`, `stands`). Only the words a person reads change, among them the values of `summary`, `says` and `short`. Slice 0 adds the fields that lines need to name a thing, such as the name alone of a removed device; no field is removed or renamed.

## 6. The slices

Most-seen first, after slice 0. Each slice is one pull request, with its records, tests and docs. The inventory of lines, kept outside the repository, is the working list.

0. **The rename, its alias, and the new fields,** since later slices print `shared reset` and name things.
1. **The status and its warnings,** with every relay line, so that it agrees with `devices`.
2. **Devices:** (a) `devices`, `add-device`, `accept`, `remove-device`, `renew`, `settle` and `phrase`; (b) `recover`; (c) `sync carry`, with the unmap and history lines on copying over.
3. **Sharing:** `shared list`, `share`, `accept --channel`, `shared reset`, `move`, `stay`, `seen`, `label`, `subscribe` and `.cordelia/members`.
4. **Messages:** `msg send`, `read`, `summary` and their refusals.
5. **Setup and help text:** `init`, `start`, `sync map`, `unmap` and `status`, `history`, `restore`, and every `--help`.

## 7. What does not change

What a command does, and what it asks a yes for; how loud a failure is (#338); the six-word check; the wire, the schema, the log, and code names.

## 8. The test that holds it

`the_plain_lines_use_no_old_words` reads the literals a person reads, as the inventory's parser did (no tests, no log, no `--json` names), and renders the main screens without `-v`. It fails on: anew, labelled, applied change, holds, held, sealed, a removal, made apart, set aside, follows, handed, the look, statement, generation, and a device's "key". An allowlist names each line that keeps a word for a reason: a relay's key, `--new-key`, "wrong key", and rule 4's words.
