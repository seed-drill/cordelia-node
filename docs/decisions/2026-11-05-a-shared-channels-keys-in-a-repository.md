# Decision: a shared channel's keys in a repository

**Date**: 2026-11-05
**Status**: Proposed. Not built: after R1. Revised twice after its reviews (section 10). It needs the fix of #291 to `shared anew` first.
**Cited as**: "decision 2026-11-05 (members), rule 3". The numbers do not change.

Words used throughout:

- **The shared channels record** is [`2026-10-10-a-shared-channel-for-messages.md`](2026-10-10-a-shared-channel-for-messages.md). Its sections are cited "§7 there".
- **A member** is a device that holds the shared channel. **The person** is the one who runs the command, at a terminal.
- **The list** is the file of rule 1.
- **In the channel**, for a key, means: in this device's table of the channel's keys (§6.3 there), whether held or refused for room, or sealed to by an offer into the channel that has not moved yet (§7 there). Today `shared anew` lists and asks about only the first kind; #291 has it list the second too, and this record rests on that.
- **Main** is commit 2007aee6 (`v0.2.0-alpha.18`). Examples say laptop and desktop, and `github.com/example/project`.

---

## 0. What this is, in one page

The person asked, on 5 November, for the way a team joins a shared channel: anyone raises a pull request against a repository to have their keys added, and once it is merged they are in. The shared channels record put this off to a later record (§14 there, item 16, S17). This is that record, in the simplest form that sits on what `v0.2.0-alpha.18` already has.

- **The list is a file in the repository,** `.cordelia/members`: one line for each device, its key and a label.
- **Joining is a pull request** that adds your lines. **Merging it is the yes.** Whoever can merge to that branch decides who is in: the repository's own rules (required review, CODEOWNERS on `.cordelia/`) are the channel's.
- **A member carries the list out with one command,** at a terminal, in a clone: `cordelia shared members <name>`.
  - It fetches the list.
  - It makes the channel anew without each key the list dropped, as `cordelia shared anew` does.
  - It then hands the channel to each key the list added, as `cordelia share` does.
  - Each of the two acts has its own yes.
  - Nothing changes on the wire, at a relay, or in what a reader shows.
- **For a key the list names, the list takes the place of the six-word check** of `share` (§3.2 there).
- **Nothing happens by itself.** The node never reads a repository. A change to the list takes effect when a member runs the command.

Until it is built, the same flow works by hand: a pull request adds the lines, and once it is merged a member runs `cordelia share <name> <key>` for each new key.

---

## 1. The file

```
# The devices whose agents share this repository's channel.
cordelia_pk1...   alice-laptop
cordelia_pk1...   alice-desktop
cordelia_pk1...   bob-laptop
```

- **Its place:** `.cordelia/members`, at the root of the repository.
- **Its form:** ASCII and line feeds only, at most 16 KiB. A line that starts with `#`, and an empty line, are skipped.
  - One line for each device: its key as `cordelia id` prints it, one or more spaces, and a label of 1 to 32 characters of `a-z`, `0-9`, `.`, `_` and `-`.
- **Keys are unique, and so are labels.**
- **At most 64 keys,** less the person's own devices that the list does not name, since those always stay (`SHARED_MAX_KEYS`, §7 there).
- **A file that does not parse does nothing:** the command names the line and stops.
- **List every device you have,** not one for each person and not only those that write. Every device of yours holds your shared channels and writes in each (§3.4 there). A device of yours left off the list is one the command would leave out, and it would come back through your other devices.
- **A label is for people reading the file.** The command shows it, and stores nothing of it. It should not name a machine: a list may be public, and a host name is a detail people keep to themselves.

## 2. The channel's repository

- **At each run, the person types the repository and branch** that the channel follows: `host/owner/name branch`. Nothing is suggested, and nothing is kept.
- **So the wrong clone, a fork, or the wrong channel name cannot hand a channel to the wrong keys, or leave a team out,** unless the person types the wrong repository.
- **Why it is typed each time, and not kept:** a kept binding needs a new table, and has to follow the channel through each making anew and each move, on every device. Typing it keeps nothing, and a repository that is renamed or moved is just typed anew. The command runs only when the list changes.

## 3. Reading the list

- **The command fetches the branch,** from a remote of the clone whose address is the channel's repository, as `git fetch --no-tags --no-recurse-submodules <remote> <branch>`. It runs `git` with no pager, no replaced objects, `core.hooksPath=/dev/null`, `gc.auto=0` and `maintenance.auto=false`, and with git's own prompts off. ssh may still ask for a passphrase or a host key: the command runs at a terminal, so it may. The command stops git after two minutes. If it cannot fetch, it stops and says why. So the list is the branch as it is now, not as the clone last saw it.
- **A remote's address** is read in one of four forms: `https://<host>/<owner>/<name>`, `ssh://git@<host>/<owner>/<name>`, `ssh://<host>/<owner>/<name>` or `git@<host>:<owner>/<name>`, with or without `.git`. It compares `host/owner/name` in lower case. No remote with that address: the command stops and says so. Two with it: either serves.
- **It reads the file from the commit it fetched** (`FETCH_HEAD`), with `git cat-file blob`. It never reads the working tree, a local branch, a remote branch or `HEAD`.
- **It shows that commit:** its hash, its date and its subject, with anything but plain printable text taken out.

## 4. What the command does

```
alice@laptop$ cd ~/Work/project
alice@laptop$ cordelia shared members design-review
```

It runs at a terminal, for a shared channel the person holds under that name. `--repo <folder>` names the clone where it is not the folder it runs in.

1. **It refuses a channel that is paused or not clean,** as `share` does (§5.5 there): `Move to the new channel first: cordelia shared move <name>.`
2. **It reads the list** by rule 3.
3. **It leaves alone** the person's own devices, and keys the person's statement lists as removed. Neither is handed the channel nor asked about.
4. **To leave out:** each key in the channel that the list does not name.
   - Where there is any, it shows them, each with the first words of its key and its six words.
   - It shows the repository and the commit, and asks the first yes: `This makes "<name>" anew without these keys.`
   - After it, it makes the channel anew as `shared anew` does. Every listed key in the channel stays, with the person's own devices, those not moved yet among them (#291). The answers come from the list, not typed key by key, and the keys asked about are checked again at the yes, as `shared anew` checks them.
   - **A making anew comes first,** so that what is handed over next is the new channel. A no makes nothing anew, and the command goes on to step 5: a device left off the list by mistake is not forced out by an addition.
5. **To hand it to:** each listed key that is not in the channel, and not a key that an offer this device made, or moved by, left out (rule 5). It lists each key it skips for that reason, with `hand it by hand, with cordelia share, if it should be back`.
   - It hands over at most 8 in one run (`MAX_TYPED_KEYS`: a device keeps no more shares waiting). It says how many are left for the next run, and checks this before its yes.
   - It shows them, each with its label from the list, the first words of its key and its six words.
   - It shows the commit, and says: `These keys come from <host/owner/name>, branch <branch>, at <commit>. Whoever can merge to that branch decides who is in.`
   - Where the person said no at step 4, it says: `The keys the list dropped still read what is written there.`
   - It asks the second yes, then hands the channel to each, as `share` does. Nobody reads six words to anyone: the list is the check.
   - It prints the line each new member runs: `cordelia accept <this device's key> --channel <name>`, within the hour.
6. **It deletes this device's waiting shares** of the channel to keys the list does not name. That is a small new function: today a share is only ever written over.
7. **Where there is nothing to do,** it says so and asks nothing.

**Two members who run it at the same moment** each make an offer, and the channel can split, as two runs of `shared anew` can (§7 there). One run is enough: a team agrees who runs it.

## 5. Joining, and leaving

- **Joining.** The new member runs `cordelia id` on each device they have, and raises a pull request that adds a line for each. Once it is merged, a member runs the command, and gives the new member the `accept` line it printed. The new member runs it within the hour, on the device named. `accept` checks that the share is signed by the key typed (§3.2 there), and the file is where the key came from.
- **Leaving.** A pull request deletes the lines. Once it is merged, a member runs the command, and the channel is made anew without them. Until a member does, they still read and write.
- **Removing one of your own devices** from your devices (`cordelia remove-device`) makes each shared channel anew without it (§3.5 there). Delete its line from the list too, in a pull request. While the line stays, members whose devices did not read that offer could hand the channel back to it.
- **A key that an offer this device made, or moved by, left out is not handed the channel from the list.** The device works this out from the old channel's table less the keys the offer was sealed to, while it still holds the old channel. Bringing such a key back is by hand, with `share` and the six words.
- **One device of a person who stays cannot be left out this way.** That person's other devices hold the new channel, and share it with their own devices (§7 there). The device goes when that person removes it from their own devices.

## 6. What it does not do, and what comes later

- **The node does not read the list by itself.** The first design (1 October) had the node carry the list out on its own, with an hour's wait before a new key got in, and a record in the channel of who let whom in. That waits until this is in use.
- **No labels from the list.** A label is the person's act, counts across all their channels, and has no field for where it came from (§2.4 there). A person labels a key by hand.
- **`accept` does not read the list.** Later, `accept --channel <name>` could take a share from any key the list names.
- **`subscribe` does not print this device's line.**
- **One list for each repository.** Later, `.cordelia/channels/<name>` could hold a narrower list, with its own rules on who may change it.
- **A channel stays flat.** A member can still hand it by hand to a key the list does not name. The next run of the command by any member makes it anew without that key.

## 7. Who can do what

- **Whoever can merge to the branch** admits any key, and removes any. That is the point: the repository decides. A stolen account with merge rights is the same.
- **The host** decides what the branch is.
- **A program that runs as a member** can change the clone's remotes and so what is fetched. It can already run `share` with a yes (the README's security section). The commit shown is the person's check.
- **A list in a public repository** shows its keys and labels. It does not let anyone read the channel: that still needs a member to hand it over.

## 8. Tests, when it is built

- The repository and branch are typed at each run: a clone with no remote of that address gives no list, and a fork's remote is not read.
- The list is read only from the commit fetched: an edit in the working tree, a local branch or a fork's remote is not read. No fetch, no list.
- An address of another form, or no remote with the address: the command stops, and says why. A fetch that does not end in two minutes is stopped.
- A file over 16 KiB, over the bound of keys, with a key or label twice, or a line that does not parse: nothing is done, and the line is named.
- A list that drops one key and adds another: the channel is made anew first, and the new channel is handed to the new key. The new key's `accept` takes the new channel.
- An addition alone makes nothing anew. The person's own devices, listed or not, are neither left out nor handed it.
- A key that an offer this device made or moved by left out is not handed back, and is listed with `hand it by hand`. A key sealed to by an offer into the channel that has not moved yet is not handed it again.
- Nine new keys: eight are handed it, and the command says one is left for the next run.
- A paused or unclean channel is refused. Each yes names what it does, nothing happens without it, and the command refuses without a terminal.

## 9. Questions for the person

1. **Is the file's name right?** `.cordelia/members`, one for each repository, as the first design had it.

## 10. The reviews, and what changed

The first review, of the first draft (commit 9e98fd04), found two high findings, six medium and seven low. Each was checked in the code before it was taken.

| # | Finding | What changed |
|---|---|---|
| H1 | The channel was handed over and then made anew, so the new keys got the old channel, and `drop_old_shares` deleted their shares | The making anew comes first (rule 4, step 4), and the new channel is handed over |
| H2 | A device left off the list made every change a making anew; one yes forced it on an addition | List every device you have (rule 1); two yeses, and an addition alone makes nothing anew (rule 4) |
| M1 | The rule for a clone that is behind compared the commit's date, which the committer sets, and kept an unlisted key in after a hand-over by hand | The command fetches the branch first (rule 3); the date rule is gone |
| M2 | A device knows only partly who an offer left out; a removed device of another person could be handed it back | A key that an offer this device knows of left out is not handed it from the list; removing your device also needs a PR (rule 5) |
| M3 | "Not in the table" took in keys sealed to by an offer that had not moved yet | "In the channel" counts keys sealed to by an offer into it (the words at the head) |
| M4 | A device keeps at most 8 shares waiting; a ninth failed halfway | At most 8 in one run, checked before the yes (rule 4, step 5) |
| M5 | A paused channel, or two runs at once, made a second offer | A paused or unclean channel is refused; two runs at once are named (rule 4) |
| M6 | Nothing tied a channel to a repository: a fork's file, the wrong clone or the wrong name could leave a team out | The person types the repository at the first run, and the device keeps it (rule 2) |
| L1 | Labels count across all channels, and hold nothing of where they came from | Labels from the list are cut (section 6) |
| L2 | Own unlisted devices could push the stays past 64 | They count in the list's bound (rule 1) |
| L3 | A listed removed key or own device made the whole making anew refuse | Both are left alone (rule 4, step 3); the keys asked about are checked at the yes |
| L4 | `git show` runs textconv; the subject was shown raw; `refs/remotes/<r>/HEAD` is not always there | `git cat-file blob`, a cleaned subject, and the branch from rule 2 |
| L5 | The new member must know which key to type, and act within the hour | The command prints the `accept` line (rule 4, step 5) |
| L6 | The rule for a clone that is behind missed keys refused for room | The rule is gone (M1), and "in the channel" counts refused keys |
| L7 | Waiting shares to keys the list dropped stayed | The command deletes them (rule 4, step 6) |

The second review, of commit 2d48676f, found H1 and H2 closed in the code (the new channel is held at once after the making anew, so it can be handed over in the same run). It found one high, one medium and five low:

| # | Finding | What changed |
|---|---|---|
| H1 | A key sealed to by an offer and not moved yet is "in the channel", but `shared anew` cannot keep it: it lists only the table. The gap is on main too | Filed as #291, which has `shared anew` list and ask about such keys; this record needs it first (status, and the words at the head) |
| M1 | A kept binding needs a new table, and must follow the channel through each making anew and move, and be cleared; nothing could change it | The repository and branch are typed at each run, and nothing is kept (rule 2) |
| L1 | After a no at the first yes, the second did not say the dropped keys still read; the first yes did not show the commit | Both said (rule 4, steps 4 and 5) |
| L2 | "No prompt" cannot be promised over ssh; git has no time limit; the settings were not named; a single-branch clone may not update the remote branch | The settings named; ssh may ask; git stopped after two minutes; the commit read from `FETCH_HEAD`; two remotes of one address, either serves (rule 3) |
| L3 | "An offer this device knows of" was too wide, and not built | Offers this device made, or moved by; how it is worked out; skipped keys are listed (rules 4 and 5) |
| L4 | The file's `repository` and `branch` lines only repeated what is typed | Cut (rule 1) |
| L5 | Deleting one waiting share is not built | Said to be new (rule 4, step 6) |
