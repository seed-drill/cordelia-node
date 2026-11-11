# Decision: joining a repository's shared channel by pull request

**Date**: 2026-11-06
**Status**: Accepted on 6 November, and built for `v0.2.0-alpha.19`. Amended by the person's rulings of 7, 8, 10 and 11 November (section 14); the last two (rule 4.5, and the one line of rule 7) come after alpha.19. It replaces the members record's command, and overturns property 16 of the shared channels record (section 7).
**Cited as**: "decision 2026-11-06 (joining), rule 4". The numbers do not change.

Words used throughout:

- **The shared channels record** is [`2026-10-10-a-shared-channel-for-messages.md`](2026-10-10-a-shared-channel-for-messages.md), cited "§7 there".
- **The members record** is [`2026-11-05-a-shared-channels-keys-in-a-repository.md`](2026-11-05-a-shared-channels-keys-in-a-repository.md). This record keeps the idea of its file, adds one line to it, and replaces its command: `cordelia shared members` is not built.
- **The list** is a repository's `.cordelia/members`. **A repository channel** is the shared channel that a list names.
- **A member** is a device that holds the channel. **In the channel**, for a key, means: in this device's table of the channel's keys, or not moved yet (#291).
- **A read** is one reading of the list by a device that follows the repository (rule 3).
- Examples say laptop and desktop, Alice and Bob, and `github.com/example/project`.

---

## 0. What this is, in one page

The person's rule: **a merged pull request is the whole join.** No `share`, no `accept`, no hour to hit, and no wait that does not say what it waits for.

**The list names the channel and its members:**
```
channel 9f2c...e41a cordelia_pk1... cordelia_pk1... without 0
cordelia_pk1...   alice-laptop
cordelia_pk1...   bob-laptop
```

**What a person does:**
- **To start a team's channel, once:** `cordelia subscribe --new` in a clone. It makes the channel and prints the `channel` line. A pull request adds that line and the maker's devices.
- **To join:** a pull request that adds a line for each of your devices. Once it is merged, run `git pull` (or `git fetch`) in your clone, then `cordelia subscribe` there, once, and type yes.

**What the nodes then do, with no one asked.** Each device that follows the repository reads the list every ten minutes.
- A member's node hands the named channel to each listed key that is not in it.
- The new member's node takes the named channel from any listed key.
- Each key new on the list shows on every follower's status, with its label and commit, until a person clears it.

**Leaving stays by hand for now.** A member runs `cordelia shared anew <name>`, which leaves the keys out and prints the new channel line. It names after `without` only the keys that the list still names. So run it before the pull request that deletes their lines, and the line names them. Run after that pull request, its line does not name a key whose line is already gone. That is safe: a key that is not listed is never handed the channel, and if a later pull request lists it again, the device that made it anew shows amber (rule 5). A pull request then puts the new line in the list. Until it is merged, nobody hands anything over, and nobody ever hands the new channel to a key the line names after `without`.

**Nothing new on the wire or at a relay.** A hand-over is today's share, and a take is today's `accept --channel`, each run by the node in place of a person.

---

## 1. The list

- **Its place:** `.cordelia/members`, at the root of the repository, on its default branch.
- **Its form:** ASCII and line feeds only, at most 16 KiB. `#` lines and empty lines are skipped.
- **One `channel` line:** `channel`, the channel's ID in hex, then the key of each of its relays, one or two (a card's relays, §8 there). It always ends with `without`, the number of keys that follow, and those keys: the keys a making anew left out (rule 5), or `without 0` for a new channel. A line whose number does not match its keys does not parse, so a line cut short does nothing. These keys do not count among the list's 64. A list without a `channel` line names members and no channel: followers wait, and say so.
- **A list that names a key as a member, and after `without`, while that key is not in the channel, names no channel for now.** Followers hand over nothing, and show rule 4.7's line, until that key's line is deleted, or until the key writes in the channel, as a device of a person who stays does when it is next on. So a key left out cannot stay listed. Bringing it back is a pull request that adds its line and takes it off `without`. The device brought back first renames the old channel it still holds, with `cordelia shared rename`: it files that channel under the repository's name, so it takes nothing under that name until then, and its status says so. A device that does not hold the channel cannot see who is in it, so the gate binds only those who hand over; a joiner still takes nothing while its own key is after `without`.
- **Then one line for each device:** its key as `cordelia id` prints it, then a label of 1 to 32 characters of `a-z`, `0-9`, `.`, `_` and `-`.
- **Keys are unique, and so are labels.**
- **At most 64 keys.** A channel that would hold more says so where it is handed over (`channel_full`).
- **A file that does not parse does nothing:** the last list read stands, and the status names the line.
- **List every device you have.** Every device of yours holds your shared channels and writes in each (§3.4 there).

## 2. Following a repository: `cordelia subscribe` in a clone

```
bob@laptop$ cd ~/Work/project
bob@laptop$ git pull
bob@laptop$ cordelia subscribe
```

**With no name, in a folder of a git repository, `subscribe` follows that repository.** It needs a terminal and one yes. The folder must be mapped, as for any agent: otherwise it says to run `cordelia sync map .`, and does nothing. It reads the list from the clone's own copy of the default branch, as the person's git last fetched it (rule 3). So a joiner runs `git pull`, or `git fetch`, in the clone once the pull request is merged, and then `subscribe`: before that fetch, the list it reads does not name the joiner's key, and it is refused (rule 2.3).

1. **The repository's identity** is `host/owner/name`, in lower case, from a remote of the clone. The remote's address must have one of four forms:
   - `https://<host>/<owner>/<name>`
   - `ssh://git@<host>/<owner>/<name>`
   - `ssh://<host>/<owner>/<name>`
   - `git@<host>:<owner>/<name>`

   With or without `.git`; nothing else, and no port.
   - With one such remote, it is the one.
   - With several that differ (a fork's `origin` and the repository's `upstream`), `--remote <name>` chooses. Without it, the command names them and does nothing.
   - The host must be reachable as HTTPS. An SSH alias such as `github.com-work` is refused, with a line that says why.
2. **It reads the list** by rule 3, and shows, in one line with what it does:
   - the identity and the commit, with the clone and its remote;
   - the channel the list names;
   - whether this device's key is on the list.

   **Its yes is two lines:** what it makes or follows, and who reads it. The commit shows by its first twelve characters, as in the status (rule 7), and the yes binds the clone, the remote and those characters. For a device that waits to be handed the channel:

   ```
   This follows <identity> from your clone at <clone> (<remote>, commit <commit>), whose list names channel <four words>, which you do not hold, and your key as <label>. A member's device hands it to you once it reads the list, and <agent> is subscribed to it then.
   Who reads it: each device on the list. Anyone in it can hand it on, and a device that only reads shows nowhere.
   ```

   The first line of each other case:
   - holding the channel: `This subscribes <agent> to "<name>", which you hold, and follows <identity> from your clone at <clone> (<remote>, commit <commit>), whose list names it, and your key as <label>.`; where the agent subscribes already, `This follows ... whose list names "<name>", which you hold, and your key as <label>. <agent> subscribes to "<name>" already.`;
   - a list that names no channel yet: `This follows ... whose list names no channel yet, and your key as <label>. A member's device hands you its channel once the list names one, and <agent> is subscribed to it then.`;
   - a key that the gate of rule 1 holds back: `This follows ... which you do not hold, and your key as <label>. <agent> is subscribed to it once this device takes it.`;
   - holding the channel the named one was made anew from (rule 6): `This follows ... which you do not hold, and your key as <label>.`, then `Run cordelia shared move <name>: the list names the channel it was made anew as.`, and no second line, as `shared move` asks its own yes.

   A key that is not on the list is said `but not your key` in place of `and your key as <label>`. Between the two lines it says only what holds: `This device follows <identity> already, from <clone> at <commit>.`; `Your clone is at <commit>, which does not come after it: you would read an older or another list.` (rule 3); the follow it stops (rule 2.5); and each key the gate holds back, `<label> is on the list of <name> but was left out of it: nothing is handed over until its line goes, or it writes in the channel.`

   **Made terser on 11 November 2026, on the person's ruling (issue #338).** The yes was five to ten lines: where it read the list, the channel, the key, what it would do, and for `--new` the whole yes of `shared new`. `cordelia status shows how it goes` is said after the yes, and not in it.
3. **Then one of these:**
   - **The person holds the channel the list names:** it follows the repository and subscribes this folder's agent.
   - **They do not, and the list names this device:** it follows the repository and waits to be handed the channel (rule 4), with the yes of rule 2.2. No yes is asked when it is taken, so its second line is where the person is told who else can read it (11 November 2026, issue #338).
   - **The list does not name this device:** `Your key is not on the list of <identity> at <commit>. Add it with a pull request, then run this again.` Nothing is done.
   - **The person dropped that channel:** it says so and does nothing, as `accept --channel` refuses today (§3.4 there): `You dropped channel <words>, and a dropped channel is not taken again.` A drop keeps no name, so the channel is said by its four words.
4. **`cordelia subscribe --new`** makes the channel for the team, once, at the person's relays, as `shared new` does. It is filed under the repository's `owner/name`. Its yes is two lines (made terser on 11 November 2026, issue #338):

   ```
   This makes the shared channel "<owner/name>" at <relay>, subscribes <agent> to it, and follows <identity> from your clone at <clone> (<remote>, commit <commit>), whose list names no channel yet, and your key as <label>.
   Who reads it: your devices now, and each device on the list once your pull request is merged. Anyone in it can hand it on, and a device that only reads shows nowhere.
   ```

   After the yes it prints the line to add, and the person's own keys and labels:

   ```
   Add these lines to .cordelia/members in a pull request:
   channel 9f2c...e41a cordelia_pk1... without 0
   cordelia_pk1...   <label>
   ```

   It is refused where the list names a channel already.
5. **What the device keeps** is a row of its own: the identity, the clone's path, the last commit read, and the keys that read named. It is keyed by the identity, not by a channel's name. Running `subscribe` again, with a yes that names the commit, starts the row afresh, for a history that was rewritten. The list says which channel the repository's is, so a rename, a making anew or a move changes nothing in the row. `shared drop` of the channel the list names stops the follow. So does `cordelia unsubscribe` with no name, in a clone, with no yes: `This device follows <identity> no more.` It unsubscribes no agent and drops no channel, and `subscribe` there follows again. A device that leaves its person deletes every row. **A channel follows one repository.** Subscribing in a clone of another repository whose list names that channel replaces the follow, with a yes that says so: `This stops following <identity>, whose list names <name> too: a channel follows one repository.` A read of a list that names another follow's channel counts for nothing, and the last list stands.
6. **One device of the person's that follows is enough.** Every follower, of every person, does the work of rule 4 for the team. Each device of yours that should read the list for you runs `subscribe` in a clone once.
7. **A device follows 16 repositories at most,** as many as the shared channels it can hold (`SHARED_MAX_CHANNELS`). `subscribe` refuses one more: `This device follows 16 repositories, the most it can. To follow another, first run cordelia unsubscribe in a clone of one it follows. Nothing was done.`

## 3. Reading the list

**The node reads the clone's own copy of the default branch, and nothing else.** No git command of the node's reaches the network (the person, 7 November).

- **From the clone, read only.** It reads `refs/remotes/<remote>/<branch>`, the default branch as the person's own git last fetched it. `<branch>` is the one that `refs/remotes/<remote>/HEAD` names, and the remote must still have an address that names the identity. Where that ref is missing, as after a default branch is renamed, the status says to run `git remote set-head <remote> --auto`. It reads the file with `git cat-file blob`, and never touches the working tree, a local branch, the clone's refs or its files.
- **When.** Every ten minutes (`MEMBERS_READ_INTERVAL_SECS`), at the node's start, and when a person follows, the node reads each clone it follows.
- **The list is as fresh as the clone,** for a public repository as for a private one. It comes from the person's own `git fetch` or `git pull`. The status says how old it is: `list of <identity> read from your clone, fetched 2 hours ago`, or that the age is not known. Where something waits on the list, the line ends with when the node next reads it: `Next read in about 2 minutes.` (#323). So does `The list has not been read yet.` So a join waits until a member's clone has the merged list: a member runs `git pull` there.
- **Nothing of the person's reaches git, so nothing can ask.** Every git command the node runs, reads of the clone included, runs in a cleared environment:
  - only `PATH` is kept, and the variables of a proxy and of a company's own certificate authority (`HTTPS_PROXY`, `https_proxy`, `NO_PROXY`, `no_proxy`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `GIT_SSL_CAINFO`), which never ask;
  - `HOME` and `XDG_CONFIG_HOME` are an empty folder of the node's, so no global setting is read, on any version of git;
  - `GIT_CONFIG_NOSYSTEM=1`, and `-c credential.helper=`, which empties the list a clone's own configuration may set;
  - `GIT_ALLOW_PROTOCOL=https`, so nothing goes over SSH and no agent is asked;
  - `GIT_NO_LAZY_FETCH=1`, so a read of a partial clone never fetches, and a partial clone is not read with a git older than 2.44, which ignores it;
  - `GIT_NO_REPLACE_OBJECTS=1` and `GIT_GRAFT_FILE=/dev/null`, so a replace ref or a graft in the clone cannot swap the list or fake never-back;
  - `GIT_TERMINAL_PROMPT=0` and an empty `GIT_ASKPASS`, with `SSH_ASKPASS` gone with the rest;
  - `http.followRedirects=false`;
  - hooks, `gc` and maintenance are off;
  - `-c safe.directory=<clone>` for a read of the clone;
  - git is stopped by TERM at its deadline (`STREAM_TIMEOUT_SECS` for a read, twice that for all of `subscribe`'s), and killed `MEMBERS_GIT_TERM_SECS` later.
- **What the clone holds stands.** A program that runs as the person can change it (rule 10).
- **A read of the clone never goes back.** It counts only where the clone's commit is the last commit read, or comes after it: `git merge-base --is-ancestor`, run in the clone. A clone left behind gives no new list, and the status says so. The last commit read is kept in the row, so a restart does not forget it.

## 4. What a node does with the list

At each read, each device that follows the repository does the following, with no one asked.

1. **It hands over only the channel the list names, and only where it holds that channel and writes there:** not paused, clean, and not moved from (§7 there). Where any of these fails, it hands over nothing, and says why (rule 6). When it takes is rule 4.4.
   - **It hands over nothing in a channel in which it has read any offer that is no fault** (§7 there): one that seals to the person, whether they then moved, stayed or are still paused, and one "without you", which leaves them out. That channel was made anew, so a device left out hands a newcomer nothing that its members are leaving. Only an offer that is a fault does not count (the person's ruling of 8 November, section 14).
2. **Hands over.** Listed keys not in the channel, not named after `without`, not the person's own devices, and not keys the person removed, are handed the channel, as `share` does. The node's shares are counted apart from the person's own, so a person's `share` by hand keeps its places. They go **four at a time, in turns:**
   - each share lives for two reads, then is deleted, and its key waits out the read at which it goes;
   - each read hands over to the next four such keys, in the list's order, starting after the last one handed;
   - so at most eight wait at once (`MAX_TYPED_KEYS`), and a device that is off for days holds no place;
   - a key that a share of any channel waits for, the person's or the node's, is passed over: a share of one channel deletes another's for the same key (`make_share`).
3. **Deletes the shares to keys the list no longer names,** whether the node made them or a person did.
4. **Takes.** A follower whose person does not hold the named channel looks for a share from each listed key, at each read.
   - It types each listed key again for that read, under a count of its own, so the person's own `accept --channel` keeps its eight places. It asks the relays once for each listed key at each read, not at every pass: 64 keys are 128 requests every ten minutes, well within what a relay allows (§8.4 there).
   - It takes only the named channel, from a listed key, once the list names this device's key as `cordelia id` prints it and its `channel` line does not name it after `without`. Rule 1's gate does not hold it back: it cannot see who is in the channel, and the members keep the gate.
   - It takes nothing while the person holds the channel the named one was made anew from: rule 6 says to move.
   - It takes only a share made within the hour of the latest read (`PAIR_KEY_TYPED_SECS`), so a share left at a relay long ago is not taken.
   - It files the channel on every device of the person's, as `accept --channel` does.
5. **Says a key is new on the list** (the person's ruling of 10 November: "by the list alone"). At each read that counts whose `channel` line names a channel, each key on the list that the list kept before did not name shows amber. Where no list was kept, or the one kept named no channel, every key on the list is new: at a first follow, at a new follow after `cordelia unsubscribe`, and at the first list with a `channel` line. The keys new at one commit share one line: `New on the list of <name> at <commit>: <label>, <label> and <n> more`. New means new to this device.
   - **Only your own devices are left out:** this device and your other devices, a twin counting as its key. A device of yours that was removed is not yours any more, so it shows where a list newly names it, or at a first follow. Its removal's own ambers cover the rest (rule 5).
   - **Nothing else counts:** not who wrote in the channel, nor when, nor whether this device holds it. So a clone that lags, and a channel made anew between two reads, hide no key. A key whose line is deleted and then added again shows again, at the commit of the read that lists it again.
   - **A read that counts for nothing shows nothing.** Following again (rule 2.5) keeps the list kept, so it shows nothing new at its yes.
   - **Each line stays until a person clears it** on that device with `cordelia shared seen <name>`, which says each line it clears. The plain status names the first six labels (`MEMBERS_LABELS_SHOWN`) and how many more; `shared list` names every label; `--json` gives the whole commit and each key, as `members` gives it.
   - **The upgrade:** a device that upgrades from `v0.2.0-alpha.19` keeps the lists it read, so a key that alpha.19 never showed is not shown now. That was the person's choice on 10 November: no catch-up amber at the upgrade. Keys listed before the upgrade still show in the status's list of members.
6. **Says a key was dropped.** A key in the channel that an earlier read named and the latest does not shows amber: `<label> is no longer on the list of <name>: make it anew with cordelia shared anew <name>`.
7. **Says a listed key was left out.** A key the list names, that its `channel` line names after `without`, and that is not in the channel, shows once, on each follower that holds the channel and so sees who is in it: `<label> is on the list of <name> but was left out of it: delete its line in a pull request, or wait for that device to write in the channel`. A follower that does not hold the channel cannot tell, and shows nothing. Until it goes, the list names no channel (rule 1). A key that is in the channel, as a device of a person who stays is (§7 there), is not shown.

## 5. Making a repository channel anew

**`cordelia shared anew <name>`, on any channel, prints the new channel line,** naming after `without` each key it left out that the list names, where this device follows the repository. A device that follows also keeps the current line's `without` keys that the list still names, so a later making anew never frees a key left out before. A device that does not follow names every key it left out, and the person may cut those that are not listed. It cannot know the current line's `without` keys: where one is still listed, the person carries it over, and the device that made the earlier making anew shows amber until it is there (below). Every making anew prints it, so no device can make a channel anew without a line that says who was left out:
```
If this channel follows a repository's list, put this line in place of its channel line, in a pull request:
channel <new ID> <relay keys> without 2 <key> <key>
```

**Until that pull request is merged, the list names the old channel, and nobody hands anything over:** a device hands over nothing in a channel in which it has read an offer that is no fault (rule 4.1), whether it moved, is paused, stayed or was left out.

**Once it is merged, the line itself says who was left out,** to every follower: one that was off, and one that joined later, included. No device has to have read the offer. While a key it names is still listed and not in the channel, the list names no channel (rule 1), so nobody is handed anything until that key's line goes. Then the key is not listed, and is never handed the channel. That holds where a member made it anew before the pull request that drops the key, and where a removal made it anew without a stolen device that is still listed.

**The device that made it anew shows the line until the list names the new channel,** amber: `<name> was made anew here: put its new channel line in .cordelia/members, in a pull request`, with the line. From then on, while a key it left out is still listed, it shows amber whenever the list's `channel` line does not name that key after `without`, at this making anew or any later one: `<label> was left out of <name>, and its channel line does not say so: add it after without, or delete its line`.
- **"Then"** is the first read of a list that this device follows whose `channel` line names the new channel, or one made anew from it, as this device knows its moves. The device keeps when that was, with the making anew.
- **That amber of a key ends only at `cordelia shared seen <name> <label>` on that device,** for a key brought back on purpose (rule 1): the making anew counts that key as left out no more, and nothing else is cleared. Otherwise it would never end. `cordelia shared seen <name>` alone does not end it, and says it is still shown: a key left out comes back in the list with a changed channel line, and clearing that notice must not clear this one, while this device hands the new channel to the key.

**Keys that cannot be named:** a key whose row the table let go, and anyone who wrote in a channel past a bound (§6.3 and §7 there). Where such a key is listed, it is handed the new channel. That errs toward the list, which decides.

**A removal** makes each shared channel anew as today (§3.5 there), and prints each new channel line, with the removed device after `without`. It keeps only the person's devices and the keys the list names, where this device follows the repository (decision 2026-10-24, rule 24). The keys a removal leaves out only for room, or because neither a list this device follows nor a label keeps them, are not named, and the list decides for them, as for keys that cannot be named. For each repository channel it shows amber until the list names the new channel: `<name> was made anew at a removal: put its new channel line in .cordelia/members`, with the line. A channel past its bound that a removal makes anew is dropped by the removal's own act (§3.5 there): on the device that made the removal, that drop counts as a move, so the follow goes on and shows the line. The person's other devices see a drop, and stop following (rule 2.5): that is rare, and `subscribe` in a clone follows again.

## 6. No silent waits

Every wait says what it waits for, in `cordelia status` and `cordelia shared list`. Each line is the word that today's command would refuse with, put plainly.

| Who | It says |
|---|---|
| A follower not on the list | `Your key is not on the list of <identity> at <commit>.` |
| A follower, the list naming no channel | `The list of <identity> names no channel yet.` |
| On the list, not yet handed it | `Waiting for a member's device to hand you <name>. Your list was read <when>. A member's device hands it over once a member's clone has the merged list: a member runs git pull there.` |
| Holding another channel of this repository, one the named channel was made anew from | `Run cordelia shared move <name>: the list names the channel it was made anew as.` |
| The list naming a channel that no device of the person's holds or can move to | amber: `The list of <identity> at <commit> names channel <words>, which no device of yours holds or can move to.` |
| The channel's relays not among the person's own | `<name> is at <relay>, which is not one of your relays: add it to your configuration.` |
| No room for one more channel, or its name taken | `You hold 16 shared channels, the most there can be`, or `You file another channel as <name>: rename it with cordelia shared rename.` |
| A member handing over | `Handing <name> to <label>: waiting for that device to take it.` |
| A member who cannot | `<name> is paused`, `not clean`, `not reached at its relays`, or `full`: `nothing is handed over until then.` |
| A member who moved | `The list names the channel you moved from. The device that made it anew shows its new channel line: put that line in .cordelia/members.` |
| An offer read in the named channel | `<name> was made anew by <label>: nothing is handed over until the list names the new channel.` |
| The gate of rule 1 | amber, rule 4.7's line, once, on a device that holds the channel: `<label> is on the list of <name> but was left out of it: delete its line in a pull request, or wait for that device to write in the channel`. Nothing is handed over until then. |
| The list, from the clone | rule 3's line, with how old it is and when the next read is |
| A list naming a channel that another follow names | `The list of <identity> names <name>, which this device follows from <other identity>: run cordelia subscribe in a clone of the one it should follow.` |
| This device follows no list of the channel | `This device follows no repository whose channel is <name>.` Said by `cordelia shared seen <name>`. Only a device that follows a repository knows that a channel is its, and another device's follows are its own. |
| The channel line changed | amber, as a key new on the list is: `The list of <identity> names a new channel for <name> at <commit>.` Cleared by `cordelia shared seen <name>`. |

## 7. What `cordelia status` shows

For each repository channel:
- **its name and identity;**
- **when the list was read,** where from, and the commit;
- **the members, by the list's labels,** each in or not yet;
- **what waits:** messages unread by the person and by an agent;
- **any line of rules 4 to 6.**

**A repository in step is one line** (made terser on 11 November 2026, on the person's ruling, issue #338). In step means: the last read counted, no line of rules 4 to 6 stands, and no member is not yet in. Nothing then waits on the list, and the plain status says `<identity>, for <name>: 2 members, all in`, with what waits unread where any does: `; 2 unread by you, 1 by an agent`. Otherwise it shows each line above, and the read's line ends with when the next read is (rule 3). A last read that counted, older than two read intervals (`MEMBERS_READ_OVERDUE_SECS`), is not in step either, so a read that keeps failing shows how long ago the list was read. `-v` and `cordelia shared list` show every line, the next read with the read. The node works out whether a repository is in step, and `--json` gives it as `in_step`, and the next read as `next_read`.

The notices of rules 4.5 to 4.7 show only on devices that follow the repository. Rule 1's gate shows as rule 4.7's line, once, on a device that holds the channel: a joiner cannot see who is in it, and shows nothing of it. Commits show by their first twelve characters (`MEMBERS_COMMIT_SHOWN_CHARS`), and the plain status names the first six members (`MEMBERS_LABELS_SHOWN`) and how many more, and so does each line of keys new on the list; `--json` gives the whole commit, every member and every key new on the list. The fingerprint words show only with `-v` (#228).

**The ambers set the status's level** (the person's ruling of 6 November): a key new on the list (4.5), a key dropped (4.6), rule 1's gate (4.7), a changed channel line and a device of yours left out (rule 6), and the three of rule 5. They overturn property 16 of the shared channels record, "nothing about a shared channel sets a level". Nothing else of a shared channel sets one.

## 8. An agent that is not in a clone

**One kind of agent: a mapped folder.**
- **A session in any folder of the clone** is the repository's agent, and sees the channel once `subscribe` has run there.
- **Any other agent** subscribes with `cordelia subscribe <name>`, as today: a workspace above several clones, home, or a folder kept for the purpose. It must be a mapped folder.

**Turned down: a mailbox folder that Cordelia makes for each channel** (`~/.cordelia/shared/<channel>`), with hooks that name the channel.
- It would be a second kind of agent, with no folder that a session runs in.
- Its hooks would name channels instead of folders.
- Mapping a folder already gives an agent, and a mapped folder's memory goes only to the person's own devices, never into a channel (§0 there).

## 9. What comes over from today

- **Nothing is carried over.** A channel made by `shared new` stays as it is, shared by hand. A repository channel is made with `subscribe --new`, and its first members join by the list.
- **`share` and `accept --channel` stay** for a channel shared by hand, with their six words.
- **The members record's command is not built.** Its leaving half is rule 5.

## 10. Who can do what

- **Whoever can merge to the default branch** admits any key, at once, and names the channel. That is the person's rule: the repository decides. Each key a merge adds shows on every follower's status (rule 4.5), at that follower's first read of a list that names it. Every key on the list shows at a first follow where the list has a `channel` line already, and otherwise at the first list with one. The one exception is a device that upgrades from `v0.2.0-alpha.19`: a key it never showed stays unshown (rule 4.5). A stolen account with merge rights is the same as its owner.
- **The host** decides what the branch is, as the person's own git fetches it. The node itself reaches no host.
- **A program that runs as a member** can change the clone, and so the list, for example with `git update-ref`. It can already run `share` with a yes (the README's security section). Each join's notice names the commit, for the person to check.
- **A list in a public repository** shows the channel's ID, its relays, its keys and their labels. None of it lets anyone read the channel: that needs a member to hand it over. Nor can a stranger with the channel's ID and relays write there, or fill its room at a relay. A relay hands a channel only on a proof made with its secret, and takes an entry only where it is signed by the channel's own key, which comes from the seed (§2.1 and §10 there; decision 2026-10-04 §2.4).
- **A member can still hand the channel to a key that is not listed,** by hand: a channel stays flat. `log` shows that key, with no label of the person's.
- **A known limit:** a device that does not follow the repository, making its channel anew, cannot carry the current line's `without` keys. Nor can any device carry what another device's making anew left out, before that line is merged. Where one of those keys is still listed and the person does not carry it over, it is let back in once the new line is merged. The device that left it out shows amber until the line names it again (rule 5). So merge the lines in order.
- **The reader shows listed keys as it shows any other key** (§2.4 there). They are not labelled for the person, and share the hour and the room of keys the person does not know (§6.3 there), until the person labels them.

## 11. Constants

Each is in `protocol.rs`, and explained at length in parameter-rationale.md §12.14.

| Name | Value | Why |
|---|---|---|
| `MEMBERS_FILE_MAX_BYTES` | 16,384 | Room for a channel line with two relays and 64 keys after `without`, and 64 devices' lines with labels of 32: 11.1 KiB together (rule 1) |
| `MEMBERS_LABEL_MAX_CHARS` | 32 | Long enough to tell devices apart, short enough to sit beside a key on one line; its characters need no escaping where it is shown (rule 1) |
| `MEMBERS_GIT_TERM_SECS` | 2 | Git ends on TERM in milliseconds; two seconds is room for a loaded machine before it is killed (rule 3) |
| `MEMBERS_READ_INTERVAL_SECS` | 600 | As `RELAY_ASK_AGAIN_SECS`: a join waits about ten minutes on each side once the list is read, and the list changes only with a merge and a fetch (rules 3 and 4) |
| `MEMBERS_READ_OVERDUE_SECS` | 1,200 | Derived: two read intervals. One late is a read running or a busy timer; two are reads that fail with no line, which the status then shows (rule 7) |
| `MEMBERS_HANDED_AT_ONCE` | 4 | Derived: half of `MAX_TYPED_KEYS`, as a share lives for two reads, so a device that is off holds no place for long (rule 4.2) |
| `MEMBERS_ASKED_PER_PASS` | 32 | The node's typings asked of the relays in one pass, across every follow: 384 requests a minute, 592 with the rest of the shared pass, within the 600 of `SHARED_REQUESTS_PER_MINUTE` (rule 4.4) |
| `MEMBERS_COMMIT_SHOWN_CHARS` | 12 | As git's short form: twelve tell commits apart in any repository a team shares, and keep a join's line short; `--json` gives the whole commit (rule 7) |
| `MEMBERS_LABELS_SHOWN` | 6 | Six labels fit on one line of a terminal; `--json` and `shared list` give every member (rule 7), and every key new on the list (rule 4.5) |

## 12. Tests

Real-process tests, with a git repository served over HTTPS on loopback, and a clone of it:

**The join itself**
- **Two people, the whole join.**
  - Bob runs `subscribe --new`, and its lines are merged.
  - Alice's line is merged, and she runs `subscribe`.
  - Within two reads, Alice holds the channel and sends a message that Bob reads.
  - Bob's status shows `New on the list of ...: alice-laptop` until `shared seen`.
  - Nobody runs `share` or `accept`.
- **Order does not matter.** Alice's line is merged, and she runs `subscribe` before any member's clone has the merged list: she follows and waits, and her status says what for (rule 6). Then a member runs `git pull`, and she joins. A key that is not listed yet is refused, and follows nothing (rule 2.3).
- **From the clone only.** No git of the node's reaches the network: the list comes from the clone, and the status says how old it is.

**Never asked, and never back**
- **Nothing asks.** The person's git configuration and environment are set to ask in each way: a credential helper, globally and in the clone's own configuration, that would ask; an `insteadOf` to SSH; `SSH_ASKPASS`; and a partial clone whose read would fetch. Each git command either goes over HTTPS without asking or fails, and no prompt opens.
- **Identity.**
  - A remote changed to a fork is not read.
  - With two remotes, `--remote` is needed.
  - A list in the working tree or on a local branch is not read.
- **A read of the clone never goes back.** A clone behind the last commit read gives no new list, across a restart too.

**Who gets the channel**
- **Only the named channel.**
  - A share of another channel from a listed key is not taken.
  - A share from an unlisted key, or one older than the hour of the latest read, is not taken.
  - A key not on the list is never handed the channel.
- **Leaving.**
  - A key dropped by a merge shows amber on every follower.
  - `shared anew` leaves it out and prints the new line, with the key after `without`.
  - Before that line is merged, nobody hands the new channel to anyone.
  - After a removal, a removed device that is still listed is never handed the new channel, even where the new channel line is merged and the device's line is not, by any follower: one that was off, and one that joined after the removal, included.
  - A list that names a left-out key both as a member and after `without` names no channel until the key's line goes.
  - A pull request that adds a key's line and takes it off `without` lets it back in.
  - After a second making anew, a key left out at the first, whose line went, is not handed the newest channel.
- **Turns.**
  - Nine new keys, with eight of them off: the ninth is handed the channel at the third read, twenty minutes after the first, as the shares of the first four go.
  - The taker's typings leave the person's eight places free.
  - The node's shares leave the person's own `share` its places.

**What it says**
- **Waits.** Each line of rule 6 appears where it should.
- **Keys new on the list** (rule 4.5), given the rows, and with real processes where marked:
  - A first follow names every key on the list but your own: this device, another of your devices, and a twin of each. It names a removed device of yours that is still listed. With real processes, the maker's first list with its channel line, a joiner's first list with a channel line, and a follow made again after `unsubscribe` each name the device already listed.
  - Following again names nothing at its yes; `unsubscribe`, then `subscribe`, names every key again.
  - A clone that lags: a key that this device held before its list named it is named at the read that first lists it.
  - A channel made anew between two reads, with the same keys listed, names nothing; a key listed for the first time then is named.
  - A key dropped, then listed again, is named again, at the commit of the read that lists it again.
  - A read that counts for nothing names nothing, one of a channel another follow names among them. A list with no `channel` line names nothing, and the first read of one with a line names every key.
  - A key's twin, listed in its place, is not new. A first follow that replaces another names every key. A list that does not parse at the yes names nothing, and the next read of one that parses names every key.
  - The plain line names six labels and how many more, and one label alone; `shared list` names them all; `--json` gives the commit and each key.
  - `shared seen <name>` clears the lines, and says each line as it clears it; `shared seen <name> <label>` leaves them.

## 13. The reviews, and what they changed

Each round's findings and what changed are on pull request #297. What changed most:
- **The list names the channel** (`channel <ID> <relays>`). A share holds only a card, so nothing else said which channel was the repository's.
- **A private repository is read from the clone,** never fetched. Every way of giving the node credentials can ask.
- **The node reads the clone only** (the person, 7 November). Its own fetch of a public repository drew findings in three rounds of slice 2's review: it fetched a whole tree; a git older than 2.44 fetches lazily; and a host sends a blob asked for by its ID whatever the filter says, so a size bound needed a watch on the fetch.
- **A channel follows one repository, and a key waits while any share of it does** (rules 2.5, 4.2 and 6). Two lists that named one channel, or one key, wrote over each other's shares.

## 14. The person's answers (6 to 11 November)

1. **`cordelia shared seen <name>`** clears the notice of a key new on the list (rule 4.5) and of a changed channel line (rule 6), on each device: yes. Rule 5's amber of a key left out has an act of its own, `cordelia shared seen <name> <label>`.
2. **The default name is the repository's `owner/name`:** yes.
3. **A private repository's list comes only from the person's own fetches.** A read-only token in the node's configuration is left for later: yes.
4. **The node reads the clone only,** with no git of its own that reaches the network (7 November): yes.
5. **A channel follows one repository** (7 November): kept.
6. **An offer "without you" stops hand-overs too** (8 November): a device hands over nothing in a channel in which it has read any offer that is no fault (rule 4.1).
7. **A join is judged by the list alone** (10 November): "by the list alone". A key shows when a list that this device reads names it and the list read before did not (rule 4.5).
8. **The plain status says a repository in step in one line** (11 November, issue #338). More shows only when something waits, and then the read says when the next read is (rules 3 and 7). A read long overdue is not in step.
