# Decision: joining a repository's shared channel by pull request

**Date**: 2026-11-06
**Status**: Proposed, for review. For `v0.2.0-alpha.19`: the person ruled on 6 November that it comes now, not after R1 (issue #293).
**Cited as**: "decision 2026-11-06 (joining), rule 4". The numbers do not change.

Words used throughout:

- **The shared channels record** is [`2026-10-10-a-shared-channel-for-messages.md`](2026-10-10-a-shared-channel-for-messages.md), cited "§7 there".
- **The members record** is [`2026-11-05-a-shared-channels-keys-in-a-repository.md`](2026-11-05-a-shared-channels-keys-in-a-repository.md). This record keeps its file (rule 1 there) and replaces its command: `cordelia shared members` is not built.
- **The list** is a repository's `.cordelia/members`. **A repository channel** is a shared channel that follows a repository's list.
- **A member** is a device that holds the channel. **In the channel**, for a key, means as the members record says: in this device's table of the channel's keys, or sealed to by an offer into it and not moved yet (#291).
- **Main** is commit 89b2397f. Examples say laptop and desktop, Alice and Bob, and `github.com/example/project`.

---

## 0. What this is, in one page

The person's rule: **a merged pull request is the whole join.** No `share`, no `accept`, no hour to hit, and nothing that waits without saying what it waits for.

**What a person does:**
1. Raises a pull request that adds a line for each of their devices to `.cordelia/members`.
2. Once it is merged, runs `cordelia subscribe` in their clone of the repository, once, and types yes.

**What the nodes then do, with no one asked:**
- Each member's node reads the list every ten minutes. It fetches it over HTTPS itself, and never makes anyone type, click or touch anything.
- A member's node hands the channel to each listed key that is not in it yet.
- The new member's node takes the channel from any listed key.
- Every member's status says "a key joined from the list", with its label and the commit, until a member clears it.

**Leaving stays by hand for now.** When the list drops a key, every member's status goes amber until someone runs `cordelia shared anew <name>`. That command lists the dropped keys and asks about each.

**Nothing new on the wire or at a relay.** A hand-over is today's share, and a take is today's `accept --channel`, each run by the node in place of a person.

---

## 1. The list

The members record's rule 1, unchanged:
- `.cordelia/members`, at the root of the repository, on its default branch;
- one line for each device: its key as `cordelia id` prints it, then a label of 1 to 32 characters of `a-z`, `0-9`, `.`, `_` and `-`;
- `#` lines and empty lines are skipped;
- ASCII, at most 16 KiB, keys unique and labels unique;
- at most 64 keys, less the person's own devices that the list does not name;
- a file that does not parse adds nobody and removes nobody, and the status names the line.

**List every device you have.** Every device of yours holds your shared channels and writes in each (§3.4 there).

## 2. Following a repository: `cordelia subscribe` in a clone

```
bob@laptop$ cd ~/Work/project
bob@laptop$ cordelia subscribe
```

**With no name, in a folder of a git repository whose default branch has `.cordelia/members`, `subscribe` follows that repository.** It needs a terminal and one yes. The folder must be mapped, as for any agent: otherwise it says to run `cordelia sync map .`, and does nothing.

1. **The repository's identity** is `host/owner/name`, in lower case, read from the clone's remote. It takes the remote whose address has one of four forms:
   - `https://<host>/<owner>/<name>`
   - `ssh://git@<host>/<owner>/<name>`
   - `ssh://<host>/<owner>/<name>`
   - `git@<host>:<owner>/<name>`

   With or without `.git`; nothing else, and no port. With no such remote, or two that differ, it says so and does nothing.
2. **The branch** is the repository's default branch, as the host answers it (rule 3). It is not taken from the clone.
3. **It reads the list** by rule 3, and shows:
   - the identity and the branch;
   - the commit;
   - whether this device's key is on the list.
4. **Then one of three things:**
   - **The person holds the repository's channel already** (one of their devices follows it): it subscribes this folder's agent, as `cordelia subscribe <name>` does today.
   - **They do not, and the list names this device:** it follows the repository and waits to be handed the channel (rule 4). The yes says: `This follows <identity>. A member's device hands you its channel once it reads the list, and you will see it in cordelia status.`
   - **They do not, and the list does not name this device:** it says `Your key is not on the list of <identity> at <commit>. Add it with a pull request, then run this again.` and does nothing.
5. **`cordelia subscribe --new`** makes the repository's channel, once, for the whole team: `shared new` at the person's relays, then following it. It is refused where a channel follows the repository already, on any of the person's devices. One person makes it; the rest are handed it. Two people who each run `--new` make two channels, and the status of each says so (rule 6).
6. **The channel is filed under `owner/name`** of the repository, in lower case. `--as <name>` gives another name.

**What the device keeps** is a row of its own, in a new table: the channel's name, the identity, the branch and the clone's path. It is the device's alone, and travels in no list. A filing's form is fixed and signed, and a device of an earlier version reading a new field would refuse the person's whole list.
- **The row follows the name.** A making anew or a move keeps the name, and so the row. `shared rename` changes it, and `shared drop` deletes it. A device that leaves its person deletes every row.
- **Each device of the person's that should read the list runs `subscribe` in a clone once.** One is enough for the person. Every member's device that follows the repository does the work of rule 4 for the team, so more followers mean more devices that hand the channel over.

## 3. Reading the list

**The node fetches the branch itself, over HTTPS, and never asks.**
- **Where:** a bare repository of its own, `~/.cordelia/repos/<host>/<owner>/<name>.git`, fetching `https://<host>/<owner>/<name>` with `git fetch --depth 1 --no-tags`. It never touches the person's clone, its refs or its files. It reads `.cordelia/members` from `FETCH_HEAD` with `git cat-file blob`.
- **When:** at `subscribe`, at the node's start, and every ten minutes (`MEMBERS_READ_INTERVAL_SECS`). The branch comes from `git ls-remote --symref`, read at the same time.
- **Never a prompt:**
  - git's own prompts are off (`GIT_TERMINAL_PROMPT=0`);
  - `GIT_ASKPASS` and `SSH_ASKPASS` are a program that fails;
  - Git Credential Manager is told never to ask (`GCM_INTERACTIVE=never`);
  - hooks, `gc` and maintenance are off;
  - git is stopped after sixty seconds (`MEMBERS_FETCH_MAX_SECS`).

  The fetch uses whatever HTTPS credential helper the person has set (the macOS keychain, `gh auth setup-git`, Git Credential Manager, libsecret), where it answers without asking.
- **Why never SSH:** an SSH fetch can make an agent ask, by Touch ID or a confirm dialog, each time. A node that fetches every ten minutes would ask all day. An SSH remote in the clone is read for its identity only, and the fetch goes over HTTPS.
- **When the fetch fails** (no credentials, offline, the host refuses), the node reads the clone's own `refs/remotes/<remote>/<branch>`, read only, as the person's own git last fetched it. It does so only where that remote's address still names the identity: a clone whose remote now points elsewhere, a fork's for one, is not read. Where neither works, the last list read stands.
- **The status always says which it read,** from where, and when: `list of <identity> read 3 minutes ago, at <commit>`, or `could not fetch the list of <identity> (<reason>): read your clone's last fetch, from 2 days ago`.

## 4. What a node does with the list

Each read gives a list. Each device that follows the repository does the following, with no one asked.

1. **Hands over.** Each listed key that is not in the channel, is not one of the person's own devices, is not a key the person removed, and was not left out by an offer this device made or moved by: the node hands it the channel, as `share` does.
   - At most eight wait at a time (`MAX_TYPED_KEYS`). The rest wait for the next read.
   - It hands over again at each read while the key stays listed and not in, so a hand-over never goes stale.
   - A share already waiting for that key is replaced, as `share` replaces one today.
2. **Takes.** A device that follows a repository whose channel the person does not hold takes a share:
   - only from a key that its own last read of the list names;
   - only once that read names this device;
   - only one made within an hour of a read that named the sharer. That keeps the hour of a typed key (`PAIR_KEY_TYPED_SECS`, decision 2026-10-04 §2.2): a share made long ago is not taken for what the list says now.

   It looks for shares from at most eight listed keys at a time, and takes the next eight at the next read. It files the channel under rule 2's name, on every device of the person's, as `accept --channel` does. **The first card taken is the repository's channel.** A share of another channel from another listed key is not taken, and the status names it (rule 6).
3. **Says a key joined.** Each key that first writes in the channel while the list names it gets an amber notice: `<label> joined <name> from the list at <commit>`. It stays until a person clears it on that device with `cordelia shared seen <name>`.
4. **Says a key was dropped.** Each key in the channel that the list no longer names, and that is not one of the person's own devices, gives amber: `<n> keys in <name> are no longer on its list: make it anew with cordelia shared anew <name>`. `shared anew` lists each one (#291), and the person answers as today. Leaving by itself, with one rule for which node makes it anew so that the channel does not split, comes later.

## 5. No silent waits

Every wait says what it waits for, on both sides, in `cordelia status` and `cordelia shared list`:

| Where | It says |
|---|---|
| A follower not on the list | `Your key is not on the list of <identity> at <commit>.` |
| On the list, not yet handed it | `Waiting for a member's device to hand you <name>. The list was read <when>.` |
| A member, the list read | `Handing <name> to <label>: waiting for that device to take it.` |
| A member, nobody follows | `No device of yours reads the list of <name>: run cordelia subscribe in a clone of <identity>.` |
| The fetch failing | rule 3's line, with the reason |

## 6. What `cordelia status` shows

For each repository channel:
- **its name and identity;**
- **when the list was read,** and the commit;
- **the members, by the list's labels,** each in or not yet;
- **what waits:** messages unread by the person and by an agent;
- **any amber of rules 4 and 5,** and these two:
  - `<identity> has two channels: <name> and <name>`, where two `--new` or two cards met;
  - `<label> handed <name> another channel: not taken`.

The fingerprint words show only with `-v` (#228).

## 7. An agent that is not in a clone

**One kind of agent: a mapped folder.**
- **A session in any folder of the clone** is the repository's agent, and sees the channel once `subscribe` has run there.
- **Any other agent** subscribes with `cordelia subscribe <name>`, as today: a workspace above several clones, home, or a folder kept for the purpose. It must be a mapped folder.

**Turned down: a mailbox folder that Cordelia makes for each channel** (`~/.cordelia/shared/<channel>`), with hooks that name the channel. It would be a second kind of agent, with no folder that a session runs in, and its hooks would name channels instead of folders. Mapping a folder already gives an agent. A mapped folder's memory goes only to the person's own devices, never into a channel (§0 there).

## 8. What comes over from today

- **Nothing is carried over.** A channel made by `shared new` stays as it is, shared by hand. A repository channel is made new, with `subscribe --new`, and its first members join by the list.
- **`share` and `accept --channel` stay** for a channel shared by hand, with their six words.
- **The members record's command is not built.** Its file is this record's list, and its leaving half is `shared anew` with rule 4's amber.

## 9. Who can do what

- **Whoever can merge to the default branch** admits any key, at once, with no person asked. That is the person's rule: the repository decides. Each join shows on every member's status (rule 4.3), and a stolen account with merge rights is the same as its owner.
- **The host** decides what the branch is, and is reached over TLS.
- **A program that runs as a member** can change the node's own repository, or the clone, and so the list. It can already run `share` with a yes (the README's security section). Each join's notice names the commit, for the person to check.
- **The credential helper** decides whether the node can fetch a private repository. Where it cannot, the node reads what the person's own git fetched.
- **A list in a public repository** shows its keys and labels. It does not let anyone read the channel: that still needs a member to hand it over.
- **A member can still hand the channel to a key that is not listed,** by hand: a channel stays flat. That key shows as dropped (rule 4.4) until it is made anew without it.

## 10. Constants

| Name | Value | Why |
|---|---|---|
| `MEMBERS_READ_INTERVAL_SECS` | 600 | As `RELAY_ASK_AGAIN_SECS`: a join waits at most about ten minutes on each side |
| `MEMBERS_FETCH_MAX_SECS` | 60 | A fetch that has not ended by then is stopped |
| `MEMBERS_FILE_MAX_BYTES` | 16,384 | The members record, rule 1 |

## 11. Tests

Real-process tests, with a git repository served over HTTPS on loopback:
- **Two people, the whole join.** Bob makes the channel with `--new`. Alice's line is merged, and she runs `subscribe`. Within two reads, Alice holds the channel and sends a message that Bob reads. Bob's status shows `alice-laptop joined ... at <commit>` until `shared seen`. Nobody runs `share` or `accept`.
- **Order does not matter.** Alice subscribes before the merge (not on the list), then the merge comes: she joins.
- **Never a prompt.** A credential helper that would ask, `GIT_TERMINAL_PROMPT`, `SSH_ASKPASS`, and a remote that is SSH only: each fetch fails or goes over HTTPS without asking, and the node falls back to the clone's fetched branch.
- **Identity.**
  - A clone whose remote is changed to a fork: it is not read.
  - A list in the working tree or on a local branch: not read.
- **Refusals.** A key not on the list is never handed the channel. A share from an unlisted key, or from a listed key long before the read, is not taken. A second card is not taken, and is named.
- **Dropped keys.** A key dropped from the list gives amber on every follower, and `shared anew` lists and asks about it.
- **Waits.** Each line of rule 5 appears where it should.
- **Bounds.**
  - Nine new keys: eight are handed it at one read, the ninth at the next.
  - A list over 64 keys, or one that does not parse: nothing changes, and the line is named.

## 12. Questions for the person

1. **`cordelia shared seen <name>`** to clear the notice of a join, on each device: is the word right?
2. **The default name `owner/name`:** right?
