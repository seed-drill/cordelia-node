# Cordelia

**Your AI agent's memory on every machine you use, readable only by you.**

AI coding agents keep memory, but it lives in one folder on one machine, filed
under the path the agent ran in. Cordelia keeps it in step across your devices:
end-to-end encrypted, carried by relays that hold only ciphertext and no keys,
and matched by project (git remote) rather than by path. Version 1 syncs Claude
Code's memory. A recovery phrase of twelve words, which only you hold, removes
a device that is lost and brings your memory back to a new machine.

- **How it works, and what it promises:** [WHITEPAPER.md](WHITEPAPER.md)
- **Where it is going:** [docs/vision.md](docs/vision.md)

## Status

**Pre-release (October 2026).** v1 is built and tested, including end-to-end
tests with real processes over QUIC through a relay. Two relays are running,
and `v0.2.0-alpha.8` is the current pre-release, for macOS and Linux:

```bash
curl -fsSL https://seeddrill.ai/install.sh | CORDELIA_VERSION=v0.2.0-alpha.8 sh
```

Running it again with a later version upgrades: it restarts a node that is
running as the service it set up, waits until the node says that it is the
new version, and ends with one line that a program can read
(`cordelia-install: installed=... running=... restart=...`). With
`CORDELIA_NO_RESTART=1` it leaves the node as it is.

It is an alpha: expect rough edges, and keep your own backup of anything you
cannot afford to lose.

## Use

On each machine:

```bash
cordelia init          # create this device's key
cordelia start         # run the node (install.sh sets it up as a service)
```

### The recovery phrase

On one machine, make your recovery phrase:

```bash
laptop$  cordelia phrase
```

It shows twelve words, once. Write them down, in their order. They are then
taken off the screen, and you type them back from what you wrote, so that a
phrase written down wrongly is found out at once, and not on the day of a
removal. No device stores them. Keep them where only you can read them.

- **Without the twelve words a device can be added, and none can ever be
  removed or recovered.** Whoever holds a copy of them can read your memory,
  through every later removal, with nothing to show it.
- They are Cordelia's recovery phrase. They come from the same list of words
  that a wallet's seed uses, and neither is to be typed into the other's
  program.
- They are typed only at the prompt of a `cordelia` command, at a terminal:
  never as an argument, never into a chat with an agent.
- Until a machine has a phrase, or is added from one that has, its memory
  stays on it: sync can be on and folders mapped, and nothing is sent.
  `cordelia status` says "no recovery phrase yet".

Make the phrase on the machine whose memory is the most up to date: what it
holds becomes the first version of each file that your other machines meet.

### A second machine

Add it from the first, one key copied in each direction:

```bash
desktop$ cordelia id                                  # prints cordelia_pk1...
laptop$  cordelia add-device cordelia_pk1... --name desktop
         #   On the other device, within the hour, run: cordelia accept cordelia_pk1...
desktop$ cordelia accept cordelia_pk1...
```

Each of the two is run at a terminal and asks a yes, and says what the yes is
for. `add-device` gives the new machine every name's memory, and the means to
read what your devices write from now on. `accept` joins the machine, and the
folders it maps, to the devices of the key you typed. The phrase is not typed
to add a device.

- Every device of yours shows a new device until you clear it there
  (`cordelia devices --clear`). A device that you did not add is one to
  remove.
- Add a machine soon after you install it. For as long as it follows no
  phrase, one yes at a terminal joins it, and its folders, to whichever
  device's key is typed. A machine that is already one of several stays where
  it is, and says so.
- Memory that the new machine had gathered alone is published, not lost: a
  file with the same text on both is agreed, and where a file differs the
  machine's own text is kept beside it as a copy.

### What syncs

Turn sync on, on each machine, and say what to sync:

```bash
cordelia sync claude                  # on: lists what it found, syncs nothing yet
cordelia sync map ~/Work/my-project   # a git project, named by its remote
cordelia sync map ~/notes lab-notes   # any other folder in your home directory, under a name you choose
cordelia sync map ~ --home            # home memory
cordelia sync status                  # what syncs, what was found, what your other devices sync
```

**Only folders that you map sync.** A folder syncs because `cordelia sync map`
declared it, and for no other reason: `cordelia sync claude --all` is refused,
and so are `cordelia sync exclude` and `cordelia sync include`, since there is
nothing left to exclude. The name is what your devices share: map the same
name on each device and Claude's memory for it stays in step. A git project
is named by its remote (`github.com/owner/repo`), so the same clone at
different paths on two machines needs no name; any other folder needs one.
Claude Code keeps one memory per repository, shared by its folders and
worktrees, so mapping any folder of a repository maps the repository.

A device stores a name's memory only once it maps that name, and home memory
is the same. It could read any of them: every device of yours can read every
name of yours, whether or not it maps it.

Home memory is named `~` unless you give it a name:
`cordelia sync map ~ my-agent --home`. Under a name of its own it can share
memory with a folder on another machine, for an agent that starts in your
home directory on one and in a project folder on the other.

Running `cordelia sync claude` again changes nothing; it keeps your settings,
and says so. `cordelia sync unmap <folder or name>` stops syncing a folder
from this device and leaves its files where they are. Mapping it again merges
it with what your other devices have, and deletes nothing. `cordelia sync off`
stops syncing.

A memory file syncs if it fits in one entry, which holds 60 KB of text with
the file's name. A larger file, or one that is not plain text, is left as it
is on the machine that has it, and your other machines keep the last version
that did sync; `cordelia sync status` names it.

Sync makes one machine's mistake every machine's: an edit or a delete is
taken by the others within seconds. So each machine keeps, for 30 days, the
text of a memory file as it was just before sync replaced or removed it
there, and any of them can put a version back:

```bash
cordelia history                               # what is kept on this machine, and how far back
cordelia history ~/Work/my-project             # its kept versions, newest first, each with an id
cordelia history ~/Work/my-project --removed   # files that were removed and are still absent
cordelia history show <id>                     # print one kept text
cordelia restore <id>                          # put it back; where the folder syncs, every machine follows
```

History stays on the machine, readable as the memory folder is, and is not
a backup: your other machines are. `cordelia history drop --all` removes
it, and `days = 0` under `[history]` in the configuration turns it off.

### Your devices

```bash
cordelia devices                 # every device, what each has applied, what each relay holds
cordelia devices --clear         # go through what this device has to tell you
cordelia remove-device <key>     # remove a device (asks for the phrase)
cordelia renew                   # a new secret for the devices that stay (asks for the phrase)
cordelia settle                  # settle two changes that were made apart (asks for the phrase)
cordelia recover                 # on a new machine, with no device left (asks for the phrase)
```

`cordelia devices` is the one place to look. It lists every device of the
last change, with whether it has applied that change and sent what it held;
every device added since, and who added it; every removed key; and, for each
relay, whether it holds the latest change. Beside each device's label are
the first four words of its key's fingerprint: two devices can have one
label, and the words tell them apart.

**To remove a device** that is lost, stolen or retired, run
`cordelia remove-device <key>` on a device that remains. It shows the device
to be removed, each device added since the last change (and asks of each
whether it stays), every device that will remain, and each name that only
the device being removed syncs. Then it asks a yes, and then the phrase.

- The removal is one change for every name at once. From the moment a
  device applies it, the removed device reads nothing that device writes,
  and nothing the removed device writes is taken.
- The command stays, and says when this machine may be closed: when every
  relay holds the change and this device has sent what it holds.
- A device that is off applies the removal when it next reaches a relay that
  holds it. Until it has heard, it still writes where the removed device can
  read. `cordelia devices` shows which devices have not applied the change.
- What the removed device wrote is kept where one of your other devices had
  taken it. `cordelia history` shows what this device took from which
  device, and `cordelia restore` puts a version back.
- Make a change on one device, once: two changes made apart stop every
  device that sees both, until `cordelia settle` on one of them, with the
  phrase.
- A device that was removed by mistake cannot come back under its key.
  `cordelia init --new-key` gives it a new one and keeps its memory folders;
  it is then added as a new device.

`cordelia renew` removes nobody. It gives the devices that stay a new secret,
and asks of each device added since the last change whether it stays: run it
once your devices are added, so that they are in a list you have looked at.

**To recover**, when you have no device left that you trust, install
Cordelia on a new machine and run `cordelia recover`. It asks for the phrase,
shows every device and asks of each whether you still have it, have lost it,
or think it may be in someone else's hands, and brings back what the relays
hold. Keep the machine on until it says that everything is sent.

- Every other device stops when it hears, and each one that you still have
  is added again from the new machine, with the two commands.
- A relay is a cache, not a backup: recovery brings back what the relays
  hold, for 90 days after the last of your devices was on.
- Where a device remains that you trust, remove the lost one from it
  instead: that stops nobody else.
- `cordelia sync carry <name>` brings in what a device that never returned
  had sent to the relays. With `--from <label>`, and the phrase, it also
  takes what a removed device wrote there.

**If the phrase is lost, or someone else has seen it,** it cannot be
replaced. Start again on every device: `cordelia phrase` on one, which makes
a new phrase, and on each other `cordelia init --new-key` and then the two
commands that add it.

### Upgrading from an earlier version

This version is a new start: each machine takes it, starts alone from its
memory folders, and is added again.

1. **Bring every machine into step first, on the version it has:** each on,
   and synced, so that every memory folder holds what the others hold. A
   file that was deleted on one machine and is still on another comes back.
2. **Upgrade each machine.** A relay is upgraded before the devices that use
   it: if you run your own, see [deploy/relay/README.md](deploy/relay/README.md). It keeps its key, its memory folders and its
   mappings. It publishes nothing, and its status says "not added yet".
3. **Run `cordelia phrase` on one machine,** the one whose memory is the most
   up to date.
4. **Add each other machine** with `cordelia add-device` and `cordelia
   accept`, as above.

A machine whose sync was set to everything it found is told which folders
stopped: `cordelia sync map` each one that is to go on. At its first start on
this version a machine copies its database into a folder named
`before-<version>` beside it, before it empties anything of the version
before. The copy holds what the machine held, some of it in the clear, and
can be deleted once you are content. Going back to the version before is in
[docs/specs/operations.md](docs/specs/operations.md), section 10.5.

### Status

`cordelia status` shows this device and, while the node runs, its peers and
memory sync. For status bars:

- `cordelia status --line` prints one short line: `● memory synced`,
  `◐ memory sending 3`, `○ memory offline`, `▲ memory: 1 conflict`,
  `▲ memory: 1 file too large`, `▲ memory: not added yet`, and so on. It
  prints nothing on a machine where Cordelia is not set up. The line shows
  the first thing of the gravest level, and its tooltip shows everything.
  - **Red** is for what stops this device syncing until you act: it was
    removed; it is in no list of the last change, and is to be added again;
    two changes were made apart, and are to be settled with the phrase; a
    change could not be opened or applied here; its first start on this
    version has not succeeded; or it has a folder mapped and no recovery
    phrase yet ("not added yet" after an upgrade, "no recovery phrase yet"
    on a new install). A machine that is not to be added turns sync off.
  - **Amber** is for what goes on, and waits on you or on a relay: a removal
    that some device has not applied, for its first seven days; a device
    added since the last change that nobody has cleared; a device that has
    said it left; a relay that has been connected for more than five minutes
    and does not hold the latest change; a relay that refuses a new channel,
    for room or because its address has added too many; names that are not
    yet in the channels of the last change, or not yet sent, for more than
    five minutes.
- `cordelia status --json` gives the same `state` (`synced`, `syncing`,
  `offline`, `attention`, `off`, `stopped`, `uninitialised`) and `summary`,
  with everything a panel or an agent needs: whether the node is `running`
  (`null` where the command did not ask it, with why in `not_asked`: the
  API's address is set to something other than `127.0.0.1` or `::1`), the
  connected relays, your devices, each folder that syncs and its name, what
  was found and is not syncing, what your other devices sync, what waits to
  reach a relay and what a relay refused, last change, the conflict files
  waiting to be merged, the files that are too large to sync, and the files
  that could not be synced in the last cycle, each with why (the first
  hundred, and how many more). With sync on and no recovery phrase the
  `state` is `attention`.

To show it in Claude Code, add this to `~/.claude/settings.json` (use the full
path, e.g. `~/.cordelia/bin/cordelia`, if `cordelia` is not on the `PATH`
Claude Code starts with):

```json
{ "statusLine": { "type": "command", "command": "cordelia status --line" } }
```

If you already have a status line command, add `$(cordelia status --line)` to
what it prints.

On [Omarchy](https://omarchy.org), the
[Cordelia panel](https://github.com/seed-drill/omarchy-cordelia) puts an icon
in the bar and opens a panel to turn sync on and off, choose what syncs and
open conflicts. Adding and removing devices is done at a terminal, with the
commands above:

```bash
omarchy plugin add https://github.com/seed-drill/omarchy-cordelia.git --enable
```

For any other bar, `cordelia status --waybar` prints an icon, a tooltip and
the state as a class, in the JSON that Waybar's custom modules take. The
icons are Nerd Font glyphs.

- **Omarchy, without the panel:** add this to `bar.layout.right` in
  `~/.config/omarchy/shell.json`. The bar highlights the icon when a conflict
  or an error needs you, and a click opens the details.
  ```json
  {
    "id": "cordelia",
    "type": "command",
    "exec": "~/.cordelia/bin/cordelia status --waybar",
    "interval": 5,
    "onClick": "omarchy-launch-floating-terminal-with-presentation '~/.cordelia/bin/cordelia status; echo; ~/.cordelia/bin/cordelia sync status'"
  }
  ```
- **Waybar:** a custom module, styled by class (`synced`, `syncing`,
  `offline`, `attention`, `off`, `stopped`).
  ```json
  "custom/cordelia": {
    "exec": "~/.cordelia/bin/cordelia status --waybar",
    "return-type": "json",
    "interval": 5
  }
  ```

## Build from source

```bash
cargo build --release          # toolchain pinned in rust-toolchain.toml
./target/release/cordelia --help
cargo test --all               # unit, protocol, and end-to-end tests
```

## Repository

| Path | What |
|---|---|
| `crates/cordelia-core` | Types, config, protocol constants (`protocol.rs`), revisions as a band and a count |
| `crates/cordelia-crypto` | Ed25519/X25519 identity, AES-256-GCM, ECIES; a channel from its secret, the recovery phrase, statements, change entries, entries and their chains, the proof |
| `crates/cordelia-storage` | SQLite: entries, what a device holds of its person, a relay's channels, sync state, local history, and the first start on this version |
| `crates/cordelia-network` | QUIC transport, governor, mini-protocols, the streams of entries |
| `crates/cordelia-api` | Local REST API; a person's devices, publishing and reading the names a device holds, what a device does at a relay |
| `crates/cordelia-sync` | The Claude Code adapter |
| `crates/cordelia-node` | The `cordelia` binary: CLI, daemon, p2p loop, a relay's and a device's side of the streams of entries |
| `deploy/relay` | Relay image, Docker Compose and a guide to running a relay |
| `docs/decisions` | Decision records; [`2026-10-04-a-persons-devices.md`](docs/decisions/2026-10-04-a-persons-devices.md) (a person's devices, the recovery phrase, relays) and [`2026-09-30-agent-memory-sync.md`](docs/decisions/2026-09-30-agent-memory-sync.md) (the adapter, ties, deletes, local history) are the v1 design |
| `docs/specs` | Protocol and component specs, each with a note on what v1 changed |
| `docs/archive` | Pre-v1 documents, kept for history |

The local API (`127.0.0.1:9473`, bearer token in `~/.cordelia/node-token`)
covers the names a device holds (`/api/v1/channels/publish`, `entries` and
`delete-key`), a person's devices (`/api/v1/devices/*`, `/api/v1/phrase/make`,
`/api/v1/change/*`), sync (`/api/v1/sync/*`) and local history
(`/api/v1/history/*`). No route takes the recovery phrase: a command reads it
at a terminal and signs in its own process.

## Security

Relays and relay operators see channel IDs, device public keys, and the
sizes (by class) and timing of entries; never content, file names, the list
of your devices, or keys. A relay stores an entry only if the channel's own
key signed it, and hands a channel only to a connection that proves it holds
that key. The node on your machine dials out to the relays it was configured
with, which it knows by name and by key (UDP 9474), and listens only on its
local API (127.0.0.1): nothing on a network you join can connect to it.

On your own machines memory is as protected as your disk. Every device of
yours can read every name of yours, and another program that runs as you,
an agent with a shell among them, can run any command that asks only a yes.
What it cannot do is anything that asks for the recovery phrase.

- [docs/security/threat-model.md](docs/security/threat-model.md) says what
  Cordelia defends against and what it does not, and names the tests that
  prove each claim. CI fails if a claim loses its test.
- [WHITEPAPER.md §4](WHITEPAPER.md#4-security-model) has the full model and
  its limits.

To report a vulnerability privately, email hello@seeddrill.ai.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
