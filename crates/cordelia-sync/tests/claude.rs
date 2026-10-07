//! The Claude Code adapter across two devices (decision
//! 2026-09-30-agent-memory-sync §4.5, §10; decision 2026-10-04 §2.2, §5.2,
//! §6, §10).
//!
//! Each device has its own home, `~/.claude`, and clone of the same
//! repository at a different path. Nodes are in-process. A stand-in relay
//! gives what one device holds in the channels of its own to the other,
//! through the one door for an entry from outside.
//!
//! Two devices of one person are made as a person makes them: the first
//! makes a recovery phrase and adds the second, which accepts. A name's
//! channel comes from the person's secret and the name, so no channel is
//! made or joined: a device that maps a name has its channel.
//!
//! A node is set up with no relay, so that a folder's first cycle waits
//! for none, unless a test says otherwise. A test does where a device
//! comes to sync a name that the other has already written in, with files
//! of its own to bring: its first cycle there then waits until the
//! stand-in has handed it the name's channel, as it does on a node that
//! has relays (decision 2026-10-04 §6).
//!
//! Only what is mapped syncs (decision 2026-10-04 §10.1): each test maps
//! the folders it syncs, and what is found beside them is listed and never
//! synced.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

use cordelia_api::state::AppState;
use cordelia_api::{adding, names, person, publish, take};
use cordelia_crypto::bech32::decode_channel_id;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{Entry, Inside, Link, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::phrase::Phrase;
use cordelia_storage::entries as stored;
use cordelia_storage::meta;
use cordelia_storage::person as held_rows;
use cordelia_sync::claude::ClaudeAdapter;

const REMOTE: &str = "git@github.com:seed-drill/cordelia-node.git";

/// This machine's clock, in seconds.
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

struct Device {
    state: AppState,
    home: PathBuf,
    adapter: ClaudeAdapter,
    _dir: tempfile::TempDir,
}

impl Device {
    /// A device that follows no recovery phrase yet. Its node is set up
    /// with no relay: a folder's first cycle waits for none.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        // Real paths, as Claude Code records them.
        let base = dir.path().canonicalize().unwrap();
        let home = base.join("home");
        let node_dir = base.join("node");
        std::fs::create_dir_all(&home).unwrap();
        let state = AppState {
            db: Mutex::new(cordelia_storage::db::open_in_memory().unwrap()),
            identity: NodeIdentity::generate().unwrap(),
            bearer_token: "t".into(),
            home_dir: node_dir,
            started_at: std::time::Instant::now(),
            sync_errors: AtomicU64::new(0),
            peers_hot: AtomicU64::new(0),
            peers_warm: AtomicU64::new(0),
            push_tx: None,
            announce_tx: None,
            peers: Default::default(),
            relays: Default::default(),
            outbox_refused: Default::default(),
            relist: Default::default(),
            sync_control: Default::default(),
            own_channels: Default::default(),
            held: Default::default(),
            history: Default::default(),
        };
        state.own_channels.set_up_with(0);
        let adapter = ClaudeAdapter::new(
            home.join(".claude"),
            home.clone(),
            &state.identity.public_key(),
        );
        Self {
            state,
            home,
            adapter,
            _dir: dir,
        }
    }

    /// Make a recovery phrase on this device, as `cordelia phrase` does:
    /// it follows the phrase from then, alone, and has a channel for
    /// every name.
    fn with_phrase(self) -> Self {
        {
            let db = self.state.db.lock().unwrap();
            let phrase = Phrase::generate().unwrap();
            person::first_statement(&db, &self.state.identity, &phrase, "desktop", now()).unwrap();
        }
        self
    }

    /// Turn sync on for this device's Claude Code directory, as
    /// `cordelia sync claude` does. A cycle does nothing until it is.
    fn sync_on(self) -> Self {
        meta::set(
            &self.state.db.lock().unwrap(),
            meta::SYNC_CLAUDE_DIR,
            &self.home.join(".claude").display().to_string(),
        )
        .unwrap();
        self
    }

    fn pk(&self) -> [u8; 32] {
        self.state.identity.public_key()
    }

    /// Claude Code's folder for `dir`, whether or not it exists.
    fn folder_of(&self, dir: &Path) -> PathBuf {
        cordelia_sync::discover::claude_folder(&self.home.join(".claude"), dir).unwrap()
    }

    /// Record a Claude Code session started in `cwd`: a transcript in the
    /// folder named after it. Returns that folder.
    fn session_in(&self, cwd: &Path) -> PathBuf {
        let folder = self.folder_of(cwd);
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(
            folder.join("session.jsonl"),
            format!(
                "{{\"type\":\"mode\"}}\n{{\"cwd\":{:?},\"type\":\"user\"}}\n",
                cwd.display().to_string()
            ),
        )
        .unwrap();
        folder
    }

    /// A Claude Code project folder whose sessions ran in `cwd`; returns
    /// its memory folder (created).
    fn claude_folder(&self, cwd: &Path) -> PathBuf {
        let memory = self.session_in(cwd).join("memory");
        std::fs::create_dir_all(&memory).unwrap();
        memory
    }

    /// A folder under this home that is not a repository.
    fn plain_dir(&self, rel: &str) -> PathBuf {
        let dir = self.home.join(rel);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn home_memory(&self) -> PathBuf {
        self.claude_folder(&self.home.clone())
    }

    /// A clone of the shared repository at `rel` under this home.
    fn clone_at(&self, rel: &str) -> PathBuf {
        self.clone_of(rel, REMOTE)
    }

    /// A repository at `rel` under this home whose origin is `remote`.
    fn clone_of(&self, rel: &str, remote: &str) -> PathBuf {
        let repo = self.home.join(rel);
        std::fs::create_dir_all(&repo).unwrap();
        for args in [vec!["init", "-q"], vec!["remote", "add", "origin", remote]] {
            assert!(
                Command::new("git")
                    .arg("-C")
                    .arg(&repo)
                    .args(&args)
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        }
        repo
    }

    fn cycle(&mut self) -> cordelia_sync::claude::CycleReport {
        let report = self.adapter.run_cycle(&self.state);
        assert!(report.errors.is_empty(), "sync errors: {:?}", report.errors);
        report
    }
}

/// The secret of a device's personal channel, in the generation it has
/// applied.
fn personal_secret(d: &Device) -> [u8; 32] {
    let db = d.state.db.lock().unwrap();
    let person = held_rows::applied_secret(&db).unwrap().unwrap();
    derive::personal_secret(&person.secret).unwrap()
}

/// The entries a device's store holds in the channel whose ID is
/// `channel`, as it holds them and in the order it stored them.
fn stored_in(d: &Device, channel: &[u8; 32]) -> Vec<stored::StoredEntry> {
    let db = d.state.db.lock().unwrap();
    stored::channel_entries_after(&db, channel, 0, 100_000).unwrap()
}

/// The channels of a device's own: the personal channel, and the channel
/// of each name it holds. None on a device that follows no phrase.
fn own_channels(d: &Device) -> Vec<[u8; 32]> {
    let db = d.state.db.lock().unwrap();
    let Some(person) = held_rows::applied_secret(&db).unwrap() else {
        return Vec::new();
    };
    let personal = derive::personal_secret(&person.secret).unwrap();
    let mut channels = vec![derive::channel_id(&personal).unwrap()];
    channels.extend(
        held_rows::names(&db)
            .unwrap()
            .into_iter()
            .map(|held| held.channel),
    );
    channels
}

/// How many entries a device's store holds, in every channel.
fn entries_held(d: &Device) -> i64 {
    let db = d.state.db.lock().unwrap();
    db.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
        .unwrap()
}

/// How far a device's store has got: the place of the last entry it
/// stored in a channel of its own, and 0 where it holds none. Every entry
/// the device writes or takes has a later place than any before it.
fn written(d: &Device) -> i64 {
    own_channels(d)
        .iter()
        .flat_map(|channel| stored_in(d, channel))
        .map(|held| held.seq)
        .max()
        .unwrap_or(0)
}

/// A stand-in relay: give `to` every entry that `from` holds in the
/// channels of its own and that `to` does not hold yet, through the one
/// door for an entry from outside, as a relay's pages do. `to` takes what
/// is of its personal channel and of the channel of a name that it holds
/// itself, and refuses the rest, which is offered again the next time.
///
/// An entry that a key signed is refused until the record that makes
/// that key count has arrived. So where a key came to count, or came to
/// may add, everything is given again, as a node reads its channels again
/// from the start.
///
/// The stand-in has then handed `to` the whole of the channel of each
/// name that `to` holds, and `to` is told so, as a node tells itself of a
/// relay: a folder there that waited for its channel waits no more.
fn relay(from: &Device, to: &Device) {
    let held: Vec<Entry> = own_channels(from)
        .iter()
        .flat_map(|channel| stored_in(from, channel))
        .map(|held| held.entry)
        .collect();
    let db = to.state.db.lock().unwrap();
    let mut again = true;
    while again {
        again = false;
        for entry in &held {
            let there = stored::author_entry(&db, &entry.channel, &entry.slot, &entry.author);
            if there.unwrap().is_some_and(|there| there.entry == *entry) {
                continue;
            }
            let entry = entry.clone().check().unwrap();
            let taken = take::take(&db, &to.state.identity, &entry, now()).unwrap();
            if let take::Taken::Own {
                came_to_count,
                came_to_add,
                ..
            } = taken
            {
                again |= came_to_count + came_to_add > 0;
            }
        }
    }
    for held in held_rows::names(&db).unwrap() {
        let handed = std::time::Instant::now();
        to.state
            .own_channels
            .fetched_from(&held.channel, "stand-in", handed);
    }
}

/// Everything flows both ways until quiet: the relay, and a cycle of each
/// device's adapter, which is what each node's loops do.
fn settle(a: &mut Device, b: &mut Device) {
    for _ in 0..5 {
        relay(a, b);
        relay(b, a);
        a.cycle();
        b.cycle();
    }
}

/// Set a per-device sync setting in node metadata.
fn set_meta(d: &Device, key: &str, value: &str) {
    let db = d.state.db.lock().unwrap();
    meta::set(&db, key, value).unwrap();
}

/// `first`, which follows a phrase, adds `new` under `label`, as
/// `cordelia add-device` does, and `new` accepts what it is handed, as
/// `cordelia accept` does: it follows the same phrase from then, and has
/// the same channel for every name.
fn add(first: &Device, new: &Device, label: &str) {
    let at = now();
    let added = {
        let db = first.state.db.lock().unwrap();
        adding::add_device(&db, &first.state.identity, &new.pk(), label, at).unwrap()
    };
    let db = new.state.db.lock().unwrap();
    let sync_on = meta::get(&db, meta::SYNC_CLAUDE_DIR).unwrap().is_some();
    let accepted = adding::accept(
        &db,
        &new.state.identity,
        &first.pk(),
        at,
        sync_on,
        &added.hand_over,
        at,
    )
    .unwrap();
    assert!(
        matches!(accepted, adding::Accepted::Joined(_)),
        "{accepted:?}"
    );
}

/// Two devices of one person: A makes a recovery phrase and adds B, and B
/// accepts. Nothing syncs until folders are mapped.
fn paired_explicit() -> (Device, Device) {
    let a = Device::new().with_phrase();
    let b = Device::new();
    add(&a, &b, "laptop");
    (a.sync_on(), b.sync_on())
}

/// Two paired devices that each map their home directory, under `~`:
/// home memory syncs between them. Returns the two, and the memory folder
/// of each.
fn paired() -> (Device, Device, PathBuf, PathBuf) {
    let (a, b) = paired_explicit();
    let (a_mem, b_mem) = (a.home_memory(), b.home_memory());
    for d in [&a, &b] {
        map(d, &d.home.clone(), "~");
    }
    (a, b, a_mem, b_mem)
}

/// The names that a device's folders are mapped to.
fn mapped(db: &rusqlite::Connection) -> Vec<String> {
    let mappings: Vec<cordelia_api::types::SyncMapping> = meta::get(db, meta::SYNC_CLAUDE_MAPPINGS)
        .unwrap()
        .map_or_else(Vec::new, |json| serde_json::from_str(&json).unwrap());
    mappings.into_iter().map(|mapping| mapping.name).collect()
}

/// Declare a mapping on a device, as `cordelia sync map` does: through the
/// node's own handler, with its checks, and with what the node then says
/// of the names it syncs.
fn map(d: &Device, folder: &Path, name: &str) {
    let request = cordelia_api::types::SyncMapRequest {
        folder: folder.display().to_string(),
        name: name.into(),
        home: folder == d.home,
    };
    let db = d.state.db.lock().unwrap();
    let before = mapped(&db);
    cordelia_api::sync::add_mapping(&d.state.sync_control, &db, &request, &d.home).unwrap();
    cordelia_api::sync::names_follow(&d.state, &db, &before);
}

/// Remove a mapping on a device, as `cordelia sync unmap` does, through
/// the node's own handler: the folder forgets what it had agreed with its
/// channel. The device says no longer that it syncs the name, and holds
/// it no more.
fn unmap(d: &Device, folder: &Path) {
    let request = cordelia_api::types::SyncUnmapRequest {
        folder: folder.display().to_string(),
    };
    let db = d.state.db.lock().unwrap();
    let before = mapped(&db);
    cordelia_api::sync::remove_mapping(&d.state.sync_control, &db, &request).unwrap();
    cordelia_api::sync::names_follow(&d.state, &db, &before);
}

/// Change a device's sync settings as `cordelia sync claude` does: through
/// the node's own handler, with what it forgets and what it then says of
/// the names it syncs. Turning sync off is followed by what the node's
/// loop does next: it sees to it that this device says of no name that it
/// syncs it, so that this person's other devices stop listing what this
/// one synced.
fn claude(d: &Device, mut body: serde_json::Value) {
    let off = body["enabled"] == false;
    if !off {
        body["enabled"] = true.into();
    }
    let request: cordelia_api::types::SyncClaudeRequest = serde_json::from_value(body).unwrap();
    {
        let db = d.state.db.lock().unwrap();
        let before = mapped(&db);
        cordelia_api::sync::set_claude(&d.state.sync_control, &db, &request, Some(&d.home))
            .unwrap();
        cordelia_api::sync::names_follow(&d.state, &db, &before);
    }
    if off {
        let count = d.state.sync_control.generation();
        assert!(cordelia_sync::claude::withdraw(&d.state, count).unwrap());
    }
}

/// Everything flows both ways until quiet, as `settle`, but returning each
/// device's last report instead of failing on a sync error.
fn settle_reporting(
    a: &mut Device,
    b: &mut Device,
) -> (
    cordelia_sync::claude::CycleReport,
    cordelia_sync::claude::CycleReport,
) {
    let mut reports = Default::default();
    for _ in 0..5 {
        relay(a, b);
        relay(b, a);
        reports = (a.adapter.run_cycle(&a.state), b.adapter.run_cycle(&b.state));
    }
    reports
}

/// The file names in a memory folder, sorted.
fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn read(dir: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(name)).ok()
}

/// The channel a device syncs `name` with: its ID, as it is written.
fn channel_of(d: &mut Device, name: &str) -> String {
    d.cycle()
        .folders
        .into_iter()
        .find(|f| f.project == name)
        .and_then(|f| f.channel_id)
        .unwrap_or_else(|| panic!("{name} is not syncing on this device"))
}

/// Whether a device has anything of the channel whose ID is written
/// `channel`: it holds the name that the channel is of, or its store
/// holds an entry of it. (Every device of a person can derive the channel
/// of every name. It fetches and keeps only those of the names it holds.)
fn holds(d: &Device, channel: &str) -> bool {
    let id = decode_channel_id(channel).unwrap();
    let named = {
        let db = d.state.db.lock().unwrap();
        held_rows::name_of_channel(&db, &id).unwrap().is_some()
    };
    named || !stored_in(d, &id).is_empty()
}

/// What a device takes as the current version of `file` in the name
/// `name`, which it holds: its revision and its value, or `None` where
/// the slot holds no version.
fn version_of(d: &Device, name: &str, file: &str) -> Option<(u64, Value)> {
    let db = d.state.db.lock().unwrap();
    let slot = publish::read(&db, name, file).unwrap().slot;
    slot.current.map(|version| (version.rev, version.value))
}

/// The entries a device holds of the current version of `file` in the
/// name `name`: for each, the key that signed it and its chain.
fn entries_of(d: &Device, name: &str, file: &str) -> Vec<([u8; 32], Option<Vec<Link>>)> {
    let db = d.state.db.lock().unwrap();
    let slot = publish::read(&db, name, file).unwrap().slot;
    let current = slot.current.expect("the slot holds a version");
    current
        .entries
        .into_iter()
        .map(|entry| (entry.author, entry.chain))
        .collect()
}

/// Put in a device's store its own entry under `name` in the channel
/// whose secret is `secret`, at `rev`, with the chain of a new file's
/// entry: what the device would hold had it written it, whatever a
/// command or the adapter would have refused to write.
fn put(d: &Device, secret: &[u8; 32], name: &str, value: Value, rev: u64) {
    let inside = Inside {
        name: name.to_string(),
        value,
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(secret, &d.state.identity, rev, &inside)
        .unwrap()
        .check()
        .unwrap();
    let db = d.state.db.lock().unwrap();
    let outcome = stored::store(&db, &entry, now()).unwrap();
    assert_eq!(outcome, stored::Outcome::Stored);
}

/// Publish `value` under `file` in the name `name`, which the device
/// holds, over whatever the slot holds: as its node's API does for any
/// caller, with none of the adapter's checks.
fn write(d: &Device, name: &str, file: &str, value: Value) {
    let db = d.state.db.lock().unwrap();
    let read = publish::read(&db, name, file).unwrap();
    let write = publish::Write {
        name,
        file,
        value,
        planned: publish::PlannedAgainst::what_is_in(&read.slot),
        merge: None,
    };
    let published = publish::publish(&db, &d.state.identity, &write, now()).unwrap();
    assert!(
        matches!(published, publish::Published::Made(_)),
        "{published:?}"
    );
}

/// What a device's store holds in the channel whose secret is `secret`,
/// opened: each entry's signer, with what the entry holds.
fn opened(d: &Device, secret: &[u8; 32]) -> Vec<([u8; 32], Inside)> {
    let channel = derive::channel_id(secret).unwrap();
    stored_in(d, &channel)
        .into_iter()
        .map(|held| {
            let entry = held.entry.check().unwrap();
            (entry.author, entry.open(secret).unwrap())
        })
        .collect()
}

/// What a chain names `text` by, as signed by the device `by`.
fn link(text: &str, by: &Device) -> Link {
    Link::of(&Value::Text(text.into()), by.pk())
}

const PROJECT: &str = "github.com/seed-drill/cordelia-node";

#[test]
fn home_memory_syncs_both_ways() {
    let (mut a, mut b, a_mem, b_mem) = paired();

    std::fs::write(a_mem.join("user_role.md"), "Prefers short answers.\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(
        read(&b_mem, "user_role.md").as_deref(),
        Some("Prefers short answers.\n")
    );

    std::fs::write(
        b_mem.join("user_role.md"),
        "Prefers short answers, in British English.\n",
    )
    .unwrap();
    settle(&mut a, &mut b);
    assert_eq!(
        read(&a_mem, "user_role.md").as_deref(),
        Some("Prefers short answers, in British English.\n")
    );

    // Deleting on one device deletes on the other.
    std::fs::remove_file(a_mem.join("user_role.md")).unwrap();
    settle(&mut a, &mut b);
    assert_eq!(read(&b_mem, "user_role.md"), None);
}

#[test]
fn project_memory_follows_the_repo_not_the_path() {
    let (mut a, mut b, a_home, b_home) = paired();
    // Same repository, different paths, so different Claude folder names:
    // each device maps its clone to the one name.
    let (a_repo, b_repo) = (a.clone_at("Work/cordelia-node"), b.clone_at("src/cn"));
    let a_mem = a.claude_folder(&a_repo);
    let b_mem = b.claude_folder(&b_repo);
    assert_ne!(
        a_mem.parent().unwrap().file_name(),
        b_mem.parent().unwrap().file_name()
    );
    map(&a, &a_repo, PROJECT);
    map(&b, &b_repo, PROJECT);

    std::fs::write(a_mem.join("decision.md"), "Invite-only channels only.\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(
        read(&b_mem, "decision.md").as_deref(),
        Some("Invite-only channels only.\n")
    );

    // One channel for the project, shared by both devices.
    let report = b.cycle();
    let project = report
        .folders
        .iter()
        .find(|f| f.project == "github.com/seed-drill/cordelia-node")
        .expect("project folder reported");
    assert!(project.channel_id.is_some() && !project.waiting);
    assert_eq!(project.channel_id, Some(channel_of(&mut a, PROJECT)));

    // Home memory does not leak into the project folder, or vice versa.
    std::fs::write(a_home.join("personal.md"), "home only\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(read(&b_mem, "personal.md"), None);
    assert_eq!(read(&b_home, "personal.md").as_deref(), Some("home only\n"));
    assert_eq!(read(&b_home, "decision.md"), None);
}

#[test]
fn concurrent_edits_leave_a_conflict_file_everywhere() {
    let (mut a, mut b, a_mem, b_mem) = paired();
    std::fs::write(a_mem.join("notes.md"), "base\n").unwrap();
    settle(&mut a, &mut b);

    // Both edit before hearing from each other.
    std::fs::write(a_mem.join("notes.md"), "from a\n").unwrap();
    std::fs::write(b_mem.join("notes.md"), "from b\n").unwrap();
    a.cycle();
    b.cycle();
    settle(&mut a, &mut b);

    // Same main file on both devices; the other edit kept beside it, on both.
    let main_a = read(&a_mem, "notes.md").unwrap();
    assert_eq!(read(&b_mem, "notes.md").unwrap(), main_a);
    let conflicts = |dir: &Path| -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("notes.conflict-"))
            .collect();
        v.sort();
        v
    };
    let on_a = conflicts(&a_mem);
    assert_eq!(on_a.len(), 1, "{on_a:?}");
    assert_eq!(conflicts(&b_mem), on_a);
    let kept = read(&a_mem, &on_a[0]).unwrap();
    let mut both = vec![main_a, kept];
    both.sort();
    assert_eq!(
        both,
        vec!["from a\n".to_string(), "from b\n".to_string()],
        "no edit lost"
    );

    // The report lists the conflict file (what the status indicator shows)
    // until it is merged and deleted.
    let listed = |report: cordelia_sync::claude::CycleReport| -> Vec<String> {
        report
            .folders
            .into_iter()
            .flat_map(|f| f.conflict_files)
            .collect()
    };
    let path = a_mem.join(&on_a[0]).display().to_string();
    assert_eq!(listed(a.cycle()), vec![path.clone()]);
    std::fs::remove_file(&path).unwrap();
    assert!(listed(a.cycle()).is_empty());
}

#[test]
fn memory_index_merges_instead_of_conflicting() {
    let (mut a, mut b, a_mem, b_mem) = paired();
    std::fs::write(a_mem.join("MEMORY.md"), "- [Base](base.md) — shared\n").unwrap();
    settle(&mut a, &mut b);

    std::fs::write(
        a_mem.join("MEMORY.md"),
        "- [Base](base.md) — shared\n- [A](a.md) — from a\n",
    )
    .unwrap();
    std::fs::write(
        b_mem.join("MEMORY.md"),
        "- [Base](base.md) — shared\n- [B](b.md) — from b\n",
    )
    .unwrap();
    a.cycle();
    b.cycle();
    settle(&mut a, &mut b);

    let index = read(&a_mem, "MEMORY.md").unwrap();
    assert_eq!(read(&b_mem, "MEMORY.md").unwrap(), index);
    for line in ["(base.md)", "(a.md)", "(b.md)"] {
        assert!(
            index.contains(line),
            "{line} missing from merged index:\n{index}"
        );
    }
    assert!(
        !std::fs::read_dir(&a_mem).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("conflict")),
        "the index merges; no conflict file"
    );
}

// ── An edit that another device has overtaken is kept ──────────────────

/// The conflict files in `dir` that are copies of `name`, each with its
/// text, sorted.
fn copies_of(dir: &Path, name: &str) -> Vec<(String, String)> {
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    let start = format!("{stem}.conflict-");
    let mut copies: Vec<(String, String)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&start))
        .map(|n| {
            let text = read(dir, &n).unwrap();
            (n, text)
        })
        .collect();
    copies.sort();
    copies
}

/// Two devices that agree on `base` as the text of one file, and are then
/// apart. Each writes the texts given to the file in turn (`None` deletes
/// it), with a cycle after each that publishes it, and hears nothing from
/// the other. Then they meet. Returns the two devices and their memory
/// folders.
fn apart(
    name: &str,
    base: &str,
    b_does: &[Option<&str>],
    a_does: &[Option<&str>],
) -> (Device, Device, PathBuf, PathBuf) {
    let (mut a, mut b, a_mem, b_mem) = paired();
    std::fs::write(a_mem.join(name), base).unwrap();
    settle(&mut a, &mut b);
    assert_eq!(read(&b_mem, name).as_deref(), Some(base));
    for (device, mem, does) in [(&mut b, &b_mem, b_does), (&mut a, &a_mem, a_does)] {
        for text in does {
            match text {
                Some(text) => std::fs::write(mem.join(name), text).unwrap(),
                None => std::fs::remove_file(mem.join(name)).unwrap(),
            }
            // Each is published by itself, so each is a revision: the
            // device that does more ends at the higher one.
            let report = device.cycle();
            let published: usize = report.folders.iter().map(|f| f.published).sum();
            assert_eq!(published, 1, "{report:?}");
        }
    }
    settle(&mut a, &mut b);
    (a, b, a_mem, b_mem)
}

/// One edit on one device against two on the other (#79). The second of
/// the two is at a higher revision than the one, which shows only that its
/// writer had made more edits. It is taken, as it always was. The one is
/// now kept beside it, on both devices: it used to be in no file on
/// either.
#[test]
fn an_edit_overtaken_by_two_is_kept_beside_the_file() {
    let (_a, _b, a_mem, b_mem) = apart(
        "notes.md",
        "base\n",
        &[Some("from b\n")],
        &[Some("from a, one\n"), Some("from a, two\n")],
    );
    for mem in [&a_mem, &b_mem] {
        assert_eq!(read(mem, "notes.md").as_deref(), Some("from a, two\n"));
        let copies = copies_of(mem, "notes.md");
        assert_eq!(copies.len(), 1, "{copies:?}");
        assert_eq!(copies[0].1, "from b\n");
    }
    assert_eq!(copies_of(&a_mem, "notes.md"), copies_of(&b_mem, "notes.md"));
}

/// Two edits against three. The first of the two was replaced by the
/// device that made it, knowingly. The second is the one that was
/// overtaken, and it is kept.
#[test]
fn the_last_of_two_edits_overtaken_by_three_is_kept() {
    let (_a, _b, a_mem, b_mem) = apart(
        "notes.md",
        "base\n",
        &[Some("from b, one\n"), Some("from b, two\n")],
        &[
            Some("from a, one\n"),
            Some("from a, two\n"),
            Some("from a, three\n"),
        ],
    );
    for mem in [&a_mem, &b_mem] {
        assert_eq!(read(mem, "notes.md").as_deref(), Some("from a, three\n"));
        let copies = copies_of(mem, "notes.md");
        assert_eq!(copies.len(), 1, "{copies:?}");
        assert_eq!(copies[0].1, "from b, two\n");
    }
}

/// One edit against an edit and then a delete. The delete is at a higher
/// revision, so the file goes on both devices, as it always did. The edit
/// that the delete was made without sight of is kept as a conflict file.
#[test]
fn an_edit_overtaken_by_an_edit_and_a_delete_is_kept() {
    let (_a, _b, a_mem, b_mem) = apart(
        "notes.md",
        "base\n",
        &[Some("from b\n")],
        &[Some("from a\n"), None],
    );
    for mem in [&a_mem, &b_mem] {
        assert_eq!(read(mem, "notes.md"), None);
        let copies = copies_of(mem, "notes.md");
        assert_eq!(copies.len(), 1, "{copies:?}");
        assert_eq!(copies[0].1, "from b\n");
    }
}

/// The index, with one line added on one device against two on the
/// other. At a higher revision it is not merged: the index is taken as
/// any file is, and the index that was overtaken is kept whole beside
/// it, with the line that used to be lost.
#[test]
fn an_index_overtaken_by_two_edits_is_kept_whole_beside_it() {
    let base = "- [Base](base.md) — shared\n";
    let from_b = format!("{base}- [B](b.md) — from b\n");
    let one = format!("{base}- [A1](a1.md) — from a\n");
    let two = format!("{one}- [A2](a2.md) — from a\n");
    let (_a, _b, a_mem, b_mem) = apart(
        "MEMORY.md",
        base,
        &[Some(&from_b)],
        &[Some(&one), Some(&two)],
    );
    for mem in [&a_mem, &b_mem] {
        assert_eq!(read(mem, "MEMORY.md").as_deref(), Some(two.as_str()));
        let copies = copies_of(mem, "MEMORY.md");
        assert_eq!(copies.len(), 1, "{copies:?}");
        assert_eq!(copies[0].1, from_b);
    }
}

/// Only the entries of memory files say what they were written after: an
/// edit's entry names, first in its chain, the version it was written
/// over. What the adapter writes in the personal channel (each device's
/// word that it syncs a name) is written after nothing: it has the chain
/// of a new file's entry, and is read from its own signer alone.
#[test]
fn only_memory_entries_say_what_they_were_written_after() {
    let (mut a, mut b, a_mem, b_mem) = paired();
    std::fs::write(a_mem.join("notes.md"), "one\n").unwrap();
    settle(&mut a, &mut b);
    std::fs::write(b_mem.join("notes.md"), "two\n").unwrap();
    settle(&mut a, &mut b);

    // Each of the two devices' words that it syncs home memory.
    let mut words: Vec<([u8; 32], Inside)> = opened(&a, &personal_secret(&a))
        .into_iter()
        .filter(|(_, inside)| inside.name.starts_with("name/"))
        .collect();
    words.sort_by_key(|(signer, _)| *signer);
    let mut signers = vec![a.pk(), b.pk()];
    signers.sort();
    assert_eq!(
        words.iter().map(|(signer, _)| *signer).collect::<Vec<_>>(),
        signers
    );
    for (_, word) in &words {
        assert_eq!(word.name, names::word_name("~"));
        assert_eq!(word.chain, Some(Vec::new()), "{word:?}");
    }

    // The one memory file, whose version is B's edit of what A wrote.
    let in_home: Vec<(String, Vec<Option<Vec<Link>>>)> = {
        let db = a.state.db.lock().unwrap();
        publish::read_name(&db, "~")
            .unwrap()
            .slots
            .into_iter()
            .filter_map(|slot| slot.current)
            .map(|version| {
                let chains = version.entries.into_iter().map(|e| e.chain).collect();
                (version.name, chains)
            })
            .collect()
    };
    assert_eq!(
        in_home,
        [("notes.md".to_string(), vec![Some(vec![link("one\n", &a)])])]
    );
}

#[test]
fn keys_that_are_not_safe_file_names_are_never_written() {
    let (mut a, mut b, a_mem, b_mem) = paired();
    std::fs::write(a_mem.join("ok.md"), "fine\n").unwrap();
    settle(&mut a, &mut b);

    // One of the person's devices publishes, through its node's API,
    // names that would escape the memory folder.
    let unsafe_names = ["../escaped.md", ".hidden.md", "sub/dir.md", "/abs.md"];
    for name in unsafe_names {
        write(&a, "~", name, Value::Text("evil".into()));
    }
    std::fs::write(a_mem.join("later.md"), "also fine\n").unwrap();
    settle(&mut a, &mut b);

    // The channel delivers, those entries with the rest; the unsafe names
    // are not written anywhere.
    assert_eq!(read(&b_mem, "later.md").as_deref(), Some("also fine\n"));
    for name in unsafe_names {
        assert_eq!(
            version_of(&b, "~", name),
            Some((1, Value::Text("evil".into()))),
            "{name}"
        );
    }
    assert!(!b_mem.parent().unwrap().join("escaped.md").exists());
    assert!(!b_mem.join(".hidden.md").exists());
    assert!(!b_mem.join("sub").exists());
    assert!(!b_mem.join("abs.md").exists());
    let mut names: Vec<String> = std::fs::read_dir(&b_mem)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["later.md", "ok.md"]);
}

#[test]
fn folders_without_a_repository_are_reported_not_synced() {
    let mut a = Device::new().with_phrase().sync_on();
    let scratch = a.home.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let mem = a.claude_folder(&scratch);
    std::fs::write(mem.join("temp.md"), "not synced\n").unwrap();

    let report = a.cycle();
    assert_eq!(
        report.unsynced,
        vec![a.folder_of(&scratch).display().to_string()]
    );
    assert!(report.folders.is_empty(), "{:?}", report.folders);
    assert!(report.available.is_empty());
}

/// A device that does not map a project has nothing of it: it does not
/// hold the name, and its store takes no entry of the name's channel,
/// though a relay hands it every one. (Every device of a person can
/// derive the channel of every name. What keeps a project's memory off a
/// device is that the device neither fetches nor stores it.)
#[test]
fn a_device_without_the_project_holds_nothing_of_it() {
    let (mut a, mut b, _, _) = paired();
    let a_repo = a.clone_at("Work/cordelia-node");
    let a_mem = a.claude_folder(&a_repo);
    std::fs::write(a_mem.join("decision.md"), "Invite-only channels only.\n").unwrap();
    map(&a, &a_repo, PROJECT);
    // B syncs only its home memory: it does not map the project.
    settle(&mut a, &mut b);

    let report = a.cycle();
    let channel = report
        .folders
        .iter()
        .find(|f| f.project == "github.com/seed-drill/cordelia-node")
        .and_then(|f| f.channel_id.clone())
        .expect("A syncs the project");
    // Not for want of being handed it: B refuses each entry of the
    // project's channel, as one of a channel that is none of its own.
    let offered = stored_in(&a, &decode_channel_id(&channel).unwrap());
    assert!(!offered.is_empty());
    for held in offered {
        let entry = held.entry.check().unwrap();
        let db = b.state.db.lock().unwrap();
        assert_eq!(
            take::take(&db, &b.state.identity, &entry, now()).unwrap(),
            take::Taken::Refused(take::NotTaken::AnotherChannel)
        );
    }
    assert!(
        !holds(&b, &channel),
        "B holds nothing of a project it does not have"
    );

    // B clones the project, and Claude Code runs there: it is found, and
    // still nothing of it is held. Once B maps its clone it has the
    // project's channel, and the memory arrives.
    let b_repo = b.clone_at("src/cn");
    let b_mem = b.claude_folder(&b_repo);
    settle(&mut a, &mut b);
    assert!(!holds(&b, &channel), "found is not mapped");
    assert_eq!(read(&b_mem, "decision.md"), None);
    map(&b, &b_repo, PROJECT);
    settle(&mut a, &mut b);
    assert_eq!(
        read(&b_mem, "decision.md").as_deref(),
        Some("Invite-only channels only.\n")
    );
    assert_eq!(channel_of(&mut b, PROJECT), channel);
}

// ── Nothing syncs until it is mapped ───────────────────────────────────

#[test]
fn nothing_syncs_until_a_folder_is_mapped() {
    let (mut a, mut b) = paired_explicit();
    let a_repo = a.clone_at("Work/cordelia-node");
    let a_mem = a.claude_folder(&a_repo);
    let a_home = a.home_memory();
    let a_notes = a.plain_dir("notes");
    let a_notes_mem = a.claude_folder(&a_notes);
    std::fs::write(a_mem.join("decision.md"), "Invite-only channels only.\n").unwrap();
    std::fs::write(a_home.join("user_role.md"), "general profile\n").unwrap();
    std::fs::write(a_notes_mem.join("idea.md"), "a thought\n").unwrap();
    let b_repo = b.clone_at("src/cn");
    let b_mem = b.claude_folder(&b_repo);
    let b_home = b.home_memory();
    settle(&mut a, &mut b);

    // Nothing syncs. What was found is listed with the folder to map and
    // the name it would get; a folder that is not a repository has none.
    let report = a.cycle();
    assert!(report.folders.is_empty(), "{:?}", report.folders);
    assert!(report.available.is_empty(), "no device syncs anything");
    let shown = |dir: &Path| Some(dir.display().to_string());
    let mut found: Vec<(Option<String>, Option<String>)> = report
        .unmapped
        .iter()
        .map(|u| (u.cwd.clone(), u.name.clone()))
        .collect();
    found.sort();
    let mut want = vec![
        (shown(&a.home), Some("~".to_string())),
        (shown(&a_repo), Some(PROJECT.to_string())),
        (shown(&a_notes), None),
    ];
    want.sort();
    assert_eq!(found, want);
    assert_eq!(
        report.unsynced,
        vec![a.folder_of(&a_notes).display().to_string()]
    );
    assert_eq!(read(&b_mem, "decision.md"), None);
    assert_eq!(read(&b_home, "user_role.md"), None);

    // A maps the project. It syncs from A; B sees the name on offer, and
    // still holds nothing of its memory.
    map(&a, &a_repo, PROJECT);
    settle(&mut a, &mut b);
    let report = a.cycle();
    assert_eq!(report.folders.len(), 1, "{:?}", report.folders);
    let folder = &report.folders[0];
    assert!(folder.mapped && folder.project == PROJECT && !folder.waiting);
    assert_eq!(folder.cwd, shown(&a_repo));
    assert_eq!(report.unmapped.len(), 2, "home and notes are still listed");
    let channel = channel_of(&mut a, PROJECT);
    assert_eq!(b.cycle().available, vec![PROJECT.to_string()]);
    assert_eq!(read(&b_mem, "decision.md"), None, "B has not mapped it");
    assert!(!holds(&b, &channel));

    // B maps its clone: the memory arrives. Home was mapped by neither.
    map(&b, &b_repo, PROJECT);
    settle(&mut a, &mut b);
    assert_eq!(
        read(&b_mem, "decision.md").as_deref(),
        Some("Invite-only channels only.\n")
    );
    assert_eq!(read(&b_home, "user_role.md"), None);
    assert_eq!(read(&b_home, "idea.md"), None);
    assert!(b.cycle().available.is_empty());
}

/// Only what is mapped syncs (decision 2026-10-04 §10.1). A folder that
/// is found and not mapped is never a target of a cycle, whatever is
/// stored of a scope, of exclusions and of a switch for home memory: the
/// adapter reads none of them. The device holds no name for it, says of
/// it to no other device that it syncs it, and publishes nothing of it.
#[test]
fn what_is_found_is_never_synced_whatever_is_stored_of_a_scope() {
    for scope in [Some("on"), Some("off"), None] {
        let mut a = Device::new().with_phrase().sync_on();
        match scope {
            Some(scope) => set_meta(&a, meta::SYNC_CLAUDE_ALL, scope),
            None => {
                let db = a.state.db.lock().unwrap();
                meta::remove(&db, meta::SYNC_CLAUDE_ALL).unwrap();
            }
        }
        // What an earlier version stored, each way round: read by nothing.
        if scope == Some("on") {
            set_meta(&a, meta::SYNC_CLAUDE_HOME, "off");
            set_meta(&a, meta::SYNC_CLAUDE_EXCLUDE, r#"["lab-notes"]"#);
        }
        let home = a.home_memory();
        std::fs::write(home.join("user_role.md"), "stays here\n").unwrap();
        let repo = a.clone_at("Work/cordelia-node");
        let in_repo = a.claude_folder(&repo);
        std::fs::write(in_repo.join("decision.md"), "stays here too\n").unwrap();
        let notes = a.plain_dir("notes");
        let mem = a.claude_folder(&notes);
        std::fs::write(mem.join("idea.md"), "a thought\n").unwrap();
        map(&a, &notes, "lab-notes");

        let report = a.cycle();
        let targets: Vec<(&str, bool)> = report
            .folders
            .iter()
            .map(|f| (f.project.as_str(), f.mapped))
            .collect();
        assert_eq!(targets, [("lab-notes", true)], "{scope:?}");
        assert!(report.excluded.is_empty(), "{scope:?}");
        let mut found: Vec<Option<&str>> =
            report.unmapped.iter().map(|u| u.name.as_deref()).collect();
        found.sort();
        assert_eq!(found, [Some(PROJECT), Some("~")], "{scope:?}");

        // The one name is held and said. Of what was found: no name, no
        // word, and no entry in the channel that each would have.
        let db = a.state.db.lock().unwrap();
        let held: Vec<String> = held_rows::names(&db)
            .unwrap()
            .into_iter()
            .map(|held| held.name)
            .collect();
        assert_eq!(held, ["lab-notes"], "{scope:?}");
        let said = names::said_here(&db, &a.state.identity).unwrap();
        assert_eq!(said.into_iter().collect::<Vec<_>>(), ["lab-notes"]);
        let person = held_rows::applied_secret(&db).unwrap().unwrap();
        for name in ["~", PROJECT] {
            let secret = derive::own_secret(&person.secret, name).unwrap();
            let channel = derive::channel_id(&secret).unwrap();
            let stored = stored::channel_entries_after(&db, &channel, 0, 10).unwrap();
            assert!(stored.is_empty(), "{scope:?}: {name}");
        }
        let published = stored::channel_entries_after(
            &db,
            &held_rows::channel_of_name(&db, "lab-notes")
                .unwrap()
                .unwrap(),
            0,
            10,
        );
        assert_eq!(published.unwrap().len(), 1, "{scope:?}");
    }
}

#[test]
fn a_folder_that_is_not_a_repository_syncs_under_a_given_name() {
    let (mut a, mut b) = paired_explicit();
    let a_notes = a.plain_dir("notes");
    let a_mem = a.claude_folder(&a_notes);
    std::fs::write(a_mem.join("idea.md"), "a thought\n").unwrap();
    map(&a, &a_notes, "lab-notes");
    settle(&mut a, &mut b);
    assert_eq!(b.cycle().available, vec!["lab-notes".to_string()]);

    // B maps a different folder to the same name, before Claude Code has
    // ever run there. The memory arrives where Claude Code will look.
    let b_notes = b.plain_dir("Documents/lab");
    let b_mem = b.folder_of(&b_notes).join("memory");
    assert!(!b_mem.exists());
    map(&b, &b_notes, "lab-notes");
    settle(&mut a, &mut b);
    assert_eq!(read(&b_mem, "idea.md").as_deref(), Some("a thought\n"));

    std::fs::write(b_mem.join("idea.md"), "a better thought\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(
        read(&a_mem, "idea.md").as_deref(),
        Some("a better thought\n")
    );
}

#[test]
fn home_memory_reaches_only_the_devices_that_map_it() {
    let (mut a, mut b) = paired_explicit();
    let a_home = a.home_memory();
    let b_home = b.home_memory();
    std::fs::write(a_home.join("user_role.md"), "general profile\n").unwrap();
    std::fs::write(b_home.join("lab_notes.md"), "lab only\n").unwrap();
    map(&a, &a.home.clone(), "~");
    settle(&mut a, &mut b);

    // B is offered home memory, and holds none of it: not the files,
    // nothing of its channel, and nothing in the personal channel that
    // every device has.
    let channel = channel_of(&mut a, "~");
    assert_eq!(b.cycle().available, vec!["~".to_string()]);
    assert_eq!(read(&b_home, "user_role.md"), None);
    assert_eq!(read(&a_home, "lab_notes.md"), None);
    assert!(!holds(&b, &channel));
    let in_personal = opened(&b, &personal_secret(&b));
    assert!(!in_personal.is_empty());
    for (_, entry) in in_personal {
        assert!(
            !String::from_utf8_lossy(entry.value.bytes()).contains("general profile"),
            "home memory in the personal channel: {}",
            entry.name
        );
    }

    // Once B maps its home directory, both sides merge.
    map(&b, &b.home.clone(), "~");
    settle(&mut a, &mut b);
    assert_eq!(
        read(&b_home, "user_role.md").as_deref(),
        Some("general profile\n")
    );
    assert_eq!(read(&a_home, "lab_notes.md").as_deref(), Some("lab only\n"));
}

#[test]
fn memory_is_kept_per_repository_not_per_folder() {
    let (mut a, mut b) = paired_explicit();
    // On A every session started in a subdirectory. Claude Code keeps the
    // memory in the repository's folder, which then has no transcripts.
    let a_repo = a.clone_at("Work/cordelia-node");
    let a_sub = a_repo.join("crates/x");
    std::fs::create_dir_all(&a_sub).unwrap();
    let a_sub_folder = a.session_in(&a_sub);
    let a_mem = a.folder_of(&a_repo).join("memory");
    std::fs::create_dir_all(&a_mem).unwrap();
    std::fs::write(a_mem.join("decision.md"), "Invite-only channels only.\n").unwrap();

    // One thing to map: the repository, not the subdirectory.
    assert_eq!(
        a.cycle().unmapped,
        vec![cordelia_sync::claude::Found {
            folder: a.folder_of(&a_repo).display().to_string(),
            cwd: Some(a_repo.display().to_string()),
            name: Some(PROJECT.to_string()),
        }]
    );
    map(&a, &a_repo, PROJECT);

    // B has only run in a subdirectory too, and maps its repository.
    let b_repo = b.clone_at("src/cn");
    let b_sub = b_repo.join("docs");
    std::fs::create_dir_all(&b_sub).unwrap();
    let b_sub_folder = b.session_in(&b_sub);
    map(&b, &b_repo, PROJECT);
    settle(&mut a, &mut b);

    // The memory arrives where Claude Code reads it: the repository's
    // folder. Session folders of subdirectories are left alone.
    assert_eq!(
        read(&b.folder_of(&b_repo).join("memory"), "decision.md").as_deref(),
        Some("Invite-only channels only.\n")
    );
    assert!(!b_sub_folder.join("memory").exists());
    assert!(!a_sub_folder.join("memory").exists());
    let report = b.cycle();
    assert_eq!(report.folders.len(), 1, "{:?}", report.folders);
    assert_eq!(
        report.folders[0].cwd,
        Some(b_repo.display().to_string()),
        "reported as the repository"
    );
    assert!(report.unmapped.is_empty(), "{:?}", report.unmapped);
}

#[test]
fn a_mapping_syncs_the_folder_named_after_it_and_no_other() {
    let (mut a, mut b) = paired_explicit();
    let a_notes = a.plain_dir("notes");
    let a_mem = a.claude_folder(&a_notes);
    std::fs::write(a_mem.join("idea.md"), "a thought\n").unwrap();
    map(&a, &a_notes, "lab-notes");

    // On B another folder's transcripts claim the mapped directory. A
    // mapping never follows transcripts: that folder is not touched.
    let b_notes = b.plain_dir("notes");
    let other = b.claude_folder(&b.plain_dir("other"));
    std::fs::write(other.join("private.md"), "stays here\n").unwrap();
    std::fs::write(
        other.parent().unwrap().join("session.jsonl"),
        format!("{{\"cwd\":{:?}}}\n", b_notes.display().to_string()),
    )
    .unwrap();
    map(&b, &b_notes, "lab-notes");
    settle(&mut a, &mut b);

    assert_eq!(
        read(&b.folder_of(&b_notes).join("memory"), "idea.md").as_deref(),
        Some("a thought\n")
    );
    assert_eq!(read(&other, "idea.md"), None);
    assert_eq!(read(&a_mem, "private.md"), None);
}

/// A tree laid out by hand, as some installs used to limit what syncs
/// before mappings existed: folders with any name, each holding a `*.jsonl`
/// that names a working directory and a `memory` link to the real folder.
/// With sync pointed at the tree, what is in it is found and listed, and
/// nothing of it syncs (decision 2026-10-04 §10.1): not under the name of
/// the repository that its transcript records, and not when that
/// repository's directory is mapped, which syncs the folder that Claude
/// Code names after the directory and no other.
#[test]
fn a_tree_laid_out_by_hand_is_listed_and_never_synced() {
    let (mut a, mut b) = paired_explicit();
    let a_repo = a.clone_at("Work/cordelia-node");
    let real = a.claude_folder(&a.plain_dir("Work"));
    std::fs::write(real.join("decision.md"), "Invite-only channels only.\n").unwrap();

    let tree = a.home.join(".cordelia/scope");
    let entry = tree.join("projects/workspace");
    std::fs::create_dir_all(&entry).unwrap();
    std::os::unix::fs::symlink(&real, entry.join("memory")).unwrap();
    std::fs::write(
        entry.join("scope.jsonl"),
        format!(
            "{{\"type\":\"scope\",\"cwd\":{:?}}}\n",
            a_repo.display().to_string()
        ),
    )
    .unwrap();
    // Sync is pointed at the tree, as `cordelia sync claude --dir` does.
    set_meta(&a, meta::SYNC_CLAUDE_DIR, &tree.display().to_string());
    a.adapter = ClaudeAdapter::new(tree.clone(), a.home.clone(), &a.pk());

    let b_repo = b.clone_at("src/cn");
    let b_mem = b.claude_folder(&b_repo);
    map(&b, &b_repo, PROJECT);
    settle(&mut a, &mut b);
    assert_eq!(read(&b_mem, "decision.md"), None);
    let report = a.cycle();
    assert!(report.folders.is_empty(), "{:?}", report.folders);
    assert_eq!(report.unmapped.len(), 1, "{:?}", report.unmapped);
    assert_eq!(report.unmapped[0].folder, entry.display().to_string());
    assert!(!holds(&a, &channel_of(&mut b, PROJECT)));

    // The repository's directory is mapped: that syncs the folder Claude
    // Code names after it under the directory that is set, which is
    // another folder than the tree's. Nothing that the tree holds leaves.
    map(&a, &a_repo, PROJECT);
    std::fs::write(b_mem.join("reply.md"), "from b\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(read(&b_mem, "decision.md"), None);
    assert_eq!(read(&real, "reply.md"), None);
    let named_after_it = cordelia_sync::discover::claude_folder(&tree, &a_repo).unwrap();
    assert_eq!(
        read(&named_after_it.join("memory"), "reply.md").as_deref(),
        Some("from b\n")
    );
    let link = entry.join("memory").symlink_metadata().unwrap();
    assert!(link.file_type().is_symlink(), "the link is left as it is");
}

#[test]
fn what_other_devices_sync_is_what_they_sync_now() {
    let (mut a, mut b) = paired_explicit();
    let a_notes = a.plain_dir("notes");
    a.claude_folder(&a_notes);
    map(&a, &a_notes, "lab-notes");
    settle(&mut a, &mut b);
    assert_eq!(b.cycle().available, vec!["lab-notes".to_string()]);
    assert!(a.cycle().available.is_empty(), "A syncs it itself");

    // A device speaks only for itself: its word that it syncs a name is
    // read from the key that signed it, and from no other. So B cannot
    // take A's word back, whatever it writes under that name: here a
    // delete, far above A's word. D, a third device, hears B's before A
    // can answer it.
    let d = Device::new();
    add(&a, &d, "laptop");
    let mut d = d.sync_on();
    settle(&mut a, &mut d);
    assert_eq!(d.cycle().available, vec!["lab-notes".to_string()]);
    let word = names::word_name("lab-notes");
    put(&b, &personal_secret(&b), &word, Value::Delete, 1000);
    relay(&b, &d);
    let in_personal = opened(&d, &personal_secret(&d));
    assert!(
        in_personal
            .iter()
            .any(|(signer, entry)| *signer == b.pk() && entry.name == word),
        "D holds what B wrote"
    );
    assert_eq!(
        d.cycle().available,
        vec!["lab-notes".to_string()],
        "a word is read only from the device that signed it"
    );
    settle(&mut a, &mut b);
    settle(&mut a, &mut d);
    assert_eq!(b.cycle().available, vec!["lab-notes".to_string()]);
    assert_eq!(d.cycle().available, vec!["lab-notes".to_string()]);

    // A stops syncing it, and its next cycle says so no longer. No device
    // syncs the name now, so it is no longer on offer.
    set_meta(&a, meta::SYNC_CLAUDE_MAPPINGS, "[]");
    settle(&mut a, &mut b);
    assert!(b.cycle().available.is_empty());

    // Likewise when sync is turned off altogether.
    map(&a, &a_notes, "lab-notes");
    settle(&mut a, &mut b);
    assert_eq!(b.cycle().available, vec!["lab-notes".to_string()]);
    claude(&a, serde_json::json!({ "enabled": false }));
    relay(&a, &b);
    assert!(b.cycle().available.is_empty());
}

#[test]
fn each_folder_reports_its_channel_and_when_it_last_sent_and_received() {
    let (mut a, mut b) = paired_explicit();
    let a_notes = a.plain_dir("notes");
    let a_mem = a.claude_folder(&a_notes);
    let b_notes = b.plain_dir("notes");
    b.claude_folder(&b_notes);
    map(&a, &a_notes, "lab-notes");
    map(&b, &b_notes, "lab-notes");

    // Nothing has moved yet.
    let folder = a.cycle().folders.remove(0);
    assert!(folder.channel_id.is_some(), "{folder:?}");
    assert_eq!(
        (&folder.last_pulled_at, &folder.last_published_at),
        (&None, &None)
    );

    std::fs::write(a_mem.join("idea.md"), "a thought\n").unwrap();
    settle(&mut a, &mut b);
    let sent = a.cycle().folders.remove(0);
    let received = b.cycle().folders.remove(0);
    assert_eq!(sent.channel_id, received.channel_id);
    assert!(sent.last_published_at.is_some() && sent.last_pulled_at.is_none());
    assert!(received.last_pulled_at.is_some() && received.last_published_at.is_none());

    // The times are of the last change, not of the last cycle, and they
    // outlive a restart of the adapter.
    let again = a.cycle().folders.remove(0);
    assert_eq!(again.last_published_at, sent.last_published_at);
    a.adapter = ClaudeAdapter::new(a.home.join(".claude"), a.home.clone(), &a.pk());
    let restarted = a.cycle().folders.remove(0);
    assert_eq!(restarted.last_published_at, sent.last_published_at);
}

#[test]
fn a_folder_that_fails_is_reported_and_the_others_still_sync() {
    let (mut a, mut b) = paired_explicit();
    let a_notes = a.plain_dir("notes");
    let a_ideas = a.plain_dir("ideas");
    std::fs::write(a.claude_folder(&a_notes).join("note.md"), "a note\n").unwrap();
    std::fs::write(a.claude_folder(&a_ideas).join("idea.md"), "an idea\n").unwrap();
    map(&a, &a_notes, "lab-notes");
    map(&a, &a_ideas, "lab-ideas");

    // On B, the place where the notes memory should go is a file, so
    // nothing can be written there.
    let b_notes = b.plain_dir("notes");
    let b_ideas = b.plain_dir("ideas");
    let blocked = b.session_in(&b_notes).join("memory");
    std::fs::write(&blocked, "not a folder").unwrap();
    let b_ideas_mem = b.claude_folder(&b_ideas);
    map(&b, &b_notes, "lab-notes");
    map(&b, &b_ideas, "lab-ideas");

    let mut report = Default::default();
    for _ in 0..5 {
        relay(&a, &b);
        relay(&b, &a);
        a.cycle();
        report = b.adapter.run_cycle(&b.state);
    }

    let by_name = |name: &str| {
        report
            .folders
            .iter()
            .find(|f| f.project == name)
            .unwrap_or_else(|| panic!("{name} is not listed: {:?}", report.folders))
    };
    let failed = by_name("lab-notes");
    assert!(failed.mapped && failed.cwd == Some(b_notes.display().to_string()));
    let error = failed.error.as_deref().expect("the failure is reported");
    assert!(error.contains("memory"), "{error}");
    assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
    assert_eq!(by_name("lab-ideas").error, None);
    assert_eq!(read(&b_ideas_mem, "idea.md").as_deref(), Some("an idea\n"));
    assert_eq!(std::fs::read_to_string(&blocked).unwrap(), "not a folder");
}

/// A file that fails in a cycle is an error of the cycle, by its path and
/// with why, and the rest of its folder still syncs. The folder's report
/// lists the file, and the folder itself is not reported as failed.
///
/// Here something is in the way of the temporary file that the incoming
/// version of one file is written through, so that file cannot be written.
#[test]
fn a_file_that_fails_is_an_error_of_the_cycle_and_the_folder_still_syncs() {
    let (mut a, mut b, a_mem, b_mem) = paired();
    std::fs::write(a_mem.join("a.md"), "base\n").unwrap();
    std::fs::write(a_mem.join("z.md"), "base\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(read(&b_mem, "a.md").as_deref(), Some("base\n"));

    // A edits both files.
    std::fs::write(a_mem.join("a.md"), "from a\n").unwrap();
    std::fs::write(a_mem.join("z.md"), "from a\n").unwrap();
    let in_the_way = b_mem.join(cordelia_storage::atomic::temporary_name("a.md"));
    std::fs::create_dir(&in_the_way).unwrap();
    a.cycle();
    relay(&a, &b);
    let report = b.adapter.run_cycle(&b.state);

    let path = b_mem.join("a.md").display().to_string();
    assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
    assert!(
        report.errors[0].starts_with(&format!("{path}: "))
            && report.errors[0].len() > path.len() + 2,
        "{:?}",
        report.errors
    );
    let folder = report
        .folders
        .iter()
        .find(|f| !f.failed.is_empty())
        .unwrap_or_else(|| panic!("{:?}", report.folders));
    assert_eq!(folder.error, None);
    assert_eq!(folder.failed.len(), 1);
    assert_eq!(folder.failed[0].name, "a.md");
    // Left as it was, and the file after it was synced.
    assert_eq!(read(&b_mem, "a.md").as_deref(), Some("base\n"));
    assert_eq!(read(&b_mem, "z.md").as_deref(), Some("from a\n"));
    assert_eq!(folder.pulled, 1);
}

// ── A folder that stops syncing, or goes missing, deletes nothing ──────

/// A command that stops a folder syncing has stopped it when it answers. A
/// cycle that read its settings before the change finds, when it comes to
/// its first folder, that they have changed. It stops: it publishes
/// nothing, and it concludes nothing about the folders it did not reach.
/// The next cycle carries on from where things stood.
#[test]
fn a_cycle_stops_when_a_setting_changes_under_it() {
    let (mut a, mut b) = paired_explicit();
    let a_one = a.plain_dir("one");
    let a_two = a.plain_dir("two");
    let a_one_mem = a.claude_folder(&a_one);
    let a_two_mem = a.claude_folder(&a_two);
    std::fs::write(a_one_mem.join("x.md"), "first\n").unwrap();
    std::fs::write(a_two_mem.join("y.md"), "to be deleted\n").unwrap();
    map(&a, &a_one, "one");
    map(&a, &a_two, "two");
    // A third folder, which sends once and then does not change.
    let a_three = a.plain_dir("three");
    std::fs::write(a.claude_folder(&a_three).join("z.md"), "quiet\n").unwrap();
    map(&a, &a_three, "three");
    let b_one = b.plain_dir("one");
    let b_two = b.plain_dir("two");
    let b_one_mem = b.folder_of(&b_one).join("memory");
    let b_two_mem = b.folder_of(&b_two).join("memory");
    map(&b, &b_one, "one");
    map(&b, &b_two, "two");
    settle(&mut a, &mut b);
    assert_eq!(read(&b_one_mem, "x.md").as_deref(), Some("first\n"));
    assert_eq!(read(&b_two_mem, "y.md").as_deref(), Some("to be deleted\n"));

    // A cycle reads its settings; then a command changes one, as every
    // settings handler does, with the database lock held.
    let settings = cordelia_sync::claude::Settings::load(&a.state).unwrap();
    a.state.sync_control.changed(&a.state.db.lock().unwrap());
    std::fs::write(a_one_mem.join("x.md"), "edited\n").unwrap();
    std::fs::remove_file(a_two_mem.join("y.md")).unwrap();
    let before = written(&a);

    let report = a.adapter.run_cycle_under(&a.state, settings);
    assert!(report.stopped, "{report:?}");
    assert!(report.folders.is_empty(), "{report:?}");
    assert!(report.errors.is_empty(), "{report:?}");
    assert_eq!(written(&a), before, "nothing was published");

    // The next cycle starts from the settings as they are. The edit goes
    // as an edit and the delete as a delete: had the stopped cycle
    // forgotten what the folders it never reached had agreed, the deleted
    // file would have been fetched back instead.
    settle(&mut a, &mut b);
    assert_eq!(read(&b_one_mem, "x.md").as_deref(), Some("edited\n"));
    assert_eq!(read(&b_two_mem, "y.md"), None);
    assert_eq!(read(&a_two_mem, "y.md"), None);
    // Nor did it conclude that the folders it never reached no longer
    // sync: when the quiet one last sent is still known.
    let report = a.cycle();
    let quiet = report.folders.iter().find(|f| f.project == "three");
    assert!(
        quiet.is_some_and(|f| f.last_published_at.is_some()),
        "{report:?}"
    );
}

/// A folder taken out and put back before any cycle has got anywhere: a
/// cycle that started while it was out is stopped by its return, and never
/// reaches the point where it would have forgotten what the folder had
/// agreed. The handler that took it out forgets, at once. So a file lost
/// in between is fetched back, and is not deleted on the other device.
#[test]
fn a_folder_taken_out_and_put_back_at_once_does_not_replay_what_it_lost() {
    let (mut a, mut b) = paired_explicit();
    let a_one = a.plain_dir("one");
    let a_mem = a.claude_folder(&a_one);
    std::fs::write(a_mem.join("x.md"), "kept\n").unwrap();
    map(&a, &a_one, "one");
    let b_one = b.plain_dir("one");
    let b_mem = b.folder_of(&b_one).join("memory");
    map(&b, &b_one, "one");
    settle(&mut a, &mut b);
    assert_eq!(read(&b_mem, "x.md").as_deref(), Some("kept\n"));

    // What the handler forgets is what the adapter recorded: the two
    // spell the folder the same way.
    let channel = channel_of(&mut a, "one");
    let dir = a.home.join(".claude").display().to_string();
    let recorded = |d: &Device| {
        let folder = cordelia_api::sync::memory_folder(&dir, &a_one.display().to_string());
        let db = d.state.db.lock().unwrap();
        cordelia_storage::sync_state::load(&db, &folder, &channel)
            .unwrap()
            .len()
    };
    assert_eq!(recorded(&a), 1);

    unmap(&a, &a_one);
    assert_eq!(recorded(&a), 0);
    let while_out = cordelia_sync::claude::Settings::load(&a.state).unwrap();
    map(&a, &a_one, "one");
    std::fs::remove_file(a_mem.join("x.md")).unwrap();
    let report = a.adapter.run_cycle_under(&a.state, while_out);
    assert!(report.stopped, "{report:?}");

    settle(&mut a, &mut b);
    assert_eq!(read(&a_mem, "x.md").as_deref(), Some("kept\n"));
    assert_eq!(read(&b_mem, "x.md").as_deref(), Some("kept\n"));
}

/// A name that is stopped and held again in one generation of the
/// settings, with a file lost in between: the device holds nothing of the
/// name's channel once it has stopped the name, and neither does a folder
/// keep a record of what it had agreed there. So the folder that comes
/// back has no record in the channel. It waits for the channel to be
/// fetched and meets it as on any first sync: the file is fetched back,
/// and nothing is published as a delete (decision 2026-10-04 §6).
#[test]
fn a_name_stopped_and_held_again_in_one_generation_deletes_nothing() {
    let (mut a, mut b) = paired_explicit();
    // Each node is set up with one relay, the stand-in: a folder with no
    // record in a channel waits until the stand-in has handed it.
    for d in [&a, &b] {
        d.state.own_channels.set_up_with(1);
    }
    let a_one = a.plain_dir("one");
    let a_mem = a.claude_folder(&a_one);
    std::fs::write(a_mem.join("x.md"), "kept\n").unwrap();
    std::fs::write(a_mem.join("y.md"), "stays\n").unwrap();
    map(&a, &a_one, "one");
    let b_one = b.plain_dir("one");
    let b_mem = b.folder_of(&b_one).join("memory");
    map(&b, &b_one, "one");
    settle(&mut a, &mut b);
    assert_eq!(files(&b_mem), ["x.md", "y.md"]);
    let channel = channel_of(&mut a, "one");
    let folder = a_mem.display().to_string();
    let recorded = |d: &Device| {
        let db = d.state.db.lock().unwrap();
        cordelia_storage::sync_state::load(&db, &folder, &channel)
            .unwrap()
            .len()
    };
    assert_eq!(recorded(&a), 2);

    // The name is stopped, as a cycle stops a name that this device said
    // it syncs and that it finds no folder for; and no setting changes.
    let generation = a.state.sync_control.generation();
    {
        let db = a.state.db.lock().unwrap();
        let stopped = names::stop(&db, &a.state.identity, "one", now()).unwrap();
        let stopped = stopped.expect("the device held the name");
        a.state.own_channels.forget_fetched(&stopped);
    }
    assert_eq!(recorded(&a), 0, "what the folder agreed went with the name");
    std::fs::remove_file(a_mem.join("x.md")).unwrap();

    // Its folder is mapped still: the next cycle holds the name again. It
    // waits for the channel, and publishes nothing meanwhile.
    let waits = a.cycle().folders.remove(0);
    assert!(waits.waiting, "{waits:?}");
    assert_eq!(a.state.sync_control.generation(), generation);
    settle(&mut a, &mut b);
    assert_eq!(read(&a_mem, "x.md").as_deref(), Some("kept\n"));
    assert_eq!(files(&b_mem), ["x.md", "y.md"]);
    for d in [&a, &b] {
        assert_eq!(
            version_of(d, "one", "x.md"),
            Some((1, Value::Text("kept\n".into()))),
            "nothing was published over the file"
        );
    }
    // The file that was there all along is agreed again as it is: it is
    // not published a second time.
    assert_eq!(
        version_of(&a, "one", "y.md"),
        Some((1, Value::Text("stays\n".into())))
    );
    assert_eq!(entries_of(&a, "one", "y.md").len(), 1);
    assert_eq!(recorded(&a), 2);
}

/// A file whose record a change could not carry is said, in `cordelia
/// devices` and in a status, until it has met its channel (decision
/// 2026-10-04 §4.2): a cycle that leaves its folder with a record of it
/// there takes it from what is said. A file that has not met its channel
/// yet stays.
#[test]
fn a_file_that_was_not_carried_is_said_until_it_has_met_its_channel() {
    let mut a = Device::new().with_phrase().sync_on();
    let one = a.plain_dir("one");
    let mem = a.claude_folder(&one);
    std::fs::write(mem.join("x.md"), "here\n").unwrap();
    map(&a, &one, "one");
    let not_carried = |d: &Device| -> Vec<String> {
        let db = d.state.db.lock().unwrap();
        let seen = cordelia_api::look::look(&db, &d.state.identity, &Default::default(), now());
        let files = seen.unwrap().not_carried;
        files.into_iter().map(|file| file.file).collect()
    };
    // As the device notes them when it applies a statement: one file
    // that its folder has, and one that is too large to meet anything.
    let big = "x".repeat(cordelia_sync::claude::MAX_FILE_BYTES + 1);
    std::fs::write(mem.join("large.md"), big).unwrap();
    set_meta(
        &a,
        meta::PERSON_NOT_CARRIED,
        r#"[{"name":"one","file":"x.md"},{"name":"one","file":"large.md"}]"#,
    );
    assert_eq!(not_carried(&a), ["x.md", "large.md"]);

    let report = a.cycle();
    assert_eq!(report.folders[0].published, 1, "{report:?}");
    assert_eq!(not_carried(&a), ["large.md"]);
}

/// Whether sync is on is a setting like the others. A cycle reads it with
/// the rest, under the lock: turned off, there is nothing for it to do,
/// even if the loop that started it saw sync on a moment before.
#[test]
fn a_cycle_does_nothing_once_sync_is_off() {
    let (mut a, mut b) = paired_explicit();
    let a_one = a.plain_dir("one");
    let a_mem = a.claude_folder(&a_one);
    std::fs::write(a_mem.join("x.md"), "first\n").unwrap();
    map(&a, &a_one, "one");
    settle(&mut a, &mut b);

    std::fs::write(a_mem.join("x.md"), "edited\n").unwrap();
    let before = written(&a);
    let off: cordelia_api::types::SyncClaudeRequest =
        serde_json::from_value(serde_json::json!({ "enabled": false })).unwrap();
    cordelia_api::sync::set_claude(
        &a.state.sync_control,
        &a.state.db.lock().unwrap(),
        &off,
        Some(&a.home),
    )
    .unwrap();

    let report = a.adapter.run_cycle(&a.state);
    assert!(report.stopped, "{report:?}");
    assert!(report.folders.is_empty(), "{report:?}");
    assert_eq!(written(&a), before, "nothing was published");
}

/// A cycle runs only for the Claude Code directory that is set, and the
/// directory is the string that is stored: what a folder agrees is
/// recorded under it, and the handlers forget by it. An adapter started
/// for another directory, or for another spelling of the same one, is not
/// for it, and a cycle of it does nothing. (The node's loop asks the same
/// question of the adapter it holds, and starts a new one.)
#[test]
fn a_cycle_runs_only_for_the_directory_that_is_set() {
    let (mut a, mut b) = paired_explicit();
    let a_one = a.plain_dir("one");
    let a_mem = a.claude_folder(&a_one);
    std::fs::write(a_mem.join("x.md"), "first\n").unwrap();
    map(&a, &a_one, "one");
    settle(&mut a, &mut b);

    std::fs::write(a_mem.join("x.md"), "edited\n").unwrap();
    let before = written(&a);
    let set = a.home.join(".claude");
    let respelled = PathBuf::from(format!("{}//.claude", a.home.display()));
    assert_eq!(respelled, set, "the same path");
    let stored = set.display().to_string();
    assert!(a.adapter.is_for(&stored));
    for other in [a.home.join(".claude-other"), respelled] {
        let mut stale = ClaudeAdapter::new(other.clone(), a.home.clone(), &a.pk());
        assert!(!stale.is_for(&stored), "{}", other.display());
        let report = stale.run_cycle(&a.state);
        assert!(report.stopped, "{}: {report:?}", other.display());
        assert!(report.folders.is_empty(), "{}", other.display());
    }
    assert_eq!(written(&a), before, "nothing was published");
    assert_eq!(a.cycle().folders[0].published, 1);
}

/// Unmapped (or home memory turned off), emptied, and mapped again: the
/// folder starts afresh. What it lost in between is not
/// sent to the other devices as deletes.
#[test]
fn mapping_a_folder_again_does_not_replay_what_it_lost() {
    let (mut a, mut b) = paired_explicit();
    let a_notes = a.plain_dir("notes");
    let a_mem = a.claude_folder(&a_notes);
    let b_notes = b.plain_dir("notes");
    let b_mem = b.claude_folder(&b_notes);
    for (name, text) in [
        ("MEMORY.md", "- [One](one.md) — a note\n"),
        ("one.md", "one\n"),
    ] {
        std::fs::write(a_mem.join(name), text).unwrap();
    }
    map(&a, &a_notes, "lab-notes");
    map(&b, &b_notes, "lab-notes");
    settle(&mut a, &mut b);
    assert_eq!(files(&b_mem), ["MEMORY.md", "one.md"]);

    // A stops syncing the folder and clears its copy. B carries on.
    unmap(&a, &a_notes);
    settle(&mut a, &mut b);
    std::fs::remove_dir_all(&a_mem).unwrap();
    std::fs::write(b_mem.join("two.md"), "two\n").unwrap();
    settle(&mut a, &mut b);
    assert!(!a_mem.exists(), "an unmapped folder is left alone");

    // A maps it again. B loses nothing, and A gets everything back.
    map(&a, &a_notes, "lab-notes");
    settle(&mut a, &mut b);
    assert_eq!(files(&b_mem), ["MEMORY.md", "one.md", "two.md"]);
    assert_eq!(files(&a_mem), ["MEMORY.md", "one.md", "two.md"]);

    // The same when sync is turned off altogether and on again, with no
    // cycle in between: the handler that turned it off forgot.
    claude(&a, serde_json::json!({ "enabled": false }));
    std::fs::remove_file(a_mem.join("one.md")).unwrap();
    claude(&a, serde_json::json!({}));
    settle(&mut a, &mut b);
    assert_eq!(files(&b_mem), ["MEMORY.md", "one.md", "two.md"]);
    assert_eq!(read(&a_mem, "one.md").as_deref(), Some("one\n"));

    // A delete made while the folder syncs still reaches the other device.
    std::fs::remove_file(a_mem.join("two.md")).unwrap();
    settle(&mut a, &mut b);
    assert_eq!(files(&b_mem), ["MEMORY.md", "one.md"]);
}

/// A mapped folder whose memory directory is gone (its disk is not
/// attached, or it was moved aside) is an error to show, never a reason to
/// delete the memory everywhere else.
#[test]
fn a_memory_folder_that_goes_missing_deletes_nothing() {
    let (mut a, mut b) = paired_explicit();
    let a_notes = a.plain_dir("notes");
    let a_mem = a.claude_folder(&a_notes);
    let b_notes = b.plain_dir("notes");
    let b_mem = b.claude_folder(&b_notes);
    std::fs::write(a_mem.join("one.md"), "one\n").unwrap();
    std::fs::write(a_mem.join("two.md"), "two\n").unwrap();
    map(&a, &a_notes, "lab-notes");
    map(&b, &b_notes, "lab-notes");
    settle(&mut a, &mut b);
    assert_eq!(files(&b_mem), ["one.md", "two.md"]);

    // The whole Claude Code directory goes away for a while.
    let claude = a.home.join(".claude");
    let aside = a.home.join("claude-aside");
    std::fs::rename(&claude, &aside).unwrap();
    let (report, _) = settle_reporting(&mut a, &mut b);
    let error = report.folders[0].error.as_deref().expect("reported");
    assert!(error.contains("were not deleted"), "{error}");
    assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
    assert_eq!(files(&b_mem), ["one.md", "two.md"], "B keeps everything");
    assert!(!claude.exists(), "and nothing is written in its place");

    // It comes back: sync carries on where it was, deletes included.
    std::fs::rename(&aside, &claude).unwrap();
    std::fs::remove_file(a_mem.join("two.md")).unwrap();
    std::fs::write(b_mem.join("three.md"), "three\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(files(&a_mem), ["one.md", "three.md"]);
    assert_eq!(files(&b_mem), ["one.md", "three.md"]);
}

/// A folder that is unmapped stops syncing, and stays out: it is not
/// picked up again under the name that its repository would give it,
/// which another device syncs. It is listed, with that name, so that a
/// person can map it again.
#[test]
fn an_unmapped_folder_stays_out_and_is_listed() {
    let (mut a, mut b) = paired_explicit();
    let a_repo = a.clone_at("Work/cordelia-node");
    let a_mem = a.claude_folder(&a_repo);
    let b_repo = b.clone_at("src/cn");
    let b_mem = b.claude_folder(&b_repo);
    std::fs::write(b_mem.join("shared.md"), "the project's memory\n").unwrap();
    map(&b, &b_repo, PROJECT);

    // A keeps its copy of the project apart, under a name of its own.
    map(&a, &a_repo, "kept-apart");
    std::fs::write(a_mem.join("private.md"), "kept apart\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(files(&a_mem), ["private.md"]);
    assert_eq!(files(&b_mem), ["shared.md"]);

    // Unmapped, it does not fall back to the project's own name.
    unmap(&a, &a_repo);
    std::fs::write(a_mem.join("later.md"), "still apart\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(files(&a_mem), ["later.md", "private.md"]);
    assert_eq!(files(&b_mem), ["shared.md"]);
    let report = a.cycle();
    assert!(report.folders.is_empty(), "{:?}", report.folders);
    assert_eq!(report.unmapped.len(), 1, "{:?}", report.unmapped);
    let found = &report.unmapped[0];
    assert_eq!(found.folder, a.folder_of(&a_repo).display().to_string());
    assert_eq!(found.name.as_deref(), Some(PROJECT));
    assert_eq!(report.available, vec![PROJECT.to_string()]);
}

/// A session can move to another directory, so a transcript in one folder
/// can start in another. A folder Claude Code named is believed only about
/// the directory it is named after: it is listed as that directory's
/// memory, and never as the memory of the directory that its newest
/// transcript starts in.
#[test]
fn a_claude_folder_is_believed_only_about_its_own_directory() {
    let mut a = Device::new().with_phrase().sync_on();
    let a_repo = a.clone_at("Work/cordelia-node");
    let a_home = a.home_memory();
    std::fs::write(a_home.join("profile.md"), "general profile\n").unwrap();

    // The newest transcript in A's home folder starts in the repository.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let home_folder = a.folder_of(&a.home.clone());
    std::fs::write(
        home_folder.join("newer.jsonl"),
        format!("{{\"cwd\":{:?}}}\n", a_repo.display().to_string()),
    )
    .unwrap();
    let report = a.cycle();
    assert_eq!(report.unmapped.len(), 1, "{:?}", report.unmapped);
    let found = &report.unmapped[0];
    assert_eq!(found.folder, home_folder.display().to_string());
    assert_eq!(found.name.as_deref(), Some("~"), "still home memory");

    // With only that transcript, nothing says whose folder it is: it is
    // listed with no directory and no name, rather than as the
    // repository's.
    std::fs::remove_file(home_folder.join("session.jsonl")).unwrap();
    a.adapter = ClaudeAdapter::new(a.home.join(".claude"), a.home.clone(), &a.pk());
    let report = a.cycle();
    assert!(report.folders.is_empty(), "{:?}", report.folders);
    assert_eq!(report.unmapped.len(), 1);
    assert_eq!(report.unmapped[0].folder, home_folder.display().to_string());
    assert_eq!(report.unmapped[0].name, None);
    assert_eq!(report.unsynced, vec![home_folder.display().to_string()]);
}

/// Two devices of one person both start syncing home memory before
/// hearing from each other (as when both take up a version under which
/// every channel starts afresh). Neither makes a channel, and neither
/// joins one: the person's secret gives each the same channel for the
/// name. They end with every file on both. A file that the two published
/// with two texts meets as a tie: one text is the file, and the other is
/// kept beside it.
#[test]
fn two_devices_starting_at_once_are_in_one_channel_with_every_file_on_both() {
    let (mut a, mut b, a_home, b_home) = paired();
    std::fs::write(a_home.join("same.md"), "the same on both\n").unwrap();
    std::fs::write(b_home.join("same.md"), "the same on both\n").unwrap();
    std::fs::write(a_home.join("only_a.md"), "from a\n").unwrap();
    std::fs::write(b_home.join("only_b.md"), "from b\n").unwrap();
    std::fs::write(a_home.join("differs.md"), "a's version\n").unwrap();
    std::fs::write(b_home.join("differs.md"), "b's version\n").unwrap();

    // Each runs a cycle before any entry has travelled, and publishes
    // what it has into a channel that is still empty.
    let first_a = channel_of(&mut a, "~");
    let first_b = channel_of(&mut b, "~");
    assert_eq!(first_a, first_b, "one channel, which neither made");
    for (device, text) in [(&a, "a's version\n"), (&b, "b's version\n")] {
        assert_eq!(
            version_of(device, "~", "differs.md"),
            Some((1, Value::Text(text.into())))
        );
    }
    settle(&mut a, &mut b);
    settle(&mut a, &mut b);

    assert_eq!(channel_of(&mut a, "~"), channel_of(&mut b, "~"));
    assert_eq!(files(&a_home), files(&b_home));
    let names = files(&a_home);
    for name in ["same.md", "only_a.md", "only_b.md", "differs.md"] {
        assert!(names.contains(&name.to_string()), "{names:?}");
    }
    // The file that was the same on both is one version, and nothing is
    // kept beside it.
    assert!(
        !names.iter().any(|n| n.starts_with("same.conflict-")),
        "{names:?}"
    );
    // The file that differed: one version in place, the other beside it.
    let kept: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("differs.conflict-"))
        .collect();
    assert_eq!(kept.len(), 1, "{names:?}");
    let mut versions = vec![
        read(&a_home, "differs.md").unwrap(),
        read(&a_home, kept[0]).unwrap(),
    ];
    versions.sort();
    assert_eq!(versions, ["a's version\n", "b's version\n"]);
    assert_eq!(read(&b_home, "differs.md"), read(&a_home, "differs.md"));
}

/// A name is on offer to a person's other devices once a device says
/// that it syncs it, and it says so from when it maps the name: also while
/// its folder there still waits for the name's channel to be fetched from
/// a relay, which is all that a folder's first cycle waits for.
#[test]
fn a_name_is_offered_only_once_a_device_syncs_it() {
    let (mut a, mut b) = paired_explicit();
    // B is set up with two relays, and has heard from neither.
    b.state.own_channels.set_up_with(2);
    let b_notes = b.plain_dir("notes");
    let b_mem = b.claude_folder(&b_notes);
    std::fs::write(b_mem.join("idea.md"), "a thought\n").unwrap();
    settle(&mut a, &mut b);
    assert!(a.cycle().available.is_empty(), "nothing to offer yet");

    // B maps a name nobody has. Its folder has no record in the name's
    // channel, and waits for the channel: nothing of it is published.
    map(&b, &b_notes, "solo");
    let waits = b.cycle().folders.remove(0);
    assert!(waits.waiting, "{waits:?}");
    assert_eq!(waits.published, 0);
    assert_eq!(version_of(&b, "solo", "idea.md"), None);
    // It has said that it syncs the name all the same: A is offered it.
    relay(&b, &a);
    assert_eq!(a.cycle().available, vec!["solo".to_string()]);

    // One relay hands B the channel: the folder still waits, for the
    // other relay to have its time. Once that one has handed it too, the
    // folder has its first cycle.
    let channel = decode_channel_id(waits.channel_id.as_deref().unwrap()).unwrap();
    let handed = std::time::Instant::now();
    b.state.own_channels.fetched_from(&channel, "one", handed);
    assert!(b.cycle().folders[0].waiting);
    b.state
        .own_channels
        .fetched_from(&channel, "another", handed);
    let synced = b.cycle().folders.remove(0);
    assert!(!synced.waiting, "{synced:?}");
    assert_eq!(synced.published, 1);
    assert_eq!(
        version_of(&b, "solo", "idea.md"),
        Some((1, Value::Text("a thought\n".into())))
    );

    // A name that could not be mapped is never passed on: it would end up
    // in a command for the person to copy.
    let personal = personal_secret(&b);
    for name in ["fine", "x; rm -rf ~", "Has Space"] {
        let word = names::word_name(name);
        put(&b, &personal, &word, Value::Text(String::new()), 1);
    }
    relay(&b, &a);
    assert_eq!(
        a.cycle().available,
        vec!["fine".to_string(), "solo".to_string()]
    );
}

/// A git repository created above a mapped folder moves its memory to the
/// repository's folder. The mapping says so rather than syncing on as if
/// nothing had changed.
#[test]
fn a_repository_appearing_above_a_mapped_folder_is_reported() {
    let mut a = Device::new().with_phrase().sync_on();
    let workspace = a.plain_dir("workspace");
    let notes = a.plain_dir("workspace/notes");
    a.claude_folder(&notes);
    map(&a, &notes, "lab-notes");
    assert_eq!(a.cycle().folders[0].error, None);

    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["init", "-q"])
            .status()
            .unwrap()
            .success()
    );
    a.adapter = ClaudeAdapter::new(a.home.join(".claude"), a.home.clone(), &a.pk());
    let report = a.adapter.run_cycle(&a.state);
    let error = report.folders[0].error.as_deref().expect("reported");
    assert!(error.contains(&workspace.display().to_string()), "{error}");
}

/// A file that grows past what an entry can carry is not carried, and is
/// not taken for deleted: the other device keeps the version it has. The
/// device with the large file keeps it, says so, and takes nothing over
/// it. When the file fits again, it syncs again.
#[test]
fn a_file_that_grows_too_large_is_left_alone_and_deleted_nowhere() {
    let (mut a, mut b, a_mem, b_mem) = paired();
    std::fs::write(a_mem.join("notes.md"), "small\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(read(&b_mem, "notes.md").as_deref(), Some("small\n"));

    let big = "x".repeat(cordelia_sync::claude::MAX_FILE_BYTES + 1);
    std::fs::write(a_mem.join("notes.md"), &big).unwrap();
    let (report, _) = settle_reporting(&mut a, &mut b);
    assert_eq!(
        read(&b_mem, "notes.md").as_deref(),
        Some("small\n"),
        "the other device lost the file"
    );
    assert_eq!(read(&a_mem, "notes.md").map(|t| t.len()), Some(big.len()));
    // A says which file it is not carrying.
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let too_large: Vec<&String> = report.folders.iter().flat_map(|f| &f.too_large).collect();
    assert_eq!(too_large, vec!["notes.md"]);

    // An edit on the other device is not written over the large file.
    std::fs::write(b_mem.join("notes.md"), "edited on b\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(read(&a_mem, "notes.md").map(|t| t.len()), Some(big.len()));

    // Small again: it takes part again. Both sides changed meanwhile, so
    // the channel's version goes in the file and A's is kept beside it.
    std::fs::write(a_mem.join("notes.md"), "small again\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(read(&a_mem, "notes.md").as_deref(), Some("edited on b\n"));
    assert!(
        files(&a_mem).iter().any(|f| f.contains(".conflict-")),
        "{:?}",
        files(&a_mem)
    );
}

/// A file can be under the size limit and still not fit in an entry: an
/// entry holds its name too, and the two are bounded together. It is found
/// when it is published, and treated the same way: left alone, reported,
/// and deleted nowhere. A text is counted as it is, whatever is in it.
#[test]
fn a_file_that_does_not_fit_with_its_name_is_left_alone_too() {
    let (mut a, mut b, a_mem, b_mem) = paired();
    std::fs::write(a_mem.join("long.md"), "small\n").unwrap();
    settle(&mut a, &mut b);

    // As large as a file may be: with its name it is over the bound. And
    // 40 KB of quotation marks, which is 40 KB in an entry.
    let long = "x".repeat(cordelia_sync::claude::MAX_FILE_BYTES);
    let quotes = "\"".repeat(40_000);
    assert!(!publish::fits("long.md", &Value::Text(long.clone())));
    assert!(publish::fits("quotes.md", &Value::Text(quotes.clone())));
    std::fs::write(a_mem.join("long.md"), &long).unwrap();
    std::fs::write(a_mem.join("quotes.md"), &quotes).unwrap();
    let (report, _) = settle_reporting(&mut a, &mut b);

    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let too_large: Vec<&String> = report.folders.iter().flat_map(|f| &f.too_large).collect();
    assert_eq!(too_large, vec!["long.md"]);
    assert_eq!(read(&b_mem, "long.md").as_deref(), Some("small\n"));
    assert_eq!(read(&a_mem, "long.md"), Some(long));
    assert_eq!(read(&b_mem, "quotes.md"), Some(quotes));
}

/// A file that stops being plain text (here, replaced by a link) is not
/// taken for deleted either.
#[cfg(unix)]
#[test]
fn a_file_replaced_by_a_link_is_deleted_nowhere() {
    let (mut a, mut b, a_mem, b_mem) = paired();
    std::fs::write(a_mem.join("notes.md"), "kept\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(read(&b_mem, "notes.md").as_deref(), Some("kept\n"));

    std::fs::remove_file(a_mem.join("notes.md")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", a_mem.join("notes.md")).unwrap();
    let (report, _) = settle_reporting(&mut a, &mut b);
    assert_eq!(read(&b_mem, "notes.md").as_deref(), Some("kept\n"));
    let skipped: Vec<&String> = report.folders.iter().flat_map(|f| &f.skipped).collect();
    assert_eq!(skipped, vec!["notes.md"]);
}

/// Local history on a device, as the node opens it: kept for 30 days, and
/// up to `max_bytes`.
fn history_on(d: &Device, max_bytes: u64) -> cordelia_storage::history::Store {
    let store = cordelia_storage::history::Store::new(&d.state.home_dir, 30, max_bytes).unwrap();
    d.state.history.open(Some(store.clone()));
    store
}

/// A sync cycle takes its turn with a restore, a drop and the sweep of
/// local history (decision 2026-09-30 §4.5b). While one of them holds the
/// turn the cycle waits, and none of it is done; when the turn is free it
/// goes ahead.
#[test]
fn a_cycle_waits_for_its_turn() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (mut a, _b, a_mem, _) = paired();
    std::fs::write(a_mem.join("notes.md"), "one\n").unwrap();
    let Device { state, adapter, .. } = &mut a;
    let state = &*state;
    let done = AtomicBool::new(false);
    let report = std::thread::scope(|scope| {
        let turn = state.history.turn();
        let cycle = scope.spawn(|| {
            let report = adapter.run_cycle(state);
            done.store(true, Ordering::SeqCst);
            report
        });
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(
            !done.load(Ordering::SeqCst),
            "the cycle ran while the turn was held"
        );
        drop(turn);
        cycle.join().unwrap()
    });
    assert!(done.load(Ordering::SeqCst));
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.folders.len(), 1, "{report:?}");
}

/// Local history is held to its size as it grows, not only once an hour:
/// a cycle that has kept enough sweeps the store as it ends. So what one
/// device holds passes its size by what one cycle keeps, and by no more.
#[test]
fn a_cycle_that_keeps_enough_sweeps_local_history() {
    let (mut a, mut b, a_mem, b_mem) = paired();
    let text = |n: usize| format!("{n}{}\n", "x".repeat(1000));
    std::fs::write(a_mem.join("notes.md"), text(0)).unwrap();
    settle(&mut a, &mut b);
    // How large one kept text is here: a record names its memory folder,
    // whose path is as long as this machine's temporary directory.
    let measured = history_on(&a, 1 << 20);
    std::fs::write(b_mem.join("notes.md"), text(1)).unwrap();
    settle(&mut a, &mut b);
    let one = measured.list().unwrap().bytes;
    assert!(one > 1000, "{one}");
    // Room for two kept texts, and not for three.
    let room = one * 5 / 2;
    let store = history_on(&a, room);
    let mut most = 0;
    for n in 2..=7 {
        std::fs::write(b_mem.join("notes.md"), text(n)).unwrap();
        settle(&mut a, &mut b);
        assert_eq!(read(&a_mem, "notes.md"), Some(text(n)));
        let listing = store.list().unwrap();
        assert!(listing.bytes <= room, "after {n}: {} bytes", listing.bytes);
        most = most.max(listing.records.len());
    }
    // It did keep them: two at a time, the newest.
    assert_eq!(most, 2);
    let newest = store.list().unwrap().records[0].id.clone();
    assert_eq!(store.read(&newest).unwrap().unwrap().1, Some(text(6)));
}

// ── Before there is a phrase, and a second device's first sync ─────────

/// A device that follows no recovery phrase has no secret, and publishes
/// nothing (decision 2026-10-04 §5.2). Sync can be on and folders mapped:
/// a cycle lists them and says why nothing syncs, and writes nothing, in
/// its store or in a folder. Once the device makes a phrase, its folders
/// are published.
#[test]
fn a_device_that_follows_no_phrase_publishes_nothing_until_it_makes_one() {
    let mut a = Device::new().sync_on();
    let home = a.home_memory();
    std::fs::write(home.join("user_role.md"), "Prefers short answers.\n").unwrap();
    let notes = a.plain_dir("notes");
    let mem = a.claude_folder(&notes);
    std::fs::write(mem.join("idea.md"), "a thought\n").unwrap();
    map(&a, &a.home.clone(), "~");
    map(&a, &notes, "lab-notes");

    // Its folders are listed, and nothing was done for either.
    let listed = |report: &cordelia_sync::claude::CycleReport| -> Vec<(String, bool)> {
        let mut listed: Vec<(String, bool)> = report
            .folders
            .iter()
            .map(|f| (f.project.clone(), f.mapped))
            .collect();
        listed.sort();
        listed
    };
    let both = [("lab-notes".to_string(), true), ("~".to_string(), true)];
    let report = a.cycle();
    assert_eq!(
        report.publishes_nothing.as_deref(),
        Some(cordelia_api::look::NO_PHRASE)
    );
    assert!(!report.stopped, "{report:?}");
    assert_eq!(listed(&report), both);
    for folder in &report.folders {
        assert_eq!(folder.channel_id, None, "{folder:?}");
        assert!(!folder.waiting, "{folder:?}");
        assert_eq!(
            (folder.published, folder.pulled, folder.conflicts),
            (0, 0, 0),
            "{folder:?}"
        );
        assert_eq!(folder.error, None, "{folder:?}");
    }
    assert!(report.available.is_empty(), "{report:?}");

    // Nothing was written: no entry, no name held, no word said, and the
    // folders are as they were.
    assert_eq!(entries_held(&a), 0);
    {
        let db = a.state.db.lock().unwrap();
        assert!(held_rows::names(&db).unwrap().is_empty());
        assert!(names::said_here(&db, &a.state.identity).unwrap().is_empty());
    }
    assert_eq!(files(&home), ["user_role.md"]);
    assert_eq!(files(&mem), ["idea.md"]);
    assert_eq!(
        read(&home, "user_role.md").as_deref(),
        Some("Prefers short answers.\n")
    );
    assert_eq!(read(&mem, "idea.md").as_deref(), Some("a thought\n"));

    // It makes a phrase: the next cycle publishes both folders, and the
    // device says of each name that it syncs it.
    let mut a = a.with_phrase();
    let report = a.cycle();
    assert_eq!(report.publishes_nothing, None);
    assert_eq!(listed(&report), both);
    for folder in &report.folders {
        assert!(folder.channel_id.is_some(), "{folder:?}");
        assert_eq!(folder.published, 1, "{folder:?}");
    }
    assert_eq!(
        version_of(&a, "~", "user_role.md"),
        Some((1, Value::Text("Prefers short answers.\n".into())))
    );
    assert_eq!(
        version_of(&a, "lab-notes", "idea.md"),
        Some((1, Value::Text("a thought\n".into())))
    );
    let db = a.state.db.lock().unwrap();
    let said = names::said_here(&db, &a.state.identity).unwrap();
    assert_eq!(said.into_iter().collect::<Vec<_>>(), ["lab-notes", "~"]);
}

/// A second device meets the person's channels at its first sync
/// (decision 2026-10-04 §10, step 5). The first device has made the
/// phrase, and has published `on_first` from its home memory. The second
/// gathered `on_second` alone, with sync on and no phrase, so nothing of
/// it was published. It is then added, and accepts.
///
/// The second device is set up with one relay, the stand-in: a folder's
/// first cycle waits until the stand-in has handed it the name's channel
/// (decision 2026-10-04 §6), so its files meet what the first device
/// sent, and are not published beside it as new files of its own.
///
/// Returns the two devices and their home memory folders, once they are
/// quiet.
fn first_sync(
    on_first: &[(&str, &str)],
    on_second: &[(&str, &str)],
) -> (Device, Device, PathBuf, PathBuf) {
    let mut a = Device::new().with_phrase().sync_on();
    let mut b = Device::new().sync_on();
    b.state.own_channels.set_up_with(1);
    let (a_mem, b_mem) = (a.home_memory(), b.home_memory());
    for d in [&a, &b] {
        map(d, &d.home.clone(), "~");
    }
    for (mem, texts) in [(&a_mem, on_first), (&b_mem, on_second)] {
        for (name, text) in texts {
            std::fs::write(mem.join(name), text).unwrap();
        }
    }
    let published: usize = a.cycle().folders.iter().map(|f| f.published).sum();
    assert_eq!(published, on_first.len());
    assert!(b.cycle().publishes_nothing.is_some());
    assert_eq!(entries_held(&b), 0);

    add(&a, &b, "laptop");
    // Its first cycle waits: it has not been handed the channel.
    let report = b.cycle();
    assert!(report.folders[0].waiting, "{report:?}");
    settle(&mut a, &mut b);
    (a, b, a_mem, b_mem)
}

/// A file with the same text on both is agreed: nothing is kept beside
/// it, and the second device publishes nothing for it. An edit of it then
/// goes over the first device's version, as an edit of a file that has
/// always synced does.
#[test]
fn at_a_first_sync_a_file_with_the_same_text_on_both_is_agreed() {
    let same = [("same.md", "the same on both\n")];
    let (mut a, mut b, a_mem, b_mem) = first_sync(&same, &same);
    for mem in [&a_mem, &b_mem] {
        assert_eq!(files(mem), ["same.md"]);
        assert_eq!(read(mem, "same.md").as_deref(), Some("the same on both\n"));
    }
    for d in [&a, &b] {
        assert_eq!(
            version_of(d, "~", "same.md"),
            Some((1, Value::Text("the same on both\n".into())))
        );
        assert_eq!(entries_of(d, "~", "same.md"), [(a.pk(), Some(Vec::new()))]);
    }

    std::fs::write(b_mem.join("same.md"), "edited on the second\n").unwrap();
    settle(&mut a, &mut b);
    for mem in [&a_mem, &b_mem] {
        assert_eq!(files(mem), ["same.md"]);
        assert_eq!(
            read(mem, "same.md").as_deref(),
            Some("edited on the second\n")
        );
    }
    let over = vec![link("the same on both\n", &a)];
    assert_eq!(entries_of(&a, "~", "same.md"), [(b.pk(), Some(over))]);
}

/// A file that differs takes the channel's text, and the second device's
/// text is kept beside it as a copy, which then reaches the first device
/// as any file does. It is so whichever of the two texts would win a tie:
/// the two do not meet as a tie.
#[test]
fn at_a_first_sync_a_file_that_differs_takes_the_channels_and_is_kept_beside_it() {
    let (one, another) = ("one text\n", "another text\n");
    for (first, second) in [(one, another), (another, one)] {
        let (a, b, a_mem, b_mem) = first_sync(&[("differs.md", first)], &[("differs.md", second)]);
        for mem in [&a_mem, &b_mem] {
            assert_eq!(read(mem, "differs.md").as_deref(), Some(first));
            let copies = copies_of(mem, "differs.md");
            assert_eq!(copies.len(), 1, "{copies:?}");
            assert_eq!(copies[0].1, second);
            assert_eq!(files(mem).len(), 2, "{:?}", files(mem));
        }
        assert_eq!(
            copies_of(&a_mem, "differs.md"),
            copies_of(&b_mem, "differs.md")
        );
        // The channel's version is still the first device's.
        for d in [&a, &b] {
            assert_eq!(
                entries_of(d, "~", "differs.md"),
                [(a.pk(), Some(Vec::new()))]
            );
        }
    }
}

/// A file that only the second device has is published: memory it had
/// gathered alone is not lost.
#[test]
fn at_a_first_sync_a_file_only_here_is_published() {
    let (a, b, a_mem, b_mem) = first_sync(
        &[("first.md", "from the first\n")],
        &[("second.md", "gathered alone\n")],
    );
    for mem in [&a_mem, &b_mem] {
        assert_eq!(files(mem), ["first.md", "second.md"]);
        assert_eq!(read(mem, "first.md").as_deref(), Some("from the first\n"));
        assert_eq!(read(mem, "second.md").as_deref(), Some("gathered alone\n"));
    }
    for d in [&a, &b] {
        assert_eq!(
            version_of(d, "~", "second.md"),
            Some((1, Value::Text("gathered alone\n".into())))
        );
        assert_eq!(
            entries_of(d, "~", "second.md"),
            [(b.pk(), Some(Vec::new()))]
        );
    }
}

/// The index is merged, as two indexes are: each device's lines are in it
/// on both, and nothing is kept beside it.
#[test]
fn at_a_first_sync_the_index_is_merged() {
    let base = "- [Base](base.md) — shared\n";
    let on_first = format!("{base}- [A](a.md) — from the first\n");
    let on_second = format!("{base}- [B](b.md) — from the second\n");
    let (_a, _b, a_mem, b_mem) =
        first_sync(&[("MEMORY.md", &on_first)], &[("MEMORY.md", &on_second)]);
    let index = read(&a_mem, "MEMORY.md").unwrap();
    assert_eq!(read(&b_mem, "MEMORY.md").unwrap(), index);
    for line in ["(base.md)", "(a.md)", "(b.md)"] {
        assert_eq!(
            index.matches(line).count(),
            1,
            "{line} in the merged index:\n{index}"
        );
    }
    for mem in [&a_mem, &b_mem] {
        assert_eq!(files(mem), ["MEMORY.md"]);
    }
}
