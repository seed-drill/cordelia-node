//! The Claude Code adapter across two devices (decision
//! 2026-09-30-agent-memory-sync §4.5, §10).
//!
//! Each device has its own home, `~/.claude`, and clone of the same
//! repository at a different path. Nodes are in-process; a stand-in relay
//! copies items between their databases.
//!
//! Most tests sync everything found (`--all`), which is how discovery is
//! exercised; the tests from `nothing_syncs_until_a_folder_is_mapped` on
//! cover declared mappings, the default.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

use cordelia_api::entries::{self, Write};
use cordelia_api::membership;
use cordelia_api::state::AppState;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_storage::{channels, items, naming};
use cordelia_sync::claude::ClaudeAdapter;

const REMOTE: &str = "git@github.com:seed-drill/cordelia-node.git";

struct Device {
    state: AppState,
    home: PathBuf,
    adapter: ClaudeAdapter,
    _dir: tempfile::TempDir,
}

impl Device {
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
            sync_control: Default::default(),
        };
        membership::ensure_own_inbox(&state).unwrap();
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
        let repo = self.home.join(rel);
        std::fs::create_dir_all(&repo).unwrap();
        for args in [vec!["init", "-q"], vec!["remote", "add", "origin", REMOTE]] {
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

/// Copy every item `from` holds that `to` can use: `to`'s inbox, and every
/// channel `to` has a row for.
fn relay(from: &Device, to: &Device) {
    let wanted: Vec<String> = {
        let db = to.state.db.lock().unwrap();
        let mut ids = channels::list_stored_channel_ids(&db).unwrap();
        ids.extend(
            channels::list_for_entity(&db, &to.pk())
                .unwrap()
                .into_iter()
                .map(|c| c.channel_id),
        );
        ids.push(naming::inbox_channel_id(&to.pk()));
        ids.sort();
        ids.dedup();
        ids
    };
    let stored: Vec<items::StoredItem> = {
        let db = from.state.db.lock().unwrap();
        wanted
            .iter()
            .flat_map(|ch| items::query_sync(&db, ch, None, 100_000).unwrap())
            .collect()
    };
    let db = to.state.db.lock().unwrap();
    for it in stored {
        let slot: Option<[u8; 32]> = it.slot.as_ref().map(|s| s.as_slice().try_into().unwrap());
        let _ = items::insert_item(
            &db,
            &items::NewItem {
                item_id: &it.item_id,
                channel_id: &it.channel_id,
                author_id: it.author_id.as_slice().try_into().unwrap(),
                item_type: &it.item_type,
                published_at: &it.published_at,
                parent_id: it.parent_id.as_deref(),
                key_version: it.key_version,
                content_hash: &it.content_hash,
                signature: &it.signature,
                encrypted_blob: &it.encrypted_blob,
                is_tombstone: it.is_tombstone,
                slot: slot.as_ref(),
                rev: it.rev,
            },
        );
    }
}

/// Everything flows both ways until quiet: relay, apply invites, grant
/// join requests, sync -- what each node's p2p loop and adapter do.
fn settle(a: &mut Device, b: &mut Device) {
    for _ in 0..5 {
        relay(a, b);
        relay(b, a);
        membership::process_inbox(&a.state).unwrap();
        membership::process_inbox(&b.state).unwrap();
        membership::process_join_requests(&a.state).unwrap();
        membership::process_join_requests(&b.state).unwrap();
        relay(a, b);
        relay(b, a);
        a.cycle();
        b.cycle();
    }
}

/// Set a per-device sync setting in node metadata.
fn set_meta(d: &Device, key: &str, value: &str) {
    let db = d.state.db.lock().unwrap();
    cordelia_storage::meta::set(&db, key, value).unwrap();
}

/// Two devices of one person: A adds B, B accepts A. Nothing syncs until
/// folders are mapped.
fn paired_explicit() -> (Device, Device) {
    let a = Device::new();
    let b = Device::new();
    membership::add_device(&a.state, &b.pk(), Some("b")).unwrap();
    relay(&a, &b);
    membership::accept(&b.state, &a.pk(), Some("a")).unwrap();
    (a, b)
}

/// Two paired devices that sync everything they find (`--all`).
fn paired() -> (Device, Device) {
    let (a, b) = paired_explicit();
    for d in [&a, &b] {
        set_meta(d, cordelia_storage::meta::SYNC_CLAUDE_ALL, "on");
    }
    (a, b)
}

/// Declare a mapping on a device, as `cordelia sync map` does.
fn map(d: &Device, folder: &Path, name: &str) {
    let db = d.state.db.lock().unwrap();
    let key = cordelia_storage::meta::SYNC_CLAUDE_MAPPINGS;
    let mut list: Vec<cordelia_sync::claude::Mapping> = cordelia_storage::meta::get(&db, key)
        .unwrap()
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
    list.push(cordelia_sync::claude::Mapping {
        folder: folder.display().to_string(),
        name: name.into(),
    });
    cordelia_storage::meta::set(&db, key, &serde_json::to_string(&list).unwrap()).unwrap();
}

/// Remove a mapping on a device, as `cordelia sync unmap` does: the
/// folder is also excluded, so nothing picks it up under another name.
fn unmap(d: &Device, folder: &Path) {
    use cordelia_storage::meta;
    let db = d.state.db.lock().unwrap();
    let folder = folder.display().to_string();
    let mut list: Vec<cordelia_sync::claude::Mapping> =
        serde_json::from_str(&meta::get(&db, meta::SYNC_CLAUDE_MAPPINGS).unwrap().unwrap())
            .unwrap();
    assert!(
        list.iter().any(|m| m.folder == folder),
        "{folder} is mapped"
    );
    list.retain(|m| m.folder != folder);
    meta::set(
        &db,
        meta::SYNC_CLAUDE_MAPPINGS,
        &serde_json::to_string(&list).unwrap(),
    )
    .unwrap();
    let mut excluded: Vec<String> = meta::get(&db, meta::SYNC_CLAUDE_EXCLUDE)
        .unwrap()
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
    excluded.push(folder);
    meta::set(
        &db,
        meta::SYNC_CLAUDE_EXCLUDE,
        &serde_json::to_string(&excluded).unwrap(),
    )
    .unwrap();
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
        for d in [&*a, &*b] {
            membership::process_inbox(&d.state).unwrap();
            membership::process_join_requests(&d.state).unwrap();
        }
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

/// The channel a device syncs `name` with.
fn channel_of(d: &mut Device, name: &str) -> String {
    d.cycle()
        .folders
        .into_iter()
        .find(|f| f.project == name)
        .and_then(|f| f.channel_id)
        .unwrap_or_else(|| panic!("{name} is not syncing on this device"))
}

/// Whether a device could read a channel: it is a member, or holds its key.
fn can_read(d: &Device, channel: &str) -> bool {
    let db = d.state.db.lock().unwrap();
    channels::is_member(&db, channel, &d.pk()).unwrap()
        || cordelia_storage::psk::read_psk(&d.state.home_dir, channel).is_ok()
}

const PROJECT: &str = "github.com/seed-drill/cordelia-node";

#[test]
fn home_memory_syncs_both_ways() {
    let (mut a, mut b) = paired();
    let a_mem = a.home_memory();
    let b_mem = b.home_memory();

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
    let (mut a, mut b) = paired();
    // Same repository, different paths, so different Claude folder names.
    let a_mem = a.claude_folder(&a.clone_at("Work/cordelia-node"));
    let b_mem = b.claude_folder(&b.clone_at("src/cn"));
    assert_ne!(
        a_mem.parent().unwrap().file_name(),
        b_mem.parent().unwrap().file_name()
    );

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

    // Home memory does not leak into the project folder, or vice versa.
    let (a_home, b_home) = (a.home_memory(), b.home_memory());
    std::fs::write(a_home.join("personal.md"), "home only\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(read(&b_mem, "personal.md"), None);
    assert_eq!(read(&b_home, "personal.md").as_deref(), Some("home only\n"));
    assert_eq!(read(&b_home, "decision.md"), None);
}

#[test]
fn concurrent_edits_leave_a_conflict_file_everywhere() {
    let (mut a, mut b) = paired();
    let a_mem = a.home_memory();
    let b_mem = b.home_memory();
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
    let (mut a, mut b) = paired();
    let a_mem = a.home_memory();
    let b_mem = b.home_memory();
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

#[test]
fn keys_that_are_not_safe_file_names_are_never_written() {
    let (mut a, mut b) = paired();
    let a_mem = a.home_memory();
    let b_mem = b.home_memory();
    std::fs::write(a_mem.join("ok.md"), "fine\n").unwrap();
    settle(&mut a, &mut b);
    let channel = channel_of(&mut a, "~");

    // A member publishes keys that would escape the memory folder.
    for key in ["../escaped.md", ".hidden.md", "sub/dir.md", "/abs.md"] {
        let db = a.state.db.lock().unwrap();
        entries::publish(
            &a.state,
            &db,
            &channel,
            &Write {
                key,
                content: &serde_json::json!("evil"),
                metadata: None,
                item_type: "memory",
                deleted: false,
            },
        )
        .unwrap();
    }
    std::fs::write(a_mem.join("later.md"), "also fine\n").unwrap();
    settle(&mut a, &mut b);

    // The channel delivers; the unsafe keys are not written anywhere.
    assert_eq!(read(&b_mem, "later.md").as_deref(), Some("also fine\n"));
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
    let mut a = Device::new();
    set_meta(&a, cordelia_storage::meta::SYNC_CLAUDE_ALL, "on");
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

#[test]
fn a_device_without_the_project_never_holds_its_key() {
    let (mut a, mut b) = paired();
    let a_mem = a.claude_folder(&a.clone_at("Work/cordelia-node"));
    std::fs::write(a_mem.join("decision.md"), "Invite-only channels only.\n").unwrap();
    b.home_memory(); // B works only in its home folder: no clone of the project
    settle(&mut a, &mut b);

    let report = a.cycle();
    let channel = report
        .folders
        .iter()
        .find(|f| f.project == "github.com/seed-drill/cordelia-node")
        .and_then(|f| f.channel_id.clone())
        .expect("A created the project channel");
    let db = b.state.db.lock().unwrap();
    assert!(
        !channels::is_member(&db, &channel, &b.pk()).unwrap(),
        "B was never added"
    );
    drop(db);
    assert!(
        cordelia_storage::psk::read_psk(&b.state.home_dir, &channel).is_err(),
        "B holds no key for a project it does not have"
    );

    // Once B clones the project, it asks, A grants, and the memory arrives.
    let b_mem = b.claude_folder(&b.clone_at("src/cn"));
    settle(&mut a, &mut b);
    assert_eq!(
        read(&b_mem, "decision.md").as_deref(),
        Some("Invite-only channels only.\n")
    );
}

#[test]
fn excluded_projects_never_sync() {
    let (mut a, mut b) = paired();
    set_meta(
        &a,
        cordelia_storage::meta::SYNC_CLAUDE_EXCLUDE,
        r#"["github.com/seed-drill/*"]"#,
    );
    let a_mem = a.claude_folder(&a.clone_at("Work/cordelia-node"));
    std::fs::write(a_mem.join("secret.md"), "stays on this machine\n").unwrap();
    let b_mem = b.claude_folder(&b.clone_at("src/cn"));
    settle(&mut a, &mut b);

    let report = a.cycle();
    assert_eq!(
        report.excluded,
        vec!["github.com/seed-drill/cordelia-node".to_string()]
    );
    assert_eq!(read(&b_mem, "secret.md"), None);
}

#[test]
fn home_memory_can_be_left_off_a_device() {
    let (mut a, mut b) = paired();
    set_meta(&b, cordelia_storage::meta::SYNC_CLAUDE_HOME, "off");
    let a_home = a.home_memory();
    let b_home = b.home_memory();
    std::fs::write(a_home.join("user_role.md"), "general profile\n").unwrap();
    std::fs::write(b_home.join("lab_notes.md"), "lab only\n").unwrap();
    settle(&mut a, &mut b);

    assert_eq!(
        read(&b_home, "user_role.md"),
        None,
        "B does not receive home memory"
    );
    assert_eq!(read(&a_home, "lab_notes.md"), None, "nor send it");
    assert!(b.cycle().excluded.contains(&"~".to_string()));
    let channel = channel_of(&mut a, "~");
    assert!(!can_read(&b, &channel), "B holds no key for home memory");
}

#[test]
fn a_device_cannot_ask_to_join_on_anothers_behalf() {
    let (mut a, mut b) = paired();
    // D is also one of this person's devices, but has no clone of the project.
    let mut d = Device::new();
    membership::add_device(&a.state, &d.pk(), Some("d")).unwrap();
    relay(&a, &d);
    membership::accept(&d.state, &a.pk(), Some("a")).unwrap();

    let a_mem = a.claude_folder(&a.clone_at("Work/cordelia-node"));
    std::fs::write(a_mem.join("decision.md"), "x\n").unwrap();
    settle(&mut a, &mut b);
    settle(&mut a, &mut d);
    let channel = a
        .cycle()
        .folders
        .into_iter()
        .find(|f| f.project == "github.com/seed-drill/cordelia-node")
        .and_then(|f| f.channel_id)
        .unwrap();

    // B, a device of the same person, publishes a request that names D.
    let personal = membership::personal_channel_id(&b.state).unwrap();
    let naming_d = format!(
        "join/{channel}/{}",
        cordelia_crypto::bech32::encode_public_key(&d.pk()).unwrap()
    );
    {
        let db = b.state.db.lock().unwrap();
        entries::publish(
            &b.state,
            &db,
            &personal,
            &Write {
                key: &naming_d,
                content: &serde_json::json!({ "channel_id": channel }),
                metadata: None,
                item_type: "membership",
                deleted: false,
            },
        )
        .unwrap();
    }
    settle(&mut a, &mut b);

    // A honours a request only from the device it names: D stays out.
    let db = a.state.db.lock().unwrap();
    assert!(!channels::is_member(&db, &channel, &d.pk()).unwrap());
}

// ── Declared mappings (the default: nothing syncs until it is mapped) ──

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
    assert!(
        report.available.is_empty(),
        "no channel exists for anything"
    );
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
    // still holds neither the memory nor its key.
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
    assert!(!can_read(&b, &channel));

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

    // B is offered home memory, and holds none of it: not the files, not
    // the key, and nothing in the personal channel that every device has.
    let channel = channel_of(&mut a, "~");
    assert_eq!(b.cycle().available, vec!["~".to_string()]);
    assert_eq!(read(&b_home, "user_role.md"), None);
    assert_eq!(read(&a_home, "lab_notes.md"), None);
    assert!(!can_read(&b, &channel));
    {
        let personal = membership::personal_channel_id(&b.state).unwrap();
        let db = b.state.db.lock().unwrap();
        for entry in entries::current(&b.state, &db, &personal).unwrap() {
            assert!(
                !entry
                    .current
                    .content
                    .to_string()
                    .contains("general profile"),
                "home memory in the personal channel: {}",
                entry.key
            );
        }
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

    // B syncs everything it finds, and has only run in a subdirectory too.
    set_meta(&b, cordelia_storage::meta::SYNC_CLAUDE_ALL, "on");
    let b_repo = b.clone_at("src/cn");
    let b_sub = b_repo.join("docs");
    std::fs::create_dir_all(&b_sub).unwrap();
    let b_sub_folder = b.session_in(&b_sub);
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
/// With `--all` it keeps working: the link is followed, and what is
/// outside the tree does not sync.
#[test]
fn a_tree_laid_out_by_hand_still_syncs_with_all() {
    let (mut a, mut b) = paired();
    let a_repo = a.clone_at("Work/cordelia-node");
    let real = a.claude_folder(&a.plain_dir("Work"));
    std::fs::write(real.join("decision.md"), "Invite-only channels only.\n").unwrap();
    let a_home = a.home_memory();
    std::fs::write(a_home.join("private.md"), "outside the tree\n").unwrap();

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
    a.adapter = ClaudeAdapter::new(tree, a.home.clone(), &a.pk());

    let b_mem = b.claude_folder(&b.clone_at("src/cn"));
    let b_home = b.home_memory();
    settle(&mut a, &mut b);
    assert_eq!(
        read(&b_mem, "decision.md").as_deref(),
        Some("Invite-only channels only.\n")
    );
    assert_eq!(read(&b_home, "private.md"), None);

    // And back, through the link, into the real folder.
    std::fs::write(b_mem.join("reply.md"), "from b\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(read(&real, "reply.md").as_deref(), Some("from b\n"));
    let link = entry.join("memory").symlink_metadata().unwrap();
    assert!(link.file_type().is_symlink(), "the link is left as it is");
    let report = a.cycle();
    assert_eq!(report.folders.len(), 1, "{:?}", report.folders);
    assert_eq!(report.folders[0].project, PROJECT);
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

    // A device speaks only for itself: B cannot list names on A's behalf.
    // D, a third device, hears B's version before A can answer it.
    let mut d = Device::new();
    membership::add_device(&a.state, &d.pk(), Some("d")).unwrap();
    relay(&a, &d);
    membership::accept(&d.state, &a.pk(), Some("a")).unwrap();
    settle(&mut a, &mut d);
    assert_eq!(d.cycle().available, vec!["lab-notes".to_string()]);
    let personal = membership::personal_channel_id(&b.state).unwrap();
    let a_key = cordelia_crypto::bech32::encode_public_key(&a.pk()).unwrap();
    {
        let db = b.state.db.lock().unwrap();
        entries::publish(
            &b.state,
            &db,
            &personal,
            &Write {
                key: &format!("syncing/{a_key}"),
                content: &serde_json::json!({ "names": ["lab-notes", "made-up"] }),
                metadata: None,
                item_type: "memory",
                deleted: false,
            },
        )
        .unwrap();
    }
    relay(&b, &d);
    assert!(
        !d.cycle().available.contains(&"made-up".to_string()),
        "a list is read only from the device it is about"
    );
    settle(&mut a, &mut b);
    settle(&mut a, &mut d);
    assert_eq!(b.cycle().available, vec!["lab-notes".to_string()]);
    assert_eq!(d.cycle().available, vec!["lab-notes".to_string()]);

    // A stops syncing it. The name stays in this person's map, but no
    // device syncs it, so it is no longer on offer.
    set_meta(&a, cordelia_storage::meta::SYNC_CLAUDE_MAPPINGS, "[]");
    settle(&mut a, &mut b);
    assert!(b.cycle().available.is_empty());

    // Likewise when sync is turned off altogether.
    map(&a, &a_notes, "lab-notes");
    settle(&mut a, &mut b);
    assert_eq!(b.cycle().available, vec!["lab-notes".to_string()]);
    cordelia_sync::claude::withdraw(&a.state).unwrap();
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
        for d in [&a, &b] {
            membership::process_inbox(&d.state).unwrap();
            membership::process_join_requests(&d.state).unwrap();
        }
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

// ── A folder that stops syncing, or goes missing, deletes nothing ──────

/// Unmapped (or home turned off, or the scope narrowed), emptied, and
/// mapped again: the folder starts afresh. What it lost in between is not
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

    // The same when sync is turned off altogether and on again.
    cordelia_sync::claude::withdraw(&a.state).unwrap();
    std::fs::remove_file(a_mem.join("one.md")).unwrap();
    settle(&mut a, &mut b);
    assert_eq!(files(&b_mem), ["MEMORY.md", "one.md", "two.md"]);
    assert_eq!(read(&a_mem, "one.md").as_deref(), Some("one\n"));

    // A delete made while the folder syncs still reaches the other device.
    std::fs::remove_file(a_mem.join("two.md")).unwrap();
    settle(&mut a, &mut b);
    assert_eq!(files(&b_mem), ["MEMORY.md", "one.md"]);
}

#[test]
fn narrowing_the_scope_and_widening_it_again_deletes_nothing() {
    let (mut a, mut b) = paired();
    let a_home = a.home_memory();
    let b_home = b.home_memory();
    std::fs::write(a_home.join("profile.md"), "general profile\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(files(&b_home), ["profile.md"]);

    // A goes back to mapped folders only (it has none), loses its copy,
    // then syncs everything it finds again.
    set_meta(&a, cordelia_storage::meta::SYNC_CLAUDE_ALL, "off");
    settle(&mut a, &mut b);
    std::fs::remove_file(a_home.join("profile.md")).unwrap();
    settle(&mut a, &mut b);
    set_meta(&a, cordelia_storage::meta::SYNC_CLAUDE_ALL, "on");
    settle(&mut a, &mut b);
    assert_eq!(files(&b_home), ["profile.md"]);
    assert_eq!(files(&a_home), ["profile.md"]);
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
    assert!(error.contains("Nothing was deleted"), "{error}");
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

/// On a device that syncs everything it finds, an unmapped folder stays
/// out: it is not picked up again under the name discovery would give it.
#[test]
fn an_unmapped_folder_stays_out_when_everything_found_syncs() {
    let (mut a, mut b) = paired();
    let a_repo = a.clone_at("Work/cordelia-node");
    let a_mem = a.claude_folder(&a_repo);
    let b_mem = b.claude_folder(&b.clone_at("src/cn"));
    std::fs::write(b_mem.join("shared.md"), "the project's memory\n").unwrap();

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
    assert_eq!(
        report.unmapped,
        vec![cordelia_sync::claude::Found {
            folder: a.folder_of(&a_repo).display().to_string(),
            cwd: Some(a_repo.display().to_string()),
            name: Some(PROJECT.to_string()),
        }],
        "listed, so it can be mapped again"
    );
}

/// A session can move to another directory, so a transcript in one folder
/// can start in another. A folder Claude Code named is believed only about
/// the directory it is named after.
#[test]
fn a_claude_folder_is_believed_only_about_its_own_directory() {
    let (mut a, mut b) = paired();
    let a_repo = a.clone_at("Work/cordelia-node");
    let a_home = a.home_memory();
    std::fs::write(a_home.join("profile.md"), "general profile\n").unwrap();
    let b_mem = b.claude_folder(&b.clone_at("src/cn"));
    let b_home = b.home_memory();

    // The newest transcript in A's home folder starts in the repository.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let home_folder = a.folder_of(&a.home.clone());
    std::fs::write(
        home_folder.join("newer.jsonl"),
        format!("{{\"cwd\":{:?}}}\n", a_repo.display().to_string()),
    )
    .unwrap();
    settle(&mut a, &mut b);
    assert_eq!(
        files(&b_mem),
        Vec::<String>::new(),
        "not the project's memory"
    );
    assert_eq!(files(&b_home), ["profile.md"], "still home memory");

    // With only that transcript, nothing says whose folder it is: it does
    // not sync at all, rather than sync as the repository's.
    std::fs::remove_file(home_folder.join("session.jsonl")).unwrap();
    a.adapter = ClaudeAdapter::new(a.home.join(".claude"), a.home.clone(), &a.pk());
    std::fs::write(a_home.join("later.md"), "more\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(files(&b_mem), Vec::<String>::new());
    assert_eq!(files(&b_home), ["profile.md"]);
    let report = a.cycle();
    assert!(report.folders.is_empty(), "{:?}", report.folders);
    assert_eq!(report.unmapped.len(), 1);
    assert_eq!(report.unmapped[0].cwd, None);
}

/// Two devices of one person, already paired, both start syncing home
/// memory before hearing from each other (as when both are upgraded). Each
/// creates a channel; they end up in one, with every file on both.
#[test]
fn two_devices_starting_at_once_end_up_in_one_channel() {
    let (mut a, mut b) = paired();
    // Let B's joining settle first, so it does not hold back.
    settle(&mut a, &mut b);
    {
        let personal = membership::personal_channel_id(&b.state).unwrap();
        let db = b.state.db.lock().unwrap();
        db.execute(
            "UPDATE channel_members SET joined_at = '2026-01-01T00:00:00Z' WHERE channel_id = ?1",
            [&personal],
        )
        .unwrap();
    }
    let a_home = a.home_memory();
    let b_home = b.home_memory();
    std::fs::write(a_home.join("same.md"), "the same on both\n").unwrap();
    std::fs::write(b_home.join("same.md"), "the same on both\n").unwrap();
    std::fs::write(a_home.join("only_a.md"), "from a\n").unwrap();
    std::fs::write(b_home.join("only_b.md"), "from b\n").unwrap();
    std::fs::write(a_home.join("differs.md"), "a's version\n").unwrap();
    std::fs::write(b_home.join("differs.md"), "b's version\n").unwrap();

    // Each runs a cycle before any item has travelled.
    let first_a = channel_of(&mut a, "~");
    let first_b = channel_of(&mut b, "~");
    assert_ne!(first_a, first_b, "each created a channel");
    settle(&mut a, &mut b);
    settle(&mut a, &mut b);

    assert_eq!(channel_of(&mut a, "~"), channel_of(&mut b, "~"));
    assert_eq!(files(&a_home), files(&b_home));
    let names = files(&a_home);
    for name in ["same.md", "only_a.md", "only_b.md", "differs.md"] {
        assert!(names.contains(&name.to_string()), "{names:?}");
    }
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
}

#[test]
fn a_name_is_offered_only_once_a_device_syncs_it() {
    let (mut a, mut b) = paired_explicit();
    // B has just joined A's devices, so it waits before making a channel
    // for a name nobody has: until then it is not syncing it.
    let b_notes = b.plain_dir("notes");
    b.claude_folder(&b_notes);
    map(&b, &b_notes, "solo");
    settle(&mut a, &mut b);
    assert!(b.cycle().folders[0].waiting);
    assert!(a.cycle().available.is_empty(), "nothing to offer yet");

    // A name that could not be mapped is never passed on: it would end up
    // in a command for the person to copy.
    let personal = membership::personal_channel_id(&b.state).unwrap();
    let b_key = cordelia_crypto::bech32::encode_public_key(&b.pk()).unwrap();
    {
        let db = b.state.db.lock().unwrap();
        entries::publish(
            &b.state,
            &db,
            &personal,
            &Write {
                key: &format!("syncing/{b_key}"),
                content: &serde_json::json!({ "names": ["fine", "x; rm -rf ~", "Has Space"] }),
                metadata: None,
                item_type: "memory",
                deleted: false,
            },
        )
        .unwrap();
    }
    relay(&b, &a);
    assert_eq!(a.cycle().available, vec!["fine".to_string()]);
}

/// A git repository created above a mapped folder moves its memory to the
/// repository's folder. The mapping says so rather than syncing on as if
/// nothing had changed.
#[test]
fn a_repository_appearing_above_a_mapped_folder_is_reported() {
    let mut a = Device::new();
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
