//! The Claude Code adapter across two devices (decision
//! 2026-09-30-agent-memory-sync §4.5, §10).
//!
//! Each device has its own home, `~/.claude`, and clone of the same
//! repository at a different path. Nodes are in-process; a stand-in relay
//! copies items between their databases.

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
        let home = dir.path().join("home");
        let node_dir = dir.path().join("node");
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

    /// A Claude Code project folder whose sessions ran in `cwd`; returns
    /// its memory folder (created).
    fn claude_folder(&self, cwd: &Path) -> PathBuf {
        let slug = cwd.display().to_string().replace(['/', '.'], "-");
        let folder = self.home.join(".claude/projects").join(slug);
        std::fs::create_dir_all(folder.join("memory")).unwrap();
        std::fs::write(
            folder.join("session.jsonl"),
            format!(
                "{{\"type\":\"mode\"}}\n{{\"cwd\":{:?},\"type\":\"user\"}}\n",
                cwd.display().to_string()
            ),
        )
        .unwrap();
        folder.join("memory")
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

/// Everything flows both ways until quiet: relay, apply invites, sync.
fn settle(a: &mut Device, b: &mut Device) {
    for _ in 0..4 {
        relay(a, b);
        relay(b, a);
        membership::process_inbox(&a.state).unwrap();
        membership::process_inbox(&b.state).unwrap();
        relay(a, b);
        relay(b, a);
        a.cycle();
        b.cycle();
    }
}

/// Two devices of one person: A adds B, B accepts A.
fn paired() -> (Device, Device) {
    let a = Device::new();
    let b = Device::new();
    membership::add_device(&a.state, &b.pk(), Some("b")).unwrap();
    relay(&a, &b);
    membership::accept(&b.state, &a.pk(), Some("a")).unwrap();
    (a, b)
}

fn read(dir: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(name)).ok()
}

#[test]
fn home_memory_syncs_both_ways() {
    let (mut a, mut b) = paired();
    let a_mem = a.home_memory();
    let b_mem = b.home_memory();

    std::fs::write(a_mem.join("user_role.md"), "Russ is the CPO.\n").unwrap();
    settle(&mut a, &mut b);
    assert_eq!(
        read(&b_mem, "user_role.md").as_deref(),
        Some("Russ is the CPO.\n")
    );

    std::fs::write(
        b_mem.join("user_role.md"),
        "Russ is the CPO of Seed Drill.\n",
    )
    .unwrap();
    settle(&mut a, &mut b);
    assert_eq!(
        read(&a_mem, "user_role.md").as_deref(),
        Some("Russ is the CPO of Seed Drill.\n")
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
    let b_mem = b.home_memory();
    let personal = membership::personal_channel_id(&a.state).unwrap();

    // A member publishes keys that would escape the memory folder.
    for key in ["home/../escaped.md", "home/.hidden.md", "home/sub/dir.md"] {
        let db = a.state.db.lock().unwrap();
        entries::publish(
            &a.state,
            &db,
            &personal,
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
    settle(&mut a, &mut b);

    assert!(!b_mem.parent().unwrap().join("escaped.md").exists());
    assert!(!b_mem.join(".hidden.md").exists());
    assert!(!b_mem.join("sub").exists());
}

#[test]
fn folders_without_a_repository_are_reported_not_synced() {
    let mut a = Device::new();
    let scratch = a.home.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let mem = a.claude_folder(&scratch);
    std::fs::write(mem.join("temp.md"), "not synced\n").unwrap();

    let report = a.cycle();
    assert_eq!(report.unsynced.len(), 1);
    assert!(report.unsynced[0].ends_with(&scratch.display().to_string().replace(['/', '.'], "-")));
}
