//! Keyed items across devices (decision 2026-09-30-agent-memory-sync §4.3).
//!
//! In-process nodes, paired through the membership protocol; a stand-in
//! relay copies a channel's items between databases through the same
//! storage rule the network path uses.

use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

use serde_json::json;

use cordelia_api::entries::{self, Write};
use cordelia_api::membership;
use cordelia_api::state::AppState;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::signing::ItemMetadata;
use cordelia_crypto::slots::{item_aad, slot_id};
use cordelia_storage::{items, naming, psk};

struct Node {
    state: AppState,
    _dir: tempfile::TempDir,
}

fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState {
        db: Mutex::new(cordelia_storage::db::open_in_memory().unwrap()),
        identity: NodeIdentity::generate().unwrap(),
        bearer_token: "t".into(),
        home_dir: dir.path().to_path_buf(),
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
        usable_keys: Default::default(),
    };
    membership::ensure_own_inbox(&state).unwrap();
    Node { state, _dir: dir }
}

impl Node {
    fn pk(&self) -> [u8; 32] {
        self.state.identity.public_key()
    }

    fn write(&self, channel: &str, key: &str, text: &str) -> u64 {
        let db = self.state.db.lock().unwrap();
        entries::publish(
            &self.state,
            &db,
            channel,
            &Write {
                key,
                content: &json!({ "text": text }),
                metadata: None,
                item_type: "memory",
                deleted: false,
                after: None,
            },
        )
        .unwrap()
        .rev
    }

    /// key -> (text, rev, conflict count)
    fn read(&self, channel: &str) -> Vec<(String, String, u64, usize)> {
        let db = self.state.db.lock().unwrap();
        entries::current(&self.state, &db, channel)
            .unwrap()
            .into_iter()
            .map(|e| {
                (
                    e.key,
                    e.current.content["text"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    e.current.rev,
                    e.conflicts.len(),
                )
            })
            .collect()
    }
}

/// Copy every item `from` holds in `channel` (or an inbox) into `to`.
fn relay(from: &Node, to: &Node, channel: &str) {
    let stored = {
        let db = from.state.db.lock().unwrap();
        items::query_sync(&db, channel, None, 10_000).unwrap()
    };
    let db = to.state.db.lock().unwrap();
    for it in stored {
        let slot: Option<[u8; 32]> = it.slot.as_ref().map(|s| s.as_slice().try_into().unwrap());
        items::insert_item(
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
        )
        .unwrap();
    }
}

/// Two devices sharing a personal channel.
fn paired() -> (Node, Node, String) {
    let a = node();
    let b = node();
    let personal = membership::add_device(&a.state, &b.pk(), None)
        .unwrap()
        .personal_channel_id;
    relay(&a, &b, &naming::inbox_channel_id(&b.pk()));
    membership::accept(&b.state, &a.pk(), None).unwrap();
    (a, b, personal)
}

#[test]
fn a_key_written_on_one_device_is_read_on_the_other() {
    let (a, b, ch) = paired();

    assert_eq!(a.write(&ch, "notes.md", "v1"), 1);
    relay(&a, &b, &ch);
    assert_eq!(b.read(&ch), vec![("notes.md".into(), "v1".into(), 1, 0)]);

    // B edits; A sees the edit, and each side keeps one current value.
    assert_eq!(b.write(&ch, "notes.md", "v2"), 2);
    relay(&b, &a, &ch);
    assert_eq!(a.read(&ch), vec![("notes.md".into(), "v2".into(), 2, 0)]);

    // A edits again after seeing B's revision.
    assert_eq!(a.write(&ch, "notes.md", "v3"), 3);
    relay(&a, &b, &ch);
    assert_eq!(b.read(&ch), vec![("notes.md".into(), "v3".into(), 3, 0)]);
}

#[test]
fn storage_keeps_one_revision_per_author_per_key() {
    let (a, _b, ch) = paired();
    for i in 1..=5 {
        a.write(&ch, "notes.md", &format!("v{i}"));
    }
    let db = a.state.db.lock().unwrap();
    assert_eq!(items::slotted_items(&db, &ch).unwrap().len(), 1);
}

#[test]
fn concurrent_edits_converge_and_surface_the_conflict() {
    let (a, b, ch) = paired();
    a.write(&ch, "notes.md", "base");
    relay(&a, &b, &ch);

    // Both edit revision 1 without seeing each other.
    assert_eq!(a.write(&ch, "notes.md", "from a"), 2);
    assert_eq!(b.write(&ch, "notes.md", "from b"), 2);
    relay(&a, &b, &ch);
    relay(&b, &a, &ch);

    let on_a = a.read(&ch);
    let on_b = b.read(&ch);
    assert_eq!(on_a, on_b, "both devices pick the same winner");
    assert_eq!(on_a[0].2, 2);
    assert_eq!(on_a[0].3, 1, "the other edit is reported as a conflict");

    // The next edit resolves it everywhere.
    a.write(&ch, "notes.md", "merged");
    relay(&a, &b, &ch);
    assert_eq!(
        b.read(&ch),
        vec![("notes.md".into(), "merged".into(), 3, 0)]
    );
}

/// Store a keyed item signed by `signer` directly into `to`'s channel.
fn inject(
    to: &Node,
    signer: &NodeIdentity,
    channel: &str,
    slot: [u8; 32],
    rev: u64,
    psk: [u8; 32],
    plaintext: serde_json::Value,
) {
    let blob = cordelia_crypto::item_encrypt(
        &psk,
        &serde_json::to_vec(&plaintext).unwrap(),
        &item_aad(channel, Some(&slot), Some(rev)),
    )
    .unwrap();
    let hash = cordelia_crypto::sha256(&blob);
    let item_id = items::generate_item_id();
    let cbor = ItemMetadata {
        author_id: &signer.public_key(),
        channel_id: channel,
        content_hash: &hash,
        is_tombstone: false,
        item_id: &item_id,
        key_version: 1,
        published_at: "2026-09-30T00:00:00Z",
        slot: Some(&slot),
        rev: Some(rev),
    }
    .encode()
    .unwrap();
    let db = to.state.db.lock().unwrap();
    items::insert_item(
        &db,
        &items::NewItem {
            item_id: &item_id,
            channel_id: channel,
            author_id: &signer.public_key(),
            item_type: "memory",
            published_at: "2026-09-30T00:00:00Z",
            parent_id: None,
            key_version: 1,
            content_hash: &hash,
            signature: &signer.sign(&cbor),
            encrypted_blob: &blob,
            is_tombstone: false,
            slot: Some(&slot),
            rev: Some(rev),
        },
    )
    .unwrap();
}

#[test]
fn only_members_writing_the_right_key_count() {
    let (a, b, ch) = paired();
    a.write(&ch, "notes.md", "real");
    let slot_key = psk::read_slot_key(&a.state.home_dir, &ch).unwrap();
    let channel_key = psk::read_psk(&a.state.home_dir, &ch).unwrap();
    let slot = slot_id(&slot_key, "notes.md");

    // A stranger who somehow has the keys still is not a member.
    let stranger = NodeIdentity::generate().unwrap();
    inject(
        &a,
        &stranger,
        &ch,
        slot,
        99,
        channel_key,
        json!({ "key": "notes.md", "content": { "text": "evil" } }),
    );
    assert_eq!(a.read(&ch), vec![("notes.md".into(), "real".into(), 1, 0)]);

    // Another member whose inner key does not map to the slot is ignored:
    // otherwise an item stored as notes.md could claim to be another file.
    // (It lands in B's own cell; A's item is untouched.)
    inject(
        &a,
        &b.state.identity,
        &ch,
        slot,
        50,
        channel_key,
        json!({ "key": "other.md", "content": { "text": "confused" } }),
    );
    assert_eq!(a.read(&ch), vec![("notes.md".into(), "real".into(), 1, 0)]);

    // Wrong channel key: does not decrypt, ignored.
    inject(
        &a,
        &b.state.identity,
        &ch,
        slot_id(&slot_key, "x.md"),
        1,
        [0x13; 32],
        json!({ "key": "x.md", "content": {} }),
    );
    assert_eq!(a.read(&ch).len(), 1);
}

/// T2. Someone who was never in the channel stores an entry under a name's
/// slot with the highest revision there is. It is not read, and it does not
/// put the name out of reach: the channel's members go on writing it.
#[test]
fn a_strangers_revision_does_not_stop_a_member_writing() {
    let (a, b, ch) = paired();
    assert_eq!(a.write(&ch, "notes.md", "one"), 1);
    let slot_key = psk::read_slot_key(&a.state.home_dir, &ch).unwrap();
    let channel_key = psk::read_psk(&a.state.home_dir, &ch).unwrap();
    let slot = slot_id(&slot_key, "notes.md");

    let stranger = NodeIdentity::generate().unwrap();
    inject(
        &a,
        &stranger,
        &ch,
        slot,
        cordelia_core::protocol::MAX_REV,
        channel_key,
        json!({ "key": "notes.md", "content": { "text": "evil" } }),
    );
    assert_eq!(a.read(&ch), vec![("notes.md".into(), "one".into(), 1, 0)]);

    assert_eq!(a.write(&ch, "notes.md", "two"), 2);
    relay(&a, &b, &ch);
    assert_eq!(b.read(&ch), vec![("notes.md".into(), "two".into(), 2, 0)]);
    assert_eq!(b.write(&ch, "notes.md", "three"), 3);
}

#[test]
fn a_removed_device_can_no_longer_write() {
    let (a, b, ch) = paired();
    a.write(&ch, "notes.md", "before");
    relay(&a, &b, &ch);

    membership::remove_device(&a.state, &b.pk()).unwrap();
    // B, not yet aware, keeps writing with the keys it held.
    b.write(&ch, "notes.md", "after removal");
    relay(&b, &a, &ch);
    assert_eq!(
        a.read(&ch),
        vec![("notes.md".into(), "before".into(), 1, 0)]
    );
}

/// T3. An entry is at most 64 KB as it travels. The device that writes it
/// refuses a larger one, and says how large it was.
#[test]
fn t03_an_entry_over_the_size_limit_is_not_written() {
    use cordelia_core::protocol::{ITEM_SEAL_OVERHEAD_BYTES, MAX_ITEM_BYTES};
    let (a, _b, ch) = paired();
    let write = |text: &str| {
        let db = a.state.db.lock().unwrap();
        entries::publish(
            &a.state,
            &db,
            &ch,
            &Write {
                key: "notes.md",
                content: &json!(text),
                metadata: None,
                item_type: "memory",
                deleted: false,
                after: None,
            },
        )
    };
    // The entry's content is {"content":"...","key":"notes.md","metadata":null}.
    let envelope =
        serde_json::to_vec(&json!({ "key": "notes.md", "content": "", "metadata": null }))
            .unwrap()
            .len();
    let fits = MAX_ITEM_BYTES - ITEM_SEAL_OVERHEAD_BYTES - envelope;

    write(&"x".repeat(fits)).unwrap();
    let stored = {
        let db = a.state.db.lock().unwrap();
        items::slotted_items(&db, &ch).unwrap()
    };
    assert_eq!(stored[0].encrypted_blob.len(), MAX_ITEM_BYTES);

    match write(&"x".repeat(fits + 1)) {
        Err(cordelia_core::CordeliaError::TooLarge { bytes, limit }) => {
            assert_eq!((bytes, limit), (MAX_ITEM_BYTES + 1, MAX_ITEM_BYTES));
        }
        other => panic!("expected a refusal for size, got {other:?}"),
    }
}

fn delete(n: &Node, channel: &str, key: &str) -> u64 {
    let db = n.state.db.lock().unwrap();
    entries::publish(
        &n.state,
        &db,
        channel,
        &Write {
            key,
            content: &serde_json::Value::Null,
            metadata: None,
            item_type: "memory",
            deleted: true,
            after: None,
        },
    )
    .unwrap()
    .rev
}

/// What a channel holds as `n` reads it: each key with its text (`None`
/// for a deleted key), its revision and its author.
fn holds(n: &Node, channel: &str) -> Vec<(String, Option<String>, u64, [u8; 32])> {
    let db = n.state.db.lock().unwrap();
    entries::current(&n.state, &db, channel)
        .unwrap()
        .into_iter()
        .map(|e| {
            let text = (!e.current.deleted)
                .then(|| e.current.content["text"].as_str().unwrap().to_string());
            (e.key, text, e.current.rev, e.current.author)
        })
        .collect()
}

/// Make `new` another device of `owner`'s, and tell `others` (devices
/// already there) about it.
fn join(owner: &Node, new: &Node, others: &[&Node]) {
    membership::add_device(&owner.state, &new.pk(), None).unwrap();
    relay(owner, new, &naming::inbox_channel_id(&new.pk()));
    membership::accept(&new.state, &owner.pk(), None).unwrap();
    for other in others {
        relay(owner, other, &naming::inbox_channel_id(&other.pk()));
        membership::process_inbox(&other.state).unwrap();
    }
}

/// What an entry says it was written after is a member of its sealed
/// content, beside the text. It is there only when the writer puts it
/// there, for a delete as for a text, and it is read back as written. An
/// entry with it is read by a version that knows nothing of it to the
/// same key and content, since that version takes the members it knows by
/// name. And an entry published again when a device is removed says
/// nothing, whatever the one it takes the place of said.
#[test]
fn what_an_entry_was_written_after_is_carried_only_when_said() {
    let (a, b, ch) = paired();
    // The sealed content of the entry by `author` that `n` holds for `key`.
    let sealed = |n: &Node, key: &str, author: &[u8; 32]| -> serde_json::Value {
        let db = n.state.db.lock().unwrap();
        let version = cordelia_storage::channels::get_by_id(&db, &ch)
            .unwrap()
            .key_version;
        let slot = slot_id(&psk::read_slot_key(&n.state.home_dir, &ch).unwrap(), key);
        let item = items::slot_items(&db, &ch, &slot)
            .unwrap()
            .into_iter()
            .find(|it| it.author_id == author)
            .unwrap();
        entries::decrypt(&n.state, version, &item).unwrap()
    };
    let said = |n: &Node, key: &str| {
        let db = n.state.db.lock().unwrap();
        let entry = entries::current_of(&n.state, &db, &ch, key).unwrap();
        entry.unwrap().current.after
    };
    let publish = |n: &Node, key: &str, after: Option<&serde_json::Value>, deleted: bool| {
        let db = n.state.db.lock().unwrap();
        let write = Write {
            key,
            content: &json!({ "text": "v" }),
            metadata: None,
            item_type: "memory",
            deleted,
            after,
        };
        entries::publish(&n.state, &db, &ch, &write).unwrap();
    };

    // Nothing said: no such member at all.
    a.write(&ch, "plain.md", "v1");
    assert!(sealed(&a, "plain.md", &a.pk()).get("after").is_none());
    assert_eq!(said(&a, "plain.md"), None);
    // `null` is nothing said.
    publish(&a, "null.md", Some(&serde_json::Value::Null), false);
    assert_eq!(said(&a, "null.md"), None);

    // Said: it is carried as written, whatever it is, and the members a
    // version from before reads are what they would be without it.
    let after = json!({ "of": { "ab": 1 }, "more": [1, 2] });
    publish(&b, "said.md", Some(&after), false);
    relay(&b, &a, &ch);
    assert_eq!(said(&a, "said.md"), Some(after.clone()));
    let whole = sealed(&a, "said.md", &b.pk());
    assert_eq!(
        whole,
        json!({ "key": "said.md", "content": { "text": "v" }, "metadata": null, "after": after })
    );
    // The same for a delete.
    publish(&b, "said.md", Some(&after), true);
    relay(&b, &a, &ch);
    assert_eq!(said(&a, "said.md"), Some(after.clone()));
    assert_eq!(holds(&a, &ch)[2], ("said.md".to_string(), None, 2, b.pk()));

    // B is removed. What it wrote is published again as A's, and says
    // nothing.
    membership::remove_device(&a.state, &b.pk()).unwrap();
    assert_eq!(holds(&a, &ch)[2], ("said.md".to_string(), None, 2, a.pk()));
    assert_eq!(said(&a, "said.md"), None);
    assert!(sealed(&a, "said.md", &a.pk()).get("after").is_none());
}

/// T16. The channel keeps what a removed device last wrote: the device
/// that removes it publishes those entries again under its own name, at
/// the same revisions. A file the removed device edited last keeps its
/// edit, a file only it wrote is still there, and a file it deleted stays
/// deleted, for the devices that remain and for one added later.
#[test]
fn t16_what_a_removed_device_last_wrote_is_kept() {
    let (a, b, ch) = paired();
    a.write(&ch, "edited.md", "by a");
    a.write(&ch, "deleted.md", "by a");
    a.write(&ch, "untouched.md", "by a");
    relay(&a, &b, &ch);
    assert_eq!(b.write(&ch, "edited.md", "by b"), 2);
    assert_eq!(delete(&b, &ch, "deleted.md"), 2);
    assert_eq!(b.write(&ch, "created.md", "by b"), 1);
    relay(&b, &a, &ch);

    membership::remove_device(&a.state, &b.pk()).unwrap();

    let expect = vec![
        (
            "created.md".to_string(),
            Some("by b".to_string()),
            1,
            a.pk(),
        ),
        ("deleted.md".to_string(), None, 2, a.pk()),
        ("edited.md".to_string(), Some("by b".to_string()), 2, a.pk()),
        (
            "untouched.md".to_string(),
            Some("by a".to_string()),
            1,
            a.pk(),
        ),
    ];
    assert_eq!(holds(&a, &ch), expect);

    // A device added afterwards gets the same.
    let c = node();
    join(&a, &c, &[]);
    relay(&a, &c, &ch);
    assert_eq!(holds(&c, &ch), expect);

    // And the next edit is the next revision.
    assert_eq!(a.write(&ch, "edited.md", "by a again"), 3);
}

/// T16. A removed device stores the highest revision there is under a
/// name, with the keys it still holds. That neither shows nor counts: the
/// devices that remain go on writing the name.
#[test]
fn t16_a_removed_device_cannot_put_a_name_out_of_reach() {
    let (a, b, ch) = paired();
    a.write(&ch, "notes.md", "one");
    relay(&a, &b, &ch);
    let slot_key = psk::read_slot_key(&a.state.home_dir, &ch).unwrap();
    let old_key = psk::read_psk(&a.state.home_dir, &ch).unwrap();

    membership::remove_device(&a.state, &b.pk()).unwrap();
    inject(
        &a,
        &b.state.identity,
        &ch,
        slot_id(&slot_key, "notes.md"),
        cordelia_core::protocol::MAX_REV,
        old_key,
        json!({ "key": "notes.md", "content": { "text": "after removal" } }),
    );

    assert_eq!(a.read(&ch), vec![("notes.md".into(), "one".into(), 1, 0)]);
    assert_eq!(a.write(&ch, "notes.md", "two"), 2);
    assert_eq!(a.read(&ch), vec![("notes.md".into(), "two".into(), 2, 0)]);
}

/// T16. A device, while still a member, gives a name a revision that
/// editing never reaches, to use the numbers up. When it is removed, what
/// it wrote is kept at an ordinary revision, and the name stays writable.
#[test]
fn t16_a_revision_meant_to_use_the_numbers_up_is_not_kept() {
    use cordelia_core::protocol::MAX_REV;
    let (a, b, ch) = paired();
    assert_eq!(a.write(&ch, "notes.md", "one"), 1);
    relay(&a, &b, &ch);
    let slot_key = psk::read_slot_key(&a.state.home_dir, &ch).unwrap();
    let key = psk::read_psk(&a.state.home_dir, &ch).unwrap();
    inject(
        &a,
        &b.state.identity,
        &ch,
        slot_id(&slot_key, "notes.md"),
        MAX_REV,
        key,
        json!({ "key": "notes.md", "content": { "text": "by b" } }),
    );
    // B is a member, so this is the channel's value for now.
    assert_eq!(
        a.read(&ch),
        vec![("notes.md".into(), "by b".into(), MAX_REV, 0)]
    );

    membership::remove_device(&a.state, &b.pk()).unwrap();
    assert_eq!(a.read(&ch), vec![("notes.md".into(), "by b".into(), 2, 0)]);
    assert_eq!(a.write(&ch, "notes.md", "three"), 3);
}

/// T16. Only the device that removes takes over what the removed device
/// wrote, with what it holds at that moment. A device that learns of the
/// removal later holds something newer from the removed device: it cannot
/// tell whether that was written before the removal or after it, so it
/// does not make it the channel's value.
#[test]
fn t16_what_a_removed_device_writes_afterwards_is_not_adopted_later() {
    let (a, b, ch) = paired();
    let r = node();
    join(&a, &r, &[&b]);
    relay(&a, &r, &ch);
    assert_eq!(r.write(&ch, "notes.md", "before"), 1);
    relay(&r, &a, &ch);
    relay(&r, &b, &ch);

    membership::remove_device(&a.state, &r.pk()).unwrap();
    // R writes on. B has not heard of the removal yet, so it reads that.
    assert_eq!(r.write(&ch, "notes.md", "after"), 2);
    relay(&r, &b, &ch);
    assert_eq!(b.read(&ch), vec![("notes.md".into(), "after".into(), 2, 0)]);

    // B hears of the removal, and receives what A published again.
    relay(&a, &b, &naming::inbox_channel_id(&b.pk()));
    relay(&a, &b, &ch);
    membership::process_inbox(&b.state).unwrap();
    assert_eq!(
        holds(&b, &ch),
        vec![(
            "notes.md".to_string(),
            Some("before".to_string()),
            1,
            a.pk()
        )]
    );
    // B publishes nothing of R's.
    relay(&b, &a, &ch);
    assert_eq!(
        holds(&a, &ch),
        vec![(
            "notes.md".to_string(),
            Some("before".to_string()),
            1,
            a.pk()
        )]
    );
}

#[test]
fn items_from_before_a_key_rotation_still_read() {
    let (a, b, ch) = paired();
    a.write(&ch, "old.md", "written under key 1");

    // Rotating (by removing a third device) moves the channel to key 2.
    let c = node();
    membership::add_device(&a.state, &c.pk(), None).unwrap();
    membership::remove_device(&a.state, &c.pk()).unwrap();
    a.write(&ch, "new.md", "written under key 2");

    let read = a.read(&ch);
    assert_eq!(read.len(), 2);
    assert!(
        read.iter()
            .any(|(k, t, _, _)| k == "old.md" && t == "written under key 1")
    );

    // B, given the whole ring in the new state, reads both.
    relay(&a, &b, &naming::inbox_channel_id(&b.pk()));
    membership::process_inbox(&b.state).unwrap();
    relay(&a, &b, &ch);
    assert_eq!(b.read(&ch).len(), 2);
}

#[test]
fn deleting_a_key_replicates_and_a_later_write_revives_it() {
    let (a, b, ch) = paired();
    a.write(&ch, "notes.md", "v1");
    relay(&a, &b, &ch);

    // A deletes: a tombstone revision.
    {
        let db = a.state.db.lock().unwrap();
        let rev = entries::publish(
            &a.state,
            &db,
            &ch,
            &Write {
                key: "notes.md",
                content: &serde_json::Value::Null,
                metadata: None,
                item_type: "memory",
                deleted: true,
                after: None,
            },
        )
        .unwrap()
        .rev;
        assert_eq!(rev, 2);
    }
    relay(&a, &b, &ch);
    let deleted = {
        let db = b.state.db.lock().unwrap();
        entries::current(&b.state, &db, &ch).unwrap()
    };
    assert_eq!(deleted.len(), 1);
    assert!(deleted[0].current.deleted, "B sees the key as deleted");
    assert_eq!(deleted[0].current.rev, 2);

    // Writing the key again after the delete brings it back everywhere.
    assert_eq!(b.write(&ch, "notes.md", "recreated"), 3);
    relay(&b, &a, &ch);
    assert_eq!(
        a.read(&ch),
        vec![("notes.md".into(), "recreated".into(), 3, 0)]
    );
}

/// One name's value is read as the channel's values are: by the same
/// rules, from that name's slot and no other. The sync adapter plans from
/// the one and checks against the other before it publishes, so the two
/// must agree on every name.
#[test]
fn one_names_value_is_read_as_the_channels_are() {
    let (a, b, ch) = paired();
    let slot_key = psk::read_slot_key(&a.state.home_dir, &ch).unwrap();
    let channel_key = psk::read_psk(&a.state.home_dir, &ch).unwrap();
    let stranger = NodeIdentity::generate().unwrap();

    // A value on its own; one written by both devices at the same
    // revision; one that is deleted.
    a.write(&ch, "plain.md", "one");
    a.write(&ch, "tied.md", "from a");
    b.write(&ch, "tied.md", "from b");
    a.write(&ch, "deleted.md", "x");
    delete(&a, &ch, "deleted.md");
    relay(&b, &a, &ch);
    // Beside a value, and at higher revisions: an entry from someone who
    // is no member, and a member's entry that names another file.
    let plain = slot_id(&slot_key, "plain.md");
    let inside = |key: &str| json!({ "key": key, "content": { "text": "not this" } });
    inject(
        &a,
        &stranger,
        &ch,
        plain,
        99,
        channel_key,
        inside("plain.md"),
    );
    inject(
        &a,
        &b.state.identity,
        &ch,
        plain,
        50,
        channel_key,
        inside("other.md"),
    );
    // A name that holds only what does not count.
    let strangers = slot_id(&slot_key, "strangers.md");
    inject(
        &a,
        &stranger,
        &ch,
        strangers,
        7,
        channel_key,
        inside("strangers.md"),
    );

    let db = a.state.db.lock().unwrap();
    // What is told of an entry: its name, the entry that counts, and the
    // entries beside it at the same revision.
    let told = |e: &entries::Entry| {
        let beside: Vec<String> = e.conflicts.iter().map(|v| v.item_id.clone()).collect();
        (
            e.key.clone(),
            e.current.item_id.clone(),
            e.current.rev,
            e.current.deleted,
            beside,
        )
    };
    let all = entries::current(&a.state, &db, &ch).unwrap();
    let names: Vec<&str> = all.iter().map(|e| e.key.as_str()).collect();
    assert_eq!(names, ["deleted.md", "plain.md", "tied.md"]);
    for entry in &all {
        let one = entries::current_of(&a.state, &db, &ch, &entry.key).unwrap();
        assert_eq!(one.as_ref().map(told), Some(told(entry)), "{}", entry.key);
    }
    assert_eq!(all[1].current.rev, 1, "plain.md");
    assert_eq!(all[2].conflicts.len(), 1, "tied.md");
    for none in ["strangers.md", "other.md", "never-written.md"] {
        let one = entries::current_of(&a.state, &db, &ch, none).unwrap();
        assert!(one.is_none(), "{none}");
    }

    // Only a member reads either. An outsider that has the channel's row
    // and its keys, and is on no list of members, is told so by both.
    drop(db);
    let outsider = node();
    psk::write_slot_key(&outsider.state.home_dir, &ch, &slot_key).unwrap();
    psk::write_psk(&outsider.state.home_dir, &ch, &channel_key).unwrap();
    let theirs = outsider.state.db.lock().unwrap();
    cordelia_storage::channels::ensure_group(&theirs, &ch, None, "realtime", &a.pk()).unwrap();
    let not_a_member = |result: Result<(), cordelia_core::CordeliaError>| {
        matches!(
            result,
            Err(cordelia_core::CordeliaError::NotAuthorised { .. })
        )
    };
    assert!(not_a_member(
        entries::current_of(&outsider.state, &theirs, &ch, "plain.md").map(|_| ())
    ));
    assert!(not_a_member(
        entries::current(&outsider.state, &theirs, &ch).map(|_| ())
    ));
}
