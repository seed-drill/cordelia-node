//! Protocol tests for device invites and channel membership (decision
//! 2026-09-30-agent-memory-sync §4.1).
//!
//! Nodes run in-process. A stand-in relay copies the items one node stored
//! for another node's inbox into that node's database, which is what relay
//! storage plus pull-sync do on the network.

use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

use cordelia_api::membership;
use cordelia_api::state::AppState;
use cordelia_crypto::channel_state::{ChannelState, MemberRole, StateMember};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_storage::{channels, invites, items, meta, naming, psk, trust};

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
        sync_control: Default::default(),
    };
    membership::ensure_own_inbox(&state).unwrap();
    Node { state, _dir: dir }
}

impl Node {
    fn pk(&self) -> [u8; 32] {
        self.state.identity.public_key()
    }

    fn personal(&self) -> Option<String> {
        meta::get(&self.state.db.lock().unwrap(), meta::PERSONAL_CHANNEL_ID).unwrap()
    }

    fn key(&self, channel_id: &str) -> [u8; 32] {
        psk::read_psk(&self.state.home_dir, channel_id).unwrap()
    }

    fn members(&self, channel_id: &str) -> Vec<([u8; 32], String)> {
        let db = self.state.db.lock().unwrap();
        let mut m = channels::list_active_members(&db, channel_id).unwrap();
        m.sort();
        m
    }

    fn key_version(&self, channel_id: &str) -> i64 {
        let db = self.state.db.lock().unwrap();
        channels::get_by_id(&db, channel_id).unwrap().key_version
    }
}

/// Copy everything `from` stored for `to`'s inbox into `to`'s database.
/// Returns how many items were new to `to`.
fn relay(from: &Node, to: &Node) -> usize {
    let inbox = naming::inbox_channel_id(&to.pk());
    let stored = {
        let db = from.state.db.lock().unwrap();
        items::query_sync(&db, &inbox, None, 10_000).unwrap()
    };
    let db = to.state.db.lock().unwrap();
    let mut delivered = 0;
    for it in stored {
        let inserted = items::insert_item(
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
                is_tombstone: false,
                slot: None,
                rev: None,
            },
        )
        .unwrap();
        delivered += usize::from(inserted);
    }
    delivered
}

/// Seal `cs` to `to`, sign the item as `signer`, and drop it straight into
/// `to`'s inbox, bypassing the honest send path.
fn deliver_crafted(signer: &NodeIdentity, to: &Node, cs: &ChannelState) {
    let sealed = cs.seal(&to.pk()).unwrap();
    insert_signed(signer, to, sealed);
}

fn insert_signed(signer: &NodeIdentity, to: &Node, blob: Vec<u8>) {
    let inbox = naming::inbox_channel_id(&to.pk());
    let item_id = items::generate_item_id();
    let published_at = chrono::Utc::now().to_rfc3339();
    let content_hash = cordelia_crypto::sha256(&blob);
    let cbor = cordelia_crypto::signing::build_item_metadata_envelope(
        &signer.public_key(),
        &inbox,
        &content_hash,
        false,
        &item_id,
        0,
        &published_at,
    )
    .unwrap();
    let signature = signer.sign(&cbor);
    let db = to.state.db.lock().unwrap();
    items::insert_item(
        &db,
        &items::NewItem {
            item_id: &item_id,
            channel_id: &inbox,
            author_id: &signer.public_key(),
            item_type: invites::INVITE_ITEM_TYPE,
            published_at: &published_at,
            parent_id: None,
            key_version: 0,
            content_hash: &content_hash,
            signature: &signature,
            encrypted_blob: &blob,
            is_tombstone: false,
            slot: None,
            rev: None,
        },
    )
    .unwrap();
}

/// A and B as two devices of one person, paired the documented way:
/// A runs `add-device B`, B runs `accept A`.
fn paired() -> (Node, Node, String) {
    let a = node();
    let b = node();
    let personal = membership::add_device(&a.state, &b.pk(), Some("b"))
        .unwrap()
        .personal_channel_id;
    relay(&a, &b);
    membership::accept(&b.state, &a.pk(), Some("a")).unwrap();
    (a, b, personal)
}

#[test]
fn add_device_then_accept_joins_the_personal_channel() {
    let a = node();
    let b = node();

    let outcome = membership::add_device(&a.state, &b.pk(), Some("imac")).unwrap();
    let personal = outcome.personal_channel_id.clone();
    assert_eq!(outcome.channels, vec![personal.clone()]);
    assert_eq!(a.personal().as_deref(), Some(personal.as_str()));

    // The invite arrives before B trusts A: it waits.
    assert_eq!(relay(&a, &b), 1);
    let first = membership::process_inbox(&b.state).unwrap();
    assert_eq!(first.pending, 1);
    assert!(first.applied.is_empty());
    assert!(b.personal().is_none());

    // `accept` trusts A and applies the waiting invite.
    let accepted = membership::accept(&b.state, &a.pk(), Some("macbook")).unwrap();
    assert_eq!(accepted.applied, vec![personal.clone()]);
    assert!(membership::list_pending(&b.state).unwrap().is_empty());

    // B now holds the same channel, key, and slot key, and adopts it as its
    // own personal channel.
    assert_eq!(b.personal().as_deref(), Some(personal.as_str()));
    assert_eq!(b.key(&personal), a.key(&personal));
    assert_eq!(
        psk::read_slot_key(&b.state.home_dir, &personal).unwrap(),
        psk::read_slot_key(&a.state.home_dir, &personal).unwrap()
    );
    let owners = vec![(a.pk(), "owner".to_string()), (b.pk(), "owner".to_string())];
    let mut expected = owners.clone();
    expected.sort();
    assert_eq!(b.members(&personal), expected);
    assert_eq!(a.members(&personal), expected);

    // Each lists the other as a device.
    let b_devices = membership::list_devices(&b.state).unwrap();
    assert!(
        b_devices
            .iter()
            .any(|d| d.key == a.pk() && d.in_personal_channel)
    );
}

#[test]
fn invite_from_already_trusted_device_applies_immediately() {
    let a = node();
    let b = node();
    membership::accept(&b.state, &a.pk(), None).unwrap();

    let personal = membership::add_device(&a.state, &b.pk(), None)
        .unwrap()
        .personal_channel_id;
    relay(&a, &b);
    let summary = membership::process_inbox(&b.state).unwrap();
    assert_eq!(summary.applied, vec![personal]);
    assert_eq!(summary.pending, 0);
}

#[test]
fn third_device_is_trusted_by_the_others_without_another_accept() {
    let (a, b, personal) = paired();
    let c = node();

    // A adds C: B hears about it through the personal channel's new state.
    membership::add_device(&a.state, &c.pk(), None).unwrap();
    relay(&a, &b);
    let update = membership::process_inbox(&b.state).unwrap();
    assert_eq!(update.applied, vec![personal.clone()]);
    assert!(b.members(&personal).iter().any(|(k, _)| *k == c.pk()));

    // C accepts A, then creates its own channel state change: B trusts C
    // as a member of the personal channel, with no `accept` on B.
    relay(&a, &c);
    membership::accept(&c.state, &a.pk(), None).unwrap();
    assert_eq!(c.personal().as_deref(), Some(personal.as_str()));

    let d = node();
    membership::add_device(&c.state, &d.pk(), None).unwrap();
    relay(&c, &b);
    let from_c = membership::process_inbox(&b.state).unwrap();
    assert_eq!(from_c.applied, vec![personal.clone()]);
    assert!(b.members(&personal).iter().any(|(k, _)| *k == d.pk()));
}

#[test]
fn remove_device_rotates_the_key_and_informs_only_remaining_members() {
    let (a, b, personal) = paired();
    let c = node();
    membership::add_device(&a.state, &c.pk(), None).unwrap();
    relay(&a, &b);
    relay(&a, &c);
    membership::process_inbox(&b.state).unwrap();
    membership::accept(&c.state, &a.pk(), None).unwrap();
    let old_key = c.key(&personal);
    let old_version = a.key_version(&personal);

    let outcome = membership::remove_device(&a.state, &c.pk()).unwrap();
    assert_eq!(outcome.channels_rotated, vec![personal.clone()]);
    assert_eq!(a.key_version(&personal), old_version + 1);
    assert_ne!(a.key(&personal), old_key);

    // B receives the new key and drops C.
    relay(&a, &b);
    membership::process_inbox(&b.state).unwrap();
    assert_eq!(b.key(&personal), a.key(&personal));
    assert!(!b.members(&personal).iter().any(|(k, _)| *k == c.pk()));

    // C receives nothing and keeps only the old key.
    assert_eq!(relay(&a, &c), 0);
    membership::process_inbox(&c.state).unwrap();
    assert_eq!(c.key(&personal), old_key);

    // B no longer trusts C: an invite from C now waits for `accept`.
    let e = node();
    membership::add_device(&c.state, &e.pk(), None).unwrap();
    let mut forged = ChannelState::open(&e.state.identity, &{
        let db = c.state.db.lock().unwrap();
        items::query_sync(&db, &naming::inbox_channel_id(&e.pk()), None, 10)
            .unwrap()
            .remove(0)
            .encrypted_blob
    })
    .unwrap();
    // Re-target C's state at B, as C could: B must not apply it.
    if forged.role_of(&b.pk()).is_none() {
        forged.members.push(StateMember {
            key: b.pk(),
            role: MemberRole::Owner,
        });
    }
    forged.epoch += 100;
    deliver_crafted(&c.state.identity, &b, &forged);
    let summary = membership::process_inbox(&b.state).unwrap();
    assert!(
        summary.applied.is_empty(),
        "revoked device must not change B's channels"
    );
    assert_eq!(summary.invalid, 1, "C is no longer an owner in B's view");
}

#[test]
fn stale_state_is_superseded() {
    let (a, b, personal) = paired();
    let c = node();

    // Capture the state A sends for epoch N, then advance to N+1.
    membership::add_device(&a.state, &c.pk(), None).unwrap();
    let newer = {
        let db = a.state.db.lock().unwrap();
        items::query_sync(&db, &naming::inbox_channel_id(&b.pk()), None, 10).unwrap()
    };
    let d = node();
    membership::add_device(&a.state, &d.pk(), None).unwrap();

    // Deliver only the newest state first...
    relay(&a, &b);
    let all_new = membership::process_inbox(&b.state).unwrap();
    assert_eq!(all_new.applied.len(), 2, "both newer states apply in order");
    assert!(b.members(&personal).iter().any(|(k, _)| *k == d.pk()));

    // ...then replay an older one: it must not undo D's membership.
    let replay = newer.last().unwrap();
    let mut old = ChannelState::open(&b.state.identity, &replay.encrypted_blob).unwrap();
    old.members.retain(|m| m.key != d.pk());
    deliver_crafted(&a.state.identity, &b, &old);
    let summary = membership::process_inbox(&b.state).unwrap();
    assert_eq!(summary.superseded, 1);
    assert!(b.members(&personal).iter().any(|(k, _)| *k == d.pk()));
}

#[test]
fn stranger_cannot_join_or_change_channels() {
    let (a, b, personal) = paired();
    let stranger = node();

    // A stranger's invite waits and never applies by itself.
    membership::add_device(&stranger.state, &b.pk(), None).unwrap();
    relay(&stranger, &b);
    let summary = membership::process_inbox(&b.state).unwrap();
    assert_eq!(summary.pending, 1);
    assert!(summary.applied.is_empty());
    assert_eq!(membership::list_pending(&b.state).unwrap().len(), 1);

    // A stranger cannot change a known channel, even with a higher epoch.
    let mut hijack = ChannelState {
        channel_id: personal.clone(),
        name: None,
        mode: "realtime".into(),
        creator: a.pk(),
        sender: stranger.pk(),
        epoch: 1_000,
        key_version: 1,
        keys: vec![(1, [0xEE; 32])],
        slot_key: [0xEE; 32],
        members: vec![
            StateMember {
                key: stranger.pk(),
                role: MemberRole::Owner,
            },
            StateMember {
                key: b.pk(),
                role: MemberRole::Owner,
            },
        ],
        personal: true,
    };
    deliver_crafted(&stranger.state.identity, &b, &hijack);
    let summary = membership::process_inbox(&b.state).unwrap();
    assert_eq!(summary.invalid, 1);
    assert_eq!(b.key(&personal), a.key(&personal));

    // Nor by re-signing a state that A sealed: the sealed sender is A.
    hijack.sender = a.pk();
    hijack.members.push(StateMember {
        key: a.pk(),
        role: MemberRole::Owner,
    });
    let sealed = hijack.seal(&b.pk()).unwrap();
    insert_signed(&stranger.state.identity, &b, sealed);
    let summary = membership::process_inbox(&b.state).unwrap();
    assert_eq!(summary.invalid, 1);
    assert_eq!(b.key(&personal), a.key(&personal));
}

#[test]
fn tampered_or_misaddressed_invites_are_invalid() {
    let a = node();
    let b = node();
    membership::accept(&b.state, &a.pk(), None).unwrap();

    // Signature over different content.
    membership::add_device(&a.state, &b.pk(), None).unwrap();
    {
        let a_db = a.state.db.lock().unwrap();
        let mut it = items::query_sync(&a_db, &naming::inbox_channel_id(&b.pk()), None, 10)
            .unwrap()
            .remove(0);
        drop(a_db);
        it.signature[0] ^= 0x01;
        let db = b.state.db.lock().unwrap();
        items::insert_item(
            &db,
            &items::NewItem {
                item_id: &it.item_id,
                channel_id: &it.channel_id,
                author_id: it.author_id.as_slice().try_into().unwrap(),
                item_type: &it.item_type,
                published_at: &it.published_at,
                parent_id: None,
                key_version: 0,
                content_hash: &it.content_hash,
                signature: &it.signature,
                encrypted_blob: &it.encrypted_blob,
                is_tombstone: false,
                slot: None,
                rev: None,
            },
        )
        .unwrap();
    }
    let summary = membership::process_inbox(&b.state).unwrap();
    assert_eq!(summary.invalid, 1);
    assert!(b.personal().is_none());

    // A state for an unknown channel that does not include B.
    let c = node();
    let not_for_b = ChannelState {
        channel_id: naming::group_channel_id(),
        name: None,
        mode: "realtime".into(),
        creator: a.pk(),
        sender: a.pk(),
        epoch: 1,
        key_version: 1,
        keys: vec![(1, [0x01; 32])],
        slot_key: [0x02; 32],
        members: vec![
            StateMember {
                key: a.pk(),
                role: MemberRole::Owner,
            },
            StateMember {
                key: c.pk(),
                role: MemberRole::Member,
            },
        ],
        personal: false,
    };
    deliver_crafted(&a.state.identity, &b, &not_for_b);
    let summary = membership::process_inbox(&b.state).unwrap();
    assert_eq!(summary.invalid, 1);
}

#[test]
fn re_adding_a_current_member_resends_without_new_epoch() {
    let (a, b, personal) = paired();
    let (epoch_before, _) = {
        let db = a.state.db.lock().unwrap();
        channels::epoch(&db, &personal).unwrap()
    };
    membership::add_device(&a.state, &b.pk(), None).unwrap();
    let (epoch_after, _) = {
        let db = a.state.db.lock().unwrap();
        channels::epoch(&db, &personal).unwrap()
    };
    assert_eq!(epoch_before, epoch_after);

    relay(&a, &b);
    let summary = membership::process_inbox(&b.state).unwrap();
    assert_eq!(
        summary.superseded, 1,
        "same epoch and author: nothing to apply"
    );
    assert!(trust::is_trusted(&b.state.db.lock().unwrap(), &a.pk()).unwrap());
}

/// Copy every item of `channel_id` that `from` holds into `to`'s database,
/// keeping slots and revisions: what pull-sync does for a keyed channel.
fn sync_channel(from: &Node, to: &Node, channel_id: &str) {
    let stored = {
        let db = from.state.db.lock().unwrap();
        items::query_sync(&db, channel_id, None, 10_000).unwrap()
    };
    let db = to.state.db.lock().unwrap();
    for it in stored {
        let slot: Option<[u8; 32]> = it.slot.as_deref().map(|s| s.try_into().unwrap());
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

/// A, B and C, all devices of one person.
fn three_devices() -> (Node, Node, Node, String) {
    let (a, b, personal) = paired();
    let c = node();
    membership::add_device(&a.state, &c.pk(), None).unwrap();
    relay(&a, &b);
    relay(&a, &c);
    membership::process_inbox(&b.state).unwrap();
    membership::accept(&c.state, &a.pk(), None).unwrap();
    (a, b, c, personal)
}

/// `joiner` asks to join `owner`'s project channel and is granted.
fn join_project(owner: &Node, joiner: &Node, personal: &str, project: &str) {
    assert!(membership::request_join(&joiner.state, project).unwrap());
    sync_channel(joiner, owner, personal);
    assert_eq!(membership::process_join_requests(&owner.state).unwrap(), 1);
    relay(owner, joiner);
    membership::process_inbox(&joiner.state).unwrap();
    assert!(
        joiner
            .members(project)
            .iter()
            .any(|(k, _)| *k == joiner.pk())
    );
}

#[test]
fn removing_a_device_reaches_projects_the_remover_does_not_have() {
    let (a, b, c, personal) = three_devices();

    // B has a project that A does not; C joins it.
    let project = membership::create_project_group(&b.state, "github.com/acme/app").unwrap();
    join_project(&b, &c, &personal, &project);
    let old_key = c.key(&project);

    // A, which is not in the project, removes C.
    let outcome = membership::remove_device(&a.state, &c.pk()).unwrap();
    assert_eq!(outcome.channels_rotated, vec![personal.clone()]);

    // B learns that C left the personal channel, and removes C from the
    // project too, with a new key.
    relay(&a, &b);
    membership::process_inbox(&b.state).unwrap();
    assert!(!b.members(&project).iter().any(|(k, _)| *k == c.pk()));
    assert_ne!(b.key(&project), old_key);

    // C is sent nothing, so keeps only the old key.
    assert_eq!(relay(&b, &c), 0);
    membership::process_inbox(&c.state).unwrap();
    assert_eq!(c.key(&project), old_key);
}

#[test]
fn only_one_remaining_owner_rotates_a_project_after_a_removal() {
    let (a, b, c, personal) = three_devices();
    let d = node();
    membership::add_device(&a.state, &d.pk(), None).unwrap();
    relay(&a, &b);
    relay(&a, &c);
    relay(&a, &d);
    membership::process_inbox(&b.state).unwrap();
    membership::process_inbox(&c.state).unwrap();
    membership::accept(&d.state, &a.pk(), None).unwrap();

    // B's project, joined by C and D; A never has it.
    let project = membership::create_project_group(&b.state, "github.com/acme/app").unwrap();
    join_project(&b, &c, &personal, &project);
    join_project(&b, &d, &personal, &project);
    relay(&b, &c);
    membership::process_inbox(&c.state).unwrap();
    let old_key = b.key(&project);

    // A removes C. B and D both hear about it.
    membership::remove_device(&a.state, &c.pk()).unwrap();
    relay(&a, &b);
    relay(&a, &d);
    membership::process_inbox(&b.state).unwrap();
    membership::process_inbox(&d.state).unwrap();

    // Exactly one of them, the one with the lower key, rotated.
    let (low, high) = if b.pk() < d.pk() { (&b, &d) } else { (&d, &b) };
    assert_ne!(low.key(&project), old_key);
    assert_eq!(
        high.key(&project),
        old_key,
        "the other owner leaves it alone"
    );

    // The other then receives the new state and converges.
    relay(low, high);
    membership::process_inbox(&high.state).unwrap();
    assert_eq!(high.key(&project), low.key(&project));
    assert!(!high.members(&project).iter().any(|(k, _)| *k == c.pk()));
}
