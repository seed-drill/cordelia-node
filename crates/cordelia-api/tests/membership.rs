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
use cordelia_storage::{channels, invites, items, meta, naming, offers, psk, trust};

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

// ── Which personal channel a device belongs to (threat model T13) ─────

fn syncing(n: &Node, on: bool) {
    let db = n.state.db.lock().unwrap();
    meta::set(
        &db,
        meta::SYNC_CLAUDE_DIR,
        if on { "/home/x/.claude" } else { "" },
    )
    .unwrap();
}

/// T13. A device that is syncing is not moved into another personal channel
/// by `accept`: the person is told why, the offer waits, and it is taken
/// only once they turn sync off and accept again.
#[test]
fn t13_a_device_that_is_syncing_keeps_its_personal_channel() {
    let other = node();
    let mine = node();
    let own = membership::personal_channel_id(&mine.state).unwrap();
    syncing(&mine, true);

    let theirs = membership::add_device(&other.state, &mine.pk(), None)
        .unwrap()
        .personal_channel_id;
    relay(&other, &mine);
    let summary = membership::accept(&mine.state, &other.pk(), None).unwrap();

    assert!(summary.applied.is_empty(), "{summary:?}");
    assert_eq!(summary.pending, 1, "{summary:?}");
    assert_eq!(summary.notes.len(), 1, "{summary:?}");
    assert!(summary.notes[0].contains("keeps its own"), "{summary:?}");
    assert!(
        summary.notes[0].contains("cordelia sync off"),
        "{summary:?}"
    );
    assert_eq!(mine.personal().as_deref(), Some(own.as_str()));
    // It holds none of the other channel's keys.
    assert!(psk::read_psk(&mine.state.home_dir, &theirs).is_err());

    // Turning sync off is not enough by itself: the offer is taken on the
    // person's act, not when the device happens to be idle.
    syncing(&mine, false);
    let summary = membership::process_inbox(&mine.state).unwrap();
    assert!(summary.applied.is_empty(), "{summary:?}");
    assert_eq!(mine.personal().as_deref(), Some(own.as_str()));

    let summary = membership::accept(&mine.state, &other.pk(), None).unwrap();
    assert_eq!(summary.applied, vec![theirs.clone()], "{summary:?}");
    assert_eq!(mine.personal().as_deref(), Some(theirs.as_str()));
}

/// T13. The decision is made when the person accepts. Turning sync on
/// afterwards, before the offer has arrived, does not stop the device from
/// joining: that is the order people do it in.
#[test]
fn t13_turning_sync_on_after_accepting_does_not_stop_the_join() {
    let other = node();
    let mine = node();

    let summary = membership::accept(&mine.state, &other.pk(), None).unwrap();
    assert!(
        summary.applied.is_empty() && summary.notes.is_empty(),
        "{summary:?}"
    );
    syncing(&mine, true);

    let theirs = membership::add_device(&other.state, &mine.pk(), None)
        .unwrap()
        .personal_channel_id;
    relay(&other, &mine);
    let summary = membership::process_inbox(&mine.state).unwrap();
    assert_eq!(summary.applied, vec![theirs.clone()], "{summary:?}");
    assert_eq!(mine.personal().as_deref(), Some(theirs.as_str()));
}

/// T13. An accept is honoured for an hour. An offer that arrives long
/// after it, from the same key, waits for the person to accept again.
#[test]
fn t13_an_offer_long_after_the_accept_waits() {
    let other = node();
    let mine = node();
    membership::accept(&mine.state, &other.pk(), None).unwrap();
    {
        let db = mine.state.db.lock().unwrap();
        let two_hours_ago = chrono::Utc::now().timestamp() - 7200;
        meta::set(
            &db,
            meta::ACCEPTED_PERSONAL_FROM,
            &format!("{} {two_hours_ago}", hex::encode(other.pk())),
        )
        .unwrap();
    }

    let theirs = membership::add_device(&other.state, &mine.pk(), None)
        .unwrap()
        .personal_channel_id;
    relay(&other, &mine);
    let summary = membership::process_inbox(&mine.state).unwrap();
    assert!(summary.applied.is_empty(), "{summary:?}");
    assert_eq!(summary.pending, 1, "{summary:?}");
    assert_ne!(mine.personal().as_deref(), Some(theirs.as_str()));
}

/// T13. A device that already has other devices is never moved either.
#[test]
fn t13_a_device_with_other_devices_keeps_its_personal_channel() {
    let (_a, b, personal) = paired();
    let other = node();

    let theirs = membership::add_device(&other.state, &b.pk(), None)
        .unwrap()
        .personal_channel_id;
    relay(&other, &b);
    let summary = membership::accept(&b.state, &other.pk(), None).unwrap();

    assert!(summary.applied.is_empty(), "{summary:?}");
    assert_eq!(summary.pending, 1, "{summary:?}");
    assert!(summary.notes[0].contains("other devices"), "{summary:?}");
    assert_eq!(b.personal().as_deref(), Some(personal.as_str()));
    assert!(psk::read_psk(&b.state.home_dir, &theirs).is_err());
}

/// T13. Trust in a key is for one purpose. A key trusted as a person is not
/// one of this person's devices: what it offers is not applied, and it
/// cannot make its channel this device's personal channel.
#[test]
fn t13_trust_in_a_person_does_not_make_a_key_a_device() {
    let other = node();
    let mine = node();
    {
        let db = mine.state.db.lock().unwrap();
        trust::trust(&db, &other.pk(), trust::TrustKind::Person, None).unwrap();
    }

    let theirs = membership::add_device(&other.state, &mine.pk(), None)
        .unwrap()
        .personal_channel_id;
    relay(&other, &mine);
    let summary = membership::process_inbox(&mine.state).unwrap();

    assert!(summary.applied.is_empty(), "{summary:?}");
    assert_eq!(summary.pending, 1, "{summary:?}");
    assert_ne!(mine.personal().as_deref(), Some(theirs.as_str()));
    assert!(psk::read_psk(&mine.state.home_dir, &theirs).is_err());
}

// ── A channel of your own holds only your own devices (T10, T20) ──────

/// How many items `from` has stored for `to`'s inbox: what it has sealed
/// to that key.
fn sealed_for(from: &Node, to: &Node) -> usize {
    let db = from.state.db.lock().unwrap();
    items::query_sync(&db, &naming::inbox_channel_id(&to.pk()), None, 10_000)
        .unwrap()
        .len()
}

/// T10. A channel's keys are never sealed to a key that is not one of this
/// person's devices, even if that key has got into the channel's member
/// list: handing over the keys hands over everything written so far.
#[test]
fn t10_a_channels_keys_are_sealed_only_to_your_own_devices() {
    let (a, b, personal) = paired();
    let project = membership::create_project_group(&a.state, "github.com/acme/app").unwrap();
    let outsider = node();

    // The outsider's key is put straight into the member list, as a bug or
    // an older endpoint might.
    {
        let db = a.state.db.lock().unwrap();
        channels::add_member(&db, &project, &outsider.pk(), "owner").unwrap();
    }
    // B joins the project, which makes A send the channel's state out.
    join_project(&a, &b, &personal, &project);

    assert_eq!(
        sealed_for(&a, &outsider),
        0,
        "A sealed the channel's keys to an outsider"
    );
    assert!(b.members(&project).iter().any(|(k, _)| *k == b.pk()));
}

/// T10, T20. A state for one of your own channels that names a key which is
/// not one of your devices is not applied, even from one of your devices:
/// a device that has been taken over cannot slip a second key in. The state
/// is kept, and applies if that key becomes one of your devices.
#[test]
fn t10_a_state_that_names_a_strangers_key_is_held_until_it_is_a_device() {
    let (a, b, personal) = paired();
    let project = membership::create_project_group(&a.state, "github.com/acme/app").unwrap();
    join_project(&a, &b, &personal, &project);
    let before = b.members(&project);
    let extra = node();

    // One of this person's devices (A) sends a state for the project that
    // adds a key which is not one of their devices.
    let owner = |key: [u8; 32]| StateMember {
        key,
        role: MemberRole::Owner,
    };
    let epoch = {
        let db = a.state.db.lock().unwrap();
        channels::epoch(&db, &project).unwrap().0
    };
    let key_version = a.key_version(&project);
    let slipped = ChannelState {
        channel_id: project.clone(),
        name: None,
        mode: "realtime".into(),
        creator: a.pk(),
        sender: a.pk(),
        epoch: epoch + 1,
        key_version: key_version as u32,
        keys: vec![(key_version as u32, a.key(&project))],
        slot_key: psk::read_slot_key(&a.state.home_dir, &project).unwrap(),
        members: vec![owner(a.pk()), owner(b.pk()), owner(extra.pk())],
        personal: false,
    };
    deliver_crafted(&a.state.identity, &b, &slipped);
    let summary = membership::process_inbox(&b.state).unwrap();

    assert!(summary.applied.is_empty(), "{summary:?}");
    assert_eq!(summary.held, 1, "{summary:?}");
    assert_eq!(
        b.members(&project),
        before,
        "the extra key must not be a member"
    );
    // It is not shown as an invitation waiting for `accept`.
    assert!(membership::list_pending(&b.state).unwrap().is_empty());

    // If the key is in fact a new device of this person, B learns of it
    // through the personal channel, and the state it kept then applies.
    membership::add_device(&a.state, &extra.pk(), None).unwrap();
    relay(&a, &b);
    let summary = membership::process_inbox(&b.state).unwrap();
    assert!(summary.applied.contains(&project), "{summary:?}");
    assert!(b.members(&project).iter().any(|(k, _)| *k == extra.pk()));
}

// ── Numbers are bounded, and strangers displace nothing (T13, T20) ──────

/// The state `from` would send for `channel` at `epoch`, with `members`.
fn state_at(
    from: &Node,
    channel: &str,
    epoch: u64,
    members: &[[u8; 32]],
    personal: bool,
) -> ChannelState {
    let key_version = from.key_version(channel) as u32;
    ChannelState {
        channel_id: channel.to_string(),
        name: None,
        mode: "realtime".into(),
        creator: from.pk(),
        sender: from.pk(),
        epoch,
        key_version,
        keys: vec![(key_version, from.key(channel))],
        slot_key: psk::read_slot_key(&from.state.home_dir, channel).unwrap(),
        members: members
            .iter()
            .map(|key| StateMember {
                key: *key,
                role: MemberRole::Owner,
            })
            .collect(),
        personal,
    }
}

fn epoch_of(n: &Node, channel: &str) -> u64 {
    channels::epoch(&n.state.db.lock().unwrap(), channel)
        .unwrap()
        .0
}

/// T20. One of your devices, taken over, sends states that jump the
/// counter that orders changes to a channel's members, to use the numbers
/// up so that the list can never change again (and it can never be
/// removed). They are refused, and the list goes on changing.
#[test]
fn t20_no_state_can_put_a_channels_members_beyond_change() {
    use cordelia_core::protocol::{MAX_EPOCH, MAX_EPOCH_STEP};
    let (a, b, personal) = paired();
    let held = epoch_of(&b, &personal);
    let both = [a.pk(), b.pk()];

    // Further than one change may move it, up to the largest valid number.
    for epoch in [held + MAX_EPOCH_STEP + 1, MAX_EPOCH] {
        deliver_crafted(
            &a.state.identity,
            &b,
            &state_at(&a, &personal, epoch, &both, true),
        );
        let summary = membership::process_inbox(&b.state).unwrap();
        assert_eq!(summary.invalid, 1, "{epoch}: {summary:?}");
        assert_eq!(epoch_of(&b, &personal), held, "{epoch}");
    }
    // Over the limit: not a state at all. Sealed without the sender's check.
    for epoch in [MAX_EPOCH + 1, u64::MAX] {
        let cs = state_at(&a, &personal, epoch, &both, true);
        let to = cordelia_crypto::identity::x25519_pub_from_ed25519_pub(&b.pk());
        let sealed = cordelia_crypto::ecies::ecies_encrypt(&to, &cs.to_cbor().unwrap())
            .unwrap()
            .to_bytes();
        insert_signed(&a.state.identity, &b, sealed);
        let summary = membership::process_inbox(&b.state).unwrap();
        assert_eq!(summary.invalid, 1, "{epoch}: {summary:?}");
        assert_eq!(epoch_of(&b, &personal), held, "{epoch}");
    }

    // The list still changes: from the other device, and from this one.
    let c = node();
    membership::add_device(&a.state, &c.pk(), None).unwrap();
    relay(&a, &b);
    membership::process_inbox(&b.state).unwrap();
    assert!(b.members(&personal).iter().any(|(k, _)| *k == c.pk()));
    membership::remove_device(&b.state, &c.pk()).unwrap();
    assert!(!b.members(&personal).iter().any(|(k, _)| *k == c.pk()));

    // A state that skips as far as one change may is taken: a device that
    // was away has missed some. (A first hears of B's change, so that its
    // state carries the key B moved the channel to.)
    relay(&b, &a);
    membership::process_inbox(&a.state).unwrap();
    let held = epoch_of(&b, &personal);
    deliver_crafted(
        &a.state.identity,
        &b,
        &state_at(&a, &personal, held + MAX_EPOCH_STEP, &both, true),
    );
    let summary = membership::process_inbox(&b.state).unwrap();
    assert_eq!(summary.applied, vec![personal.clone()], "{summary:?}");
    assert_eq!(epoch_of(&b, &personal), held + MAX_EPOCH_STEP);
}

/// An offer of a personal channel from a key nobody here has heard of.
fn offer_from_a_stranger(to: &Node) {
    let stranger = NodeIdentity::generate().unwrap();
    let cs = ChannelState {
        channel_id: naming::group_channel_id(),
        name: None,
        mode: "realtime".into(),
        creator: stranger.public_key(),
        sender: stranger.public_key(),
        epoch: 1,
        key_version: 1,
        keys: vec![(1, [0x01; 32])],
        slot_key: [0x02; 32],
        members: [stranger.public_key(), to.pk()]
            .iter()
            .map(|key| StateMember {
                key: *key,
                role: MemberRole::Owner,
            })
            .collect(),
        personal: true,
    };
    deliver_crafted(&stranger, to, &cs);
}

/// T13. A stranger who knows a device's key can fill its list of waiting
/// invitations, which keeps only so many. That must not push out a state
/// that one of the person's own devices sent and that the device is
/// holding: the cap counts, and drops, only what strangers sent.
#[test]
fn t13_invitations_from_strangers_do_not_push_out_what_your_own_devices_sent() {
    let (a, b, personal) = paired();
    let project = membership::create_project_group(&a.state, "github.com/acme/app").unwrap();
    join_project(&a, &b, &personal, &project);
    let extra = node();

    // A state from A that B holds: it names a device B has not heard of.
    let held = epoch_of(&b, &project);
    let members = [a.pk(), b.pk(), extra.pk()];
    deliver_crafted(
        &a.state.identity,
        &b,
        &state_at(&a, &project, held + 1, &members, false),
    );
    assert_eq!(membership::process_inbox(&b.state).unwrap().held, 1);

    // Then more invitations from strangers than the list keeps.
    for _ in 0..invites::MAX_PENDING_INVITES + 5 {
        offer_from_a_stranger(&b);
    }
    let summary = membership::process_inbox(&b.state).unwrap();
    assert_eq!(summary.held, 1, "{summary:?}");
    assert_eq!(
        membership::list_pending(&b.state).unwrap().len(),
        invites::MAX_PENDING_INVITES,
        "the list of strangers' invitations is capped"
    );

    // The held state is still there, and applies once the device is known.
    membership::add_device(&a.state, &extra.pk(), None).unwrap();
    relay(&a, &b);
    let summary = membership::process_inbox(&b.state).unwrap();
    assert!(summary.applied.contains(&project), "{summary:?}");
    assert!(b.members(&project).iter().any(|(k, _)| *k == extra.pk()));
}

// ── A change is offered until each member holds it (T16, T20) ───────────

/// The members that have not confirmed something `n` sent them.
fn unconfirmed(n: &Node) -> Vec<[u8; 32]> {
    let db = n.state.db.lock().unwrap();
    let mut members: Vec<[u8; 32]> = offers::unconfirmed(&db)
        .unwrap()
        .into_iter()
        .map(|offer| offer.member)
        .collect();
    members.sort();
    members.dedup();
    members
}

/// Everything `from` sent `to` arrives, and `to` acts on it.
fn deliver(from: &Node, to: &Node) {
    relay(from, to);
    membership::process_inbox(&to.state).unwrap();
}

/// As if a relay had stored everything `n` has written so far: its outbox
/// is empty.
fn all_relayed(n: &Node) {
    let db = n.state.db.lock().unwrap();
    let waiting = items::outbox(&db, &n.pk(), 10_000, usize::MAX, &Default::default()).unwrap();
    let ids: Vec<String> = waiting.into_iter().map(|i| i.item_id).collect();
    items::mark_relayed(&db, &ids).unwrap();
}

fn outbox_len(n: &Node) -> u64 {
    items::outbox_len(&n.state.db.lock().unwrap(), &n.pk()).unwrap()
}

/// A change to a channel's members waits, on the device that made it, until
/// each other member is seen to hold it. A member that applies it answers,
/// and `cordelia devices` shows who has not.
#[test]
fn a_change_waits_until_each_member_confirms_it() {
    let (a, b, _personal) = paired();
    // B joined and answered; once A hears, nothing waits.
    assert_eq!(unconfirmed(&a), vec![b.pk()]);
    deliver(&b, &a);
    assert!(unconfirmed(&a).is_empty());

    let c = node();
    membership::add_device(&a.state, &c.pk(), None).unwrap();
    let mut both = vec![b.pk(), c.pk()];
    both.sort();
    assert_eq!(unconfirmed(&a), both);

    // B applies the change and answers. C has not accepted yet.
    deliver(&a, &b);
    deliver(&b, &a);
    assert_eq!(unconfirmed(&a), vec![c.pk()]);
    let devices = membership::list_devices(&a.state).unwrap();
    let since = |key: [u8; 32]| {
        devices
            .iter()
            .find(|d| d.key == key)
            .unwrap()
            .unconfirmed_since
    };
    assert!(since(c.pk()).is_some());
    assert_eq!(since(b.pk()), None);

    // Answers are not themselves waited for, or two devices would answer
    // each other for ever.
    assert!(unconfirmed(&b).is_empty());
    deliver(&a, &b);
    deliver(&b, &a);
    assert!(unconfirmed(&b).is_empty());
    assert_eq!(unconfirmed(&a), vec![c.pk()]);
}

/// T16. A device is removed, and the relay loses the change before another
/// device fetches it. The device that removed it offers the change again,
/// at a slowing pace, until the other device answers that it holds it.
#[test]
fn t16_a_removal_is_offered_again_until_the_others_hold_it() {
    let (a, b, r, personal) = three_devices();
    deliver(&b, &a);
    deliver(&r, &a);
    assert!(unconfirmed(&a).is_empty());

    let now = chrono::Utc::now().timestamp();
    membership::remove_device(&a.state, &r.pk()).unwrap();
    assert_eq!(unconfirmed(&a), vec![b.pk()]);
    // A relay answered for it, and then lost it: B never gets it.
    all_relayed(&a);
    assert_eq!(outbox_len(&a), 0);

    // Not offered again at once...
    assert_eq!(membership::offer_again(&a.state, now + 30).unwrap(), 0);
    assert_eq!(outbox_len(&a), 0);
    // ...but after a minute, the same item goes back into the outbox.
    assert_eq!(membership::offer_again(&a.state, now + 61).unwrap(), 1);
    assert_eq!(outbox_len(&a), 1);
    // The pace slows: next, two minutes after that.
    all_relayed(&a);
    assert_eq!(
        membership::offer_again(&a.state, now + 61 + 119).unwrap(),
        0
    );
    assert_eq!(
        membership::offer_again(&a.state, now + 61 + 121).unwrap(),
        1
    );

    // B receives it, drops R, and answers. A stops offering.
    assert!(b.members(&personal).iter().any(|(k, _)| *k == r.pk()));
    deliver(&a, &b);
    assert!(!b.members(&personal).iter().any(|(k, _)| *k == r.pk()));
    deliver(&b, &a);
    assert!(unconfirmed(&a).is_empty());
    all_relayed(&a);
    assert_eq!(
        membership::offer_again(&a.state, now + 1_000_000).unwrap(),
        0
    );
    assert_eq!(outbox_len(&a), 0);
}

/// T20. One of your devices, taken over, fills a channel's key ring: a
/// state holds only so many keys. The next removal would not fit in a
/// state, and so could not be sent. It is sent with the oldest keys left
/// out, and the device is removed all the same.
#[test]
fn t20_a_full_key_ring_does_not_stop_a_removal() {
    let most = cordelia_core::protocol::MAX_STATE_KEYS as u32;
    let (a, b, c, personal) = three_devices();
    let all = [a.pk(), b.pk(), c.pk()];
    let held = epoch_of(&a, &personal);

    let mut full = state_at(&b, &personal, held + u64::from(most) - 1, &all, true);
    full.key_version = most;
    full.keys = (1..=most)
        .map(|v| {
            (
                v,
                if v == 1 {
                    a.key(&personal)
                } else {
                    [v as u8; 32]
                },
            )
        })
        .collect();
    deliver_crafted(&b.state.identity, &a, &full);
    let summary = membership::process_inbox(&a.state).unwrap();
    assert_eq!(summary.applied, vec![personal.clone()], "{summary:?}");
    assert_eq!(a.key_version(&personal), i64::from(most));

    membership::remove_device(&a.state, &b.pk()).unwrap();
    assert_eq!(a.key_version(&personal), i64::from(most) + 1);
    // The other device can open what A sent, and drops B.
    deliver(&a, &c);
    assert!(!c.members(&personal).iter().any(|(k, _)| *k == b.pk()));
    assert_eq!(c.key(&personal), a.key(&personal));
}

/// T16. One of your devices, taken over and not yet removed, sends a state
/// that changes nothing but carries a key for the version the channel will
/// have next. If that key were kept, the removal that follows would put it
/// in place as the channel's new key, and the removed device would go on
/// reading. A state may carry no key above its own version.
#[test]
fn t16_a_state_cannot_carry_the_key_a_removal_will_make() {
    let (a, b, c, personal) = three_devices();
    let all = [a.pk(), b.pk(), c.pk()];
    let chosen = [0x4a; 32];

    let mut ahead = state_at(&c, &personal, epoch_of(&a, &personal) + 1, &all, true);
    ahead.keys.push((ahead.key_version + 1, chosen));
    // Sealed without the sender's check, as a hostile sender would.
    let to = cordelia_crypto::identity::x25519_pub_from_ed25519_pub(&a.pk());
    let sealed = cordelia_crypto::ecies::ecies_encrypt(&to, &ahead.to_cbor().unwrap())
        .unwrap()
        .to_bytes();
    insert_signed(&c.state.identity, &a, sealed);
    let summary = membership::process_inbox(&a.state).unwrap();
    assert_eq!(summary.invalid, 1, "{summary:?}");

    membership::remove_device(&a.state, &c.pk()).unwrap();
    assert_ne!(a.key(&personal), chosen);
    deliver(&a, &b);
    assert_eq!(b.key(&personal), a.key(&personal));
}

/// T16. The same key, already in this device's key ring file (a version of
/// the node that kept it, or anything else that wrote it there), and
/// another waiting for the version after. The removal makes its own key
/// all the same, hands that one to the devices that remain, and neither
/// waiting key is left in the file.
#[test]
fn t16_a_key_waiting_for_the_next_version_is_not_used_by_a_removal() {
    let (a, b, c, personal) = three_devices();
    let chosen = [0x4a; 32];
    let version = a.key_version(&personal);

    let later = [0x4b; 32];
    let mut ring = psk::read_ring(&a.state.home_dir, &personal).unwrap();
    for (ahead, key) in [(1, chosen), (2, later)] {
        ring.keys.push(psk::KeyRingEntry {
            version: version + ahead,
            psk_hex: hex::encode(key),
            rotated_at: chrono::Utc::now().to_rfc3339(),
        });
    }
    psk::write_ring(&a.state.home_dir, &ring).unwrap();

    membership::remove_device(&a.state, &c.pk()).unwrap();
    assert_eq!(a.key_version(&personal), version + 1);
    assert_ne!(a.key(&personal), chosen);
    let recorded = {
        let db = a.state.db.lock().unwrap();
        channels::get_by_id(&db, &personal).unwrap().psk_hash
    };
    assert_eq!(
        recorded.as_deref(),
        Some(&cordelia_crypto::sha256(&a.key(&personal))[..])
    );
    deliver(&a, &b);
    assert_eq!(b.key(&personal), a.key(&personal));
    for node in [&a, &b] {
        let ring = psk::read_ring(&node.state.home_dir, &personal).unwrap();
        for waiting in [chosen, later] {
            assert!(ring.keys.iter().all(|e| e.psk_hex != hex::encode(waiting)));
        }
    }
}

/// T20. One of your devices, taken over, sends a state whose key version
/// is the largest there is, so that no key could follow it and no device
/// could be removed. A state may move the key version only as far as its
/// changes can, and never back.
#[test]
fn t20_no_state_can_run_the_key_version_out() {
    let most = cordelia_core::protocol::MAX_STATE_KEYS as u32;
    let (a, b, personal) = paired();
    let both = [a.pk(), b.pk()];
    let held = epoch_of(&a, &personal);
    let real = a.key(&personal);
    let refused = |key_version: u32, epoch: u64| {
        let mut cs = state_at(&b, &personal, epoch, &both, true);
        cs.key_version = key_version;
        cs.keys = vec![(1, real), (key_version, [0x55; 32])];
        cs.keys.dedup_by_key(|(v, _)| *v);
        deliver_crafted(&b.state.identity, &a, &cs);
        let summary = membership::process_inbox(&a.state).unwrap();
        assert_eq!(summary.invalid, 1, "{key_version} at {epoch}: {summary:?}");
        assert_eq!(a.key_version(&personal), 1, "{key_version} at {epoch}");
        assert_eq!(a.key(&personal), real);
    };
    // The largest version; two versions in one change; more versions than
    // a state has room for keys, however far the epoch moves.
    refused(u32::MAX, held + 1);
    refused(3, held + 1);
    refused(most + 2, held + 100_000);

    // A removes a third device, which moves the key on. A state that goes
    // back to the old version is refused too.
    let c = node();
    membership::add_device(&a.state, &c.pk(), None).unwrap();
    membership::remove_device(&a.state, &c.pk()).unwrap();
    assert_eq!(a.key_version(&personal), 2);
    let moved_on = a.key(&personal);
    let mut back = state_at(&b, &personal, epoch_of(&a, &personal) + 1, &both, true);
    back.key_version = 1;
    back.keys = vec![(1, real)];
    deliver_crafted(&b.state.identity, &a, &back);
    assert_eq!(membership::process_inbox(&a.state).unwrap().invalid, 1);
    assert_eq!((a.key_version(&personal), a.key(&personal)), (2, moved_on));

    // And B can still be removed.
    membership::remove_device(&a.state, &b.pk()).unwrap();
    assert_eq!(a.key_version(&personal), 3);
}

/// A device stores only what members of a channel wrote, so it has refused
/// anything a member it had not heard of wrote there. When a state adds
/// members, the channel is marked to be listed again from the start.
#[test]
fn a_channel_is_listed_again_when_its_members_change() {
    let (a, b, personal) = paired();
    b.state.relist.lock().unwrap().clear();
    let marked = |n: &Node| n.state.relist.lock().unwrap().contains(&personal);

    // A state that changes nothing about who is in the channel.
    deliver(&a, &b);
    assert!(!marked(&b));

    let c = node();
    membership::add_device(&a.state, &c.pk(), None).unwrap();
    deliver(&a, &b);
    assert!(marked(&b), "b was not told to list the channel again");
}
