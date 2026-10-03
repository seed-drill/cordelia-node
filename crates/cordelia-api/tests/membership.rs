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
        usable_keys: Default::default(),
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

/// The key that is the curve's identity (`01 00..00`): a point of small
/// order, and so no device's key.
fn nobodys_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = 1;
    key
}

/// A signature that is accepted for any message under [`nobodys_key`]: R
/// is the base point and S is one. A signature is good when `[S]B` equals
/// `R + [k]A`, and with `A` the identity the last term is nothing, whatever
/// the message makes `k`. This is what "anyone can sign under a key of
/// small order" means.
fn signed_by_nobody() -> [u8; 64] {
    let mut signature = [0x66u8; 64];
    signature[0] = 0x58;
    signature[32..].fill(0);
    signature[32] = 1;
    signature
}

/// Store in `n`'s database an item of `channel_id` written by
/// [`nobodys_key`], as it would arrive from a relay. Returns the item as
/// it is stored.
fn insert_from_nobody(
    n: &Node,
    channel_id: &str,
    item_type: &str,
    blob: Vec<u8>,
    key_version: i64,
    slot_and_rev: Option<([u8; 32], u64)>,
) -> items::StoredItem {
    let item_id = items::generate_item_id();
    let db = n.state.db.lock().unwrap();
    items::insert_item(
        &db,
        &items::NewItem {
            item_id: &item_id,
            channel_id,
            author_id: &nobodys_key(),
            item_type,
            published_at: &chrono::Utc::now().to_rfc3339(),
            parent_id: None,
            key_version,
            content_hash: &cordelia_crypto::sha256(&blob),
            signature: &signed_by_nobody(),
            encrypted_blob: &blob,
            is_tombstone: false,
            slot: slot_and_rev.as_ref().map(|(slot, _)| slot),
            rev: slot_and_rev.map(|(_, rev)| rev),
        },
    )
    .unwrap();
    let stored = items::query_sync(&db, channel_id, None, 10_000).unwrap();
    stored.into_iter().find(|it| it.item_id == item_id).unwrap()
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

    let outcome = membership::add_device(&a.state, &b.pk(), Some("desktop")).unwrap();
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
    let accepted = membership::accept(&b.state, &a.pk(), Some("laptop")).unwrap();
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
        let to = cordelia_crypto::identity::x25519_pub_from_ed25519_pub(&b.pk()).unwrap();
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
    let to = cordelia_crypto::identity::x25519_pub_from_ed25519_pub(&a.pk()).unwrap();
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

/// How many items `n` holds for the inbox of `key`.
fn held_for(n: &Node, key: &[u8; 32]) -> usize {
    let db = n.state.db.lock().unwrap();
    items::query_sync(&db, &naming::inbox_channel_id(key), None, 100)
        .unwrap()
        .len()
}

/// Keys that are no device's, each all zero after its first byte: a point
/// of order 4, the identity, bytes that are not a point on the curve, and
/// a point of mixed order. They are the four in
/// `docs/reference/encryption-test-vectors.md`.
fn unusable_keys() -> Vec<[u8; 32]> {
    [0u8, 1, 2, 5]
        .into_iter()
        .map(|first| {
            let mut key = [0u8; 32];
            key[0] = first;
            key
        })
        .collect()
}

/// T20. Bytes that are not a usable key (not a point on the curve, or a
/// point that is not of the order every real key has) are never a device.
/// What is sealed to a point of small order is sealed under a secret
/// anyone can work out, so whatever it was sent could be read by anyone
/// who fetched its inbox. Such a key is not added, not accepted, not
/// trusted and sent nothing. Listed in a state from one of your devices,
/// it is left out, and the rest of the state is taken.
#[test]
fn t20_a_key_that_is_not_usable_is_never_a_device() {
    let (a, b, personal) = paired();
    let before = a.members(&personal);
    let trusted = |n: &Node, key: &[u8; 32]| {
        trust::is_trusted_as(&n.state.db.lock().unwrap(), key, trust::TrustKind::Device).unwrap()
    };

    for bad in unusable_keys() {
        assert!(!cordelia_crypto::identity::is_usable_public_key(&bad));
        assert!(membership::add_device(&a.state, &bad, Some("x")).is_err());
        assert!(membership::accept(&a.state, &bad, Some("x")).is_err());
        assert_eq!(a.members(&personal), before, "{bad:02x?}");
        assert_eq!(held_for(&a, &bad), 0, "nothing was sealed to it");
        assert!(!trusted(&a, &bad));

        // One of your devices lists it in a state: taken over, or not yet
        // upgraded. The state is applied without it.
        let epoch = epoch_of(&a, &personal) + 1;
        let listed = state_at(&b, &personal, epoch, &[a.pk(), b.pk(), bad], true);
        deliver_crafted(&b.state.identity, &a, &listed);
        let summary = membership::process_inbox(&a.state).unwrap();
        assert_eq!(
            (summary.applied.len(), summary.invalid),
            (1, 0),
            "{summary:?}"
        );
        assert_eq!(epoch_of(&a, &personal), epoch);
        assert_eq!(a.members(&personal), before, "{bad:02x?}");
        assert!(!trusted(&a, &bad));
        assert_eq!(held_for(&a, &bad), 0, "nothing was sealed to it");
    }

    // A real device is still added, and sent the channel.
    let c = node();
    membership::add_device(&a.state, &c.pk(), None).unwrap();
    assert_eq!(held_for(&a, &c.pk()), 1);
}

/// T20. A key of that kind that was stored before such keys were refused
/// blocks nothing. A state this device builds leaves it out, so a removal
/// made with it still listed is made whole and reaches the other devices,
/// and so does an addition.
#[test]
fn t20_a_key_that_was_stored_before_blocks_nothing() {
    let (a, b, personal) = paired();
    let c = node();
    membership::add_device(&a.state, &c.pk(), Some("c")).unwrap();
    relay(&a, &c);
    membership::accept(&c.state, &a.pk(), Some("a")).unwrap();
    deliver(&a, &b);
    let three = a.members(&personal);
    assert_eq!(three.len(), 3);
    assert_eq!(b.members(&personal), three);

    // As an older version left it: a member of the personal channel, and
    // trusted as a device.
    let bad = unusable_keys();
    {
        let db = a.state.db.lock().unwrap();
        for key in &bad {
            channels::add_member(&db, &personal, key, "owner").unwrap();
            trust::trust(&db, key, trust::TrustKind::Device, Some("stored before")).unwrap();
        }
    }
    assert_eq!(a.members(&personal).len(), 3 + bad.len());

    // A removal is made whole: the other device hears of it, and holds
    // the key that follows it.
    let before = a.key(&personal);
    membership::remove_device(&a.state, &c.pk()).unwrap();
    assert_ne!(a.key(&personal), before);
    deliver(&a, &b);
    assert_eq!(b.key(&personal), a.key(&personal));
    let two: Vec<[u8; 32]> = b.members(&personal).into_iter().map(|(k, _)| k).collect();
    let mut expected = vec![a.pk(), b.pk()];
    expected.sort();
    assert_eq!(two, expected);
    // So is an addition.
    let d = node();
    membership::add_device(&a.state, &d.pk(), Some("d")).unwrap();
    deliver(&a, &b);
    assert_eq!(b.members(&personal).len(), 3);
    for key in &bad {
        assert_eq!(held_for(&a, key), 0, "nothing was sealed to it");
    }
}

/// T20. A key of that kind that was stored before does not stay. When the
/// node starts, every row for it goes, with the trust in it and what this
/// device had stored to send it. No channel's key is changed on its
/// account, then or later: a change of key is a change of membership that
/// one device publishes, and made from a list that is behind it could undo
/// a removal made elsewhere. So removing such a key is refused, and
/// changes nothing, whether or not it was ever listed here.
#[test]
fn t20_a_key_that_was_stored_before_is_taken_off_and_no_key_is_changed() {
    let (a, b, personal) = paired();
    let project = membership::create_project_group(&a.state, "project:x").unwrap();
    // A channel this device is not in and holds nothing of.
    let left = naming::group_channel_id();
    let bad = unusable_keys();
    let [in_personal, trusted_only, in_left, in_both] = bad[..] else {
        panic!("four keys");
    };
    {
        let db = a.state.db.lock().unwrap();
        channels::ensure_group(&db, &left, None, "realtime", &b.pk()).unwrap();
        channels::add_member(&db, &left, &in_left, "owner").unwrap();
        for key in [&in_personal, &in_both] {
            channels::add_member(&db, &personal, key, "owner").unwrap();
        }
        channels::add_member(&db, &project, &in_both, "owner").unwrap();
        for key in [&in_personal, &trusted_only] {
            trust::trust(&db, key, trust::TrustKind::Device, Some("stored before")).unwrap();
        }
        // What an older version stored to send to one of them.
        let inbox = naming::inbox_channel_id(&in_personal);
        channels::ensure_inbox(&db, &inbox, &in_personal, false).unwrap();
    }
    insert_signed(&a.state.identity, &a, vec![1, 2, 3]);
    {
        // The same item, in the inbox of the key instead of this device's.
        let db = a.state.db.lock().unwrap();
        let own = naming::inbox_channel_id(&a.pk());
        let inbox = naming::inbox_channel_id(&in_personal);
        db.execute(
            "UPDATE items SET channel_id = ?1 WHERE channel_id = ?2 AND author_id = ?3",
            rusqlite::params![inbox, own, a.pk().as_slice()],
        )
        .unwrap();
    }
    assert_eq!(held_for(&a, &in_personal), 1);
    let listed = |n: &Node, channel: &str, key: &[u8; 32]| {
        channels::is_member(&n.state.db.lock().unwrap(), channel, key).unwrap()
    };
    assert!(listed(&a, &left, &in_left));
    let unrelated = membership::create_project_group(&a.state, "project:y").unwrap();
    // Each channel's key, key version and epoch.
    let keys_of = |n: &Node| -> Vec<([u8; 32], i64, u64)> {
        [&personal, &project, &unrelated]
            .iter()
            .map(|channel| (n.key(channel), n.key_version(channel), epoch_of(n, channel)))
            .collect()
    };
    let before = keys_of(&a);
    let sent_before = held_for(&a, &b.pk());

    let mut went = membership::drop_unusable_keys(&a.state).unwrap();
    went.sort();
    let mut all = bad.clone();
    all.sort();
    assert_eq!(went, all);

    // Every row, in every channel; the trust; and what was stored to send.
    for key in &bad {
        for channel in [&personal, &project, &left] {
            assert!(!listed(&a, channel, key), "{key:02x?} in {channel}");
        }
        assert!(!trust::is_trusted(&a.state.db.lock().unwrap(), key).unwrap());
        assert_eq!(held_for(&a, key), 0);
    }
    assert!(trust::is_trusted(&a.state.db.lock().unwrap(), &b.pk()).unwrap());
    // No key is changed, and nothing is sent to the other device.
    assert_eq!(keys_of(&a), before);
    assert_eq!(held_for(&a, &b.pk()), sent_before);

    // Done again, it finds nothing.
    assert!(membership::drop_unusable_keys(&a.state).unwrap().is_empty());
    assert_eq!(keys_of(&a), before);

    // Removing such a key is refused: it is no device, and no key is
    // changed on its account. Nothing changes and nothing is sent, for a
    // key that was listed here and for one that never was.
    let never_listed = keys_of_nobodys(1)[0];
    for key in [in_both, in_personal, trusted_only, never_listed] {
        let refused = membership::remove_device(&a.state, &key).unwrap_err();
        let said = refused.to_string();
        assert!(
            said.contains("not a usable public key, so it is no device's key")
                && said.contains("nothing is removed")
                && said.contains("If this device listed it, this device took it off")
                && said.contains("on an older version may still list it")
                && said.contains("The channels that listed it keep their keys"),
            "{said}"
        );
    }
    assert_eq!(keys_of(&a), before);
    assert_eq!(held_for(&a, &b.pk()), sent_before);

    // A real device is removed as it always was.
    let outcome = membership::remove_device(&a.state, &b.pk()).unwrap();
    assert_eq!(outcome.channels_rotated, std::slice::from_ref(&personal));
}

/// T20. Under a key of small order anyone can sign. While such a key was
/// listed, what a stranger wrote under it counted as a device's. Once the
/// key is off the list, what was written under it counts for nothing. And
/// it is never published again as this device's, as what a removed device
/// wrote is: removing such a key is refused.
#[test]
fn t20_what_was_written_under_a_key_anyone_can_sign_with_stops_counting() {
    use cordelia_api::entries::{self, Write};
    use cordelia_crypto::slots::{item_aad, slot_id};

    let nobody = nobodys_key();
    // A device with its own text at revision 1, and the next revision
    // written under the key by anyone who has the channel's key (which was
    // sealed to this one): it counts, while the key is an owner.
    let forged_over = || -> (Node, String) {
        let (a, _b, personal) = paired();
        {
            let db = a.state.db.lock().unwrap();
            let mine = Write {
                key: "notes.md",
                content: &serde_json::json!("mine"),
                metadata: None,
                item_type: "memory",
                deleted: false,
            };
            entries::publish(&a.state, &db, &personal, &mine).unwrap();
            channels::add_member(&db, &personal, &nobody, "owner").unwrap();
        }
        let slot_key = psk::read_slot_key(&a.state.home_dir, &personal).unwrap();
        let slot = slot_id(&slot_key, "notes.md");
        let envelope =
            serde_json::json!({ "key": "notes.md", "content": "forged", "metadata": null });
        let blob = cordelia_crypto::item_encrypt(
            &a.key(&personal),
            &serde_json::to_vec(&envelope).unwrap(),
            &item_aad(&personal, Some(&slot), Some(2)),
        )
        .unwrap();
        let forged = insert_from_nobody(
            &a,
            &personal,
            "memory",
            blob,
            a.key_version(&personal),
            Some((slot, 2)),
        );
        assert!(cordelia_api::verify::verify_item_signature(&forged));
        (a, personal)
    };
    let text_of = |n: &Node, personal: &str| -> (Vec<u8>, serde_json::Value) {
        let db = n.state.db.lock().unwrap();
        let all = entries::current(&n.state, &db, personal).unwrap();
        let entry = all.into_iter().find(|e| e.key == "notes.md").unwrap();
        (entry.current.author.to_vec(), entry.current.content)
    };

    // The key is taken off when the node starts, and then removed.
    let (a, personal) = forged_over();
    assert_eq!(
        text_of(&a, &personal),
        (nobody.to_vec(), serde_json::json!("forged"))
    );
    assert_eq!(membership::drop_unusable_keys(&a.state).unwrap(), [nobody]);
    let mine = (a.pk().to_vec(), serde_json::json!("mine"));
    assert_eq!(text_of(&a, &personal), mine);
    assert!(membership::remove_device(&a.state, &nobody).is_err());
    assert_eq!(text_of(&a, &personal), mine);

    // Removing it while it is still on the list is refused as well, so
    // nothing written under it is published again as this device's. The
    // forged text counts only until the node next starts.
    let (a, personal) = forged_over();
    let version = a.key_version(&personal);
    assert!(membership::remove_device(&a.state, &nobody).is_err());
    assert_eq!(a.key_version(&personal), version);
    assert_eq!(
        text_of(&a, &personal),
        (nobody.to_vec(), serde_json::json!("forged"))
    );
    assert_eq!(membership::drop_unusable_keys(&a.state).unwrap(), [nobody]);
    assert_eq!(
        text_of(&a, &personal),
        (a.pk().to_vec(), serde_json::json!("mine"))
    );
}

/// T20. Nothing is taken from a sender whose key is not usable, whatever
/// this device has stored about it. A key of small order that an older
/// version left as an owner of a channel is one anyone can sign under: a
/// state signed with it would hand the channel a key of the sender's
/// choosing and drop the other devices.
#[test]
fn t20_nothing_is_taken_from_a_sender_whose_key_is_not_usable() {
    let (a, b, personal) = paired();
    let nobody = nobodys_key();
    channels::add_member(&a.state.db.lock().unwrap(), &personal, &nobody, "owner").unwrap();

    let version = a.key_version(&personal) as u32;
    let state = ChannelState {
        channel_id: personal.clone(),
        name: None,
        mode: "realtime".into(),
        creator: a.pk(),
        sender: nobody,
        epoch: epoch_of(&a, &personal) + 1,
        key_version: version,
        keys: vec![(version, [0x66; 32])],
        slot_key: [0x77; 32],
        members: [nobody, a.pk()]
            .iter()
            .map(|key| StateMember {
                key: *key,
                role: MemberRole::Owner,
            })
            .collect(),
        personal: true,
    };
    let sealed = state.seal(&a.pk()).unwrap();
    let inbox = naming::inbox_channel_id(&a.pk());
    let item = insert_from_nobody(&a, &inbox, invites::INVITE_ITEM_TYPE, sealed, 0, None);
    // The signature is good, and the state opens: only the sender's key
    // is wrong with it.
    assert!(cordelia_api::verify::verify_item_signature(&item));
    assert!(ChannelState::open(&a.state.identity, &item.encrypted_blob).is_ok());

    let before = (a.key(&personal), a.members(&personal));
    let summary = membership::process_inbox(&a.state).unwrap();
    assert_eq!(
        (summary.applied.len(), summary.invalid),
        (0, 1),
        "{summary:?}"
    );
    assert_eq!((a.key(&personal), a.members(&personal)), before);
    assert!(a.members(&personal).iter().any(|(key, _)| *key == b.pk()));
}

/// T20. A key that is not usable is left out of every state that is
/// applied, by whichever way it comes: a channel this device is joining,
/// a channel it is in, and the personal channel, where the same state
/// also removes a device. Without that, a project's state that listed one
/// would wait for ever as naming a stranger.
#[test]
fn t20_a_key_that_is_not_usable_is_left_out_of_every_state_that_is_applied() {
    let (a, b, c, personal) = three_devices();
    let bad = unusable_keys();
    let with_bad = |devices: &[[u8; 32]]| -> Vec<[u8; 32]> {
        devices.iter().chain(bad.iter()).copied().collect()
    };
    let keys_of = |n: &Node, channel: &str| -> Vec<[u8; 32]> {
        n.members(channel).into_iter().map(|(key, _)| key).collect()
    };
    let mut both = vec![a.pk(), b.pk()];
    both.sort();

    // A project channel this device does not have yet.
    let project = membership::create_project_group(&b.state, "project:x").unwrap();
    let offer = state_at(
        &b,
        &project,
        epoch_of(&b, &project),
        &with_bad(&[a.pk(), b.pk()]),
        false,
    );
    deliver_crafted(&b.state.identity, &a, &offer);
    let summary = membership::process_inbox(&a.state).unwrap();
    assert_eq!(
        (summary.applied.len(), summary.held, summary.invalid),
        (1, 0, 0),
        "{summary:?}"
    );
    assert_eq!(keys_of(&a, &project), both);

    // The same channel, now that this device is in it.
    let epoch = epoch_of(&a, &project) + 1;
    let change = state_at(&b, &project, epoch, &with_bad(&[a.pk(), b.pk()]), false);
    deliver_crafted(&b.state.identity, &a, &change);
    let summary = membership::process_inbox(&a.state).unwrap();
    assert_eq!(
        (summary.applied.len(), summary.held, summary.invalid),
        (1, 0, 0),
        "{summary:?}"
    );
    assert_eq!(epoch_of(&a, &project), epoch);
    assert_eq!(keys_of(&a, &project), both);

    // The personal channel: a device not yet upgraded removes C while its
    // list still holds such keys. The removal is taken, and the keys are
    // not.
    assert!(trust::is_trusted(&a.state.db.lock().unwrap(), &c.pk()).unwrap());
    let epoch = epoch_of(&a, &personal) + 1;
    let removal = state_at(&b, &personal, epoch, &with_bad(&[a.pk(), b.pk()]), true);
    deliver_crafted(&b.state.identity, &a, &removal);
    let summary = membership::process_inbox(&a.state).unwrap();
    assert_eq!(summary.applied, vec![personal.clone()], "{summary:?}");
    assert_eq!(keys_of(&a, &personal), both);
    assert!(!trust::is_trusted(&a.state.db.lock().unwrap(), &c.pk()).unwrap());
    for key in &bad {
        assert!(!trust::is_trusted(&a.state.db.lock().unwrap(), key).unwrap());
        assert_eq!(held_for(&a, key), 0, "nothing was sealed to it");
    }

    // No key is changed on their account: removing one is refused.
    let versions = (a.key_version(&project), a.key_version(&personal));
    assert!(membership::remove_device(&a.state, &bad[0]).is_err());
    assert_eq!(
        (a.key_version(&project), a.key_version(&personal)),
        versions
    );
}

/// `n` keys that are no device's: not usable public keys.
fn keys_of_nobodys(n: usize) -> Vec<[u8; 32]> {
    let found: Vec<[u8; 32]> = (0..4096u32)
        .map(|i| {
            let mut key = [0x42; 32];
            key[..4].copy_from_slice(&i.to_le_bytes());
            key
        })
        .filter(|key| !cordelia_crypto::identity::is_usable_public_key(key))
        .take(n)
        .collect();
    assert_eq!(found.len(), n);
    found
}

/// A state for `channel_id` at `epoch` and `key_version`, from `sender`,
/// that lists `sender`, `to` and `others`.
fn state_listing(
    channel_id: &str,
    sender: &[u8; 32],
    to: &[u8; 32],
    (epoch, key_version, key): (u64, u32, [u8; 32]),
    personal: bool,
    others: &[[u8; 32]],
) -> ChannelState {
    let members: Vec<[u8; 32]> = [*sender, *to]
        .into_iter()
        .chain(others.iter().copied())
        .collect();
    ChannelState {
        channel_id: channel_id.to_string(),
        name: None,
        mode: "realtime".into(),
        creator: *sender,
        sender: *sender,
        epoch,
        key_version,
        keys: vec![(key_version, key)],
        slot_key: [0x02; 32],
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

/// The same, listing keys of any kind up to the most a state holds.
fn state_listing_the_most(
    channel_id: &str,
    sender: &[u8; 32],
    to: &[u8; 32],
    at: (u64, u32, [u8; 32]),
    personal: bool,
) -> ChannelState {
    let others: Vec<[u8; 32]> = (0..1022u32)
        .map(|n| {
            let mut key = [0x42; 32];
            key[..4].copy_from_slice(&n.to_le_bytes());
            key
        })
        .collect();
    state_listing(channel_id, sender, to, at, personal, &others)
}

/// T20. Checking a key costs a multiplication on the curve, and a state
/// lists up to 1,024. A stranger who knows a device's key can leave states
/// waiting in its inbox, which is looked at every few seconds. A state
/// that only waits is not checked key by key: on each pass one key is
/// checked for it, its sender's. The keys are checked when the state is
/// about to be applied, which a stranger's never is.
#[test]
fn t20_what_a_stranger_sends_is_not_checked_key_by_key() {
    use cordelia_crypto::identity::{is_usable_public_key, key_checks};

    let a = node();
    let stranger = NodeIdentity::generate().unwrap();
    let offered = naming::group_channel_id();
    let cs = state_listing_the_most(
        &offered,
        &stranger.public_key(),
        &a.pk(),
        (1, 1, [0x01; 32]),
        true,
    );
    deliver_crafted(&stranger, &a, &cs);

    let before = key_checks();
    for _ in 0..3 {
        let summary = membership::process_inbox(&a.state).unwrap();
        assert_eq!((summary.pending, summary.invalid), (1, 0), "{summary:?}");
    }
    assert_eq!(
        key_checks() - before,
        3,
        "one key for each pass: the sender's"
    );

    // The same from a sender this device trusts, while the offer waits for
    // the person: a personal channel is taken only after `accept`.
    trust::trust(
        &a.state.db.lock().unwrap(),
        &stranger.public_key(),
        trust::TrustKind::Device,
        None,
    )
    .unwrap();
    let before = key_checks();
    for _ in 0..3 {
        let summary = membership::process_inbox(&a.state).unwrap();
        assert_eq!((summary.pending, summary.invalid), (1, 0), "{summary:?}");
    }
    assert_eq!(key_checks() - before, 3);

    // The control: the person accepts that sender, and the same state is
    // applied, as this device's personal channel. Now every key is
    // checked, and those that are no device's are left out.
    let before = key_checks();
    let summary = membership::accept(&a.state, &stranger.public_key(), Some("x")).unwrap();
    assert_eq!(summary.applied, vec![offered.clone()], "{summary:?}");
    assert!(key_checks() - before >= 1024);
    assert_eq!(a.personal().as_deref(), Some(offered.as_str()));
    let members = a.members(&offered);
    assert!(
        members.len() < 1024 && members.len() >= 2,
        "{}",
        members.len()
    );
    assert!(members.iter().all(|(key, _)| is_usable_public_key(key)));
}

/// T20. A state that is held is looked at again on every pass, so what
/// it costs to hold must not grow with what it lists.
///
/// - One whose sender is not this person's device is held before its keys
///   are looked at: one key check a pass, the sender's. A device removed
///   from the personal channel can still be an owner of a project the
///   remover is not in, and its states for that project are held for ever.
/// - One from this person's own device that names a stranger has every
///   key checked once. The answer for each is remembered while the node
///   runs, so each later pass checks one key, the sender's.
///
/// What is remembered is the answer the check gave, so what becomes of the
/// state is the same: it is held, and it is applied without the keys that
/// are no device's once the stranger is one of this person's devices (see
/// `t20_a_state_held_for_a_device_not_yet_known_is_taken_when_it_is`).
#[test]
fn t20_a_state_that_is_held_has_its_keys_checked_once() {
    use cordelia_crypto::identity::key_checks;

    let (a, b, _personal) = paired();
    let project = membership::create_project_group(&a.state, "project:x").unwrap();
    let gone = NodeIdentity::generate().unwrap();
    {
        let db = a.state.db.lock().unwrap();
        for owner in [gone.public_key(), b.pk()] {
            channels::add_member(&db, &project, &owner, "owner").unwrap();
        }
    }
    let pass = |held: usize| -> u64 {
        let before = key_checks();
        let summary = membership::process_inbox(&a.state).unwrap();
        assert_eq!((summary.held, summary.invalid), (held, 0), "{summary:?}");
        key_checks() - before
    };
    let few = keys_of_nobodys(5);
    let next = |a: &Node| {
        (
            epoch_of(a, &project) + 1,
            a.key_version(&project) as u32,
            a.key(&project),
        )
    };

    // A sender that is an owner of the project and no device of this
    // person's, listing a few keys that would each be checked.
    let from_gone = state_listing(&project, &gone.public_key(), &a.pk(), next(&a), false, &few);
    deliver_crafted(&gone, &a, &from_gone);
    for _ in 0..3 {
        assert_eq!(pass(1), 1);
    }

    // The same for a channel this device does not have yet, from a sender
    // it trusts by name and that is not in its personal channel.
    trust::trust(
        &a.state.db.lock().unwrap(),
        &gone.public_key(),
        trust::TrustKind::Device,
        None,
    )
    .unwrap();
    let new_to_a = state_listing(
        &naming::group_channel_id(),
        &gone.public_key(),
        &a.pk(),
        (1, 1, [0x01; 32]),
        false,
        &few,
    );
    deliver_crafted(&gone, &a, &new_to_a);
    for _ in 0..3 {
        assert_eq!(pass(2), 2);
    }
    assert_eq!(
        a.state.usable_keys.kept(),
        0,
        "none of those keys was checked"
    );

    // From one of this person's own devices, a state that lists as many
    // keys as a state holds, strangers among them. Every key is checked
    // once: the three senders' and the 1,024 it lists. After that a pass
    // checks the three senders' keys and no other.
    let many = state_listing_the_most(&project, &b.pk(), &a.pk(), next(&a), false);
    deliver_crafted(&b.state.identity, &a, &many);
    assert_eq!(pass(3), 3 + 1024);
    assert_eq!(a.state.usable_keys.kept(), 1024);
    for _ in 0..3 {
        assert_eq!(pass(3), 3);
    }

    // Another state that lists the same keys costs nothing more for them.
    let again = state_listing_the_most(&project, &b.pk(), &a.pk(), next(&a), false);
    deliver_crafted(&b.state.identity, &a, &again);
    assert_eq!(pass(4), 4);
    assert_eq!(a.state.usable_keys.kept(), 1024);

    // The same for a channel this device has not got, from one of this
    // person's own devices: the keys it has not seen are checked on the
    // first look, and none on the next.
    let strangers: Vec<[u8; 32]> = (0..3)
        .map(|_| NodeIdentity::generate().unwrap().public_key())
        .collect();
    let unknown = state_listing(
        &naming::group_channel_id(),
        &b.pk(),
        &a.pk(),
        (1, 1, [0x01; 32]),
        false,
        &strangers,
    );
    deliver_crafted(&b.state.identity, &a, &unknown);
    assert_eq!(pass(5), 5 + 3);
    assert_eq!(a.state.usable_keys.kept(), 1024 + 3);
    assert_eq!(pass(5), 5);
}

/// T20. What is remembered of keys is bounded. Where the keys of a state
/// that waits do not fit in it, every look checks them all again, a check
/// for each key, and what becomes of the state is the same: it is held,
/// and it is applied without the keys that are no device's once the
/// stranger it names is one of this person's devices.
#[test]
fn t20_past_what_is_remembered_a_state_costs_a_check_a_key_and_ends_the_same() {
    use cordelia_api::state::UsableKeys;
    use cordelia_crypto::identity::{is_usable_public_key, key_checks};

    let (mut a, b, personal) = paired();
    a.state.usable_keys = UsableKeys::keeping(100);
    let project = membership::create_project_group(&a.state, "project:x").unwrap();
    channels::add_member(&a.state.db.lock().unwrap(), &project, &b.pk(), "owner").unwrap();
    let at = (
        epoch_of(&a, &project) + 1,
        a.key_version(&project) as u32,
        a.key(&project),
    );
    let many = state_listing_the_most(&project, &b.pk(), &a.pk(), at, false);
    let strangers: Vec<[u8; 32]> = many
        .members
        .iter()
        .map(|m| m.key)
        .filter(|key| is_usable_public_key(key) && *key != a.pk() && *key != b.pk())
        .collect();
    assert!(!strangers.is_empty());
    deliver_crafted(&b.state.identity, &a, &many);
    for _ in 0..3 {
        let before = key_checks();
        let summary = membership::process_inbox(&a.state).unwrap();
        assert_eq!((summary.applied.len(), summary.held), (0, 1), "{summary:?}");
        assert_eq!(
            key_checks() - before,
            1 + 1024,
            "the sender's, and every key"
        );
        assert!(a.state.usable_keys.kept() <= 100);
    }

    // The strangers become this person's devices: the state is applied,
    // with every usable key it lists and none of the others.
    {
        let db = a.state.db.lock().unwrap();
        for key in &strangers {
            channels::add_member(&db, &personal, key, "owner").unwrap();
        }
    }
    let summary = membership::process_inbox(&a.state).unwrap();
    assert_eq!((summary.applied.len(), summary.held), (1, 0), "{summary:?}");
    let mut want: Vec<[u8; 32]> = strangers.iter().copied().chain([a.pk(), b.pk()]).collect();
    want.sort();
    let mut members: Vec<[u8; 32]> = a.members(&project).into_iter().map(|(k, _)| k).collect();
    members.sort();
    assert_eq!(members, want);
}

/// T20. A state is taken however many keys it lists that are no device's:
/// they are left out, and the rest of it is applied. What becomes of a
/// state is never decided by a count.
///
/// The state here is a removal, from a device that has not been upgraded
/// and still lists such keys. Held, it would leave the removed device a
/// member on this one, which is the thing a taken-over device wants.
#[test]
fn t20_a_state_is_taken_however_many_keys_of_nobodys_it_lists() {
    for planted in [1, 9, 300] {
        let (a, b, _personal) = paired();
        let project = membership::create_project_group(&a.state, "project:x").unwrap();
        let removed = NodeIdentity::generate().unwrap().public_key();
        {
            let db = a.state.db.lock().unwrap();
            for owner in [b.pk(), removed] {
                channels::add_member(&db, &project, &owner, "owner").unwrap();
            }
        }
        assert_eq!(a.members(&project).len(), 3);

        // The removal: the list without the removed device, and the next
        // key version.
        let at = (
            epoch_of(&a, &project) + 1,
            a.key_version(&project) as u32 + 1,
            [0x07; 32],
        );
        let keys = keys_of_nobodys(planted);
        let removal = state_listing(&project, &b.pk(), &a.pk(), at, false, &keys);
        deliver_crafted(&b.state.identity, &a, &removal);
        let summary = membership::process_inbox(&a.state).unwrap();
        assert_eq!(
            (summary.applied.len(), summary.held, summary.invalid),
            (1, 0, 0),
            "{planted}: {summary:?}"
        );
        let mut both = vec![a.pk(), b.pk()];
        both.sort();
        let mut members: Vec<[u8; 32]> = a.members(&project).into_iter().map(|(k, _)| k).collect();
        members.sort();
        assert_eq!(members, both, "{planted}");
        assert_eq!(a.key(&project), [0x07; 32], "{planted}");
    }
}

/// T20. A state held for a key it names is applied once that key is one of
/// this person's devices, without the keys that are no device's: what was
/// remembered of its keys while it waited changes nothing.
#[test]
fn t20_a_state_held_for_a_device_not_yet_known_is_taken_when_it_is() {
    let (a, b, personal) = paired();
    let project = membership::create_project_group(&a.state, "project:x").unwrap();
    channels::add_member(&a.state.db.lock().unwrap(), &project, &b.pk(), "owner").unwrap();
    let new_device = NodeIdentity::generate().unwrap().public_key();
    let others: Vec<[u8; 32]> = keys_of_nobodys(3).into_iter().chain([new_device]).collect();
    let at = (
        epoch_of(&a, &project) + 1,
        a.key_version(&project) as u32,
        a.key(&project),
    );
    let state = state_listing(&project, &b.pk(), &a.pk(), at, false, &others);
    deliver_crafted(&b.state.identity, &a, &state);
    for _ in 0..2 {
        let summary = membership::process_inbox(&a.state).unwrap();
        assert_eq!((summary.applied.len(), summary.held), (0, 1), "{summary:?}");
    }

    // The device is added to the personal channel, as it is when the
    // state that adds it arrives.
    channels::add_member(&a.state.db.lock().unwrap(), &personal, &new_device, "owner").unwrap();
    let summary = membership::process_inbox(&a.state).unwrap();
    assert_eq!((summary.applied.len(), summary.held), (1, 0), "{summary:?}");
    let mut want = vec![a.pk(), b.pk(), new_device];
    want.sort();
    let mut members: Vec<[u8; 32]> = a.members(&project).into_iter().map(|(k, _)| k).collect();
    members.sort();
    assert_eq!(members, want);
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
