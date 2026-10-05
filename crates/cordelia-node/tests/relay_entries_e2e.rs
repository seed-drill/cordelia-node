//! End to end, with real processes: a relay that carries channels from
//! their secrets over real connections, beside the older kind of channel
//! (decision 2026-10-04 §2.4, §2.5, §4.6).
//!
//! Each test starts a relay of its own on this machine, through the
//! harness. The test is the client: it connects as any node may, opens
//! the streams itself, and reads what comes back. What a relay holds is
//! read from its answers, and from its database where a test asks what an
//! answer does not say (since when a channel is held).

mod common;

use std::sync::Arc;
use std::time::Duration;

use cordelia_core::protocol::{
    BAN_THRESHOLD, ENTRY_REQUESTS_PER_PEER_PER_MINUTE, ERR_RATE_LIMIT,
    MAX_ENTRY_NAME_AND_VALUE_BYTES, MAX_ITEM_BYTES, NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR,
    PUSH_BYTES_PER_PEER_PER_MINUTE, entry_cost,
};
use cordelia_crypto::entry::{CheckedEntry, Entry, Inside, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::{derive, proof};
use cordelia_network::messages::{
    ChannelProve, EntryPull, EntryPulled, EntryPush, EntryRefused, EntryShow, Item, Protocol,
    PushAck, PushAnswer, PushPayload, RelayChannelsAsk, RelayEntry, RelayPull, RelayPush,
    ShowAnswer, WireMessage,
};
use cordelia_network::{codec, connection, transport};
use cordelia_storage::relay::HeldChannel;

use common::*;

/// The mark of no holding: what a client asks with that has no place yet.
const NO_MARK: [u8; 8] = [0; 8];

/// What an entry with a small text is counted at: 256 bytes of content
/// and what an entry takes beyond it.
const SMALL: u64 = 256 + 1024;

/// What an entry of the largest size is counted at.
const LARGEST: u64 = 65_536 + 1024;

/// The secret of the channel numbered `c`.
fn secret(c: u16) -> [u8; 32] {
    let mut secret = [0x6b; 32];
    secret[..2].copy_from_slice(&c.to_be_bytes());
    secret
}

/// The ID of the channel numbered `c`.
fn channel(c: u16) -> [u8; 32] {
    derive::channel_id(&secret(c)).unwrap()
}

/// A client of a relay that is not a node: it connects as any node may,
/// and opens whatever streams the test has it open.
struct Client {
    identity: Arc<NodeIdentity>,
    conn: quinn::Connection,
    _manager: connection::ConnectionManager,
}

/// Connect a new client, with a key of its own, to `relay`.
async fn client_of(relay: &Node) -> Result<Client, String> {
    client_as(Arc::new(NodeIdentity::generate().unwrap()), relay).await
}

/// Connect a client with the key `identity` to `relay`.
async fn client_as(identity: Arc<NodeIdentity>, relay: &Node) -> Result<Client, String> {
    let endpoint = transport::create_endpoint(&identity, "127.0.0.1:0".parse().unwrap()).unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let mut manager = connection::ConnectionManager::new(
        identity.clone(),
        endpoint,
        vec![],
        vec!["personal".into()],
        port,
    );
    let relay_id = manager
        .connect_to(format!("127.0.0.1:{}", relay.p2p).parse().unwrap())
        .await
        .map_err(|e| e.to_string())?;
    let conn = manager.get_connection(&relay_id).unwrap().clone();
    Ok(Client {
        identity,
        conn,
        _manager: manager,
    })
}

/// Ask one thing on a new stream of `protocol` on `conn`, and read the
/// answer. `Err` where the stream was refused, or nothing was answered.
async fn ask_on(
    conn: &quinn::Connection,
    protocol: Protocol,
    request: WireMessage,
) -> Result<WireMessage, String> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let mut stream = tokio::io::join(&mut recv, &mut send);
    let answer = codec::send_request(&mut stream, protocol, &request)
        .await
        .map_err(|e| e.to_string());
    let _ = send.finish();
    answer
}

impl Client {
    async fn ask(&self, protocol: Protocol, request: WireMessage) -> Result<WireMessage, String> {
        ask_on(&self.conn, protocol, request).await
    }

    /// An entry of channel `c` that this client made of `said` under
    /// `name` at `rev`: it holds the channel's secret.
    fn made(&self, c: u16, rev: u64, name: &str, said: &str) -> CheckedEntry {
        made_by(&self.identity, c, rev, name, said)
    }

    /// Show `entry`. `Err` where nothing was answered.
    async fn show(&self, entry: Vec<u8>) -> Result<ShowAnswer, String> {
        match self
            .ask(
                Protocol::EntryShow,
                WireMessage::EntryShow(EntryShow { entry }),
            )
            .await?
        {
            WireMessage::EntryShown(shown) => Ok(shown.answer),
            other => Err(format!("not an answer to a show: {other:?}")),
        }
    }

    /// Push `entries`. `Err` where nothing was answered.
    async fn push(&self, entries: Vec<Vec<u8>>) -> Result<Vec<PushAnswer>, String> {
        let push = EntryPush {
            entries: entries.into_iter().map(Into::into).collect(),
        };
        match self
            .ask(Protocol::EntryPush, WireMessage::EntryPush(push))
            .await?
        {
            WireMessage::EntryPushed(pushed) => Ok(pushed.answers),
            other => Err(format!("not an answer to a push: {other:?}")),
        }
    }

    /// The proof that this end of this connection holds the key of the
    /// channel numbered `c`: over the value that this connection's TLS
    /// session exports, and this client's node key.
    fn proof(&self, c: u16) -> [u8; 64] {
        let session = transport::session_value(&self.conn).unwrap();
        proof::make(&secret(c), &session, &self.identity.public_key()).unwrap()
    }

    /// Send `proof` as the proof of the channel numbered `c`.
    async fn prove_with(&self, c: u16, proof: [u8; 64]) -> bool {
        let prove = ChannelProve {
            channel: channel(c),
            proof,
        };
        match self
            .ask(Protocol::ChannelProve, WireMessage::ChannelProve(prove))
            .await
        {
            Ok(WireMessage::ChannelProved(proved)) => proved.proved,
            other => panic!("not an answer to a proof: {other:?}"),
        }
    }

    /// Prove the channel numbered `c`, as a holder of its secret does.
    async fn prove(&self, c: u16) -> bool {
        self.prove_with(c, self.proof(c)).await
    }

    /// Ask for a page of the channel with this ID. `Err` where nothing
    /// was answered.
    async fn pull_id(
        &self,
        channel: [u8; 32],
        mark: [u8; 8],
        after: u64,
    ) -> Result<EntryPulled, String> {
        let pull = EntryPull {
            channel,
            mark,
            after,
            limit: 100,
        };
        match self
            .ask(Protocol::EntryPull, WireMessage::EntryPull(pull))
            .await?
        {
            WireMessage::EntryPulled(page) => Ok(page),
            other => Err(format!("not a page: {other:?}")),
        }
    }

    /// Ask for a page of the channel numbered `c`.
    async fn pull(&self, c: u16, mark: [u8; 8], after: u64) -> EntryPulled {
        self.pull_id(channel(c), mark, after)
            .await
            .expect("a pull is answered")
    }

    /// An item of the older kind of channel, of `bytes` bytes in
    /// `channel`, signed by this client, as it travels.
    fn item(&self, channel: &str, bytes: usize) -> Item {
        let mut blob = vec![7u8; bytes];
        let item_id = cordelia_storage::items::generate_item_id();
        let tag = item_id.as_bytes();
        blob[..tag.len().min(bytes)].copy_from_slice(&tag[..tag.len().min(bytes)]);
        let hash = cordelia_crypto::sha256(&blob);
        let published_at = "2026-10-05T00:00:00Z";
        let cbor = cordelia_crypto::signing::build_item_metadata_envelope(
            &self.identity.public_key(),
            channel,
            &hash,
            false,
            &item_id,
            1,
            published_at,
        )
        .unwrap();
        Item {
            item_id,
            channel_id: channel.into(),
            item_type: "memory".into(),
            content_length: blob.len() as u32,
            encrypted_blob: blob,
            content_hash: hash.to_vec(),
            author_id: self.identity.public_key().to_vec(),
            signature: self.identity.sign(&cbor).to_vec(),
            key_version: 1,
            published_at: published_at.into(),
            is_tombstone: false,
            parent_id: None,
            slot: None,
            rev: None,
        }
    }

    /// Push items of the older kind. `Err` where nothing was answered.
    async fn push_items(&self, items: Vec<Item>) -> Result<PushAck, String> {
        match self
            .ask(
                Protocol::ItemPush,
                WireMessage::PushPayload(PushPayload { items }),
            )
            .await?
        {
            WireMessage::PushAck(ack) => Ok(ack),
            other => Err(format!("not an answer to a push of items: {other:?}")),
        }
    }
}

/// An entry of channel `c` that `author` made of `said` under `name` at
/// `rev`, with the channel's secret.
fn made_by(author: &NodeIdentity, c: u16, rev: u64, name: &str, said: &str) -> CheckedEntry {
    let inside = Inside {
        name: name.to_string(),
        value: Value::Text(said.to_string()),
        chain: Some(Vec::new()),
    };
    Entry::seal(&secret(c), author, rev, &inside)
        .unwrap()
        .check()
        .unwrap()
}

/// An entry of channel `c` of the largest size, under the name `name`.
fn largest_by(author: &NodeIdentity, c: u16, name: &str) -> CheckedEntry {
    let text = "x".repeat(MAX_ENTRY_NAME_AND_VALUE_BYTES - name.len());
    let entry = made_by(author, c, 5, name, &text);
    assert_eq!(entry.content.len(), MAX_ITEM_BYTES);
    entry
}

/// What the entries of a page say, opened with the secret of the channel
/// numbered `c`: each checked first, as whoever is handed one checks it.
fn texts(page: &EntryPulled, c: u16) -> Vec<String> {
    page.entries
        .iter()
        .map(|bytes| {
            let entry = Entry::from_wire(bytes).unwrap().check().unwrap();
            assert_eq!(entry.channel, channel(c));
            match entry.open(&secret(c)).unwrap().value {
                Value::Text(text) => text,
                other => panic!("not a text: {other:?}"),
            }
        })
        .collect()
}

/// A node's database, opened for reading while the node runs.
fn store_of(node: &Node) -> rusqlite::Connection {
    let db = rusqlite::Connection::open_with_flags(
        node.data_dir().join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    db
}

/// The channel numbered `c` as `relay` holds it, read from its database.
fn held(relay: &Node, c: u16) -> Option<HeldChannel> {
    cordelia_storage::relay::held_channel(&store_of(relay), &channel(c)).unwrap()
}

/// Time goes by for the channel numbered `c` as `relay` holds it: it was
/// last used `secs` earlier than the relay has it. Written to the relay's
/// database beside the relay, which reads the time each time it asks.
fn used_earlier(relay: &Node, c: u16, secs: i64) {
    let db = rusqlite::Connection::open(relay.data_dir().join("cordelia.db")).unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    let changed = db
        .execute(
            "UPDATE relay_channels SET used_at = used_at - ?1 WHERE channel_id = ?2",
            rusqlite::params![secs, channel(c).as_slice()],
        )
        .unwrap();
    assert_eq!(changed, 1, "the relay does not hold channel {c}");
}

/// What `relay` holds of channels from their secrets, as entries are
/// counted, and of the older kind, as its items are.
fn holds(relay: &Node) -> (u64, u64) {
    let db = store_of(relay);
    (
        cordelia_storage::relay::used_bytes(&db).unwrap(),
        cordelia_storage::items::stored_cost(&db).unwrap(),
    )
}

/// A relay of the test's own, started, that may hold `max_bytes` where
/// that is given.
fn relay_started(max_bytes: Option<u64>) -> Node {
    let mut relay = node("relay", "relay", None);
    if let Some(max_bytes) = max_bytes {
        relay.max_storage_bytes(max_bytes);
    }
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    relay
}

/// A client that holds a channel's secret pushes entries, proves the
/// channel's key on its connection, and pulls them back, each as it was
/// made. Before the proof it is handed nothing. What a connection proved
/// is that connection's: on a new one, under the same key, nothing is
/// handed until it proves again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_with_a_channels_secret_pushes_proves_and_pulls_its_entries_back() {
    let relay = relay_started(None);
    let client = client_of(&relay).await.expect("the client connects");

    let entries = [
        client.made(1, 5, "notes.md", "what the file holds"),
        client.made(1, 3, "other.md", "another file"),
        made_by(
            &NodeIdentity::generate().unwrap(),
            1,
            9,
            "notes.md",
            "by another device",
        ),
    ];
    let wire: Vec<Vec<u8>> = entries.iter().map(|entry| entry.to_wire()).collect();
    assert_eq!(
        client.push(wire.clone()).await.unwrap(),
        [PushAnswer::Stored, PushAnswer::Stored, PushAnswer::Stored]
    );
    // Pushed again, each is held already.
    assert_eq!(
        client.push(wire.clone()).await.unwrap(),
        [PushAnswer::Held, PushAnswer::Held, PushAnswer::Held]
    );

    // Before it has proved the channel's key: nothing, and the place and
    // the mark it asked with.
    let before = client.pull(1, NO_MARK, 0).await;
    assert_eq!(
        before,
        EntryPulled {
            entries: Vec::new(),
            next: 0,
            mark: NO_MARK,
        }
    );

    // It proves, and is handed the channel: each entry as it was made.
    assert!(client.prove(1).await, "a true proof was refused");
    let page = client.pull(1, NO_MARK, 0).await;
    let handed: Vec<Vec<u8>> = page.entries.iter().map(|entry| entry.to_vec()).collect();
    assert_eq!(handed, wire);
    assert_eq!(
        texts(&page, 1),
        ["what the file holds", "another file", "by another device"]
    );
    assert_eq!(page.next, 3);
    assert_ne!(page.mark, NO_MARK, "the holding has a mark of its own");
    // From its place, with the mark it was told: nothing more.
    let caught_up = client.pull(1, page.mark, page.next).await;
    assert_eq!((caught_up.entries.len(), caught_up.next), (0, 3));
    assert_eq!(caught_up.mark, page.mark);

    // A newer revision is handed next, from the place that was kept.
    let newer = client.made(1, 6, "notes.md", "what it holds now");
    assert_eq!(
        client
            .push(vec![newer.to_wire(), entries[0].to_wire()])
            .await
            .unwrap(),
        [PushAnswer::Stored, PushAnswer::Older]
    );
    let next = client.pull(1, page.mark, page.next).await;
    assert_eq!(texts(&next, 1), ["what it holds now"]);
    assert_eq!((next.next, next.mark), (4, page.mark));
    // With a mark that is no holding's, the channel is handed from the
    // start whatever place is asked after.
    let from_the_start = client.pull(1, [0x4d; 8], 4).await;
    assert_eq!(
        texts(&from_the_start, 1),
        ["another file", "by another device", "what it holds now"]
    );
    assert_eq!((from_the_start.next, from_the_start.mark), (4, page.mark));

    // A channel that the relay does not hold yet, proved as it should be:
    // no. When its first entry arrives, the connection is handed it with
    // no proof more.
    assert!(!client.prove(2).await);
    assert!(client.pull(2, NO_MARK, 0).await.entries.is_empty());
    let late = client.made(2, 1, "late.md", "arrived after the proof");
    assert_eq!(
        client.push(vec![late.to_wire()]).await.unwrap(),
        [PushAnswer::Stored]
    );
    assert_eq!(
        texts(&client.pull(2, NO_MARK, 0).await, 2),
        ["arrived after the proof"]
    );

    // A new connection under the same key has proved nothing: what the
    // first one proved was that connection's.
    let made_on_the_first = client.proof(1);
    let again = client_as(client.identity.clone(), &relay)
        .await
        .expect("the client connects again");
    assert!(again.pull(1, NO_MARK, 0).await.entries.is_empty());
    // The proof that the first connection made is none on this one.
    assert!(!again.prove_with(1, made_on_the_first).await);
    assert!(again.pull(1, NO_MARK, 0).await.entries.is_empty());
    // Its own is.
    assert!(again.prove(1).await);
    assert_eq!(again.pull(1, NO_MARK, 0).await.entries.len(), 3);
}

/// A stranger that knows a channel's ID, and holds no key of it, gets
/// nothing. What it pushes is not stored: it cannot sign as the channel.
/// A proof that it makes up, and a true proof that it captured from
/// another connection, are both answered no. What it pulls is an empty
/// page: the same answer as for a channel that the relay does not hold.
/// And a proof that the relay's end of a connection would make does not
/// hold when the other end sends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_with_only_a_channels_id_gets_nothing() {
    let relay = relay_started(None);
    let holder = client_of(&relay).await.expect("the holder connects");
    let held_entry = holder.made(1, 5, "notes.md", "what the file holds");
    assert_eq!(
        holder.push(vec![held_entry.to_wire()]).await.unwrap(),
        [PushAnswer::Stored]
    );
    // The holder proves on its connection. The stranger has seen the
    // proof go by, and the entry.
    let captured = holder.proof(1);
    assert!(holder.prove_with(1, captured).await);

    let stranger = client_of(&relay).await.expect("the stranger connects");
    // What it can make: an entry that names the channel, in the slot it
    // has seen, signed as its author by its own key. The channel's
    // signature it cannot make: it leaves it out, or signs with its own
    // key, or with the key of a channel of its own.
    let own_channel = derive::signing_key(&secret(99)).unwrap();
    let made_up: Vec<Vec<u8>> = [None, Some(&*stranger.identity), Some(&own_channel)]
        .into_iter()
        .map(|by_channel| {
            let mut entry = Entry {
                channel: channel(1),
                slot: held_entry.slot,
                author: stranger.identity.public_key(),
                rev: 9,
                delete: false,
                content: vec![0x5a; 256],
                author_signature: [0; 64],
                channel_signature: [0; 64],
            };
            let form = entry.signed_bytes();
            let under = |label: &[u8]| [label, form.as_slice()].concat();
            entry.author_signature = stranger
                .identity
                .sign(&under(cordelia_core::protocol::LABEL_ENTRY_AUTHOR));
            if let Some(key) = by_channel {
                entry.channel_signature =
                    key.sign(&under(cordelia_core::protocol::LABEL_ENTRY_CHANNEL));
            }
            entry.to_wire()
        })
        .collect();
    let refused = PushAnswer::Refused(EntryRefused::NotSigned);
    assert_eq!(
        stranger.push(made_up.clone()).await.unwrap(),
        [refused, refused, refused]
    );
    for entry in &made_up {
        assert_eq!(
            stranger.show(entry.clone()).await.unwrap(),
            ShowAnswer::Refused(EntryRefused::NotSigned)
        );
    }

    // It proves: with a proof it made up, with one signed by its own
    // key, and with the true proof it captured from the holder's
    // connection. Each is answered no.
    let session = transport::session_value(&stranger.conn).unwrap();
    let mut what_it_signs = cordelia_core::protocol::LABEL_CHANNEL_PROOF.to_vec();
    what_it_signs.extend_from_slice(&session);
    what_it_signs.extend_from_slice(&stranger.identity.public_key());
    what_it_signs.extend_from_slice(&channel(1));
    for forged in [
        [7u8; 64],
        stranger.identity.sign(&what_it_signs),
        own_channel.sign(&what_it_signs),
        captured,
    ] {
        assert!(!stranger.prove_with(1, forged).await);
    }
    // The control: the captured proof is a true one, where it was made.
    assert!(holder.prove_with(1, captured).await);

    // It pulls: an empty page, whatever mark and place it asks with. The
    // answer is the one for a channel that the relay does not hold, to
    // the byte.
    let not_held: [u8; 32] = channel(77);
    for (mark, after) in [(NO_MARK, 0), ([9; 8], 0), ([9; 8], 7)] {
        let page = stranger.pull(1, mark, after).await;
        assert_eq!(
            page,
            EntryPulled {
                entries: Vec::new(),
                next: after,
                mark,
            }
        );
        let other = stranger.pull_id(not_held, mark, after).await.unwrap();
        assert_eq!(
            codec::encode_message(&WireMessage::EntryPulled(page)).unwrap(),
            codec::encode_message(&WireMessage::EntryPulled(other)).unwrap()
        );
    }
    // And the answer to its proof is the answer to a true proof of a
    // channel that is not held: no.
    assert!(!holder.prove(77).await);

    // A proof that the relay's end of the connection would make, over
    // the value that both ends export, does not hold when this end sends
    // it: a proof says which end made it. A holder of the secret makes
    // one for the relay's key, on a connection that has proved nothing.
    let other_holder = client_of(&relay).await.expect("a holder connects");
    let relays_key = transport::peer_key(&other_holder.conn).unwrap();
    let session = transport::session_value(&other_holder.conn).unwrap();
    let by_the_relays_end = proof::make(&secret(1), &session, &relays_key).unwrap();
    assert!(proof::check(
        &channel(1),
        &session,
        &relays_key,
        &by_the_relays_end
    ));
    assert!(!other_holder.prove_with(1, by_the_relays_end).await);
    assert!(other_holder.pull(1, NO_MARK, 0).await.entries.is_empty());
    // Its own proof, over the same value, holds.
    assert!(other_holder.prove(1).await);

    // Nothing of all that changed what the relay holds: the one entry.
    let page = holder.pull(1, NO_MARK, 0).await;
    assert_eq!(texts(&page, 1), ["what the file holds"]);
    assert_eq!(holds(&relay).0, SMALL);
}

/// A pull without a proof is answered with nothing, and so is a pull
/// after a proof of another channel. The proof is what opens a channel,
/// on the connection it was made on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pull_without_a_proof_is_handed_nothing() {
    let relay = relay_started(None);
    let client = client_of(&relay).await.expect("the client connects");
    for c in [1, 2] {
        let entry = client.made(c, 1, "notes.md", &format!("of channel {c}"));
        client.push(vec![entry.to_wire()]).await.unwrap();
    }
    for c in [1, 2] {
        assert!(client.pull(c, NO_MARK, 0).await.entries.is_empty(), "{c}");
    }
    // The first is proved: it is handed, and the second is still not.
    assert!(client.prove(1).await);
    assert_eq!(
        texts(&client.pull(1, NO_MARK, 0).await, 1),
        ["of channel 1"]
    );
    assert!(client.pull(2, NO_MARK, 0).await.entries.is_empty());
    // The proof of the first, sent as the proof of the second: no.
    assert!(!client.prove_with(2, client.proof(1)).await);
    assert!(client.pull(2, NO_MARK, 0).await.entries.is_empty());
    // Another connection that has proved neither is handed neither.
    let other = client_of(&relay).await.expect("another client connects");
    for c in [1, 2] {
        assert!(other.pull(c, NO_MARK, 0).await.entries.is_empty(), "{c}");
    }
}

/// Shown an entry, a relay answers with what it holds: it holds that
/// entry; it held none from that author in that slot, or an earlier one,
/// and took this one; or it holds another, and here it is. It answers a
/// connection that has proved no key: only a holder of an entry can ask.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shown_an_entry_a_relay_answers_held_taken_or_another() {
    let relay = relay_started(None);
    let client = client_of(&relay).await.expect("the client connects");
    let first = client.made(1, 5, "change", "the first");

    // It holds none from that author in that slot: it takes this one.
    assert_eq!(
        client.show(first.to_wire()).await.unwrap(),
        ShowAnswer::Taken
    );
    // It holds that very entry.
    assert_eq!(
        client.show(first.to_wire()).await.unwrap(),
        ShowAnswer::Held
    );

    // Another connection, which has proved nothing, shows an earlier
    // one, and one at that revision: each is answered with the one that
    // the relay holds, which passes the check.
    let behind = client_of(&relay).await.expect("another client connects");
    for shown in [
        client.made(1, 4, "change", "an earlier one"),
        client.made(1, 5, "change", "another at that revision"),
    ] {
        let ShowAnswer::Another(bytes) = behind.show(shown.to_wire()).await.unwrap() else {
            panic!("not answered with the entry that is held");
        };
        assert_eq!(bytes, first.to_wire());
        assert_eq!(Entry::from_wire(&bytes).unwrap().check().unwrap(), first);
    }

    // A later one is taken, and then the first is answered with it.
    let later = client.made(1, 6, "change", "a later one");
    assert_eq!(
        behind.show(later.to_wire()).await.unwrap(),
        ShowAnswer::Taken
    );
    assert_eq!(
        client.show(first.to_wire()).await.unwrap(),
        ShowAnswer::Another(later.to_wire())
    );
    assert_eq!(
        client.show(later.to_wire()).await.unwrap(),
        ShowAnswer::Held
    );

    // An entry that is not signed as it must be is refused, and bytes
    // that are no entry's.
    let mut changed = later.clone().into_entry();
    changed.rev = 7;
    for bytes in [changed.to_wire(), vec![1, 2, 3]] {
        assert_eq!(
            client.show(bytes).await.unwrap(),
            ShowAnswer::Refused(EntryRefused::NotSigned)
        );
    }
    // The relay holds the later one, and nothing else.
    assert!(client.prove(1).await);
    assert_eq!(texts(&client.pull(1, NO_MARK, 0).await, 1), ["a later one"]);
    assert_eq!(holds(&relay).0, SMALL);
}

/// A relay near its cap for channels from their secrets: it takes no
/// channel that it does not hold, pushed or shown, and no entry that
/// makes a channel hold more. A newer revision that is no larger is still
/// taken, and nothing that it holds is dropped. Its room for the older
/// kind of channel is another room: an item of that kind is still taken,
/// and what it holds of one kind is not counted for the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_near_its_cap_takes_no_new_channel_and_drops_nothing() {
    // Room for three small entries, of each kind.
    let relay = relay_started(Some(3 * SMALL));
    let client = client_of(&relay).await.expect("the client connects");
    let first = |c: u16| client.made(c, 5, "notes.md", "a small text").to_wire();

    assert_eq!(
        client
            .push(vec![first(1), first(2), first(3)])
            .await
            .unwrap(),
        [PushAnswer::Stored, PushAnswer::Stored, PushAnswer::Stored]
    );
    assert_eq!(holds(&relay), (3 * SMALL, 0));

    // At its cap: a new channel is refused, pushed and shown, and so is
    // an entry more in a channel that it holds.
    let no_room = PushAnswer::Refused(EntryRefused::NoRoom);
    assert_eq!(
        client
            .push(vec![
                first(4),
                client.made(1, 5, "other.md", "another name").to_wire()
            ])
            .await
            .unwrap(),
        [no_room, no_room]
    );
    assert_eq!(
        client.show(first(4)).await.unwrap(),
        ShowAnswer::Refused(EntryRefused::NoRoom)
    );
    // A newer revision of the same size is taken, pushed and shown, and
    // a larger one is not.
    let newer = client.made(1, 6, "notes.md", "a newer text");
    assert_eq!(
        client.push(vec![newer.to_wire()]).await.unwrap(),
        [PushAnswer::Stored]
    );
    let newest = client.made(2, 7, "notes.md", "the newest");
    assert_eq!(
        client.show(newest.to_wire()).await.unwrap(),
        ShowAnswer::Taken
    );
    let larger = client.made(3, 8, "notes.md", &"x".repeat(300));
    assert_eq!(
        client.push(vec![larger.to_wire()]).await.unwrap(),
        [no_room]
    );

    // Nothing was dropped: each of the three channels holds its entry.
    for (c, text) in [(1, "a newer text"), (2, "the newest"), (3, "a small text")] {
        assert!(client.prove(c).await, "{c}");
        assert_eq!(texts(&client.pull(c, NO_MARK, 0).await, c), [text]);
    }
    assert!(!client.prove(4).await);
    assert_eq!(holds(&relay), (3 * SMALL, 0));

    // The older kind has a room of its own, of the same size: with this
    // kind at its cap, an item of the older kind is taken.
    let old = "grp_550e8400-e29b-41d4-a716-446655440000";
    let ack = client.push_items(vec![client.item(old, 64)]).await.unwrap();
    assert_eq!((ack.stored, ack.refused.len()), (1, 0), "{ack:?}");
    assert_eq!(holds(&relay), (3 * SMALL, entry_cost(64)));
    // And what the relay says it has in use, of its cap, is the older
    // kind's own count.
    let stats: serde_json::Value = serde_json::from_str(&relay.cli(&["stats", "--json"])).unwrap();
    assert_eq!(stats["storage_used_bytes"], entry_cost(64), "{stats}");
    assert_eq!(stats["storage_max_bytes"], 3 * SMALL, "{stats}");

    // The older kind is filled to its own cap, by its own rule: a write
    // that takes it over drops its newest channel. This kind's channels
    // are as they were.
    let ack = client
        .push_items(vec![client.item(old, 64), client.item(old, 64)])
        .await
        .unwrap();
    assert_eq!(ack.stored, 2, "{ack:?}");
    let another = "grp_550e8400-e29b-41d4-a716-446655440001";
    let ack = client
        .push_items(vec![client.item(another, 2000)])
        .await
        .unwrap();
    assert_eq!(ack.stored, 0, "{ack:?}");
    assert_eq!(holds(&relay), (3 * SMALL, 3 * entry_cost(64)));
    for c in [1, 2, 3] {
        assert_eq!(client.pull(c, NO_MARK, 0).await.entries.len(), 1, "{c}");
    }
    // And still, at this kind's cap, a newer revision is taken.
    let again = client.made(3, 9, "notes.md", "edited again");
    assert_eq!(
        client.push(vec![again.to_wire()]).await.unwrap(),
        [PushAnswer::Stored]
    );
}

/// One address may make a relay take 256 new channels from their secrets
/// in an hour. The 257th is refused, pushed or shown. An entry in a
/// channel that the relay holds is no new channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_address_may_make_a_relay_take_so_many_new_channels_an_hour() {
    assert_eq!(NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR, 256);
    let relay = relay_started(None);
    let client = client_of(&relay).await.expect("the client connects");
    let first = |c: u16| client.made(c, 5, "notes.md", "a small text").to_wire();

    // 256 channels, from two connections at the one address.
    let other = client_of(&relay).await.expect("another client connects");
    for (from, by) in [(0u16, &client), (100, &other), (200, &client)] {
        let to = (from + 100).min(256);
        let answers = by.push((from..to).map(first).collect()).await.unwrap();
        assert!(
            answers.iter().all(|answer| *answer == PushAnswer::Stored),
            "{from}: {answers:?}"
        );
    }
    // The 257th: over the limit, from either connection, pushed or shown.
    let over = EntryRefused::OverLimit;
    for by in [&client, &other] {
        assert_eq!(
            by.push(vec![first(256)]).await.unwrap(),
            [PushAnswer::Refused(over)]
        );
        assert_eq!(
            by.show(first(256)).await.unwrap(),
            ShowAnswer::Refused(over)
        );
    }
    assert_eq!(held(&relay, 256), None);
    assert_eq!(holds(&relay).0, 256 * SMALL);

    // An entry in a channel that is held is taken: another name, and a
    // newer revision.
    assert_eq!(
        client
            .push(vec![
                client.made(7, 5, "other.md", "another name").to_wire(),
                client.made(7, 6, "notes.md", "a newer text").to_wire(),
            ])
            .await
            .unwrap(),
        [PushAnswer::Stored, PushAnswer::Stored]
    );
}

/// The limits by address are the older kind's, and count both kinds
/// together: what a connection pushes in a minute, in items and in
/// entries, is one allowance; what it is handed is bounded as what may be
/// fetched is; and a peer that pushes over it as many times as cut a peer
/// off today is cut off, with its address refused for a time.
///
/// A pull for more than the connection may be handed for now is refused,
/// with the error of a limit, and is no breach however often it is made:
/// the relay sized the page, and the asker cannot know its room. And the
/// entry that answers a show is handed all the same to a connection that
/// has had its bytes for the minute: so a device hears of a change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_limits_by_address_count_both_kinds_of_channel_together() {
    let relay = relay_started(None);
    let client = client_of(&relay).await.expect("the client connects");
    let old = "grp_550e8400-e29b-41d4-a716-446655440000";
    let largest = |by: &Client, from: usize, to: usize| -> Vec<Vec<u8>> {
        (from..to)
            .map(|n| largest_by(&by.identity, 1, &format!("{n:04}.md")).to_wire())
            .collect()
    };

    // A megabyte of items of the older kind, and then a megabyte of
    // entries: together they are what one connection may push in a
    // minute, less a little.
    let megabyte: Vec<Item> = (0..15).map(|_| client.item(old, MAX_ITEM_BYTES)).collect();
    assert_eq!(client.push_items(megabyte).await.unwrap().stored, 15);
    let entries = largest(&client, 0, 15);
    let answers = client.push(entries[..13].to_vec()).await.unwrap();
    assert!(answers.iter().all(|answer| *answer == PushAnswer::Stored));
    let answers = client.push(entries[13..].to_vec()).await.unwrap();
    assert_eq!(answers, [PushAnswer::Stored, PushAnswer::Stored]);
    // Thirty of the largest are within what a connection may push in a
    // minute, and thirty-two are not.
    assert_eq!(PUSH_BYTES_PER_PEER_PER_MINUTE / LARGEST, 31);

    // Two entries more are over it: the push is refused whole, and
    // nothing of it is stored. That is the first breach.
    let two_more = largest(&client, 15, 17);
    assert!(
        client.push(two_more).await.is_err(),
        "entries were taken past what the connection may push with the older kind"
    );
    // And so are two items of the older kind: the second breach.
    let two_items = vec![
        client.item(old, MAX_ITEM_BYTES),
        client.item(old, MAX_ITEM_BYTES),
    ];
    assert!(client.push_items(two_items).await.is_err());
    assert_eq!(holds(&relay), (15 * LARGEST, 15 * LARGEST));
    // What is left of the allowance still takes a push that fits in it,
    // of either kind.
    assert_eq!(
        client
            .push(vec![
                client.made(2, 5, "notes.md", "a small text").to_wire()
            ])
            .await
            .unwrap(),
        [PushAnswer::Stored]
    );
    assert_eq!(
        client
            .push_items(vec![client.item(old, 64)])
            .await
            .unwrap()
            .stored,
        1
    );

    // Another connection at the address has an allowance of its own to
    // push with: the channel comes to hold 35 entries of the largest
    // size, which is more than may be fetched in a minute.
    let other = client_of(&relay).await.expect("another client connects");
    let more = largest(&other, 15, 35);
    for push in more.chunks(10) {
        let answers = other.push(push.to_vec()).await.unwrap();
        assert!(answers.iter().all(|answer| *answer == PushAnswer::Stored));
    }
    assert_eq!(holds(&relay).0, 35 * LARGEST + SMALL);

    // The first connection proves the channel and pulls it. It is handed
    // whole pages while its allowance has room for the most a page can
    // be counted at, then as many entries as fit: 31 in all.
    assert!(client.prove(1).await);
    let (mut mark, mut after) = (NO_MARK, 0);
    let mut handed = Vec::new();
    for _ in 0..3 {
        let page = client.pull(1, mark, after).await;
        handed.push(page.entries.len());
        (mark, after) = (page.mark, page.next);
    }
    assert_eq!(handed, [13, 13, 5]);
    // A page with nothing in it is still answered.
    assert!(client.pull(1, mark, 35).await.entries.is_empty());

    // The next entry does not fit in what is left: the pull is refused,
    // with the error of a limit. It is no breach: made many more times
    // than cut a peer off, it is refused each time, and the connection
    // stays.
    assert_eq!(BAN_THRESHOLD, 3);
    for _ in 0..2 * BAN_THRESHOLD {
        let refused = client.pull_id(channel(1), mark, after).await;
        let why = refused.expect_err("the connection was handed more than may be fetched");
        assert!(
            why.ends_with(&format!("stream reset by peer: error {ERR_RATE_LIMIT}")),
            "refused for another reason: {why}"
        );
    }
    assert!(
        client.conn.close_reason().is_none(),
        "the pulls were breaches"
    );
    // A pull that hands nothing is still answered.
    assert!(client.pull(1, mark, 35).await.entries.is_empty());

    // It shows an entry, in a slot where the relay holds a later one of
    // the largest size. It has no room left to be handed that: it is
    // answered with the entry all the same.
    let earlier = client.made(1, 4, "0000.md", "an earlier one");
    match client.show(earlier.to_wire()).await {
        Ok(ShowAnswer::Another(bytes)) => assert_eq!(bytes, entries[0]),
        other => panic!("a connection over its bytes was not answered with the entry: {other:?}"),
    }
    // And once more: it is over by an entry now, and is answered still.
    assert!(matches!(
        client.show(earlier.to_wire()).await,
        Ok(ShowAnswer::Another(_))
    ));
    assert!(client.conn.close_reason().is_none());

    // What it pushes over its allowance is a breach, as before: the third
    // one, counted with the two above, and the relay cuts the connection
    // off and says why.
    assert!(client.push(largest(&client, 40, 42)).await.is_err());
    let closed = tokio::time::timeout(Duration::from_secs(10), client.conn.closed())
        .await
        .expect("the relay did not close the connection");
    match closed {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.error_code,
                quinn::VarInt::from_u32(ERR_RATE_LIMIT),
                "{close:?}"
            );
        }
        other => panic!("closed for another reason: {other:?}"),
    }
    // Its address is refused for a time: no new connection is let in,
    // under a new key either.
    assert!(
        client_of(&relay).await.is_err(),
        "the address was let back in"
    );
}

/// A relay counts the requests that a connection makes on the streams of
/// entries, all of them together: 3,000 in a minute are answered,
/// whichever stream each is on. One more is refused, and is a breach: as
/// many breaches as cut a peer off today close the connection, and the
/// relay says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_may_make_so_many_requests_a_minute_on_the_streams_of_entries() {
    assert_eq!(ENTRY_REQUESTS_PER_PEER_PER_MINUTE, 3_000);
    let relay = relay_started(None);
    let client = client_of(&relay).await.expect("the client connects");
    let held = client.made(1, 5, "notes.md", "what the file holds");
    assert_eq!(
        client.push(vec![held.to_wire()]).await.unwrap(),
        [PushAnswer::Stored]
    );
    assert!(client.prove(1).await);
    let mut asked = 2;

    // Requests that cost the relay little, on each of the streams: a
    // pull of a channel that was not proved, a proof that fails, a push
    // of nothing, and a pull of the channel that was proved, from its
    // end. Some at a time, so that they are all made within the minute.
    let began = std::time::Instant::now();
    while asked < ENTRY_REQUESTS_PER_PEER_PER_MINUTE {
        let mut some = tokio::task::JoinSet::new();
        for n in 0..(ENTRY_REQUESTS_PER_PEER_PER_MINUTE - asked).min(24) {
            let conn = client.conn.clone();
            let (protocol, request) = match (asked + n) % 4 {
                0 => (
                    Protocol::EntryPull,
                    WireMessage::EntryPull(EntryPull {
                        channel: channel(9),
                        mark: NO_MARK,
                        after: 0,
                        limit: 100,
                    }),
                ),
                1 => (
                    Protocol::ChannelProve,
                    WireMessage::ChannelProve(ChannelProve {
                        channel: channel(9),
                        proof: [7; 64],
                    }),
                ),
                2 => (
                    Protocol::EntryPush,
                    WireMessage::EntryPush(EntryPush {
                        entries: Vec::new(),
                    }),
                ),
                _ => (
                    Protocol::EntryPull,
                    WireMessage::EntryPull(EntryPull {
                        channel: channel(1),
                        mark: NO_MARK,
                        after: 1,
                        limit: 100,
                    }),
                ),
            };
            some.spawn(async move { ask_on(&conn, protocol, request).await });
        }
        while let Some(answer) = some.join_next().await {
            let answer = answer.unwrap();
            assert!(
                answer.is_ok(),
                "request {asked} of the minute was refused: {answer:?}"
            );
            asked += 1;
        }
    }
    assert!(
        began.elapsed() < Duration::from_secs(50),
        "the requests took {:?}: they were not all made within one minute",
        began.elapsed()
    );

    // One more, of any kind: refused. That is the first breach, and the
    // third closes the connection.
    assert_eq!(BAN_THRESHOLD, 3);
    assert!(
        client.pull_id(channel(1), NO_MARK, 0).await.is_err(),
        "a request beyond the count was answered"
    );
    assert!(client.show(held.to_wire()).await.is_err());
    assert!(client.push(vec![held.to_wire()]).await.is_err());
    let closed = tokio::time::timeout(Duration::from_secs(10), client.conn.closed())
        .await
        .expect("the relay did not close the connection");
    match closed {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.error_code,
                quinn::VarInt::from_u32(ERR_RATE_LIMIT),
                "{close:?}"
            );
        }
        other => panic!("closed for another reason: {other:?}"),
    }
}

/// Two relays that their operator lists together pass the entries of a
/// channel from its secret between them, without the proof, each with
/// since when the channel is held and when it was last used. A relay
/// that starts later pulls what the other holds; an entry that one takes
/// is passed on to the other; and a channel that is proved at one is
/// known at the other to be in use. A peer that the operator does not
/// list is refused the stream between relays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_relays_that_work_together_pass_entries_on_with_how_long_each_was_held() {
    let key_of = |n: &Node| n.cli(&["id"]).trim().to_string();
    let mut r1 = node("relay1", "relay", None);
    let mut r2 = node_with_relays(
        "relay2",
        "relay",
        &[(format!("localhost:{}", r1.p2p), Some(key_of(&r1)))],
    );
    r1.add_relay(&format!("localhost:{}", r2.p2p), Some(&key_of(&r2)));
    r1.start();
    wait_for("relay1 healthy", &[&r1], 30, || healthy(&r1));

    // The first relay alone takes a channel.
    let at_r1 = client_of(&r1).await.expect("the client connects to relay1");
    let first = at_r1.made(1, 5, "notes.md", "taken before the other relay started");
    assert_eq!(
        at_r1.push(vec![first.to_wire()]).await.unwrap(),
        [PushAnswer::Stored]
    );
    let since = held(&r1, 1).expect("relay1 holds it").held_since;
    // The channel was last used two hours ago, as the first relay has it:
    // a relay writes down a use at most once an hour.
    used_earlier(&r1, 1, 2 * 60 * 60);
    // Some seconds go by before the second relay starts.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(since < started);
    r2.start();
    wait_for("relay2 healthy", &[&r1, &r2], 30, || healthy(&r2));

    // The second relay asks the first what it holds, and pulls the
    // channel: it holds it since the first relay took it, and not since
    // it took it itself.
    let pulled = wait_for("relay2 pulls the channel", &[&r1, &r2], 90, || held(&r2, 1));
    assert_eq!(pulled.held_since, since);
    assert!(pulled.held_since < started);
    assert_eq!(pulled.bytes, SMALL);
    // It was last used when the first relay last saw it used.
    assert_eq!(pulled.used_at, held(&r1, 1).unwrap().used_at);

    // A client of the second relay that holds the secret proves the
    // channel there, and is handed the entry.
    let at_r2 = client_of(&r2).await.expect("the client connects to relay2");
    assert!(at_r2.prove(1).await);
    assert_eq!(
        texts(&at_r2.pull(1, NO_MARK, 0).await, 1),
        ["taken before the other relay started"]
    );

    // An entry that the first relay takes now is passed on to the
    // second, in a channel that is new to both: held there since the
    // first took it.
    let second = at_r1.made(2, 1, "notes.md", "passed on");
    assert_eq!(
        at_r1.push(vec![second.to_wire()]).await.unwrap(),
        [PushAnswer::Stored]
    );
    let passed_on = wait_for("relay2 is passed the entry", &[&r1, &r2], 90, || {
        held(&r2, 2)
    });
    assert_eq!(passed_on.held_since, held(&r1, 2).unwrap().held_since);
    // The first relay passed it on itself, as it took it: it did not
    // wait to be asked. (The channel it took while it was alone was
    // passed on to nobody: that one was pulled.)
    wait_for(
        "relay1 says it passed the entry on",
        &[&r1, &r2],
        30,
        || passed_on_by(&r1).then_some(()),
    );
    assert!(at_r2.prove(2).await);
    assert_eq!(texts(&at_r2.pull(2, NO_MARK, 0).await, 2), ["passed on"]);
    // And the other way: what the second takes reaches the first.
    let third = at_r2.made(3, 1, "notes.md", "from the second relay");
    assert_eq!(
        at_r2.show(third.to_wire()).await.unwrap(),
        ShowAnswer::Taken
    );
    let back = wait_for("relay1 is passed the entry", &[&r1, &r2], 90, || {
        held(&r1, 3)
    });
    assert_eq!(back.held_since, held(&r2, 3).unwrap().held_since);
    wait_for(
        "relay2 says it passed the entry on",
        &[&r1, &r2],
        30,
        || passed_on_by(&r2).then_some(()),
    );

    // The first channel was proved at the second relay, two hours after
    // the first relay last saw it used. The first relay sees no proof of
    // it: it is told, and keeps the later time, so that it does not drop
    // as unused a channel that is in use at the other.
    let used_there = held(&r2, 1).unwrap().used_at;
    assert!(used_there >= started, "the proof was not written down");
    wait_for(
        "relay1 is told the channel is in use",
        &[&r1, &r2],
        90,
        || (held(&r1, 1)?.used_at == used_there).then_some(()),
    );
    // Since when each holds it is as it was.
    assert_eq!(held(&r1, 1).unwrap().held_since, since);
    assert_eq!(held(&r2, 1).unwrap().held_since, since);

    // A peer that is not a listed relay is refused the stream between
    // relays: it is not told which channels are held, not handed a
    // channel without the proof, and nothing that it passes on is taken.
    let stranger = client_of(&r1).await.expect("a stranger connects");
    let forth = made_by(
        &stranger.identity,
        4,
        1,
        "notes.md",
        "passed on by a stranger",
    );
    for request in [
        WireMessage::RelayChannelsAsk(RelayChannelsAsk {
            after: [0; 32],
            limit: 1000,
        }),
        WireMessage::RelayPull(RelayPull {
            channel: channel(1),
            mark: NO_MARK,
            after: 0,
            limit: 100,
        }),
        WireMessage::RelayPush(RelayPush {
            entries: vec![RelayEntry {
                entry: forth.to_wire(),
                held_since: 1,
                used_at: 1,
            }],
        }),
    ] {
        let answer = stranger.ask(Protocol::RelayEntries, request).await;
        assert!(answer.is_err(), "a stranger was answered: {answer:?}");
    }
    assert_eq!(held(&r1, 4), None);
    // The streams that are for anyone still answer it.
    assert_eq!(
        stranger.push(vec![forth.to_wire()]).await.unwrap(),
        [PushAnswer::Stored]
    );
    // A channel that it makes the relay take is held from now, whatever
    // it would have said.
    assert!(held(&r1, 4).unwrap().held_since >= started);
}

/// Whether `relay` says, in its log, that it passed entries on to a relay
/// it works with.
fn passed_on_by(relay: &Node) -> bool {
    std::fs::read_to_string(relay.log())
        .unwrap_or_default()
        .contains("passed entries on")
}

/// A relay's room for channels from their secrets is the cap that its
/// operator set, read when it starts. A relay whose cap came down holds
/// more than its cap when it starts again: it drops the channels it has
/// held for the shortest time, until it is within it, and keeps what it
/// has held longest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_whose_cap_came_down_drops_its_newest_channels_when_it_starts() {
    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let identity = {
        let client = client_of(&relay).await.expect("the client connects");
        let first = |c: u16| client.made(c, 5, "notes.md", "a small text").to_wire();
        assert_eq!(
            client
                .push(vec![first(1), first(2), first(3)])
                .await
                .unwrap(),
            [PushAnswer::Stored, PushAnswer::Stored, PushAnswer::Stored]
        );
        client.identity.clone()
    };
    assert_eq!(holds(&relay).0, 3 * SMALL);

    // The operator brings the cap down to what two of the three take.
    relay.stop();
    relay.max_storage_bytes(2 * SMALL);
    relay.start();
    wait_for("relay healthy again", &[&relay], 30, || healthy(&relay));
    wait_for("the relay is within its cap", &[&relay], 30, || {
        (holds(&relay).0 == 2 * SMALL).then_some(())
    });
    // The newest went, with its entry. The two it held before it stay.
    assert_eq!(held(&relay, 3), None);
    assert!(held(&relay, 1).is_some() && held(&relay, 2).is_some());

    // At its cap it takes no new channel, and still a newer revision.
    let client = client_as(identity, &relay)
        .await
        .expect("the client connects again");
    assert_eq!(
        client
            .push(vec![
                client.made(3, 5, "notes.md", "a small text").to_wire(),
                client.made(1, 6, "notes.md", "a newer text").to_wire(),
            ])
            .await
            .unwrap(),
        [
            PushAnswer::Refused(EntryRefused::NoRoom),
            PushAnswer::Stored
        ]
    );
    assert_eq!(holds(&relay).0, 2 * SMALL);
}

/// A relay drops the channels from their secrets that nobody has used
/// for 90 days: when it starts, and each hour after. One that was used
/// 89 days ago stays. A channel that went is taken again as a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_drops_what_nobody_has_used_for_90_days() {
    const DAY: i64 = 24 * 60 * 60;
    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let identity = {
        let client = client_of(&relay).await.expect("the client connects");
        let first = |c: u16| client.made(c, 5, "notes.md", "a small text").to_wire();
        assert_eq!(
            client.push(vec![first(1), first(2)]).await.unwrap(),
            [PushAnswer::Stored, PushAnswer::Stored]
        );
        client.identity.clone()
    };
    let before = held(&relay, 1).expect("the relay holds the first channel");

    // While the relay is stopped, time goes by for what it holds: the
    // first channel was last used 91 days ago, and the second 89.
    relay.stop();
    {
        let db = rusqlite::Connection::open(relay.data_dir().join("cordelia.db")).unwrap();
        for (c, days) in [(1, 91), (2, 89)] {
            let changed = db
                .execute(
                    "UPDATE relay_channels SET used_at = used_at - ?1 WHERE channel_id = ?2",
                    rusqlite::params![days * DAY, channel(c).as_slice()],
                )
                .unwrap();
            assert_eq!(changed, 1, "{c}");
        }
    }
    relay.start();
    wait_for("relay healthy again", &[&relay], 30, || healthy(&relay));
    wait_for("the unused channel goes", &[&relay], 30, || {
        held(&relay, 1).is_none().then_some(())
    });
    assert!(held(&relay, 2).is_some(), "a channel used 89 days ago went");
    assert_eq!(holds(&relay).0, SMALL);

    // Its entries went with it: whoever holds its key is handed nothing.
    let client = client_as(identity, &relay)
        .await
        .expect("the client connects again");
    assert!(!client.prove(1).await);
    assert!(client.pull(1, NO_MARK, 0).await.entries.is_empty());
    // Taken again, it is another holding: under another mark, and new.
    assert_eq!(
        client
            .push(vec![
                client.made(1, 5, "notes.md", "a small text").to_wire()
            ])
            .await
            .unwrap(),
        [PushAnswer::Stored]
    );
    let again = held(&relay, 1).expect("the relay holds it again");
    assert_ne!(again.mark, before.mark);
    assert!(again.held_since >= before.held_since);
    // The connection proved it while it was not held, and is handed it
    // now, from the start: the place it kept was in the other holding.
    let page = client.pull(1, before.mark, 1).await;
    assert_eq!(
        (page.entries.len(), page.next, page.mark),
        (1, 1, again.mark)
    );
}

/// A stand-in for a relay, which a personal node dials: the test holds
/// the relay's end of the connection.
async fn stand_in_for_a_relay() -> (u16, tokio::sync::oneshot::Receiver<quinn::Connection>) {
    let identity = Arc::new(NodeIdentity::generate().unwrap());
    let endpoint = transport::create_endpoint(&identity, "127.0.0.1:0".parse().unwrap()).unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let manager = connection::ConnectionManager::new(
        identity,
        endpoint.clone(),
        vec![],
        vec!["relay".into()],
        port,
    );
    let ctx = manager.connect_context();
    let (connected, connection) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _manager = manager; // keeps the endpoint's context alive
        let mut connected = Some(connected);
        while let Some(incoming) = endpoint.accept().await {
            let Ok(outcome) = connection::inbound_accept(&ctx, incoming).await else {
                continue;
            };
            // Whatever the node opens is left unanswered.
            if let Some(connected) = connected.take() {
                let _ = connected.send(outcome.conn.clone());
            }
            let conn = outcome.conn;
            tokio::spawn(async move { while conn.accept_bi().await.is_ok() {} });
        }
    });
    (port, connection)
}

/// A personal node answers none of the streams of entries, from its own
/// relay either: a relay's rules count and drop what a store holds as
/// the relay's own, and a device's store is its own. It stores nothing of
/// what it is sent on them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_personal_node_answers_none_of_the_streams_of_entries() {
    let (port, connection) = stand_in_for_a_relay().await;
    let mut device = node("device", "personal", Some(port));
    device.start();
    wait_for("device healthy", &[&device], 30, || healthy(&device));
    wait_for("the device reaches its relay", &[&device], 60, || {
        has_hot_peer(&device)
    });
    let conn = tokio::time::timeout(Duration::from_secs(30), connection)
        .await
        .expect("the device did not connect")
        .unwrap();

    let author = NodeIdentity::generate().unwrap();
    let entry = made_by(&author, 1, 5, "notes.md", "what the file holds").to_wire();
    let session = transport::session_value(&conn).unwrap();
    let own_key = transport::peer_key(&conn).unwrap();
    let proof = proof::make(&secret(1), &session, &own_key).unwrap();
    let requests = [
        (
            Protocol::EntryShow,
            WireMessage::EntryShow(EntryShow {
                entry: entry.clone(),
            }),
        ),
        (
            Protocol::EntryPush,
            WireMessage::EntryPush(EntryPush {
                entries: vec![entry.clone().into()],
            }),
        ),
        (
            Protocol::ChannelProve,
            WireMessage::ChannelProve(ChannelProve {
                channel: channel(1),
                proof,
            }),
        ),
        (
            Protocol::EntryPull,
            WireMessage::EntryPull(EntryPull {
                channel: channel(1),
                mark: NO_MARK,
                after: 0,
                limit: 100,
            }),
        ),
        (
            Protocol::RelayEntries,
            WireMessage::RelayChannelsAsk(RelayChannelsAsk {
                after: [0; 32],
                limit: 1000,
            }),
        ),
        (
            Protocol::RelayEntries,
            WireMessage::RelayPull(RelayPull {
                channel: channel(1),
                mark: NO_MARK,
                after: 0,
                limit: 100,
            }),
        ),
        (
            Protocol::RelayEntries,
            WireMessage::RelayPush(RelayPush {
                entries: vec![RelayEntry {
                    entry: entry.clone(),
                    held_since: 1,
                    used_at: 1,
                }],
            }),
        ),
    ];
    for (protocol, request) in requests {
        let answer = ask_on(&conn, protocol, request).await;
        assert!(
            answer.is_err(),
            "a personal node answered on a stream of {protocol:?}: {answer:?}"
        );
    }

    // The control: on the same connection, the device answers its relay
    // on a stream that it does serve.
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    codec::write_protocol_byte(&mut send, Protocol::ItemSync)
        .await
        .unwrap();
    let page = cordelia_network::item_sync::send_sync_page(
        &mut send,
        &mut recv,
        "grp_550e8400-e29b-41d4-a716-446655440000",
        0,
        10,
    )
    .await
    .expect("the device answers its relay on a stream it serves");
    assert!(page.items.is_empty());

    // And it stored nothing of what it was sent: no entry, and no
    // channel held as a relay holds one.
    let db = store_of(&device);
    let (entries, channels): (i64, i64) = db
        .query_row(
            "SELECT (SELECT COUNT(*) FROM entries), (SELECT COUNT(*) FROM relay_channels)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((entries, channels), (0, 0));
}

/// The older kind of channel still syncs through a relay that carries
/// the new kind beside it, and that is at its cap for the new kind: two
/// devices pair through the relay, and what one publishes reaches the
/// other. The older kind's room is counted by its own items, so what the
/// relay holds of the new kind is no part of it, and neither kind is
/// refused or dropped for the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_older_kind_syncs_through_a_relay_that_is_full_of_the_new_kind() {
    // Room for three entries of the largest size, of each kind.
    let cap = 3 * LARGEST;
    let relay = relay_started(Some(cap));
    let client = client_of(&relay).await.expect("the client connects");

    // The new kind is filled to its cap, before the relay holds anything
    // of the older kind.
    let large: Vec<Vec<u8>> = (1..=4)
        .map(|c| largest_by(&client.identity, c, "notes.md").to_wire())
        .collect();
    assert_eq!(
        client.push(large.clone()).await.unwrap(),
        [
            PushAnswer::Stored,
            PushAnswer::Stored,
            PushAnswer::Stored,
            PushAnswer::Refused(EntryRefused::NoRoom)
        ]
    );
    assert_eq!(holds(&relay), (cap, 0));

    // Two devices, and the relay between them. Every channel of theirs
    // is new to the relay, and of the older kind.
    let mut a = node("a", "personal", Some(relay.p2p));
    let mut b = node("b", "personal", Some(relay.p2p));
    a.start();
    b.start();
    let all = [&relay, &a, &b];
    wait_for("a healthy", &all, 30, || healthy(&a));
    wait_for("b healthy", &all, 30, || healthy(&b));
    wait_for("a connected to the relay", &all, 60, || has_hot_peer(&a));
    wait_for("b connected to the relay", &all, 60, || has_hot_peer(&b));
    let personal = pair(&a, &b, "b", &all);

    // What one publishes reaches the other, through the relay.
    a.post(
        "/api/v1/channels/publish",
        serde_json::json!({ "channel": personal, "content": { "text": "hello from a" } }),
    );
    wait_for("b receives a's item", &all, 90, || {
        let listened = b.post(
            "/api/v1/channels/listen",
            serde_json::json!({ "channel": personal, "limit": 10 }),
        );
        listened["items"]
            .as_array()?
            .iter()
            .any(|i| i["content"]["text"] == "hello from a" && i["signature_valid"] == true)
            .then_some(())
    });

    // The relay holds items of the older kind now, counted by what they
    // are: far less than its cap, though its database holds a cap's
    // worth of entries beside them.
    let (new, older) = holds(&relay);
    assert_eq!(
        new, cap,
        "the new kind's room was touched by the older kind"
    );
    assert!(older > 0 && older < cap, "{older}");
    let stats: serde_json::Value = serde_json::from_str(&relay.cli(&["stats", "--json"])).unwrap();
    assert_eq!(stats["storage_used_bytes"], older, "{stats}");
    assert!(stats["database_bytes"].as_u64().unwrap() > cap, "{stats}");

    // The new kind is as it was: its three channels are held, each with
    // its entry, and the fourth still finds no room.
    for c in 1..=3 {
        assert!(client.prove(c).await, "{c}");
        let page = client.pull(c, NO_MARK, 0).await;
        assert_eq!(page.entries.len(), 1, "{c}");
        assert_eq!(page.entries[0].to_vec(), large[c as usize - 1]);
    }
    assert_eq!(
        client.push(vec![large[3].clone()]).await.unwrap(),
        [PushAnswer::Refused(EntryRefused::NoRoom)]
    );
    // And both kinds still take what they have room for.
    let newer = client.made(1, 9, "other.md", "a small text");
    assert_eq!(
        client.push(vec![newer.to_wire()]).await.unwrap(),
        [PushAnswer::Refused(EntryRefused::NoRoom)]
    );
    b.post(
        "/api/v1/channels/publish",
        serde_json::json!({ "channel": personal, "content": { "text": "and back" } }),
    );
    wait_for("a receives b's item", &all, 90, || {
        let listened = a.post(
            "/api/v1/channels/listen",
            serde_json::json!({ "channel": personal, "limit": 10 }),
        );
        listened["items"]
            .as_array()?
            .iter()
            .any(|i| i["content"]["text"] == "and back")
            .then_some(())
    });
    assert_eq!(holds(&relay).0, cap);
}
