//! The published test vectors of the change entry's layout with its
//! lineage (decision 2026-10-24 rule 13, unit test 14), in
//! `docs/reference/change-entry-test-vectors.json`, and the tests that hold
//! the code to them.
//!
//! The file pins the three sizes of the layout and where each place is,
//! the layout of the version before (0.2.0-alpha.16), the mark, and the
//! lineage of the two statements of `step4-test-vectors.json`, byte by
//! byte. Those are made from fixed inputs, and a change here that changes
//! one fails the test until the file is written again, on purpose:
//!
//! ```text
//! CORDELIA_WRITE_VECTORS=1 cargo test -p cordelia-crypto change_entry_vectors
//! ```
//!
//! Beside them are two whole entries of the second statement, one in each
//! layout. Their parts are sealed with random nonces and ephemeral keys,
//! so they are not made again when the file is read: they are kept as
//! published, and opened, by this version's code and by the rules of the
//! version before, to what the file says. They are made again only when
//! the file is written.

use std::sync::OnceLock;

use serde_json::{Value, json};

use cordelia_core::protocol::{
    CHANGE_ENTRY_BYTES, CHANGE_ENTRY_DEVICES_PART_BYTES, CHANGE_ENTRY_LINEAGE_BYTES,
    CHANGE_ENTRY_PHRASE_PART_BEFORE_BYTES, CHANGE_ENTRY_PHRASE_PART_BYTES, LABEL_CHANGE_LINEAGE,
    LINEAGE_HASH_BYTES, LINEAGE_MARK_BYTES, MAX_LINEAGE_BYTES,
};

use crate::change_entry::{self, DeviceSecret, ForPhrase, Layout, Lineage, before, lineage_mark};
use crate::derive;
use crate::entry::CheckedEntry;
use crate::identity::NodeIdentity;
use crate::phrase::Phrase;
use crate::statement::{Device, SignedStatement, Statement};
use crate::vectors::{WORDS, as_written, counting, differences};

/// Where the vectors are published, from this crate.
const PUBLISHED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/reference/change-entry-test-vectors.json"
);

/// When the changes of the vectors were made, by their maker's clock: 1
/// October 2026, 00:00:00 UTC.
const MADE_AT: [u64; 2] = [1_790_812_800, 1_790_899_200];

/// The inputs of `step4-test-vectors.json`: its phrase, its two devices,
/// and its two statements with their secrets.
struct Inputs {
    phrase: Phrase,
    desktop: NodeIdentity,
    laptop: NodeIdentity,
    statements: [SignedStatement; 2],
    secrets: [[u8; 32]; 2],
}

fn inputs() -> Inputs {
    let phrase = Phrase::parse(WORDS).unwrap();
    let desktop = NodeIdentity::from_seed(counting(0x60)).unwrap();
    let laptop = NodeIdentity::from_seed(counting(0x80)).unwrap();
    let gone = NodeIdentity::from_seed(counting(0xe0)).unwrap();
    let secrets = [counting(0xa0), counting(0xc0)];
    let phrase_key = phrase.public_key().unwrap();
    let key = phrase.signing_key().unwrap();
    let first = Statement::first(
        Device::new(desktop.public_key(), "desktop").unwrap(),
        &secrets[0],
        phrase_key,
    )
    .unwrap();
    let second = first
        .next(
            desktop.public_key(),
            &secrets[1],
            vec![
                Device::new(desktop.public_key(), "desktop").unwrap(),
                Device::new(laptop.public_key(), "laptop").unwrap(),
            ],
            &[gone.public_key()],
        )
        .unwrap();
    Inputs {
        statements: [first.sign(&key).unwrap(), second.sign(&key).unwrap()],
        phrase,
        desktop,
        laptop,
        secrets,
    }
}

/// What the part for the phrase says in the entry of the second statement:
/// its secret, and the first's.
fn second_for_phrase(inputs: &Inputs) -> ForPhrase {
    ForPhrase::following(
        inputs.secrets[1],
        &[(1, &ForPhrase::first(inputs.secrets[0]))],
    )
}

/// A place in the content: where it begins, and how long it is.
fn place(offset: usize, bytes: usize) -> Value {
    json!({ "offset": offset, "bytes": bytes })
}

/// The lineage of one statement: its fields, and the bytes it opens its
/// region with, up to where the zeros begin.
fn lineage_vector(statement: &SignedStatement, made_at: u64) -> Value {
    let lineage = Lineage::of(&statement.statement, made_at).unwrap();
    let bytes = lineage.to_bytes().unwrap();
    let said = LINEAGE_MARK_BYTES + 8 + LINEAGE_HASH_BYTES + 2 + lineage.chain.len() * 8;
    assert!(bytes[said..].iter().all(|b| *b == 0));
    json!({
        "number": statement.statement.number,
        "statement_hash": hex::encode(statement.statement.hash().unwrap()),
        "made_at": made_at,
        "lineage_statement": hex::encode(lineage.statement),
        "lineage_chain": lineage.chain.iter().map(hex::encode).collect::<Vec<_>>(),
        "bytes": hex::encode(&bytes[..said]),
    })
}

/// Two whole entries of the second statement, made now: one in this
/// layout, one in the layout before.
fn made_entries(inputs: &Inputs) -> Value {
    let phrase = &inputs.phrase;
    let (statement_key, seal_key) = (
        *phrase.statement_key().unwrap(),
        *phrase.seal_key().unwrap(),
    );
    let said = second_for_phrase(inputs);
    let statement = &inputs.statements[1];
    let with =
        change_entry::build(statement, &said, &statement_key, &seal_key, MADE_AT[1]).unwrap();
    let made_before = before::build(statement, &said, &statement_key, &seal_key).unwrap();
    json!({
        "with_lineage": hex::encode(with),
        "before": hex::encode(made_before),
    })
}

/// The content of the published file, with `entries` as its whole
/// entries.
fn vectors(entries: Value) -> Value {
    let inputs = inputs();
    let lineages: Vec<Value> = inputs
        .statements
        .iter()
        .zip(MADE_AT)
        .map(|(statement, made_at)| lineage_vector(statement, made_at))
        .collect();
    json!({
        "about": "Test vectors for decision 2026-10-24, rule 13: the layout of a change \
                  entry with its lineage, and the layout of the version before \
                  (0.2.0-alpha.16). Bytes are in hex; offsets and sizes are in bytes of the \
                  entry's content. The inputs are those of step4-test-vectors.json: its \
                  phrase, its devices and its two statements. A lineage is its mark, the \
                  time (eight bytes, the higher first), the statement's hash cut to eight \
                  bytes, a count (two bytes) and the hash of each statement on its chain \
                  cut to eight bytes; then zeros to the end of its region. The two entries \
                  are of the second statement at revision 2, sealed under the phrase's \
                  statement key and seal key, and open to its secret for the desktop and \
                  the laptop. This file is written by \
                  crates/cordelia-crypto/src/change_entry_vectors.rs, and tests there check \
                  the code against it.",
        "layout": {
            "content_bytes": CHANGE_ENTRY_BYTES,
            "devices_part": place(0, CHANGE_ENTRY_DEVICES_PART_BYTES),
            "phrase_part": place(CHANGE_ENTRY_DEVICES_PART_BYTES, CHANGE_ENTRY_PHRASE_PART_BYTES),
            "lineage": place(
                CHANGE_ENTRY_DEVICES_PART_BYTES + CHANGE_ENTRY_PHRASE_PART_BYTES,
                CHANGE_ENTRY_LINEAGE_BYTES
            ),
            "lineage_at_its_bound_bytes": MAX_LINEAGE_BYTES,
            "phrase_part_at_its_bound_bytes": 12 + 16 + 32 + 2 + 8 * (8 + 32),
        },
        "layout_before": {
            "content_bytes": CHANGE_ENTRY_BYTES,
            "devices_part": place(0, CHANGE_ENTRY_DEVICES_PART_BYTES),
            "phrase_part": place(
                CHANGE_ENTRY_DEVICES_PART_BYTES,
                CHANGE_ENTRY_PHRASE_PART_BEFORE_BYTES
            ),
        },
        "label": String::from_utf8(LABEL_CHANGE_LINEAGE.to_vec()).unwrap(),
        "mark": hex::encode(lineage_mark()),
        "lineages": lineages,
        "entries": entries,
    })
}

/// The published file, read once for the tests here. It is written first,
/// with entries made afresh, where that was asked for.
fn published() -> &'static str {
    static READ: OnceLock<String> = OnceLock::new();
    READ.get_or_init(|| {
        if std::env::var_os("CORDELIA_WRITE_VECTORS").is_some() {
            let made = vectors(made_entries(&inputs()));
            std::fs::write(PUBLISHED, as_written(&made)).unwrap();
        }
        std::fs::read_to_string(PUBLISHED)
            .unwrap_or_else(|e| panic!("{PUBLISHED} cannot be read: {e}"))
    })
}

/// The entry of the phrase's channel at revision 2 that carries `content`,
/// as the phrase writes it.
fn carrying(phrase: &Phrase, content: Vec<u8>) -> CheckedEntry {
    let channel_key = derive::signing_key(&phrase.channel_secret().unwrap()).unwrap();
    let slot = change_entry::slot(&channel_key.public_key());
    crate::entry::signed(
        &channel_key,
        &phrase.signing_key().unwrap(),
        slot,
        2,
        false,
        content,
    )
    .check()
    .unwrap()
}

/// The code gives the published vectors, each of them, and the file is as
/// the helper writes it. Its whole entries are the file's own.
#[test]
fn the_code_gives_the_published_change_entry_vectors() {
    let read: Value = serde_json::from_str(published()).unwrap();
    let made = vectors(read["entries"].clone());
    let mut differ = Vec::new();
    differences("", &made, &read, &mut differ);
    assert!(
        differ.is_empty(),
        "the code no longer gives the published vectors at: {differ:?}"
    );
    assert_eq!(
        as_written(&made),
        published(),
        "the file is not as the helper writes it"
    );
}

/// The sizes the file pins, read from it: the part for the devices is
/// 28,672 bytes at the start in both layouts, the part for the phrase
/// 1,024 after it and the lineage the last 3,072, and the part for the
/// phrase of the layout before the last 4,096.
#[test]
fn the_published_layout_pins_the_three_sizes() {
    let file: Value = serde_json::from_str(published()).unwrap();
    let at = |place: &Value| {
        (
            place["offset"].as_u64().unwrap(),
            place["bytes"].as_u64().unwrap(),
        )
    };
    let layout = &file["layout"];
    assert_eq!(layout["content_bytes"], 32_768);
    assert_eq!(at(&layout["devices_part"]), (0, 28_672));
    assert_eq!(at(&layout["phrase_part"]), (28_672, 1024));
    assert_eq!(at(&layout["lineage"]), (29_696, 3072));
    assert_eq!(layout["lineage_at_its_bound_bytes"], 2074);
    assert_eq!(layout["phrase_part_at_its_bound_bytes"], 382);
    let before = &file["layout_before"];
    assert_eq!(at(&before["devices_part"]), (0, 28_672));
    assert_eq!(at(&before["phrase_part"]), (28_672, 4096));
    assert_eq!(
        file["mark"].as_str().unwrap(),
        hex::encode(&crate::sha256(b"cordelia v2 lineage")[..8])
    );
}

/// Each published lineage follows from its statement by another road than
/// the helper's: the mark, the time, the first 8 bytes of SHA-256 of the
/// statement's canonical form, a count and its chain's hashes.
#[test]
fn the_published_lineages_follow_from_their_statements() {
    let file: Value = serde_json::from_str(published()).unwrap();
    let inputs = inputs();
    let lineages = file["lineages"].as_array().unwrap();
    assert_eq!(lineages.len(), 2);
    for (vector, statement) in lineages.iter().zip(&inputs.statements) {
        let statement = &statement.statement;
        let form = statement.to_bytes().unwrap();
        let mut expected = crate::sha256(b"cordelia v2 lineage")[..8].to_vec();
        expected.extend_from_slice(&vector["made_at"].as_u64().unwrap().to_be_bytes());
        expected.extend_from_slice(&crate::sha256(&form)[..8]);
        expected.extend_from_slice(&(statement.chain.len() as u16).to_be_bytes());
        for link in &statement.chain {
            expected.extend_from_slice(&link.hash[..8]);
        }
        assert_eq!(hex::encode(&expected), vector["bytes"].as_str().unwrap());
    }
    // The second names the first on its chain.
    assert_eq!(
        lineages[1]["lineage_chain"][0].as_str().unwrap(),
        lineages[0]["lineage_statement"].as_str().unwrap()
    );
}

/// The published entries open as the file says: the one with a lineage by
/// this version and, for its part for the devices, by the rules of the
/// version before; the one of the layout before by both, its part for the
/// phrase at 4,096 bytes.
#[test]
fn the_published_entries_open_in_each_layout() {
    let file: Value = serde_json::from_str(published()).unwrap();
    let inputs = inputs();
    let phrase = &inputs.phrase;
    let phrase_key = phrase.public_key().unwrap();
    let channel = derive::channel_id(&phrase.channel_secret().unwrap()).unwrap();
    let statement_key = *phrase.statement_key().unwrap();
    let seal_key = *phrase.seal_key().unwrap();
    let content = |name: &str| hex::decode(file["entries"][name].as_str().unwrap()).unwrap();
    let said = second_for_phrase(&inputs);
    let statement = &inputs.statements[1];

    let with = content("with_lineage");
    let made_before = content("before");
    assert_eq!(change_entry::layout(&with), Ok(Layout::WithLineage));
    assert_eq!(change_entry::layout(&made_before), Ok(Layout::Before));
    // Its lineage is the published one, in the clear where the file says.
    let region = &with[29_696..];
    let published = hex::decode(file["lineages"][1]["bytes"].as_str().unwrap()).unwrap();
    assert_eq!(region[..published.len()], published[..]);
    assert!(region[published.len()..].iter().all(|b| *b == 0));
    assert_eq!(
        change_entry::lineage(&with).unwrap().unwrap(),
        Lineage::of(&statement.statement, MADE_AT[1]).unwrap()
    );

    for content in [with, made_before] {
        let entry = carrying(phrase, content);
        for device in [&inputs.desktop, &inputs.laptop] {
            let now = change_entry::open_for_device(
                &entry,
                &phrase_key,
                &channel,
                &statement_key,
                device,
            )
            .unwrap();
            let then =
                before::open_for_device(&entry, &phrase_key, &channel, &statement_key, device)
                    .unwrap();
            assert_eq!(now.statement, *statement);
            assert_eq!(now.secret, DeviceSecret::Opened(inputs.secrets[1]));
            assert_eq!(then, now);
        }
        assert_eq!(
            change_entry::open_for_phrase(&entry, &phrase_key, &channel, &seal_key),
            Ok(said.clone())
        );
        let of_the_version_before =
            before::open_for_phrase(&entry, &phrase_key, &channel, &seal_key);
        match change_entry::layout(&entry.content).unwrap() {
            Layout::Before => assert_eq!(of_the_version_before, Ok(said.clone())),
            Layout::WithLineage => assert_eq!(
                of_the_version_before,
                Err(change_entry::ChangeEntryError::DidNotOpen)
            ),
        }
    }
}
