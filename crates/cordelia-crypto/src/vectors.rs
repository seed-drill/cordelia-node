//! The published test vectors of decision 2026-10-04, in
//! `docs/reference/step4-test-vectors.json`, and the test that holds the
//! code to them.
//!
//! [`vectors`] makes the file's content from fixed inputs: each derivation
//! from a channel's secret, the secret of each kind of channel, what a
//! recovery phrase gives, a commitment, and two statements with their
//! bytes, hashes and signatures. Another implementation checks itself
//! against the file, and a change here that changes a value fails the test
//! until the file is written again, on purpose:
//!
//! ```text
//! CORDELIA_WRITE_VECTORS=1 cargo test -p cordelia-crypto vectors
//! ```

use std::sync::OnceLock;

use serde_json::{Value, json};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::bech32::{encode_channel_id, encode_public_key};
use crate::derive;
use crate::identity::{NodeIdentity, x25519_from_ed25519_seed};
use crate::phrase::Phrase;
use crate::statement::{Device, SignedStatement, Statement, commitment};

/// Where the vectors are published, from this crate.
const PUBLISHED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/reference/step4-test-vectors.json"
);

/// The twelve words of the phrase in the vectors: one of the vectors of
/// BIP39's reference implementation.
const WORDS: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// 32 bytes that count up from `first`.
fn counting(first: u8) -> [u8; 32] {
    std::array::from_fn(|i| first + i as u8)
}

/// One statement, with everything another implementation would check: its
/// fields, its canonical form, its hash and its signature.
fn statement(signed: &SignedStatement, secret: &[u8; 32]) -> Value {
    let statement = &signed.statement;
    let chain: Vec<Value> = statement
        .chain
        .iter()
        .map(|link| json!({ "number": link.number, "hash": hex::encode(link.hash) }))
        .collect();
    let devices: Vec<Value> = statement
        .devices
        .iter()
        .map(|device| json!({ "key": hex::encode(device.key), "label": device.label }))
        .collect();
    let removed: Vec<String> = statement.removed.iter().map(hex::encode).collect();
    json!({
        "number": statement.number,
        "maker": hex::encode(statement.maker),
        "chain": chain,
        "secret": hex::encode(secret),
        "commitment": hex::encode(statement.commitment),
        "devices": devices,
        "removed": removed,
        "phrase_key": hex::encode(statement.phrase_key),
        "bytes": hex::encode(statement.to_bytes().unwrap()),
        "hash": hex::encode(statement.hash().unwrap()),
        "signature": hex::encode(signed.signature),
    })
}

/// The content of the published file.
fn vectors() -> Value {
    let channel_secret = counting(0x00);
    let person_secret = counting(0x20);
    let lock_key = counting(0x40);
    let desktop = NodeIdentity::from_seed(counting(0x60)).unwrap();
    let laptop = NodeIdentity::from_seed(counting(0x80)).unwrap();
    let gone = NodeIdentity::from_seed(counting(0xe0)).unwrap();
    let (first_secret, second_secret) = (counting(0xa0), counting(0xc0));
    let phrase = Phrase::parse(WORDS).unwrap();

    // A channel from its secret.
    let channel_id = derive::channel_id(&channel_secret).unwrap();
    let channel = json!({
        "secret": hex::encode(channel_secret),
        "entry_key": hex::encode(derive::entry_key(&channel_secret).unwrap()),
        "slot_key": hex::encode(derive::slot_key(&channel_secret).unwrap()),
        "signing_key_seed": hex::encode(derive::signing_key(&channel_secret).unwrap().seed()),
        "id": hex::encode(channel_id),
        "id_text": encode_channel_id(&channel_id).unwrap(),
    });

    // The secret of each kind of channel.
    let own: Vec<Value> = ["~", "github.com/owner/repo"]
        .iter()
        .map(|name| {
            json!({
                "name": name,
                "secret": hex::encode(derive::own_secret(&person_secret, name).unwrap()),
            })
        })
        .collect();
    let (desktop_x25519, _) = x25519_from_ed25519_seed(desktop.seed());
    let (_, laptop_x25519) = x25519_from_ed25519_seed(laptop.seed());
    let shared = StaticSecret::from(desktop_x25519).diffie_hellman(&PublicKey::from(laptop_x25519));
    let pair = derive::pair_secret(&desktop, &laptop.public_key()).unwrap();
    assert_eq!(
        pair,
        derive::pair_secret(&laptop, &desktop.public_key()).unwrap()
    );
    let kinds = json!({
        "person_secret": hex::encode(person_secret),
        "personal": hex::encode(derive::personal_secret(&person_secret).unwrap()),
        "own": own,
        "pair": {
            "one_seed": hex::encode(desktop.seed()),
            "one_key": hex::encode(desktop.public_key()),
            "other_seed": hex::encode(laptop.seed()),
            "other_key": hex::encode(laptop.public_key()),
            "x25519": hex::encode(shared.as_bytes()),
            "secret": hex::encode(pair),
        },
        "locked": {
            "lock_key": hex::encode(lock_key),
            "name": "notes",
            "secret": hex::encode(
                derive::locked_secret(&person_secret, &lock_key, "notes").unwrap()
            ),
        },
    });

    // What the phrase gives.
    let phrase_key = phrase.public_key().unwrap();
    let phrase_channel = phrase.channel_secret().unwrap();
    let phrase_channel_id = derive::channel_id(&phrase_channel).unwrap();
    let from_the_phrase = json!({
        "words": WORDS,
        "bytes": hex::encode([0x7f_u8; 16]),
        "signing_key_seed": hex::encode(phrase.signing_key().unwrap().seed()),
        "public_key": hex::encode(phrase_key),
        "public_key_text": encode_public_key(&phrase_key).unwrap(),
        "channel_secret": hex::encode(phrase_channel),
        "channel_id": hex::encode(phrase_channel_id),
        "channel_id_text": encode_channel_id(&phrase_channel_id).unwrap(),
        "statement_key": hex::encode(phrase.statement_key().unwrap()),
        "seal_key": hex::encode(phrase.seal_key().unwrap()),
    });

    // Two statements: the first, and one made after it on the same device,
    // which lists a second device and removes a key.
    let key = phrase.signing_key().unwrap();
    let first = Statement::first(
        Device::new(desktop.public_key(), "desktop").unwrap(),
        &first_secret,
        phrase_key,
    )
    .unwrap();
    let second = first
        .next(
            desktop.public_key(),
            &second_secret,
            vec![
                Device::new(desktop.public_key(), "desktop").unwrap(),
                Device::new(laptop.public_key(), "laptop").unwrap(),
            ],
            &[gone.public_key()],
        )
        .unwrap();
    let statements = vec![
        statement(&first.sign(&key).unwrap(), &first_secret),
        statement(&second.sign(&key).unwrap(), &second_secret),
    ];

    json!({
        "about": "Test vectors for decision 2026-10-04: a channel from its secret, the secret \
                  of each kind of channel, the recovery phrase, and the statement. Bytes are in \
                  hex. Every derivation is HKDF-SHA256 with an empty salt, under the label that \
                  crates/cordelia-core/src/protocol.rs gives it. A seed is an Ed25519 seed. \
                  This file is written by crates/cordelia-crypto/src/vectors.rs, and a test \
                  there checks the code against it.",
        "channel": channel,
        "kinds": kinds,
        "phrase": from_the_phrase,
        "commitment": {
            "secret": hex::encode(first_secret),
            "commitment": hex::encode(commitment(&first_secret)),
        },
        "statements": statements,
    })
}

/// The paths at which two documents differ, for a failure that says where.
fn differences(path: &str, made: &Value, published: &Value, out: &mut Vec<String>) {
    match (made, published) {
        (Value::Object(made), Value::Object(published)) => {
            for name in made.keys().chain(published.keys()) {
                let at = format!("{path}/{name}");
                match (made.get(name), published.get(name)) {
                    (Some(made), Some(published)) => differences(&at, made, published, out),
                    _ if !out.contains(&at) => out.push(at),
                    _ => {}
                }
            }
        }
        (Value::Array(made), Value::Array(published)) if made.len() == published.len() => {
            for (i, (made, published)) in made.iter().zip(published).enumerate() {
                differences(&format!("{path}/{i}"), made, published, out);
            }
        }
        _ if made != published => out.push(path.to_string()),
        _ => {}
    }
}

/// The file as the helper writes it: its content, set out one value to a
/// line.
fn as_written(vectors: &Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(vectors).unwrap())
}

/// The published file, read once for the tests here. It is written first
/// where that was asked for.
fn published() -> &'static str {
    static READ: OnceLock<String> = OnceLock::new();
    READ.get_or_init(|| {
        if std::env::var_os("CORDELIA_WRITE_VECTORS").is_some() {
            std::fs::write(PUBLISHED, as_written(&vectors())).unwrap();
        }
        std::fs::read_to_string(PUBLISHED)
            .unwrap_or_else(|e| panic!("{PUBLISHED} cannot be read: {e}"))
    })
}

/// The code gives the published vectors, each of them, and the file is as
/// the helper writes it.
#[test]
fn the_code_gives_the_published_vectors() {
    let made = vectors();
    let published = published();
    let read: Value = serde_json::from_str(published).unwrap();

    let mut differ = Vec::new();
    differences("", &made, &read, &mut differ);
    assert!(
        differ.is_empty(),
        "the code no longer gives the published vectors at: {differ:?}"
    );
    assert_eq!(
        as_written(&made),
        published,
        "the file is not as the helper writes it"
    );
}

/// What the vectors say, held against the code by another road than the
/// helper's: each value read from the file, and worked out from the file's
/// own inputs.
#[test]
fn the_published_vectors_follow_from_their_own_inputs() {
    use crate::ecies::{hkdf_sha256, hkdf_sha256_of};
    use crate::identity::verify_signature;

    let file: Value = serde_json::from_str(published()).unwrap();
    let bytes = |value: &Value| hex::decode(value.as_str().unwrap()).unwrap();
    let key = |value: &Value| -> [u8; 32] { bytes(value).try_into().unwrap() };

    // A channel from its secret.
    let channel = &file["channel"];
    let secret = key(&channel["secret"]);
    let under = |label: &[u8]| hkdf_sha256(&secret, &[], label).unwrap();
    assert_eq!(key(&channel["entry_key"]), under(b"cordelia v2 entry"));
    assert_eq!(key(&channel["slot_key"]), under(b"cordelia v2 slot"));
    assert_eq!(
        key(&channel["signing_key_seed"]),
        under(b"cordelia v2 sign")
    );
    let signing = NodeIdentity::from_seed(key(&channel["signing_key_seed"])).unwrap();
    assert_eq!(key(&channel["id"]), signing.public_key());
    assert_eq!(
        crate::bech32::decode_channel_id(channel["id_text"].as_str().unwrap()).unwrap(),
        key(&channel["id"])
    );

    // The kinds.
    let kinds = &file["kinds"];
    let person = key(&kinds["person_secret"]);
    assert_eq!(
        key(&kinds["personal"]),
        hkdf_sha256(&person, &[], b"cordelia v2 personal").unwrap()
    );
    for own in kinds["own"].as_array().unwrap() {
        let name = own["name"].as_str().unwrap();
        let mut info = b"cordelia v2 own".to_vec();
        info.extend_from_slice(&(name.len() as u16).to_be_bytes());
        info.extend_from_slice(name.as_bytes());
        assert_eq!(
            key(&own["secret"]),
            hkdf_sha256(&person, &[], &info).unwrap()
        );
    }
    let pair = &kinds["pair"];
    let mut keys = [key(&pair["one_key"]), key(&pair["other_key"])];
    keys.sort_unstable();
    let mut info = b"cordelia v2 pair".to_vec();
    info.extend_from_slice(&keys[0]);
    info.extend_from_slice(&keys[1]);
    assert_eq!(
        key(&pair["secret"]),
        hkdf_sha256(&key(&pair["x25519"]), &[], &info).unwrap()
    );
    for (seed, public) in [("one_seed", "one_key"), ("other_seed", "other_key")] {
        let device = NodeIdentity::from_seed(key(&pair[seed])).unwrap();
        assert_eq!(device.public_key(), key(&pair[public]));
    }
    let locked = &kinds["locked"];
    let name = locked["name"].as_str().unwrap();
    let mut info = b"cordelia v2 locked".to_vec();
    info.extend_from_slice(&(name.len() as u16).to_be_bytes());
    info.extend_from_slice(name.as_bytes());
    let mut together = person.to_vec();
    together.extend_from_slice(&bytes(&locked["lock_key"]));
    assert_eq!(
        key(&locked["secret"]),
        hkdf_sha256_of(&together, &[], &info).unwrap()
    );

    // The phrase.
    let phrase = &file["phrase"];
    let typed = Phrase::parse(phrase["words"].as_str().unwrap()).unwrap();
    assert_eq!(
        typed.words().unwrap().as_str(),
        phrase["words"].as_str().unwrap()
    );
    let encoded = bytes(&phrase["bytes"]);
    assert_eq!(encoded.len(), 16);
    let under = |label: &[u8]| hkdf_sha256_of(&encoded, &[], label).unwrap();
    assert_eq!(
        key(&phrase["signing_key_seed"]),
        under(b"cordelia v2 phrase sign")
    );
    assert_eq!(
        key(&phrase["channel_secret"]),
        under(b"cordelia v2 recovery")
    );
    assert_eq!(
        key(&phrase["statement_key"]),
        under(b"cordelia v2 phrase statement")
    );
    assert_eq!(key(&phrase["seal_key"]), under(b"cordelia v2 phrase seal"));
    let phrase_key = key(&phrase["public_key"]);
    assert_eq!(
        NodeIdentity::from_seed(key(&phrase["signing_key_seed"]))
            .unwrap()
            .public_key(),
        phrase_key
    );
    assert_eq!(
        crate::bech32::decode_public_key(phrase["public_key_text"].as_str().unwrap()).unwrap(),
        phrase_key
    );
    assert_eq!(
        key(&phrase["channel_id"]),
        derive::channel_id(&key(&phrase["channel_secret"])).unwrap()
    );
    assert_eq!(
        crate::bech32::decode_channel_id(phrase["channel_id_text"].as_str().unwrap()).unwrap(),
        key(&phrase["channel_id"])
    );

    // The commitment.
    let mut hashed = b"cordelia v2 commitment".to_vec();
    hashed.extend_from_slice(&bytes(&file["commitment"]["secret"]));
    assert_eq!(
        key(&file["commitment"]["commitment"]),
        crate::sha256(&hashed)
    );

    // The statements: each read from its bytes, and its hash, commitment
    // and signature worked out from them.
    let statements = file["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 2);
    for (i, vector) in statements.iter().enumerate() {
        let form = bytes(&vector["bytes"]);
        let read = Statement::from_bytes(&form).unwrap();
        assert_eq!(read.to_bytes().unwrap(), form);
        assert_eq!(read.number, vector["number"].as_u64().unwrap());
        assert_eq!(read.number, i as u64 + 1);
        assert_eq!(read.maker, key(&vector["maker"]));
        assert_eq!(read.phrase_key, phrase_key);
        assert_eq!(read.commitment, key(&vector["commitment"]));
        assert!(read.commits_to(&key(&vector["secret"])));
        assert_eq!(
            bytes(&vector["hash"]),
            crate::sha256(&form)[..16],
            "statement {i}"
        );
        let devices = vector["devices"].as_array().unwrap();
        assert_eq!(read.devices.len(), devices.len());
        for (device, listed) in read.devices.iter().zip(devices) {
            assert_eq!(device.key, key(&listed["key"]));
            assert_eq!(device.label, listed["label"].as_str().unwrap());
        }
        let removed: Vec<[u8; 32]> = vector["removed"]
            .as_array()
            .unwrap()
            .iter()
            .map(key)
            .collect();
        assert_eq!(read.removed, removed);
        let chain = vector["chain"].as_array().unwrap();
        assert_eq!(read.chain.len(), chain.len());
        for (link, named) in read.chain.iter().zip(chain) {
            assert_eq!(link.number, named["number"].as_u64().unwrap());
            assert_eq!(link.hash.to_vec(), bytes(&named["hash"]));
        }

        let signature: [u8; 64] = bytes(&vector["signature"]).try_into().unwrap();
        let mut signed = b"cordelia v2 statement".to_vec();
        signed.extend_from_slice(&form);
        assert!(verify_signature(&phrase_key, &signed, &signature));
        let whole = SignedStatement {
            statement: read,
            signature,
        };
        assert_eq!(whole.verify(), Ok(()));
    }
    // The second names the first on its chain, by the first's own hash.
    assert_eq!(statements[1]["chain"][0]["hash"], statements[0]["hash"]);
    assert_eq!(statements[1]["chain"][0]["number"], 1);
}
