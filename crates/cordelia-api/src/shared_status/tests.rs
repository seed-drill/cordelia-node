//! Tests of the status's `shared` object (decision 2026-10-10 §9),
//! in-process.

use super::*;
use crate::lists::Do;
use crate::shared::tests::{acts, anew, bob, holds, labels, member, out, stores};
use crate::state::SharedSaid;
use cordelia_crypto::acts::Subscription;

/// The relay of the channels of `crate::lists::tests::filing`, known by its
/// key.
const AT: [u8; 32] = [3; 32];

fn relays() -> Vec<OwnRelay> {
    vec![OwnRelay {
        name: "relay.example.org:9474".into(),
        key: AT,
    }]
}

/// The object on device `n` of `s` at `now`, with the relay connected and
/// `said` as what the shared pass said.
fn object(s: &crate::several::Several, n: usize, said: &SharedSaid, now: i64) -> Option<Value> {
    let own = relays();
    let beside = Beside {
        own_relays: &own,
        connected: &[AT],
        said,
    };
    status_of(&s[n].conn, &s[n].identity, &beside, now).unwrap()
}

/// The object says each channel held, with its keys, labels, subscriptions,
/// relays by the configuration's address and what the shared pass said;
/// a key's six words and its whole key, never another person's text.
#[test]
fn the_shared_object_says_each_channel_held() {
    let s = bob(2);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let carol = member(1);
    let dave = member(2);
    for member in [&carol, &dave] {
        stores(&s, 0, &anew(member, &channel, 1), now);
    }
    labels(&s, 0, &carol.public_key(), Some("carol"), now);
    acts(
        &s,
        0,
        Do::Subscribe(Subscription {
            channel: channel.id,
            agent: "github.com/owner/repo".into(),
            subscribed: true,
        }),
        now,
    );
    let mut said = SharedSaid::default();
    said.not_stored.insert(channel.id, 3);
    said.refused_at.insert((channel.id, AT), 2);
    let shared = object(&s, 0, &said, now + 1).unwrap();
    let one = &shared["channels"][0];
    assert_eq!(one["id"], hex::encode(channel.id), "{shared}");
    assert_eq!(one["name"], "review");
    assert_eq!(one["words"], channel_words(&channel.id));
    assert_eq!(
        (one["keys"].as_u64(), one["labelled"].as_u64()),
        (Some(2), Some(1))
    );
    assert_eq!(one["subscribed"], json!(["github.com/owner/repo"]));
    assert_eq!(one["not_stored"], 3);
    assert_eq!(one["refused_at_a_relay"], 2);
    assert_eq!(one["reached"], true);
    assert_eq!(
        one["relays"],
        json!([{
            "relay": "relay.example.org:9474",
            "words": fingerprint::shown(&AT),
            "connected": true,
            "not_reached": null,
        }])
    );
    assert_eq!(one["also_a_name"], false);
    assert_eq!(shared["removed_device_holds"], json!([]));
    assert_eq!(shared["acts_of_removed_devices"], json!([]));
    // A relay with no room for the channel's proof says so; one the
    // configuration does not know by its key is not the device's own.
    said.no_proof_room.insert((channel.id, AT));
    let shared = object(&s, 0, &said, now + 1).unwrap();
    assert_eq!(
        shared["channels"][0]["relays"][0]["not_reached"],
        "no_proof_room"
    );
    let none: Vec<OwnRelay> = Vec::new();
    let beside = Beside {
        own_relays: &none,
        connected: &[],
        said: &said,
    };
    let unreached = status_of(&s[0].conn, &s[0].identity, &beside, now + 1)
        .unwrap()
        .unwrap();
    let one = &unreached["channels"][0];
    assert_eq!(one["reached"], false);
    assert_eq!(one["relays"][0]["relay"], Value::Null);
    assert_eq!(one["relays"][0]["not_reached"], "not_own");
    assert_eq!(one["relays"][0]["connected"], false);
}

/// The object is absent on a device that does not stand applied (§9).
#[test]
fn the_shared_object_is_absent_where_the_device_does_not_stand_applied() {
    let mut s = bob(2);
    let now = s.now + 10;
    holds(&s, 0, 7, "review", now);
    assert!(object(&s, 1, &SharedSaid::default(), now).is_some());
    // The desktop removes the laptop: the laptop stops.
    s.meet(&[0, 1]);
    s.change(1, &[1], &[0]);
    s.pass(1, 0);
    assert!(object(&s, 0, &SharedSaid::default(), s.now).is_none());
}

/// A removed device that held a shared channel, which the person has not
/// made anew (decision 2026-10-10 §3.5, §9; decision 2026-10-24, rule 25):
/// the device that applies the removal and does not make it says the
/// channel under `removed_device_holds`, since when it applied it, and
/// the removed device by its label; a drop ends it. This is the fact the
/// level reads (`indicator::shared`).
#[test]
fn a_channel_not_yet_clean_is_said_as_held_by_a_removed_device() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    s.change(0, &[0, 1], &[2]);
    s.pass(0, 1);
    let now = s.now + 20;
    let shared = object(&s, 1, &SharedSaid::default(), now).unwrap();
    let holds_it = shared["removed_device_holds"].as_array().unwrap();
    assert_eq!(holds_it.len(), 1, "{shared}");
    assert_eq!(holds_it[0]["channels"], json!(["review"]));
    let device = holds_it[0]["device"].as_str().unwrap();
    assert!(device.contains(&fingerprint::shown(&s.key(2))), "{device}");
    let since = chrono::DateTime::parse_from_rfc3339(holds_it[0]["since"].as_str().unwrap())
        .unwrap()
        .timestamp();
    assert!(since <= now, "{since} {now}");
    // Dropped, the removed device holds nothing the person holds.
    acts(&s, 1, Do::Drop(channel.id), now);
    let shared = object(&s, 1, &SharedSaid::default(), now).unwrap();
    assert_eq!(shared["removed_device_holds"], json!([]), "{shared}");
    assert_eq!(shared["channels"], json!([]));
}
