//! The one place that builds an entry's chain (decision 2026-10-04 §2.3,
//! §7.3).
//!
//! A chain is what an entry says it was written after: a link for each
//! version it descends from, the newest first ([`crate::entry::Link`]).
//! Whoever writes an entry builds its chain from an entry it holds, whose
//! signature it has checked, so that a chain always says who signed each
//! version in it. There are three ways an entry comes to be written, and
//! each has its function here:
//!
//! - **Written over an entry** ([`written_over`]): that entry's link
//!   first, and then its chain.
//! - **Carried from an entry** ([`carried_from`]): the entry's chain as it
//!   is where the device that carries signed it, and otherwise as one
//!   written over it.
//! - **A merge of two versions** ([`merged`]): written over the one, with
//!   the other and what it descends from woven in.
//!
//! A chain holds 100 links at most, and each of the three cuts it there,
//! from the old end: what is older than the hundredth is not said. A link
//! may stand in a chain twice, and none is left out for standing there
//! already. A chain that could not be read is not copied: what is built
//! on it says nothing of what came before.

use cordelia_core::protocol::MAX_ENTRY_LINKS;

use crate::entry::{Link, Value};

/// The chain of an entry that is written over the entry which holds
/// `value`, was signed by the key `signer`, and says `chain`.
///
/// That entry's link comes first: the hash of its value, and its signer.
/// Then its chain, cut to 100 links from the old end. Where the entry
/// lacks its chain (`None`), nothing is copied: the result is the one
/// link.
pub fn written_over(value: &Value, signer: &[u8; 32], chain: Option<&[Link]>) -> Vec<Link> {
    let mut built = vec![Link::of(value, *signer)];
    built.extend_from_slice(chain.unwrap_or_default());
    built.truncate(MAX_ENTRY_LINKS);
    built
}

/// The chain of the entry that carries a version into another channel,
/// from the entry which holds `value`, was signed by the key `signer`, and
/// says `chain`. `own` is the key of the device that carries.
///
/// Where that device signed the entry itself, the carried entry has the
/// entry's chain as it is: it is the same word, said again. Where another
/// key signed it, the carried entry is this device's word that it held
/// that key's entry, and its chain is as one written over it
/// ([`written_over`]): that entry's link first, and then its chain.
///
/// An entry that lacks its chain is carried with none: it was known to
/// follow nothing, and still is.
pub fn carried_from(
    value: &Value,
    signer: &[u8; 32],
    chain: Option<&[Link]>,
    own: &[u8; 32],
) -> Vec<Link> {
    if signer != own {
        return written_over(value, signer, chain);
    }
    let mut built = chain.unwrap_or_default().to_vec();
    built.truncate(MAX_ENTRY_LINKS);
    built
}

/// The chain of an entry that merges two versions (decision 2026-10-04
/// §7.3): a merged index. It is written over the channel's version, which
/// holds `value`, was signed by `signer`, and says `chain`. The other
/// source is the version that the file held, given as a folder keeps it:
/// its link (`other`: the hash of its value, and its signer) and its
/// chain (`others_chain`).
///
/// - Written over the channel's version, as any entry: that version's
///   link first, and then its chain.
/// - **Where the other's hash is already in that chain, nothing is
///   added.** The channel's version descends from it, and every link
///   between the two stays between them.
/// - **Where it is not,** the two were written apart. The other's link
///   comes second, and after it the links of the two chains, one from
///   each in turn, the channel's first. A hash that stands in both chains
///   comes at the later of its two places: the link at the earlier place
///   is left out. So a version that both descend from stands after every
///   link of either chain that is newer than it, and whoever signed any
///   of those is asked about before a folder at that version is told that
///   the merge follows it.
///
/// The result is cut to 100 links from the old end. A chain that could
/// not be read (`None`) gives no links.
pub fn merged(
    value: &Value,
    signer: &[u8; 32],
    chain: Option<&[Link]>,
    other: &Link,
    others_chain: Option<&[Link]>,
) -> Vec<Link> {
    let over = Link::of(value, *signer);
    let ours = chain.unwrap_or_default();
    if over.hash == other.hash || ours.iter().any(|link| link.hash == other.hash) {
        return written_over(value, signer, chain);
    }
    let theirs = others_chain.unwrap_or_default();

    // One from each in turn, the channel's first, each with whether it is
    // the channel's.
    let mut in_turn = Vec::with_capacity(ours.len() + theirs.len());
    for place in 0..ours.len().max(theirs.len()) {
        in_turn.extend(ours.get(place).map(|link| (*link, true)));
        in_turn.extend(theirs.get(place).map(|link| (*link, false)));
    }

    let mut built = vec![over, *other];
    for (place, (link, is_ours)) in in_turn.iter().enumerate() {
        let stands_later_in_the_other = in_turn[place + 1..]
            .iter()
            .any(|(later, later_is_ours)| later.hash == link.hash && later_is_ours != is_ours);
        if !stands_later_in_the_other {
            built.push(*link);
        }
    }
    built.truncate(MAX_ENTRY_LINKS);
    built
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::testing::*;
    use crate::entry::{Entry, Inside, known_to_follow};

    fn text_of(said: &str) -> Value {
        Value::Text(said.to_string())
    }

    /// A chain of `links` links, each of another text, all signed by
    /// device `n`: `first` names the newest.
    fn chain_of(first: usize, links: usize, n: u8) -> Vec<Link> {
        (first..first + links)
            .map(|place| link(&format!("text {place}"), n))
            .collect()
    }

    /// Whether only the devices numbered so count.
    fn only(devices: &[u8]) -> impl Fn(&[u8; 16]) -> bool {
        let signers: Vec<[u8; 16]> = devices.iter().map(|n| signer(*n)).collect();
        move |by| signers.contains(by)
    }

    /// An entry may be made that says the chain, and opens to it.
    fn is_sealed_and_read(chain: &[Link]) {
        let inside = Inside {
            chain: Some(chain.to_vec()),
            ..text("a.md", "what the entry holds")
        };
        let entry = Entry::seal(&SECRET, &device(1), 7, &inside).unwrap();
        let opened = entry.check().unwrap().open(&SECRET).unwrap();
        assert_eq!(opened.chain.as_deref(), Some(chain));
    }

    // ── Written over an entry ────────────────────────────────────────

    #[test]
    fn an_entry_written_over_another_has_that_ones_link_and_then_its_chain() {
        let chain = [link("B", 2), link("A", 1)];
        let built = written_over(&text_of("C"), &key(3), Some(&chain));
        assert_eq!(built, [link("C", 3), link("B", 2), link("A", 1)]);
        is_sealed_and_read(&built);

        // Over a new name's entry, whose chain is empty: the one link.
        assert_eq!(
            written_over(&text_of("A"), &key(1), Some(&[])),
            [link("A", 1)]
        );
        // Over a delete, which a chain names by zeros.
        let built = written_over(&Value::Delete, &key(2), Some(&chain[1..]));
        assert_eq!(built, [Link::of(&Value::Delete, key(2)), link("A", 1)]);
        // Over bytes that are no text.
        let bytes = Value::Other(vec![0xff, 0x00]);
        assert_eq!(
            written_over(&bytes, &key(2), Some(&[])),
            [Link::of(&bytes, key(2))]
        );
    }

    /// A chain that cannot be read is not copied: the entry written over
    /// such a version has the one link, and is known to follow that
    /// version and nothing before it.
    #[test]
    fn a_chain_that_cannot_be_read_is_not_copied() {
        let built = written_over(&text_of("C"), &key(3), None);
        assert_eq!(built, [link("C", 3)]);
        assert!(known_to_follow(Some(&built), &named("C"), only(&[])));
        assert!(!known_to_follow(
            Some(&built),
            &named("B"),
            only(&[1, 2, 3])
        ));
    }

    /// A chain is cut to 100 links from the old end: over an entry that
    /// says 100, the oldest falls off. Over one that says 99, none does.
    #[test]
    fn a_chain_is_cut_to_a_hundred_links_from_the_old_end() {
        let hundred = chain_of(1, 100, 1);
        let built = written_over(&text_of("the newest"), &key(2), Some(&hundred));
        assert_eq!(built.len(), 100);
        assert_eq!(built[0], link("the newest", 2));
        assert_eq!(built[1..], hundred[..99]);
        assert!(!built.contains(&hundred[99]));
        is_sealed_and_read(&built);

        let built = written_over(&text_of("the newest"), &key(2), Some(&hundred[..99]));
        assert_eq!(built.len(), 100);
        assert_eq!(built[99], hundred[98]);

        // Whatever it is given, what it gives can be said by an entry.
        let long = chain_of(1, 250, 1);
        let built = written_over(&text_of("the newest"), &key(2), Some(&long));
        assert_eq!(built.len(), 100);
        assert_eq!(built[1..], long[..99]);
    }

    /// A file that goes A, B, A again: the entry written over the second A
    /// descends from A twice, and its chain says so. No link is left out
    /// for standing there already.
    #[test]
    fn a_link_that_stands_in_the_chain_already_is_put_first_all_the_same() {
        // One device wrote each. The second A's entry says B, then A.
        let of_the_second_a = written_over(&text_of("B"), &key(1), Some(&[link("A", 1)]));
        assert_eq!(of_the_second_a, [link("B", 1), link("A", 1)]);
        let of_c = written_over(&text_of("A"), &key(1), Some(&of_the_second_a));
        assert_eq!(of_c, [link("A", 1), link("B", 1), link("A", 1)]);
        is_sealed_and_read(&of_c);
        // A folder at A is answered by the newest link with that hash.
        assert!(known_to_follow(Some(&of_c), &named("A"), only(&[])));
        assert!(known_to_follow(Some(&of_c), &named("B"), only(&[1])));

        // Two deletes by one device.
        let a_delete = Link::of(&Value::Delete, key(1));
        let built = written_over(&Value::Delete, &key(1), Some(&[link("A", 1), a_delete]));
        assert_eq!(built, [a_delete, link("A", 1), a_delete]);
        is_sealed_and_read(&built);
    }

    // ── Carried from an entry ────────────────────────────────────────

    /// Where the device that carries signed the entry, the chain is as it
    /// was. Where another key signed it, that entry's link is put first.
    #[test]
    fn a_carried_chain_is_the_entrys_own_or_as_one_written_over_it() {
        let chain = [link("B", 2), link("A", 1)];
        let value = text_of("C");

        let own = carried_from(&value, &key(3), Some(&chain), &key(3));
        assert_eq!(own, chain);
        let anothers = carried_from(&value, &key(2), Some(&chain), &key(3));
        assert_eq!(anothers, [link("C", 2), link("B", 2), link("A", 1)]);
        assert_eq!(anothers, written_over(&value, &key(2), Some(&chain)));

        // A new name's entry: nothing, and the one link.
        assert_eq!(carried_from(&value, &key(3), Some(&[]), &key(3)), []);
        assert_eq!(
            carried_from(&value, &key(2), Some(&[]), &key(3)),
            [link("C", 2)]
        );

        // An entry that lacks its chain is carried with none: its own, and
        // another's behind its link.
        assert_eq!(carried_from(&value, &key(3), None, &key(3)), []);
        assert_eq!(carried_from(&value, &key(2), None, &key(3)), [link("C", 2)]);
    }

    #[test]
    fn a_carried_chain_is_cut_to_a_hundred_links() {
        let hundred = chain_of(1, 100, 1);
        let value = text_of("the newest");
        // Its own: all 100, as they were.
        assert_eq!(
            carried_from(&value, &key(3), Some(&hundred), &key(3)),
            hundred
        );
        // Whatever it is given, what it gives can be said by an entry: of
        // more than 100, the newest 100.
        let long = chain_of(1, 250, 1);
        assert_eq!(
            carried_from(&value, &key(3), Some(&long), &key(3)),
            long[..100]
        );
        // Another's: the link first, and the oldest falls off.
        let built = carried_from(&value, &key(2), Some(&hundred), &key(3));
        assert_eq!(built.len(), 100);
        assert_eq!(built[0], link("the newest", 2));
        assert_eq!(built[1..], hundred[..99]);
        is_sealed_and_read(&built);

        // A link that stands in the chain already stays where it stands.
        let again = [link("between", 1), link("the same", 2), link("first", 1)];
        let built = carried_from(&text_of("the same"), &key(2), Some(&again), &key(3));
        assert_eq!(
            built,
            [
                link("the same", 2),
                link("between", 1),
                link("the same", 2),
                link("first", 1)
            ]
        );
        is_sealed_and_read(&built);
    }

    // ── A merge ──────────────────────────────────────────────────────

    /// Where the version the file held is already in the chain of the
    /// channel's version, the merge is written over the channel's version
    /// and nothing is added: the channel's version descends from it.
    #[test]
    fn a_merge_adds_nothing_where_the_other_source_is_in_the_chain() {
        let value = text_of("the channel's");
        let chain = [link("C", 2), link("B", 1), link("A", 1)];
        let over = written_over(&value, &key(2), Some(&chain));

        // The file held B, which the channel's version was written after.
        let held = link("B", 1);
        let held_after = [link("A", 1)];
        assert_eq!(
            merged(&value, &key(2), Some(&chain), &held, Some(&held_after)),
            over
        );
        // Whoever signed the entry the folder took it from.
        let by_another = link("B", 9);
        assert_eq!(
            merged(&value, &key(2), Some(&chain), &by_another, None),
            over
        );
        // The oldest of them, and the channel's version itself.
        for held in [link("A", 1), link("the channel's", 3)] {
            assert_eq!(
                merged(&value, &key(2), Some(&chain), &held, Some(&[])),
                over
            );
        }
        // Every link between the two stays between them: a folder at B is
        // told that the merge follows it only where C's signer counts.
        assert!(known_to_follow(Some(&over), &named("B"), only(&[2])));
        assert!(!known_to_follow(Some(&over), &named("B"), only(&[1])));
    }

    /// Where the two were written apart, the other source's link comes
    /// second, and after it the links of the two chains, one from each in
    /// turn, the channel's first.
    #[test]
    fn a_merge_of_two_written_apart_lists_both_and_their_chains_in_turn() {
        let value = text_of("the channel's");
        let ours = [link("x1", 1), link("x2", 1), link("x3", 1)];
        let held = link("the file's", 2);
        let theirs = [link("y1", 2)];
        let built = merged(&value, &key(1), Some(&ours), &held, Some(&theirs));
        assert_eq!(
            built,
            [
                link("the channel's", 1),
                link("the file's", 2),
                link("x1", 1),
                link("y1", 2),
                link("x2", 1),
                link("x3", 1),
            ]
        );
        is_sealed_and_read(&built);

        // The longer chain is the other's.
        let built = merged(&value, &key(1), Some(&ours[..1]), &held, Some(&ours[1..]));
        assert_eq!(
            built,
            [
                link("the channel's", 1),
                link("the file's", 2),
                link("x1", 1),
                link("x2", 1),
                link("x3", 1),
            ]
        );
        // Two new files that met: neither says anything before it.
        assert_eq!(
            merged(&value, &key(1), Some(&[]), &held, Some(&[])),
            [link("the channel's", 1), link("the file's", 2)]
        );
        // A chain that cannot be read gives no links, whichever it is.
        assert_eq!(
            merged(&value, &key(1), None, &held, Some(&theirs)),
            [
                link("the channel's", 1),
                link("the file's", 2),
                link("y1", 2)
            ]
        );
        assert_eq!(
            merged(&value, &key(1), Some(&ours[..1]), &held, None),
            [
                link("the channel's", 1),
                link("the file's", 2),
                link("x1", 1)
            ]
        );
    }

    /// A merge lists both of its sources. A folder behind either keeps
    /// its text where the other source, or anything between, was signed
    /// by a key that does not count.
    #[test]
    fn a_folder_behind_either_source_of_a_merge_is_asked_about_the_other() {
        let value = text_of("the channel's");
        // Device 1 wrote the channel's version over x1, and device 9 the
        // version the file held, over y1.
        let built = merged(
            &value,
            &key(1),
            Some(&[link("x1", 1)]),
            &link("the file's", 9),
            Some(&[link("y1", 1)]),
        );
        let everyone = only(&[1, 9]);
        for said in ["the channel's", "the file's", "x1", "y1"] {
            assert!(
                known_to_follow(Some(&built), &named(said), &everyone),
                "{said}"
            );
        }
        // Where device 9 does not count: a folder at the channel's version
        // has nothing between, and every other has device 9's link above
        // it.
        let without_9 = only(&[1]);
        assert!(known_to_follow(
            Some(&built),
            &named("the channel's"),
            &without_9
        ));
        // A folder at the version the file held: the channel's version
        // stands above it, and its signer counts.
        assert!(known_to_follow(
            Some(&built),
            &named("the file's"),
            &without_9
        ));
        for said in ["x1", "y1"] {
            assert!(
                !known_to_follow(Some(&built), &named(said), &without_9),
                "{said}"
            );
        }
        // Where device 1 does not count, a folder behind the version the
        // file held keeps its text too.
        let without_1 = only(&[9]);
        for said in ["the file's", "x1", "y1"] {
            assert!(
                !known_to_follow(Some(&built), &named(said), &without_1),
                "{said}"
            );
        }
    }

    /// A hash that stands in both chains comes at the later of its two
    /// places, so that every link of either chain that is newer than it
    /// stands above it.
    #[test]
    fn a_hash_in_both_chains_of_a_merge_comes_at_the_later_of_its_two_places() {
        let value = text_of("the channel's");
        let held = link("the file's", 2);
        // Both descend from "common", and from "first" before it. The
        // channel's version is one version from it, and the file's three.
        let ours = [link("common", 1), link("first", 1)];
        let theirs = [
            link("y1", 2),
            link("y2", 9),
            link("common", 1),
            link("first", 1),
        ];
        let built = merged(&value, &key(1), Some(&ours), &held, Some(&theirs));
        assert_eq!(
            built,
            [
                link("the channel's", 1),
                link("the file's", 2),
                link("y1", 2),
                link("y2", 9),
                link("common", 1),
                link("first", 1),
            ]
        );
        // A folder at the common version is told that the merge follows it
        // only where every version of either branch above it counts:
        // device 9 signed one of the file's.
        assert!(known_to_follow(
            Some(&built),
            &named("common"),
            only(&[1, 2, 9])
        ));
        assert!(!known_to_follow(
            Some(&built),
            &named("common"),
            only(&[1, 2])
        ));

        // The other way round: the channel's is the longer branch.
        let built = merged(&value, &key(1), Some(&theirs), &held, Some(&ours));
        assert_eq!(
            built,
            [
                link("the channel's", 1),
                link("the file's", 2),
                link("y1", 2),
                link("y2", 9),
                link("common", 1),
                link("first", 1),
            ]
        );
        assert!(!known_to_follow(
            Some(&built),
            &named("common"),
            only(&[1, 2])
        ));

        // Where two keys signed the entries that the two were taken from,
        // the link at the later place stands, with its own signer.
        let theirs = [link("y1", 2), link("common", 3)];
        let built = merged(&value, &key(1), Some(&ours[..1]), &held, Some(&theirs));
        assert_eq!(
            built,
            [
                link("the channel's", 1),
                link("the file's", 2),
                link("y1", 2),
                link("common", 3),
            ]
        );

        // A link that stands twice in one chain, and in no other, stays
        // twice: it is the other chain's link that puts one out.
        let ours = [link("A", 1), link("B", 1), link("A", 1)];
        let theirs = [link("y1", 2)];
        let built = merged(&value, &key(1), Some(&ours), &held, Some(&theirs));
        assert_eq!(
            built,
            [
                link("the channel's", 1),
                link("the file's", 2),
                link("A", 1),
                link("y1", 2),
                link("B", 1),
                link("A", 1),
            ]
        );

        // A hash that stands twice in one chain, and once in the other:
        // each of its links is left out that has the other chain's link
        // with that hash further on.
        let ours = [link("A", 1), link("B", 1), link("A", 1)];
        let theirs = [link("A", 2)];
        let built = merged(&value, &key(1), Some(&ours), &held, Some(&theirs));
        assert_eq!(
            built,
            [
                link("the channel's", 1),
                link("the file's", 2),
                link("B", 1),
                link("A", 1),
            ]
        );
    }

    #[test]
    fn a_merged_chain_is_cut_to_a_hundred_links() {
        let value = text_of("the channel's");
        let held = link("the file's", 2);
        let ours = chain_of(1, 100, 1);
        let theirs = chain_of(1001, 100, 2);
        let built = merged(&value, &key(1), Some(&ours), &held, Some(&theirs));
        assert_eq!(built.len(), 100);
        assert_eq!(built[..2], [link("the channel's", 1), held]);
        // 49 from each, in turn.
        for place in 0..49 {
            assert_eq!(built[2 + 2 * place], ours[place], "{place}");
            assert_eq!(built[3 + 2 * place], theirs[place], "{place}");
        }
        is_sealed_and_read(&built);

        // Where nothing is added, it is cut as an entry written over the
        // channel's version is.
        let in_the_chain = ours[99];
        let built = merged(&value, &key(1), Some(&ours), &in_the_chain, None);
        assert_eq!(built, written_over(&value, &key(1), Some(&ours)));
        assert_eq!(built.len(), 100);
    }
}
