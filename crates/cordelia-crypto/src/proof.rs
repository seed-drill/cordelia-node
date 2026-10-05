//! The proof that a connection holds a channel's key (decision 2026-10-04
//! §2.4, item 3).
//!
//! A relay hands a channel's entries only to a connection that has proved
//! it holds the channel's key. The proof is a signature by the channel's
//! signing key ([`crate::derive::signing_key`]), under a label of its own,
//! over three things:
//!
//! ```text
//! session's value   32: what both ends export from this one TLS session
//! prover's key      32: the node key of the end that proves
//! channel's ID      32
//! ```
//!
//! The session's value is the same at both ends of one connection and at
//! no other, so a proof that was made on one connection is no proof on
//! another, nor on a later one, and no clock is needed. It is given here
//! as bytes: where it is exported is the connection's business.
//!
//! Both ends export the same value, so the proof also says which end made
//! it: the node key that the prover holds for the connection. Whoever
//! checks a proof knows that key from the connection, and checks against
//! the key of the peer that sent the proof. So a proof that one end sent
//! is no proof when the other end sends it back.
//!
//! [`make`] needs the channel's secret. [`check`] needs the channel's ID
//! alone, as a relay has it, and looks nothing up.

use cordelia_core::protocol::{LABEL_CHANNEL_PROOF, SESSION_VALUE_BYTES};

use crate::CryptoError;
use crate::derive;
use crate::identity::{is_usable_public_key, verify_signature};

/// Prove, on the connection whose TLS session exports `session`, that this
/// end holds the key of the channel whose secret is `secret`. `prover` is
/// the node key that this end holds for the connection.
pub fn make(
    secret: &[u8; 32],
    session: &[u8; SESSION_VALUE_BYTES],
    prover: &[u8; 32],
) -> Result<[u8; 64], CryptoError> {
    let key = derive::signing_key(secret)?;
    Ok(key.sign(&signed(session, prover, &key.public_key())))
}

/// Whether `proof` shows that the other end of the connection whose TLS
/// session exports `session` holds the key of the channel whose ID is
/// `channel`. `prover` is the node key of the peer that sent the proof, as
/// the connection says it.
///
/// No, for a proof made for another channel, for one made over another
/// session's value, and for one that another node made: this end's own
/// proof, sent back to it, among them. No as well where the channel's ID
/// is not a usable public key: under a point of small order anyone can
/// make a signature that is accepted.
pub fn check(
    channel: &[u8; 32],
    session: &[u8; SESSION_VALUE_BYTES],
    prover: &[u8; 32],
    proof: &[u8; 64],
) -> bool {
    is_usable_public_key(channel)
        && verify_signature(channel, &signed(session, prover, channel), proof)
}

/// What the channel's signing key signs: the proof's label, the session's
/// value, the prover's node key, and the channel's ID.
fn signed(session: &[u8; SESSION_VALUE_BYTES], prover: &[u8; 32], channel: &[u8; 32]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(LABEL_CHANNEL_PROOF.len() + SESSION_VALUE_BYTES + 64);
    signed.extend_from_slice(LABEL_CHANNEL_PROOF);
    signed.extend_from_slice(session);
    signed.extend_from_slice(prover);
    signed.extend_from_slice(channel);
    signed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::testing::*;
    use cordelia_core::protocol::{LABEL_ENTRY_AUTHOR, LABEL_ENTRY_CHANNEL};

    const SESSION: [u8; 32] = [0x51; 32];
    const OTHER_SESSION: [u8; 32] = [0x52; 32];

    fn channel() -> [u8; 32] {
        derive::channel_id(&SECRET).unwrap()
    }

    fn other_channel() -> [u8; 32] {
        derive::channel_id(&OTHER_SECRET).unwrap()
    }

    /// The node key of the end that proves: device 7's.
    fn prover() -> [u8; 32] {
        key(7)
    }

    /// The node key of the other end of the connection: device 8's.
    fn other_end() -> [u8; 32] {
        key(8)
    }

    #[test]
    fn a_proof_is_made_from_the_secret_and_checked_from_the_id_alone() {
        let proof = make(&SECRET, &SESSION, &prover()).unwrap();
        assert!(check(&channel(), &SESSION, &prover(), &proof));
        // Another channel's, on the same connection, by the same end.
        let others = make(&OTHER_SECRET, &SESSION, &prover()).unwrap();
        assert!(check(&other_channel(), &SESSION, &prover(), &others));
        assert_ne!(proof, others);
    }

    /// What is signed, spelled here as it is published: a change to the
    /// label, or to what is signed under it, fails here.
    #[test]
    fn a_proof_is_under_its_own_label_over_the_session_the_prover_and_the_channel() {
        let proof = make(&SECRET, &SESSION, &prover()).unwrap();
        let mut form = b"cordelia v2 proof".to_vec();
        form.extend_from_slice(&SESSION);
        form.extend_from_slice(&prover());
        form.extend_from_slice(&channel());
        assert_eq!(form.len(), 17 + 32 + 32 + 32);
        assert!(verify_signature(&channel(), &form, &proof));
        assert_eq!(signed(&SESSION, &prover(), &channel()), form);

        // It is the channel's signing key that signs, and no other key
        // that comes from the secret.
        assert_eq!(proof, channel_key().sign(&form));

        // Not over the three alone, nor with them in another order, nor
        // with any one of them left out.
        let label = &b"cordelia v2 proof"[..];
        let (session, by, of) = (&SESSION[..], &prover()[..], &channel()[..]);
        for other in [
            [session, by, of].concat(),
            [label, by, session, of].concat(),
            [label, session, of, by].concat(),
            [label, of, by, session].concat(),
            [label, session, of].concat(),
            [label, by, of].concat(),
            [label, session, by].concat(),
        ] {
            assert!(!verify_signature(&channel(), &other, &proof));
        }
    }

    /// Both ends of a connection export the same value. A proof that one
    /// end sent is no proof when the other end sends it back: the end
    /// that holds no key proves nothing with it.
    #[test]
    fn a_proof_sent_back_by_the_other_end_does_not_hold() {
        // This end holds the channel's key, and proves it to the other.
        let proof = make(&SECRET, &SESSION, &prover()).unwrap();
        // The control: the other end checks it against the key of the
        // peer that sent it, and it holds.
        assert!(check(&channel(), &SESSION, &prover(), &proof));

        // The other end holds no key of the channel. It sends the same 64
        // bytes back on that connection, for that channel. This end checks
        // them against the key of the peer that sent them: no.
        assert!(!check(&channel(), &SESSION, &other_end(), &proof));

        // Nor can the other end make its own: it can name itself as the
        // prover, and still cannot sign as the channel.
        let by_its_node_key = device(8).sign(&signed(&SESSION, &other_end(), &channel()));
        assert!(!check(&channel(), &SESSION, &other_end(), &by_its_node_key));
    }

    #[test]
    fn a_proof_made_for_another_prover_does_not_hold() {
        // A node that holds the key made it for itself. A third node that
        // came by the 64 bytes sends them as its own.
        let proof = make(&SECRET, &SESSION, &prover()).unwrap();
        for another in [other_end(), key(9), channel(), SESSION, [0; 32]] {
            assert!(!check(&channel(), &SESSION, &another, &proof));
        }
        // A prover's key that differs by one bit, at either end.
        for place in [0, 31] {
            let mut another = prover();
            another[place] ^= 1;
            assert!(!check(&channel(), &SESSION, &another, &proof), "{place}");
        }
        // The control: each prover's own proof holds for it, and the two
        // are two.
        let others = make(&SECRET, &SESSION, &other_end()).unwrap();
        assert!(check(&channel(), &SESSION, &other_end(), &others));
        assert!(!check(&channel(), &SESSION, &prover(), &others));
        assert_ne!(proof, others);
    }

    #[test]
    fn a_proof_for_another_channel_is_refused() {
        // The holder of another channel's key proves that one, and shows
        // the proof for this channel.
        let others = make(&OTHER_SECRET, &SESSION, &prover()).unwrap();
        assert!(!check(&channel(), &SESSION, &prover(), &others));
        // And this channel's proof is none for the other.
        let proof = make(&SECRET, &SESSION, &prover()).unwrap();
        assert!(!check(&other_channel(), &SESSION, &prover(), &proof));

        // A key that holds the other channel signs what this channel's
        // proof would be: the channel's ID is in what is signed, and the
        // signature is still another key's.
        let other_key = derive::signing_key(&OTHER_SECRET).unwrap();
        let forged = other_key.sign(&signed(&SESSION, &prover(), &channel()));
        assert!(!check(&channel(), &SESSION, &prover(), &forged));
        // And a signature by this channel's key over the other's ID is no
        // proof for this one: the ID that is checked is the one signed.
        let for_other = channel_key().sign(&signed(&SESSION, &prover(), &other_channel()));
        assert!(!check(&channel(), &SESSION, &prover(), &for_other));
        assert!(!check(&other_channel(), &SESSION, &prover(), &for_other));
    }

    #[test]
    fn a_proof_made_over_another_sessions_value_is_refused() {
        let proof = make(&SECRET, &SESSION, &prover()).unwrap();
        // Replayed on another connection, or on a later one.
        assert!(!check(&channel(), &OTHER_SESSION, &prover(), &proof));
        // A value that differs by one bit, at either end.
        for place in [0, 31] {
            let mut session = SESSION;
            session[place] ^= 1;
            assert!(!check(&channel(), &session, &prover(), &proof), "{place}");
        }
        // The control: made over that session's value, it holds there and
        // not here.
        let there = make(&SECRET, &OTHER_SESSION, &prover()).unwrap();
        assert!(check(&channel(), &OTHER_SESSION, &prover(), &there));
        assert!(!check(&channel(), &SESSION, &prover(), &there));
    }

    #[test]
    fn a_proof_that_is_missing_or_changed_is_refused() {
        let proof = make(&SECRET, &SESSION, &prover()).unwrap();
        assert!(!check(&channel(), &SESSION, &prover(), &[0; 64]));
        for place in [0, 31, 32, 63] {
            let mut changed = proof;
            changed[place] ^= 1;
            assert!(!check(&channel(), &SESSION, &prover(), &changed), "{place}");
        }
    }

    /// Whoever holds an entry of the channel holds two signatures over
    /// it, one of them the channel's. Neither is a proof, and a proof is
    /// neither: a device that holds only what a relay holds proves
    /// nothing.
    #[test]
    fn an_entrys_signature_is_no_proof_and_a_proof_signs_no_entry() {
        let entry = entry(1, 5, &text("notes.md", "what the file holds"));
        assert_eq!(entry.channel, channel());
        for session in [SESSION, entry.slot, entry.author, entry.id()] {
            for by in [prover(), entry.author, entry.slot] {
                assert!(!check(&channel(), &session, &by, &entry.channel_signature));
                assert!(!check(&channel(), &session, &by, &entry.author_signature));
            }
        }

        // The channel's key signs the same three things under each of an
        // entry's labels, and under none: no proof.
        let three = [&SESSION[..], &prover()[..], &channel()[..]].concat();
        for label in [LABEL_ENTRY_CHANNEL, LABEL_ENTRY_AUTHOR, b""] {
            let signature = channel_key().sign(&[label, three.as_slice()].concat());
            assert!(!check(&channel(), &SESSION, &prover(), &signature));
        }

        // A device that writes in the channel signs with its own key: its
        // signature over what a proof signs is no proof, also where it is
        // the prover.
        let by_a_device = device(1).sign(&signed(&SESSION, &key(1), &channel()));
        assert!(!check(&channel(), &SESSION, &key(1), &by_a_device));

        // And a proof in the place of an entry's signature does not pass
        // the entry's check.
        let proof = make(&SECRET, &SESSION, &prover()).unwrap();
        let mut signed_by_a_proof = entry.clone().into_entry();
        signed_by_a_proof.channel_signature = proof;
        assert!(signed_by_a_proof.check().is_err());
    }

    /// Under a point of small order anyone can make a signature that is
    /// accepted, for any message. A channel with such an ID is proved by
    /// nobody.
    #[test]
    fn a_proof_for_an_id_that_anyone_can_sign_for_is_refused() {
        // The identity, and with it a signature that is the identity and
        // zero.
        let mut anyones = [0u8; 32];
        anyones[0] = 1;
        let mut signature = [0u8; 64];
        signature[0] = 1;
        // The control: it is accepted as a signature over what a proof
        // signs.
        assert!(verify_signature(
            &anyones,
            &signed(&SESSION, &prover(), &anyones),
            &signature
        ));
        assert!(!check(&anyones, &SESSION, &prover(), &signature));

        // Bytes that are no point at all.
        assert!(!check(&[0x02; 32], &SESSION, &prover(), &signature));
    }
}
