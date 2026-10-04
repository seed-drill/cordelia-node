//! ECIES envelope encryption for PSK distribution.
//!
//! Construction: X25519 DH -> HKDF-SHA256 -> AES-256-GCM
//! Envelope format: eph_pk[32] || iv[12] || ct[N] || tag[16] = (60 + N) bytes
//! For 32-byte PSK: 32 + 12 + 32 + 16 = 92 bytes
//!
//! Spec: seed-drill/specs/ecies-envelope-encryption.md §4

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{self, KeyType};
use ring::rand::{SecureRandom, SystemRandom};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::CryptoError;

const HKDF_INFO: &[u8] = b"cordelia-key-wrap-v1";
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// HKDF output length (AES-256 = 32 bytes).
struct WrapKeyLen;
impl KeyType for WrapKeyLen {
    fn len(&self) -> usize {
        32
    }
}

/// ECIES envelope: ephemeral X25519 public key + AES-256-GCM encrypted payload.
///
/// Binary format: eph_pk[32] || iv[12] || ciphertext[N] || auth_tag[16]
#[derive(Debug, Clone)]
pub struct EciesEnvelope {
    /// Ephemeral X25519 public key (32 bytes).
    pub ephemeral_pk: [u8; 32],
    /// AES-256-GCM initialisation vector (12 bytes).
    pub iv: [u8; IV_LEN],
    /// Encrypted ciphertext.
    pub ciphertext: Vec<u8>,
    /// AES-256-GCM authentication tag (16 bytes).
    pub auth_tag: [u8; TAG_LEN],
}

impl EciesEnvelope {
    /// Serialise to binary: eph_pk || iv || ciphertext || auth_tag
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + IV_LEN + self.ciphertext.len() + TAG_LEN);
        out.extend_from_slice(&self.ephemeral_pk);
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.auth_tag);
        out
    }

    /// Deserialise from binary. `plaintext_len` is the expected plaintext size
    /// (e.g. 32 for a PSK). Total expected: 32 + 12 + plaintext_len + 16.
    pub fn from_bytes(bytes: &[u8], plaintext_len: usize) -> Result<Self, CryptoError> {
        let expected = 32 + IV_LEN + plaintext_len + TAG_LEN;
        if bytes.len() != expected {
            return Err(CryptoError::EncryptionFailed(format!(
                "envelope size mismatch: expected {expected}, got {}",
                bytes.len()
            )));
        }

        let mut ephemeral_pk = [0u8; 32];
        ephemeral_pk.copy_from_slice(&bytes[0..32]);

        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&bytes[32..32 + IV_LEN]);

        let ciphertext = bytes[32 + IV_LEN..32 + IV_LEN + plaintext_len].to_vec();

        let mut auth_tag = [0u8; TAG_LEN];
        auth_tag.copy_from_slice(&bytes[32 + IV_LEN + plaintext_len..]);

        Ok(Self {
            ephemeral_pk,
            iv,
            ciphertext,
            auth_tag,
        })
    }

    /// Deserialise an envelope whose plaintext length is not known in
    /// advance (e.g. a sealed channel state): everything between the IV and
    /// the tag is ciphertext.
    pub fn from_bytes_any(bytes: &[u8]) -> Result<Self, CryptoError> {
        let overhead = 32 + IV_LEN + TAG_LEN;
        if bytes.len() <= overhead {
            return Err(CryptoError::DecryptionFailed);
        }
        Self::from_bytes(bytes, bytes.len() - overhead)
    }
}

/// Derive a 32-byte wrapping key from an X25519 shared secret via HKDF-SHA256.
///
/// Per RFC 5869 §2.2: empty salt is treated as 32 zero bytes.
pub fn hkdf_sha256(
    shared_secret: &[u8; 32],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32], CryptoError> {
    hkdf_sha256_of(shared_secret, salt, info)
}

/// [`hkdf_sha256`] from key material of any length: the 16 bytes that a
/// recovery phrase encodes, or two secrets together (decision 2026-10-04
/// §2.2, §5, §11).
pub fn hkdf_sha256_of(
    key_material: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let effective_salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };
    let hkdf_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, effective_salt);
    let prk = hkdf_salt.extract(key_material);
    let info_refs = [info];
    let okm_material = prk
        .expand(&info_refs, WrapKeyLen)
        .map_err(|_| CryptoError::KeyDerivationFailed("HKDF expand failed".into()))?;
    let mut okm = [0u8; 32];
    okm_material
        .fill(&mut okm)
        .map_err(|_| CryptoError::KeyDerivationFailed("HKDF fill failed".into()))?;
    Ok(okm)
}

/// Encrypt plaintext to a recipient's X25519 public key using ECIES.
///
/// Generates a fresh ephemeral X25519 keypair and random IV.
pub fn ecies_encrypt(
    recipient_pk: &[u8; 32],
    plaintext: &[u8],
) -> Result<EciesEnvelope, CryptoError> {
    ecies_encrypt_for(recipient_pk, plaintext, HKDF_INFO)
}

/// [`ecies_encrypt`] for one purpose: the wrapping key is derived under
/// `info`, which says what the envelope is for. An envelope sealed so
/// opens only for whoever asks for that purpose
/// ([`ecies_decrypt_for`]): it is no envelope for any other use of the
/// recipient's key, and what was sealed for another use is none for this
/// one.
///
/// [`ecies_encrypt`] seals under the general key-wrap info, as it always
/// has.
pub fn ecies_encrypt_for(
    recipient_pk: &[u8; 32],
    plaintext: &[u8],
    info: &[u8],
) -> Result<EciesEnvelope, CryptoError> {
    let rng = SystemRandom::new();
    let mut eph_sk = [0u8; 32];
    rng.fill(&mut eph_sk)
        .map_err(|_| CryptoError::EncryptionFailed("RNG failure".into()))?;
    let mut iv = [0u8; IV_LEN];
    rng.fill(&mut iv)
        .map_err(|_| CryptoError::EncryptionFailed("RNG failure".into()))?;
    ecies_seal_for(&eph_sk, &iv, recipient_pk, plaintext, info)
}

/// Seal with explicit ephemeral key and IV (deterministic, for test vectors).
#[cfg(test)]
fn ecies_seal(
    ephemeral_sk: &[u8; 32],
    iv: &[u8; IV_LEN],
    recipient_pk: &[u8; 32],
    plaintext: &[u8],
) -> Result<EciesEnvelope, CryptoError> {
    ecies_seal_for(ephemeral_sk, iv, recipient_pk, plaintext, HKDF_INFO)
}

/// Seal with an explicit ephemeral key and IV, under the wrapping key
/// that `info` gives.
fn ecies_seal_for(
    ephemeral_sk: &[u8; 32],
    iv: &[u8; IV_LEN],
    recipient_pk: &[u8; 32],
    plaintext: &[u8],
    info: &[u8],
) -> Result<EciesEnvelope, CryptoError> {
    let eph_secret = StaticSecret::from(*ephemeral_sk);
    let eph_public = PublicKey::from(&eph_secret);
    let recipient = PublicKey::from(*recipient_pk);

    let shared = eph_secret.diffie_hellman(&recipient);
    // A key of small order (all zero among them) gives the same secret to
    // everyone. Sealing under it would seal to nobody in particular.
    if !shared.was_contributory() {
        return Err(CryptoError::EncryptionFailed(
            "the recipient's key gives no secret of its own".into(),
        ));
    }

    let wrapping_key = hkdf_sha256(shared.as_bytes(), &[], info)?;

    let unbound = UnboundKey::new(&AES_256_GCM, &wrapping_key)
        .map_err(|_| CryptoError::EncryptionFailed("invalid wrapping key".into()))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(iv)
        .map_err(|_| CryptoError::EncryptionFailed("nonce error".into()))?;

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::EncryptionFailed("AES-GCM seal failed".into()))?;

    let tag_start = in_out.len() - TAG_LEN;
    let ciphertext = in_out[..tag_start].to_vec();
    let mut auth_tag = [0u8; TAG_LEN];
    auth_tag.copy_from_slice(&in_out[tag_start..]);

    Ok(EciesEnvelope {
        ephemeral_pk: *eph_public.as_bytes(),
        iv: *iv,
        ciphertext,
        auth_tag,
    })
}

/// Decrypt an ECIES envelope using the recipient's X25519 private key.
pub fn ecies_decrypt(
    recipient_sk: &[u8; 32],
    envelope: &EciesEnvelope,
) -> Result<Vec<u8>, CryptoError> {
    ecies_decrypt_for(recipient_sk, envelope, HKDF_INFO)
}

/// [`ecies_decrypt`] for one purpose: opens an envelope that was sealed
/// under `info` ([`ecies_encrypt_for`]), and no other.
pub fn ecies_decrypt_for(
    recipient_sk: &[u8; 32],
    envelope: &EciesEnvelope,
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let secret = StaticSecret::from(*recipient_sk);
    let eph_pk = PublicKey::from(envelope.ephemeral_pk);

    let shared = secret.diffie_hellman(&eph_pk);
    // An envelope whose ephemeral key is of small order was sealed under a
    // secret that is the same for every recipient: it would open for any
    // of them, so it is not an envelope for this one.
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidMessage(
            "the envelope was sealed under a secret that anyone can work out".into(),
        ));
    }

    let wrapping_key = hkdf_sha256(shared.as_bytes(), &[], info)?;

    let unbound =
        UnboundKey::new(&AES_256_GCM, &wrapping_key).map_err(|_| CryptoError::DecryptionFailed)?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&envelope.iv)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let mut in_out = Vec::with_capacity(envelope.ciphertext.len() + TAG_LEN);
    in_out.extend_from_slice(&envelope.ciphertext);
    in_out.extend_from_slice(&envelope.auth_tag);

    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::x25519_from_ed25519_seed;

    /// T20. A secret agreed with a key of small order is the same for
    /// everyone: all zero. Nothing is sealed under it, and an envelope that
    /// was sealed under it is not opened.
    #[test]
    fn a_secret_anyone_can_work_out_seals_and_opens_nothing() {
        use curve25519_dalek::constants::EIGHT_TORSION;

        let mut small: Vec<[u8; 32]> = EIGHT_TORSION
            .iter()
            .map(|point| point.to_montgomery().to_bytes())
            .collect();
        small.push([0u8; 32]);
        for key in &small {
            assert!(
                ecies_encrypt(key, b"a channel's key").is_err(),
                "{key:02x?}"
            );
        }

        // An envelope made by hand under a given secret, as someone would
        // who holds no key at all.
        let sealed_under = |secret: &[u8; 32], ephemeral_pk: [u8; 32]| {
            let iv = [7u8; IV_LEN];
            let wrapping_key = hkdf_sha256(secret, &[], HKDF_INFO).unwrap();
            let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &wrapping_key).unwrap());
            let mut in_out = b"made by hand".to_vec();
            key.seal_in_place_append_tag(
                Nonce::try_assume_unique_for_key(&iv).unwrap(),
                Aad::empty(),
                &mut in_out,
            )
            .unwrap();
            let tag_start = in_out.len() - TAG_LEN;
            EciesEnvelope {
                ephemeral_pk,
                iv,
                ciphertext: in_out[..tag_start].to_vec(),
                auth_tag: in_out[tag_start..].try_into().unwrap(),
            }
        };
        // With an ephemeral key of small order the secret is all zero for
        // whoever opens it. Without the check, every recipient would.
        let forged = sealed_under(&[0u8; 32], [0u8; 32]);
        for seed in [[1u8; 32], [2u8; 32]] {
            let (recipient_sk, recipient_pk) = x25519_from_ed25519_seed(&seed);
            assert!(matches!(
                ecies_decrypt(&recipient_sk, &forged),
                Err(CryptoError::InvalidMessage(_))
            ));
            // The control: made the same way under a secret that is this
            // recipient's alone, the envelope opens. So the one above is
            // refused for its secret, and not for how it was made.
            let ephemeral = StaticSecret::from([9u8; 32]);
            let secret = ephemeral.diffie_hellman(&PublicKey::from(recipient_pk));
            let real = sealed_under(secret.as_bytes(), PublicKey::from(&ephemeral).to_bytes());
            assert_eq!(
                ecies_decrypt(&recipient_sk, &real).unwrap(),
                b"made by hand"
            );
        }
    }

    #[test]
    fn test_hkdf_sha256_tv() {
        let shared_secret: [u8; 32] =
            hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .unwrap()
                .try_into()
                .unwrap();

        let okm = hkdf_sha256(&shared_secret, &[], HKDF_INFO).unwrap();

        assert_eq!(
            hex::encode(okm),
            "f1f4ea6c1d40b1c6a968574803e9e21173846d7b184d522223e8a42705124f9a"
        );
    }

    /// RFC 5869, test cases 1 and 3: key material that is not 32 bytes,
    /// with a salt and with none. The first 32 bytes of each output.
    #[test]
    fn hkdf_from_key_material_of_any_length_gives_the_rfc_5869_vectors() {
        let key_material = [0x0b_u8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        assert_eq!(
            hex::encode(hkdf_sha256_of(&key_material, &salt, &info).unwrap()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
        assert_eq!(
            hex::encode(hkdf_sha256_of(&key_material, &[], &[]).unwrap()),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );
        // From 32 bytes it is the function that was here before.
        let secret = [0x4a_u8; 32];
        assert_eq!(
            hkdf_sha256_of(&secret, &[], HKDF_INFO).unwrap(),
            hkdf_sha256(&secret, &[], HKDF_INFO).unwrap()
        );
    }

    #[test]
    fn test_ecies_full_tv() {
        // Recipient: RFC 8032 TV1
        let recipient_seed =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let (recipient_sk, recipient_pk) = x25519_from_ed25519_seed(&recipient_seed);
        assert_eq!(
            hex::encode(recipient_pk),
            "d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e"
        );

        // Ephemeral: libsodium ed25519_convert.c seed
        let eph_seed =
            hex::decode("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee")
                .unwrap();
        let (eph_sk, eph_pk) = x25519_from_ed25519_seed(&eph_seed);
        assert_eq!(
            hex::encode(eph_pk),
            "f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50"
        );

        // Verify ECDH shared secret
        let ss_fwd = StaticSecret::from(eph_sk).diffie_hellman(&PublicKey::from(recipient_pk));
        let ss_rev = StaticSecret::from(recipient_sk).diffie_hellman(&PublicKey::from(eph_pk));
        assert_eq!(ss_fwd.as_bytes(), ss_rev.as_bytes());
        assert_eq!(
            hex::encode(ss_fwd.as_bytes()),
            "7f19aee0fce03d5068dceef0ae6bcbe10042087dda5251b3256a32daa1c25a61"
        );

        // Verify HKDF wrapping key
        let wrapping_key = hkdf_sha256(ss_fwd.as_bytes(), &[], HKDF_INFO).unwrap();
        assert_eq!(
            hex::encode(wrapping_key),
            "8530a1a213d630eca929f96c2392cef56fb7234d2cd556d9b0cdf71b96875b63"
        );

        // Deterministic seal
        let plaintext =
            hex::decode("aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd")
                .unwrap();
        let iv: [u8; 12] = hex::decode("000102030405060708090a0b")
            .unwrap()
            .try_into()
            .unwrap();

        let envelope = ecies_seal(&eph_sk, &iv, &recipient_pk, &plaintext).unwrap();

        assert_eq!(
            hex::encode(&envelope.ciphertext),
            "63492d378ec7ea1aa85bee72eaad32e3fb857c2fad42b8c67bd9464c9a35318c"
        );
        assert_eq!(
            hex::encode(envelope.auth_tag),
            "77769938269c0d6d5e00fc13c1c9f017"
        );

        // Round-trip
        let decrypted = ecies_decrypt(&recipient_sk, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// An envelope sealed for one purpose opens for that purpose, and for
    /// no other: not for another purpose, and not as a general envelope.
    /// The general sealing is what it was: under the key-wrap info.
    #[test]
    fn an_envelope_sealed_for_one_purpose_opens_for_no_other() {
        let (sk, pk) = x25519_from_ed25519_seed(&[7u8; 32]);
        let secret = [0x42u8; 32];
        let purpose = b"one purpose, with a number 3";

        let sealed = ecies_encrypt_for(&pk, &secret, purpose).unwrap();
        assert_eq!(sealed.to_bytes().len(), 92);
        assert_eq!(ecies_decrypt_for(&sk, &sealed, purpose).unwrap(), secret);
        for other in [
            &b"one purpose, with a number 4"[..],
            b"one purpose",
            b"",
            HKDF_INFO,
        ] {
            assert!(matches!(
                ecies_decrypt_for(&sk, &sealed, other),
                Err(CryptoError::DecryptionFailed)
            ));
        }
        assert!(matches!(
            ecies_decrypt(&sk, &sealed),
            Err(CryptoError::DecryptionFailed)
        ));
        // And for nobody else under that purpose.
        let (other_sk, _) = x25519_from_ed25519_seed(&[8u8; 32]);
        assert!(ecies_decrypt_for(&other_sk, &sealed, purpose).is_err());

        // A general envelope is no envelope for a purpose.
        let general = ecies_encrypt(&pk, &secret).unwrap();
        assert_eq!(ecies_decrypt(&sk, &general).unwrap(), secret);
        assert!(ecies_decrypt_for(&sk, &general, purpose).is_err());
        // It is sealed under the key-wrap info, as it always was: the two
        // ways of sealing and of opening are one under that info.
        assert_eq!(HKDF_INFO, b"cordelia-key-wrap-v1");
        assert_eq!(
            ecies_decrypt_for(&sk, &general, b"cordelia-key-wrap-v1").unwrap(),
            secret
        );
        let under_it = ecies_encrypt_for(&pk, &secret, b"cordelia-key-wrap-v1").unwrap();
        assert_eq!(ecies_decrypt(&sk, &under_it).unwrap(), secret);

        // The same checks as the general one: a key of small order seals
        // nothing.
        assert!(ecies_encrypt_for(&[0u8; 32], &secret, purpose).is_err());
    }

    #[test]
    fn test_ecies_binary_serialisation() {
        let rng = SystemRandom::new();
        let mut sk = [0u8; 32];
        rng.fill(&mut sk).unwrap();
        let pk = *PublicKey::from(&StaticSecret::from(sk)).as_bytes();

        let psk = [0x42u8; 32]; // 32-byte PSK
        let envelope = ecies_encrypt(&pk, &psk).unwrap();

        // Serialise and deserialise
        let bytes = envelope.to_bytes();
        assert_eq!(bytes.len(), 92); // 32 + 12 + 32 + 16

        let recovered = EciesEnvelope::from_bytes(&bytes, 32).unwrap();
        let decrypted = ecies_decrypt(&sk, &recovered).unwrap();
        assert_eq!(decrypted, psk);
    }

    #[test]
    fn test_ecies_random_round_trip() {
        let rng = SystemRandom::new();
        let mut sk = [0u8; 32];
        rng.fill(&mut sk).unwrap();
        let pk = *PublicKey::from(&StaticSecret::from(sk)).as_bytes();

        let plaintext = b"cordelia PSK material";
        let envelope = ecies_encrypt(&pk, plaintext).unwrap();
        let decrypted = ecies_decrypt(&sk, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ecies_wrong_key_fails() {
        let rng = SystemRandom::new();
        let mut sk1 = [0u8; 32];
        let mut sk2 = [0u8; 32];
        rng.fill(&mut sk1).unwrap();
        rng.fill(&mut sk2).unwrap();

        let pk1 = *PublicKey::from(&StaticSecret::from(sk1)).as_bytes();
        let envelope = ecies_encrypt(&pk1, b"secret").unwrap();
        assert!(ecies_decrypt(&sk2, &envelope).is_err());
    }

    #[test]
    fn test_ecies_tampered_ciphertext_fails() {
        let rng = SystemRandom::new();
        let mut sk = [0u8; 32];
        rng.fill(&mut sk).unwrap();
        let pk = *PublicKey::from(&StaticSecret::from(sk)).as_bytes();

        let mut envelope = ecies_encrypt(&pk, b"data").unwrap();
        envelope.ciphertext[0] ^= 0xff;
        assert!(ecies_decrypt(&sk, &envelope).is_err());
    }

    #[test]
    fn test_ecies_tampered_auth_tag_fails() {
        let rng = SystemRandom::new();
        let mut sk = [0u8; 32];
        rng.fill(&mut sk).unwrap();
        let pk = *PublicKey::from(&StaticSecret::from(sk)).as_bytes();

        let mut envelope = ecies_encrypt(&pk, b"data").unwrap();
        envelope.auth_tag[0] ^= 0xff;
        assert!(ecies_decrypt(&sk, &envelope).is_err());
    }

    // T3-2 (MEDIUM): Tampered ephemeral public key
    #[test]
    fn test_ecies_tampered_ephemeral_pk_fails() {
        let rng = SystemRandom::new();
        let mut sk = [0u8; 32];
        rng.fill(&mut sk).unwrap();
        let pk = *PublicKey::from(&StaticSecret::from(sk)).as_bytes();

        let mut envelope = ecies_encrypt(&pk, b"secret data").unwrap();
        envelope.ephemeral_pk[0] ^= 0xff;
        assert!(ecies_decrypt(&sk, &envelope).is_err());
    }

    // T3-3 (MEDIUM): Tampered IV
    #[test]
    fn test_ecies_tampered_iv_fails() {
        let rng = SystemRandom::new();
        let mut sk = [0u8; 32];
        rng.fill(&mut sk).unwrap();
        let pk = *PublicKey::from(&StaticSecret::from(sk)).as_bytes();

        let mut envelope = ecies_encrypt(&pk, b"secret data").unwrap();
        envelope.iv[0] ^= 0xff;
        assert!(ecies_decrypt(&sk, &envelope).is_err());
    }

    // T3-1 (MEDIUM): from_bytes wrong size
    #[test]
    fn test_ecies_from_bytes_wrong_size() {
        let short = vec![0u8; 91]; // 92 expected for 32-byte plaintext
        assert!(EciesEnvelope::from_bytes(&short, 32).is_err());

        let long = vec![0u8; 93];
        assert!(EciesEnvelope::from_bytes(&long, 32).is_err());
    }

    // T5-2 (MEDIUM): Variable plaintext sizes
    #[test]
    fn test_ecies_variable_plaintext_sizes() {
        let rng = SystemRandom::new();
        let mut sk = [0u8; 32];
        rng.fill(&mut sk).unwrap();
        let pk = *PublicKey::from(&StaticSecret::from(sk)).as_bytes();

        for size in [1, 16, 64, 256] {
            let plaintext = vec![0xAA; size];
            let envelope = ecies_encrypt(&pk, &plaintext).unwrap();
            let decrypted = ecies_decrypt(&sk, &envelope).unwrap();
            assert_eq!(decrypted, plaintext, "failed for size {size}");
        }
    }

    // T8-1 (MEDIUM): Wrong key returns specific error variant
    #[test]
    fn test_ecies_wrong_key_returns_decryption_failed() {
        let rng = SystemRandom::new();
        let mut sk1 = [0u8; 32];
        let mut sk2 = [0u8; 32];
        rng.fill(&mut sk1).unwrap();
        rng.fill(&mut sk2).unwrap();
        let pk1 = *PublicKey::from(&StaticSecret::from(sk1)).as_bytes();

        let envelope = ecies_encrypt(&pk1, b"secret").unwrap();
        match ecies_decrypt(&sk2, &envelope) {
            Err(CryptoError::DecryptionFailed) => {} // expected
            other => panic!("expected DecryptionFailed, got {:?}", other),
        }
    }
}
