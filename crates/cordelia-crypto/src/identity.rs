//! Ed25519 node identity -- keypair generation, storage, X25519 derivation.
//!
//! Key format: raw 32-byte Ed25519 seed (not PKCS#8 DER).
//! Storage: ~/.cordelia/identity.key (mode 0600)
//!
//! Spec: seed-drill/specs/identity.md

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256, Sha512};
use std::path::Path;

use crate::CryptoError;

/// Node identity wrapping an Ed25519 keypair.
///
/// The canonical identifier is the Ed25519 public key (32 bytes),
/// encoded as Bech32 `cordelia_pk1...` for human-readable contexts.
pub struct NodeIdentity {
    keypair: Ed25519KeyPair,
    seed: [u8; 32],
}

impl NodeIdentity {
    /// Generate a new random identity from CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let rng = SystemRandom::new();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed)
            .map_err(|_| CryptoError::IdentityError("RNG failure".into()))?;
        Self::from_seed(seed)
    }

    /// Create identity from a raw 32-byte Ed25519 seed.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, CryptoError> {
        // ring requires PKCS#8 DER, so we wrap the seed
        let pkcs8 = seed_to_pkcs8(&seed)?;
        let keypair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pkcs8)
            .map_err(|e| CryptoError::IdentityError(e.to_string()))?;
        Ok(Self { keypair, seed })
    }

    /// Load identity from file (raw 32-byte seed).
    pub fn from_file(path: &Path) -> Result<Self, CryptoError> {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            return Err(CryptoError::IdentityError(format!(
                "identity file must be exactly 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Self::from_seed(seed)
    }

    /// Load identity from file, or generate and save if file doesn't exist.
    pub fn load_or_create(path: &Path) -> Result<Self, CryptoError> {
        if path.exists() {
            Self::from_file(path)
        } else {
            let identity = Self::generate()?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, identity.seed)?;
            // Set file permissions to 0600 on unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(identity)
        }
    }

    /// Raw 32-byte Ed25519 seed.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Ed25519 public key (32 bytes). This is the canonical node identifier.
    pub fn public_key(&self) -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(self.keypair.public_key().as_ref());
        pk
    }

    /// Entity ID: `<name>_<4 hex chars>` derived from SHA-256 of public key.
    /// The name is provided externally; this returns only the 4-char suffix.
    pub fn entity_id_suffix(&self) -> String {
        let hash = Sha256::digest(self.keypair.public_key().as_ref());
        hex::encode(&hash[..2]) // First 2 bytes = 4 hex chars
    }

    /// Sign data with Ed25519.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        let sig = self.keypair.sign(data);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }

    /// X25519 private key (derived from Ed25519 seed).
    pub fn x25519_private_key(&self) -> [u8; 32] {
        x25519_from_ed25519_seed(&self.seed).0
    }

    /// X25519 public key (derived from Ed25519 seed).
    pub fn x25519_public_key(&self) -> [u8; 32] {
        x25519_from_ed25519_seed(&self.seed).1
    }
}

/// Derive X25519 keypair from a raw Ed25519 seed.
///
/// Algorithm: SHA-512(seed) -> first 32 bytes -> RFC 7748 clamping -> scalarMultBase.
/// Returns (x25519_private_key, x25519_public_key).
pub fn x25519_from_ed25519_seed(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hash = Sha512::digest(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    // RFC 7748 clamping
    scalar[0] &= 0xF8;
    scalar[31] &= 0x7F;
    scalar[31] |= 0x40;

    let secret = x25519_dalek::StaticSecret::from(scalar);
    let public = x25519_dalek::PublicKey::from(&secret);
    let pub_key = *public.as_bytes();

    (scalar, pub_key)
}

/// Derive X25519 public key from an Ed25519 public key using the birational map.
///
/// This is the Edwards-to-Montgomery conversion: u = (1 + y) / (1 - y) mod p.
/// Used when we have only the peer's Ed25519 public key (no seed access).
pub fn x25519_pub_from_ed25519_pub(ed_pk: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY(*ed_pk);
    match compressed.decompress() {
        Some(point) => point.to_montgomery().to_bytes(),
        None => [0u8; 32], // Invalid Ed25519 point
    }
}

/// Wrap a raw 32-byte Ed25519 seed in PKCS#8 v1 DER for ring.
///
/// ring doesn't accept raw seeds directly -- it requires PKCS#8 DER.
/// This constructs the minimal v1 DER envelope around the seed.
/// We use `from_pkcs8_maybe_unchecked` since ring 0.17's `from_pkcs8`
/// requires v2 (with public key embedded).
fn seed_to_pkcs8(seed: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let mut der = Vec::with_capacity(48);
    // SEQUENCE (outer)
    der.push(0x30);
    der.push(0x2e); // length = 46 bytes
    // INTEGER 0 (version v1)
    der.extend_from_slice(&[0x02, 0x01, 0x00]);
    // SEQUENCE { OID 1.3.101.112 }
    der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    // OCTET STRING { OCTET STRING { 32-byte seed } }
    der.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]);
    der.extend_from_slice(seed);

    // Verify ring accepts this (v1 requires maybe_unchecked)
    Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der)
        .map_err(|e| CryptoError::IdentityError(format!("PKCS#8 construction failed: {e}")))?;

    Ok(der)
}

/// Verify an Ed25519 signature against a public key.
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use ring::signature::{UnparsedPublicKey, ED25519};
    let peer_pk = UnparsedPublicKey::new(&ED25519, public_key);
    peer_pk.verify(message, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let id = NodeIdentity::generate().unwrap();
        assert_eq!(id.public_key().len(), 32);
        assert_eq!(id.seed().len(), 32);
    }

    #[test]
    fn test_from_seed_deterministic() {
        let seed = [0x42u8; 32];
        let id1 = NodeIdentity::from_seed(seed).unwrap();
        let id2 = NodeIdentity::from_seed(seed).unwrap();
        assert_eq!(id1.public_key(), id2.public_key());
    }

    #[test]
    fn test_load_or_create() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");

        let id1 = NodeIdentity::load_or_create(&path).unwrap();
        let id2 = NodeIdentity::load_or_create(&path).unwrap();

        assert_eq!(id1.public_key(), id2.public_key());
        assert_eq!(id1.seed(), id2.seed());

        // File should be exactly 32 bytes
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let id = NodeIdentity::generate().unwrap();
        let message = b"test message";
        let sig = id.sign(message);
        assert!(verify_signature(&id.public_key(), message, &sig));

        // Wrong message fails
        assert!(!verify_signature(&id.public_key(), b"wrong", &sig));
    }

    #[test]
    fn test_entity_id_suffix() {
        let id = NodeIdentity::generate().unwrap();
        let suffix = id.entity_id_suffix();
        assert_eq!(suffix.len(), 4);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_x25519_on_real_identity() {
        let id = NodeIdentity::generate().unwrap();
        let x_priv = id.x25519_private_key();
        let x_pub = id.x25519_public_key();

        let secret = x25519_dalek::StaticSecret::from(x_priv);
        let derived_pub = x25519_dalek::PublicKey::from(&secret);
        assert_eq!(&x_pub, derived_pub.as_bytes());
    }

    // ========================================================================
    // X25519 derivation test vectors (from encryption-test-vectors.md)
    // ========================================================================

    #[test]
    fn test_x25519_tv1_rfc8032() {
        let seed =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let (x_priv, x_pub) = x25519_from_ed25519_seed(&seed);

        assert_eq!(
            hex::encode(x_priv),
            "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f"
        );
        assert_eq!(
            hex::encode(x_pub),
            "d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e"
        );
    }

    #[test]
    fn test_x25519_tv2_all_zeros() {
        let seed = [0u8; 32];
        let (x_priv, x_pub) = x25519_from_ed25519_seed(&seed);

        assert_eq!(
            hex::encode(x_priv),
            "5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f156"
        );
        assert_eq!(
            hex::encode(x_pub),
            "5bf55c73b82ebe22be80f3430667af570fae2556a6415e6b30d4065300aa947d"
        );
    }

    #[test]
    fn test_x25519_tv3_libsodium() {
        let seed =
            hex::decode("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee")
                .unwrap();
        let (x_priv, x_pub) = x25519_from_ed25519_seed(&seed);

        assert_eq!(
            hex::encode(x_priv),
            "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166"
        );
        assert_eq!(
            hex::encode(x_pub),
            "f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50"
        );
    }

    #[test]
    fn test_x25519_tv4_ed2curve_js() {
        let seed =
            hex::decode("9fc9b77445f8b077c29fe27fc581c52beb668ecd25f5bb2ba5777dee2a411e97")
                .unwrap();
        let (x_priv, x_pub) = x25519_from_ed25519_seed(&seed);

        assert_eq!(
            hex::encode(x_priv),
            "28e9e1d48cb0e52e437080e4a180058d7a42a07abcd05ea2ec4e6122cded8f6a"
        );
        assert_eq!(
            hex::encode(x_pub),
            "26100e941bdd2103038d8dec9a1884694736f591ee814e66ae6e2e2284757136"
        );
    }

    #[test]
    fn test_x25519_ecdh_shared_secret() {
        let seed_a =
            hex::decode("397ceb5a8d21d74a9258c20c33fc45ab152b02cf479b2e3081285f77454cf347")
                .unwrap();
        let seed_b =
            hex::decode("70559b9eecdc578d5fc2ca37f9969630029f1592aff3306392ab15546c6a184a")
                .unwrap();
        let (priv_a, pub_a) = x25519_from_ed25519_seed(&seed_a);
        let (priv_b, pub_b) = x25519_from_ed25519_seed(&seed_b);

        assert_eq!(
            hex::encode(priv_a),
            "48cb217ef470512fd65aba03f501d3d31a91aaed3f32c053caf9b69e26ffbb4c"
        );
        assert_eq!(
            hex::encode(pub_a),
            "243cc5b065ea4a4c0bce1264de6a2f3e5c0a578fb1ecb08b0aab6bc90e1cf318"
        );

        let sk_a = x25519_dalek::StaticSecret::from(priv_a);
        let pk_b = x25519_dalek::PublicKey::from(pub_b);
        let shared_ab = sk_a.diffie_hellman(&pk_b);

        let sk_b = x25519_dalek::StaticSecret::from(priv_b);
        let pk_a = x25519_dalek::PublicKey::from(pub_a);
        let shared_ba = sk_b.diffie_hellman(&pk_a);

        assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
        assert_eq!(
            hex::encode(shared_ab.as_bytes()),
            "4546babdb9482396c167af11d21953bfa49eb9f630c45de93ee4d3b9ef059576"
        );
    }
}
