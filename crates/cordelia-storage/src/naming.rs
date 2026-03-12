//! Channel name validation, canonicalization, and ID derivation.
//!
//! Spec: seed-drill/specs/channel-naming.md

use cordelia_core::CordeliaError;
use sha2::{Digest, Sha256};

/// Validate and canonicalize a user-supplied channel name.
///
/// Steps: trim whitespace, lowercase, validate against RFC 1035 label rules.
/// Returns canonical name or error with reason.
pub fn canonicalize(input: &str) -> Result<String, CordeliaError> {
    let trimmed = input.trim();
    let lower = trimmed.to_lowercase();

    validate_channel_name(&lower)?;
    Ok(lower)
}

/// Validate a (already-lowercased) channel name against RFC 1035 label rules.
///
/// Regex equivalent: `^[a-z][a-z0-9-]{1,61}[a-z0-9]$`
fn validate_channel_name(name: &str) -> Result<(), CordeliaError> {
    let len = name.len();

    if len < 3 {
        return Err(CordeliaError::InvalidChannelName {
            reason: format!("too short ({len} chars, minimum 3)"),
        });
    }
    if len > 63 {
        return Err(CordeliaError::InvalidChannelName {
            reason: format!("too long ({len} chars, maximum 63)"),
        });
    }

    let bytes = name.as_bytes();

    // Must start with a-z
    if !bytes[0].is_ascii_lowercase() {
        return Err(CordeliaError::InvalidChannelName {
            reason: "must start with a letter (a-z)".into(),
        });
    }

    // Must end with a-z or 0-9 (not hyphen)
    let last = bytes[len - 1];
    if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
        return Err(CordeliaError::InvalidChannelName {
            reason: "must end with a letter or digit".into(),
        });
    }

    // All chars must be a-z, 0-9, or hyphen
    for (i, &b) in bytes.iter().enumerate() {
        if !b.is_ascii_lowercase() && !b.is_ascii_digit() && b != b'-' {
            return Err(CordeliaError::InvalidChannelName {
                reason: format!(
                    "invalid character '{}' at position {i} (allowed: a-z, 0-9, hyphen)",
                    b as char
                ),
            });
        }
    }

    Ok(())
}

/// Derive channel ID for a named channel.
///
/// `channel_id = hex(SHA-256("cordelia:channel:" + canonical_name))`
pub fn named_channel_id(canonical_name: &str) -> String {
    let preimage = format!("cordelia:channel:{canonical_name}");
    let hash = Sha256::digest(preimage.as_bytes());
    hex::encode(hash)
}

/// Derive channel ID for a DM between two Ed25519 public keys.
///
/// `channel_id = "dm_" + hex(SHA-256("cordelia:dm:" || sorted_keys[0] || sorted_keys[1]))`
/// Keys are sorted by raw byte values (not hex).
pub fn dm_channel_id(pk_a: &[u8; 32], pk_b: &[u8; 32]) -> String {
    let (first, second) = if pk_a[..] <= pk_b[..] {
        (pk_a, pk_b)
    } else {
        (pk_b, pk_a)
    };

    let mut preimage = Vec::with_capacity(76);
    preimage.extend_from_slice(b"cordelia:dm:");
    preimage.extend_from_slice(first);
    preimage.extend_from_slice(second);

    let hash = Sha256::digest(&preimage);
    format!("dm_{}", hex::encode(hash))
}

/// Generate channel ID for a group conversation.
///
/// `channel_id = "grp_" + UUID_v4()`
pub fn group_channel_id() -> String {
    format!("grp_{}", uuid::Uuid::new_v4())
}

/// Derive channel ID for the __personal system channel.
///
/// `SHA-256("cordelia:channel:__personal:" + hex(pubkey))`
pub fn personal_channel_id(pubkey: &[u8; 32]) -> String {
    let preimage = format!("cordelia:channel:__personal:{}", hex::encode(pubkey));
    let hash = Sha256::digest(preimage.as_bytes());
    hex::encode(hash)
}

/// Derive a well-known PSK for a protocol channel.
///
/// `protocol_psk = SHA-256("cordelia-protocol-channel:" + channel_name)`
pub fn protocol_channel_psk(channel_name: &str) -> [u8; 32] {
    let preimage = format!("cordelia-protocol-channel:{channel_name}");
    let hash = Sha256::digest(preimage.as_bytes());
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&hash);
    psk
}

/// Determine channel type from an ID string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelType {
    Named,
    Dm,
    Group,
    Protocol,
}

impl ChannelType {
    /// Infer channel type from prefix disambiguation (channel-naming.md §5).
    pub fn from_id(id: &str) -> Self {
        if id.starts_with("dm_") {
            Self::Dm
        } else if id.starts_with("grp_") {
            Self::Group
        } else if id.starts_with("cordelia:") {
            Self::Protocol
        } else {
            Self::Named
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Named => "named",
            Self::Dm => "dm",
            Self::Group => "group",
            Self::Protocol => "protocol",
        }
    }
}

impl std::fmt::Display for ChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ================================================================
    // Canonicalization (channel-naming.md §7.1)
    // ================================================================

    #[test]
    fn test_canonicalize_no_change() {
        assert_eq!(canonicalize("research-findings").unwrap(), "research-findings");
    }

    #[test]
    fn test_canonicalize_lowercase() {
        assert_eq!(canonicalize("Research-Findings").unwrap(), "research-findings");
    }

    #[test]
    fn test_canonicalize_trim() {
        assert_eq!(canonicalize("  ai-signals  ").unwrap(), "ai-signals");
    }

    #[test]
    fn test_canonicalize_uppercase() {
        assert_eq!(canonicalize("ENGINEERING").unwrap(), "engineering");
    }

    #[test]
    fn test_canonicalize_min_length() {
        assert_eq!(canonicalize("abc").unwrap(), "abc");
    }

    #[test]
    fn test_reject_too_short_1() {
        assert!(canonicalize("a").is_err());
    }

    #[test]
    fn test_reject_too_short_2() {
        assert!(canonicalize("ab").is_err());
    }

    #[test]
    fn test_reject_starts_with_digit() {
        assert!(canonicalize("3research").is_err());
    }

    #[test]
    fn test_reject_trailing_hyphen() {
        assert!(canonicalize("research-").is_err());
    }

    #[test]
    fn test_reject_underscore() {
        assert!(canonicalize("my_channel").is_err());
    }

    #[test]
    fn test_reject_period() {
        assert!(canonicalize("my.channel").is_err());
    }

    #[test]
    fn test_reject_colon() {
        assert!(canonicalize("cordelia:test").is_err());
    }

    #[test]
    fn test_max_length_63() {
        let name = "a".repeat(63);
        assert!(canonicalize(&name).is_ok());
    }

    #[test]
    fn test_reject_64_chars() {
        let name = "a".repeat(64);
        assert!(canonicalize(&name).is_err());
    }

    #[test]
    fn test_idempotent() {
        let input = "  Research-Findings  ";
        let c1 = canonicalize(input).unwrap();
        let c2 = canonicalize(&c1).unwrap();
        assert_eq!(c1, c2);
    }

    // ================================================================
    // Channel ID derivation (channel-naming.md §7.2)
    // ================================================================

    #[test]
    fn test_named_id_research_findings() {
        assert_eq!(
            named_channel_id("research-findings"),
            "fe028fdaf943c16ec8a1fc496818274ce7e86e921ad926f9712886fa26d309d6"
        );
    }

    #[test]
    fn test_named_id_engineering() {
        assert_eq!(
            named_channel_id("engineering"),
            "743e760f7c729ecc93ad08d0a4d942de047f98ae53dc1459af99af826deb3ba9"
        );
    }

    #[test]
    fn test_named_id_abc() {
        assert_eq!(
            named_channel_id("abc"),
            "0a7d0ae0a65b98af92058dd0c5f538591afa09413c4634e9f8f930ff6528259c"
        );
    }

    #[test]
    fn test_named_id_max_length() {
        let name = "a".repeat(63);
        assert_eq!(
            named_channel_id(&name),
            "a97ac4b49075f79200906cb8fb80c286dc4424e067caf869caebf0516cf21d54"
        );
    }

    #[test]
    fn test_dm_channel_id() {
        let alice = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap();
        let bob = hex::decode("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
            .unwrap();

        let mut pk_a = [0u8; 32];
        let mut pk_b = [0u8; 32];
        pk_a.copy_from_slice(&alice);
        pk_b.copy_from_slice(&bob);

        let id = dm_channel_id(&pk_a, &pk_b);
        assert_eq!(id, "dm_c56ea36e17c1c3dba0524822fb0ac3dc16ff442dd3c792f5a2989a0a77a30cd0");

        // Symmetric: dm(a,b) == dm(b,a)
        let id_reverse = dm_channel_id(&pk_b, &pk_a);
        assert_eq!(id, id_reverse);
    }

    #[test]
    fn test_group_channel_id_format() {
        let id = group_channel_id();
        assert!(id.starts_with("grp_"));
        assert_eq!(id.len(), 4 + 36); // "grp_" + UUID
    }

    #[test]
    fn test_group_channel_id_unique() {
        let id1 = group_channel_id();
        let id2 = group_channel_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_protocol_channel_psk() {
        let psk = protocol_channel_psk("cordelia:directory");
        assert_eq!(
            hex::encode(psk),
            "1d1b02d7fa1fb8eef894c6dd042c2711be63df24699d6c0134ae629c071ae725"
        );
    }

    // ================================================================
    // Prefix disambiguation (channel-naming.md §7.3)
    // ================================================================

    #[test]
    fn test_channel_type_named() {
        assert_eq!(
            ChannelType::from_id("fe028fdaf943c16ec8a1fc496818274ce7e86e921ad926f9712886fa26d309d6"),
            ChannelType::Named
        );
    }

    #[test]
    fn test_channel_type_dm() {
        assert_eq!(
            ChannelType::from_id("dm_c56ea36e17c1c3dba0524822fb0ac3dc16ff442dd3c792f5a2989a0a77a30cd0"),
            ChannelType::Dm
        );
    }

    #[test]
    fn test_channel_type_group() {
        assert_eq!(
            ChannelType::from_id("grp_550e8400-e29b-41d4-a716-446655440000"),
            ChannelType::Group
        );
    }

    #[test]
    fn test_channel_type_protocol() {
        assert_eq!(
            ChannelType::from_id("cordelia:directory"),
            ChannelType::Protocol
        );
    }
}
