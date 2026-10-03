//! Channel state messages: how a channel's keys and member list reach its
//! members (decision 2026-09-30-agent-memory-sync §4.1).
//!
//! A channel state carries everything a member needs for one channel: the
//! key ring, the slot key, the member list, and a monotonic epoch. It is
//! sealed to a single recipient with ECIES and published as an `invite`
//! item in the recipient's inbox channel. An invite is simply the first
//! state a node receives for a channel; adding or removing a member, or
//! rotating the channel key, sends the next epoch to every remaining member.
//!
//! The sealed payload names its sender. A receiver must check that the
//! sender equals the item's signature-verified author, so a state sealed
//! by one node cannot be re-signed by another and presented as its own.
//!
//! Wire format: CBOR map, sealed as an ECIES envelope
//! (`eph_pk[32] || iv[12] || ciphertext || tag[16]`, see [`crate::ecies`]).
//!
//! ```cbor
//! {
//!   "v":        1,
//!   "ch":       "grp_...",                 -- channel ID (group channels only in v1)
//!   "name":     "..." / null,
//!   "mode":     "realtime" / "batch",
//!   "creator":  h'<32>',                   -- channel creator (Ed25519)
//!   "sender":   h'<32>',                   -- must equal the item author
//!   "epoch":    <uint>,
//!   "kv":       <uint>,                    -- current key version
//!   "keys":     [[<uint>, h'<32>'], ...],  -- key ring: kv, and versions below it
//!   "slot_key": h'<32>',                   -- never rotated (§4.3)
//!   "members":  [[h'<32>', "owner" / "member"], ...],
//!   "personal": <bool>                     -- sender's personal channel
//! }
//! ```

use ciborium::Value;

use crate::CryptoError;
use crate::ecies::{EciesEnvelope, ecies_decrypt, ecies_encrypt};
use crate::identity::{NodeIdentity, x25519_pub_from_ed25519_pub};

/// Payload format version.
pub const CHANNEL_STATE_VERSION: u64 = 1;

/// Upper bounds applied when decoding, so a hostile payload cannot make a
/// node allocate without limit. Far above anything v1 needs.
const MAX_MEMBERS: usize = 1024;
const MAX_KEYS: usize = cordelia_core::protocol::MAX_STATE_KEYS;

/// A member's role within a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberRole {
    /// May change membership and rotate keys. A person's devices are owners
    /// of that person's channels.
    Owner,
    /// May read and write items.
    Member,
}

impl MemberRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Member => "member",
        }
    }

    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        match s {
            "owner" => Ok(Self::Owner),
            "member" => Ok(Self::Member),
            other => Err(CryptoError::InvalidMessage(format!(
                "unknown member role '{other}'"
            ))),
        }
    }
}

/// One entry in a channel's member list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateMember {
    /// Ed25519 public key.
    pub key: [u8; 32],
    pub role: MemberRole,
}

/// Everything a member needs to participate in one channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelState {
    pub channel_id: String,
    pub name: Option<String>,
    pub mode: String,
    /// Ed25519 key of the channel's creator.
    pub creator: [u8; 32],
    /// Ed25519 key of the node that sealed this state.
    pub sender: [u8; 32],
    /// Monotonic per channel; receivers ignore states that are not newer,
    /// and states that move it further than one change may. At most
    /// `MAX_EPOCH`.
    pub epoch: u64,
    /// Current key version; must be present in `keys`.
    pub key_version: u32,
    /// Full key ring (version, PSK), so a new member can read history.
    pub keys: Vec<(u32, [u8; 32])>,
    /// Keys item slots (§4.3). Never rotated.
    pub slot_key: [u8; 32],
    pub members: Vec<StateMember>,
    /// True when this is the sender's personal channel.
    pub personal: bool,
}

impl ChannelState {
    /// The current channel PSK.
    pub fn current_key(&self) -> Option<&[u8; 32]> {
        self.keys
            .iter()
            .find(|(v, _)| *v == self.key_version)
            .map(|(_, k)| k)
    }

    /// The role of `key` in this state's member list, if it is a member.
    pub fn role_of(&self, key: &[u8; 32]) -> Option<MemberRole> {
        self.members.iter().find(|m| &m.key == key).map(|m| m.role)
    }

    /// Structural checks every state must pass before it is sealed or applied.
    ///
    /// Does not decide whether the sender is trusted; that depends on the
    /// receiver's view and is the caller's job.
    pub fn validate(&self) -> Result<(), CryptoError> {
        let invalid = |msg: &str| Err(CryptoError::InvalidMessage(msg.to_string()));

        if !is_group_channel_id(&self.channel_id) {
            return invalid("channel state must name a group channel (grp_<uuid>)");
        }
        if self.mode != "realtime" && self.mode != "batch" {
            return invalid("mode must be 'realtime' or 'batch'");
        }
        if self.epoch > cordelia_core::protocol::MAX_EPOCH {
            return invalid("epoch is over the limit");
        }
        if self.current_key().is_none() {
            return invalid("key ring lacks the current key version");
        }
        let mut versions: Vec<u32> = self.keys.iter().map(|(v, _)| *v).collect();
        versions.sort_unstable();
        versions.dedup();
        if versions.len() != self.keys.len() {
            return invalid("key ring has duplicate versions");
        }
        // A key for a version the channel has not reached would wait in the
        // receiver's ring for the removal that makes that version, and be
        // put in place then: the key after a removal would be one the
        // sender chose.
        if versions.last().is_some_and(|v| *v > self.key_version) {
            return invalid("key ring holds a version above the current one");
        }
        let mut members: Vec<[u8; 32]> = self.members.iter().map(|m| m.key).collect();
        members.sort_unstable();
        members.dedup();
        if members.len() != self.members.len() {
            return invalid("member list has duplicate keys");
        }
        if self.role_of(&self.sender) != Some(MemberRole::Owner) {
            return invalid("sender must be an owner in the member list");
        }
        if self.members.len() > MAX_MEMBERS || self.keys.len() > MAX_KEYS {
            return invalid("channel state exceeds size limits");
        }
        Ok(())
    }

    /// Encode as a CBOR map (format in the module docs).
    pub fn to_cbor(&self) -> Result<Vec<u8>, CryptoError> {
        let keys = self
            .keys
            .iter()
            .map(|(v, k)| Value::Array(vec![Value::Integer((*v).into()), Value::Bytes(k.to_vec())]))
            .collect();
        let members = self
            .members
            .iter()
            .map(|m| {
                Value::Array(vec![
                    Value::Bytes(m.key.to_vec()),
                    Value::Text(m.role.as_str().into()),
                ])
            })
            .collect();

        let map = Value::Map(vec![
            (text("v"), Value::Integer(CHANNEL_STATE_VERSION.into())),
            (text("ch"), Value::Text(self.channel_id.clone())),
            (
                text("name"),
                self.name.clone().map(Value::Text).unwrap_or(Value::Null),
            ),
            (text("mode"), Value::Text(self.mode.clone())),
            (text("creator"), Value::Bytes(self.creator.to_vec())),
            (text("sender"), Value::Bytes(self.sender.to_vec())),
            (text("epoch"), Value::Integer(self.epoch.into())),
            (text("kv"), Value::Integer(self.key_version.into())),
            (text("keys"), Value::Array(keys)),
            (text("slot_key"), Value::Bytes(self.slot_key.to_vec())),
            (text("members"), Value::Array(members)),
            (text("personal"), Value::Bool(self.personal)),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf)
            .map_err(|e| CryptoError::InvalidMessage(format!("CBOR encoding failed: {e}")))?;
        Ok(buf)
    }

    /// Decode a CBOR map produced by [`ChannelState::to_cbor`].
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
        let value: Value = ciborium::from_reader(bytes)
            .map_err(|e| CryptoError::InvalidMessage(format!("CBOR decoding failed: {e}")))?;
        let Value::Map(entries) = value else {
            return Err(CryptoError::InvalidMessage(
                "channel state is not a map".into(),
            ));
        };
        let field = |name: &str| -> Result<&Value, CryptoError> {
            entries
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
                .map(|(_, v)| v)
                .ok_or_else(|| CryptoError::InvalidMessage(format!("missing field '{name}'")))
        };

        let version = as_u64(field("v")?, "v")?;
        if version != CHANNEL_STATE_VERSION {
            return Err(CryptoError::InvalidMessage(format!(
                "unsupported channel state version {version}"
            )));
        }

        let Value::Array(raw_keys) = field("keys")? else {
            return Err(CryptoError::InvalidMessage(
                "'keys' must be an array".into(),
            ));
        };
        if raw_keys.len() > MAX_KEYS {
            return Err(CryptoError::InvalidMessage("too many keys".into()));
        }
        let mut keys = Vec::with_capacity(raw_keys.len());
        for entry in raw_keys {
            match entry {
                Value::Array(pair) if pair.len() == 2 => {
                    let v = u32::try_from(as_u64(&pair[0], "keys.version")?).map_err(|_| {
                        CryptoError::InvalidMessage("key version out of range".into())
                    })?;
                    keys.push((v, as_key(&pair[1], "keys.psk")?));
                }
                _ => {
                    return Err(CryptoError::InvalidMessage(
                        "'keys' entries must be [version, key]".into(),
                    ));
                }
            }
        }

        let Value::Array(raw_members) = field("members")? else {
            return Err(CryptoError::InvalidMessage(
                "'members' must be an array".into(),
            ));
        };
        if raw_members.len() > MAX_MEMBERS {
            return Err(CryptoError::InvalidMessage("too many members".into()));
        }
        let mut members = Vec::with_capacity(raw_members.len());
        for entry in raw_members {
            match entry {
                Value::Array(pair) if pair.len() == 2 => members.push(StateMember {
                    key: as_key(&pair[0], "members.key")?,
                    role: MemberRole::parse(as_text(&pair[1], "members.role")?)?,
                }),
                _ => {
                    return Err(CryptoError::InvalidMessage(
                        "'members' entries must be [key, role]".into(),
                    ));
                }
            }
        }

        let name = match field("name")? {
            Value::Null => None,
            other => Some(as_text(other, "name")?.to_string()),
        };
        let personal = match field("personal")? {
            Value::Bool(b) => *b,
            _ => {
                return Err(CryptoError::InvalidMessage(
                    "'personal' must be a bool".into(),
                ));
            }
        };

        Ok(Self {
            channel_id: as_text(field("ch")?, "ch")?.to_string(),
            name,
            mode: as_text(field("mode")?, "mode")?.to_string(),
            creator: as_key(field("creator")?, "creator")?,
            sender: as_key(field("sender")?, "sender")?,
            epoch: as_u64(field("epoch")?, "epoch")?,
            key_version: u32::try_from(as_u64(field("kv")?, "kv")?)
                .map_err(|_| CryptoError::InvalidMessage("kv out of range".into()))?,
            keys,
            slot_key: as_key(field("slot_key")?, "slot_key")?,
            members,
            personal,
        })
    }

    /// Validate, encode, and seal this state to one recipient's Ed25519 key.
    pub fn seal(&self, recipient_ed25519: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        self.validate()?;
        let plaintext = self.to_cbor()?;
        let recipient_x25519 = x25519_pub_from_ed25519_pub(recipient_ed25519).ok_or_else(|| {
            CryptoError::InvalidMessage("the recipient's key is not a usable public key".into())
        })?;
        Ok(ecies_encrypt(&recipient_x25519, &plaintext)?.to_bytes())
    }

    /// Open a sealed state with the recipient's identity, then validate it.
    pub fn open(recipient: &NodeIdentity, sealed: &[u8]) -> Result<Self, CryptoError> {
        let envelope = EciesEnvelope::from_bytes_any(sealed)?;
        let plaintext = ecies_decrypt(&recipient.x25519_private_key(), &envelope)?;
        let state = Self::from_cbor(&plaintext)?;
        state.validate()?;
        Ok(state)
    }
}

/// `grp_` followed by a lowercase hyphenated UUID, as `group_channel_id`
/// generates. Channel IDs from other nodes become file names, so nothing
/// looser is accepted.
fn is_group_channel_id(id: &str) -> bool {
    let Some(uuid) = id.strip_prefix("grp_") else {
        return false;
    };
    uuid.len() == 36
        && uuid.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_digit() || ('a'..='f').contains(&c),
        })
}

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn as_u64(v: &Value, name: &str) -> Result<u64, CryptoError> {
    match v {
        Value::Integer(i) => u64::try_from(*i)
            .map_err(|_| CryptoError::InvalidMessage(format!("'{name}' out of range"))),
        _ => Err(CryptoError::InvalidMessage(format!(
            "'{name}' must be an unsigned integer"
        ))),
    }
}

fn as_text<'a>(v: &'a Value, name: &str) -> Result<&'a str, CryptoError> {
    match v {
        Value::Text(t) => Ok(t),
        _ => Err(CryptoError::InvalidMessage(format!(
            "'{name}' must be text"
        ))),
    }
}

fn as_key(v: &Value, name: &str) -> Result<[u8; 32], CryptoError> {
    match v {
        Value::Bytes(b) => b
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidMessage(format!("'{name}' must be 32 bytes"))),
        _ => Err(CryptoError::InvalidMessage(format!(
            "'{name}' must be bytes"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::is_usable_public_key;

    fn sample(sender: &NodeIdentity, recipient: &NodeIdentity) -> ChannelState {
        ChannelState {
            channel_id: "grp_550e8400-e29b-41d4-a716-446655440000".into(),
            name: Some("personal".into()),
            mode: "realtime".into(),
            creator: sender.public_key(),
            sender: sender.public_key(),
            epoch: 3,
            key_version: 2,
            keys: vec![(1, [0x11; 32]), (2, [0x22; 32])],
            slot_key: [0x33; 32],
            members: vec![
                StateMember {
                    key: sender.public_key(),
                    role: MemberRole::Owner,
                },
                StateMember {
                    key: recipient.public_key(),
                    role: MemberRole::Owner,
                },
            ],
            personal: true,
        }
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let sender = NodeIdentity::generate().unwrap();
        let recipient = NodeIdentity::generate().unwrap();
        let state = sample(&sender, &recipient);

        let sealed = state.seal(&recipient.public_key()).unwrap();
        let opened = ChannelState::open(&recipient, &sealed).unwrap();

        assert_eq!(opened, state);
        assert_eq!(opened.current_key(), Some(&[0x22; 32]));
        assert_eq!(
            opened.role_of(&sender.public_key()),
            Some(MemberRole::Owner)
        );
    }

    #[test]
    fn test_only_recipient_can_open() {
        let sender = NodeIdentity::generate().unwrap();
        let recipient = NodeIdentity::generate().unwrap();
        let other = NodeIdentity::generate().unwrap();
        let sealed = sample(&sender, &recipient)
            .seal(&recipient.public_key())
            .unwrap();

        assert!(ChannelState::open(&other, &sealed).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let sender = NodeIdentity::generate().unwrap();
        let recipient = NodeIdentity::generate().unwrap();
        let mut sealed = sample(&sender, &recipient)
            .seal(&recipient.public_key())
            .unwrap();
        let mid = sealed.len() / 2;
        sealed[mid] ^= 0x01;

        assert!(ChannelState::open(&recipient, &sealed).is_err());
    }

    #[test]
    fn test_validate_rejects_bad_states() {
        let sender = NodeIdentity::generate().unwrap();
        let recipient = NodeIdentity::generate().unwrap();

        let mut no_current_key = sample(&sender, &recipient);
        no_current_key.key_version = 9;
        assert!(no_current_key.validate().is_err());

        let mut sender_not_owner = sample(&sender, &recipient);
        sender_not_owner.members[0].role = MemberRole::Member;
        assert!(sender_not_owner.validate().is_err());

        let mut sender_absent = sample(&sender, &recipient);
        sender_absent.members.remove(0);
        assert!(sender_absent.validate().is_err());

        let mut duplicate_member = sample(&sender, &recipient);
        duplicate_member
            .members
            .push(duplicate_member.members[1].clone());
        assert!(duplicate_member.validate().is_err());

        let mut duplicate_version = sample(&sender, &recipient);
        duplicate_version.keys.push((2, [0x44; 32]));
        assert!(duplicate_version.validate().is_err());

        let mut not_group = sample(&sender, &recipient);
        not_group.channel_id = "dm_abc".into();
        assert!(not_group.validate().is_err());

        for bad_id in [
            "grp_../../../etc/passwd",
            "grp_550e8400-e29b-41d4-a716-44665544000", // short
            "grp_550E8400-E29B-41D4-A716-446655440000", // uppercase
            "grp_550e8400xe29b-41d4-a716-446655440000", // bad separator
        ] {
            let mut s = sample(&sender, &recipient);
            s.channel_id = bad_id.into();
            assert!(s.validate().is_err(), "{bad_id}");
        }

        // Invalid states cannot even be sealed.
        assert!(not_group.seal(&recipient.public_key()).is_err());
    }

    /// T20. A state whose epoch is over the limit is not valid: it can be
    /// neither sealed nor, sealed some other way, opened.
    #[test]
    fn an_epoch_over_the_limit_is_not_a_valid_state() {
        use cordelia_core::protocol::MAX_EPOCH;
        let sender = NodeIdentity::generate().unwrap();
        let recipient = NodeIdentity::generate().unwrap();

        let mut state = sample(&sender, &recipient);
        state.epoch = MAX_EPOCH;
        let sealed = state.seal(&recipient.public_key()).unwrap();
        assert_eq!(
            ChannelState::open(&recipient, &sealed).unwrap().epoch,
            MAX_EPOCH
        );

        for epoch in [MAX_EPOCH + 1, i64::MAX as u64, u64::MAX] {
            state.epoch = epoch;
            assert!(state.validate().is_err(), "{epoch}");
            assert!(state.seal(&recipient.public_key()).is_err(), "{epoch}");

            // Sealed without the check, as a hostile sender would.
            let to = x25519_pub_from_ed25519_pub(&recipient.public_key()).unwrap();
            let sealed = ecies_encrypt(&to, &state.to_cbor().unwrap())
                .unwrap()
                .to_bytes();
            assert!(ChannelState::open(&recipient, &sealed).is_err(), "{epoch}");
        }
    }

    /// T20. No state is sealed to bytes that are not a usable key: the
    /// secret it would be sealed under is one anyone can work out. A state
    /// that only lists such a key is still read, so that the device that
    /// reads it can leave the key out and take the rest (a device not yet
    /// upgraded may send one).
    #[test]
    fn a_state_is_sealed_to_no_key_that_is_not_usable() {
        let sender = NodeIdentity::generate().unwrap();
        let recipient = NodeIdentity::generate().unwrap();
        let not_a_point = (0u8..=255)
            .map(|b| {
                let mut key = [0x42; 32];
                key[0] = b;
                key
            })
            .find(|key| !is_usable_public_key(key))
            .unwrap();
        // Two points of small order: the identity, and the all-zero bytes.
        let mut identity = [0u8; 32];
        identity[0] = 1;

        let state = sample(&sender, &recipient);
        assert!(state.seal(&recipient.public_key()).is_ok());
        for bad in [not_a_point, identity, [0u8; 32]] {
            assert!(state.seal(&bad).is_err(), "{bad:02x?}");

            let mut listed = sample(&sender, &recipient);
            listed.members.push(StateMember {
                key: bad,
                role: MemberRole::Owner,
            });
            let sealed = listed.seal(&recipient.public_key()).unwrap();
            let opened = ChannelState::open(&recipient, &sealed).unwrap();
            assert_eq!(opened.members.len(), 3);
        }
    }

    /// T16. A state that carries a key for a version above its own is not
    /// valid: it can be neither sealed nor, sealed some other way, opened.
    /// Kept by the receiver, that key would become the channel's key at the
    /// removal that makes the version.
    #[test]
    fn a_key_above_the_current_version_is_not_a_valid_state() {
        let sender = NodeIdentity::generate().unwrap();
        let recipient = NodeIdentity::generate().unwrap();

        let mut state = sample(&sender, &recipient);
        assert!(state.validate().is_ok());
        state.keys.push((state.key_version + 1, [0x4a; 32]));
        assert!(state.validate().is_err());
        assert!(state.seal(&recipient.public_key()).is_err());

        let to = x25519_pub_from_ed25519_pub(&recipient.public_key()).unwrap();
        let sealed = ecies_encrypt(&to, &state.to_cbor().unwrap())
            .unwrap()
            .to_bytes();
        assert!(ChannelState::open(&recipient, &sealed).is_err());
    }

    #[test]
    fn test_decode_rejects_unknown_version() {
        let sender = NodeIdentity::generate().unwrap();
        let recipient = NodeIdentity::generate().unwrap();
        let cbor = sample(&sender, &recipient).to_cbor().unwrap();

        let mut value: Value = ciborium::from_reader(cbor.as_slice()).unwrap();
        if let Value::Map(entries) = &mut value {
            entries[0].1 = Value::Integer(2.into());
        }
        let mut reencoded = Vec::new();
        ciborium::into_writer(&value, &mut reencoded).unwrap();

        assert!(ChannelState::from_cbor(&reencoded).is_err());
    }

    #[test]
    fn test_name_is_optional() {
        let sender = NodeIdentity::generate().unwrap();
        let recipient = NodeIdentity::generate().unwrap();
        let mut state = sample(&sender, &recipient);
        state.name = None;
        state.personal = false;

        let decoded = ChannelState::from_cbor(&state.to_cbor().unwrap()).unwrap();
        assert_eq!(decoded, state);
    }
}
