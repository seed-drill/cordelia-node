//! Seen table for epidemic relay forwarding (network-protocol.md §7.2).
//!
//! Tracks which peers have seen each content hash, enabling loop-free
//! multi-hop forwarding across the relay mesh. Each entry records the
//! set of peers that have already received (or sent) a given item.
//!
//! Shared via `Arc<RwLock<SeenTable>>` between the inbound push handler
//! (records senders) and the repush flush timer (computes forward targets).

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use cordelia_core::NodeId;

/// Content hash: SHA-256 of the item payload.
pub type ContentHash = [u8; 32];

/// A single seen table entry tracking which peers have seen an item.
pub struct SeenEntry {
    /// Peers that have sent or been forwarded this item.
    pub peers: HashSet<NodeId>,
    /// When this entry was first created (for TTL eviction).
    pub first_seen: Instant,
}

/// Epidemic forwarding seen table.
///
/// Records which peers have seen each item (by content hash).
/// Used to compute forward targets (hot relay peers minus seen set)
/// and to prevent forwarding loops.
pub struct SeenTable {
    entries: HashMap<ContentHash, SeenEntry>,
}

impl SeenTable {
    /// Create an empty seen table.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Record that `sender` has seen the item with `hash`.
    /// Creates a new entry if absent.
    pub fn record_sender(&mut self, hash: &ContentHash, sender: &NodeId) {
        self.entries
            .entry(*hash)
            .or_insert_with(|| SeenEntry {
                peers: HashSet::new(),
                first_seen: Instant::now(),
            })
            .peers
            .insert(sender.clone());
    }

    /// Return hot relay peers that have NOT seen this item.
    /// If the hash is unknown, returns all peers (new item, no one has seen it).
    pub fn forward_targets(
        &self,
        hash: &ContentHash,
        hot_relay_peers: &[NodeId],
    ) -> Vec<NodeId> {
        match self.entries.get(hash) {
            Some(entry) => hot_relay_peers
                .iter()
                .filter(|p| !entry.peers.contains(p))
                .cloned()
                .collect(),
            None => hot_relay_peers.to_vec(),
        }
    }

    /// Record that `targets` will be forwarded this item (pre-send).
    /// Prevents double-sends if the flush fires again before delivery.
    pub fn record_targets(&mut self, hash: &ContentHash, targets: &[NodeId]) {
        if let Some(entry) = self.entries.get_mut(hash) {
            for t in targets {
                entry.peers.insert(t.clone());
            }
        }
    }

    /// Evict expired entries (TTL sweep), then cap at SEEN_TABLE_MAX
    /// by removing oldest entries first.
    pub fn evict(&mut self) {
        let ttl = std::time::Duration::from_secs(
            cordelia_core::protocol::SEEN_TABLE_TTL_SECS,
        );
        let now = Instant::now();

        // TTL sweep
        self.entries.retain(|_, entry| now.duration_since(entry.first_seen) < ttl);

        // Cap enforcement: remove oldest first
        let max = cordelia_core::protocol::SEEN_TABLE_MAX;
        if self.entries.len() > max {
            let mut by_age: Vec<(ContentHash, Instant)> = self
                .entries
                .iter()
                .map(|(h, e)| (*h, e.first_seen))
                .collect();
            by_age.sort_by_key(|(_, t)| *t);
            let to_remove = self.entries.len() - max;
            for (hash, _) in by_age.into_iter().take(to_remove) {
                self.entries.remove(&hash);
            }
        }
    }

    /// Number of entries currently tracked.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> ContentHash {
        let mut h = [0u8; 32];
        h[0] = n;
        h
    }

    fn node(n: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = n;
        NodeId(id)
    }

    #[test]
    fn empty_table() {
        let st = SeenTable::new();
        assert_eq!(st.len(), 0);
    }

    #[test]
    fn record_sender_creates_entry() {
        let mut st = SeenTable::new();
        st.record_sender(&hash(1), &node(1));
        assert_eq!(st.len(), 1);
    }

    #[test]
    fn record_sender_idempotent() {
        let mut st = SeenTable::new();
        st.record_sender(&hash(1), &node(1));
        st.record_sender(&hash(1), &node(1));
        assert_eq!(st.len(), 1);
        // Peer set still has 1 entry
        let targets = st.forward_targets(&hash(1), &[node(1)]);
        assert!(targets.is_empty());
    }

    #[test]
    fn forward_targets_excludes_seen() {
        let mut st = SeenTable::new();
        st.record_sender(&hash(1), &node(1));
        let peers = vec![node(1), node(2), node(3)];
        let targets = st.forward_targets(&hash(1), &peers);
        assert_eq!(targets.len(), 2);
        assert!(!targets.contains(&node(1)));
        assert!(targets.contains(&node(2)));
        assert!(targets.contains(&node(3)));
    }

    #[test]
    fn unknown_hash_returns_all() {
        let st = SeenTable::new();
        let peers = vec![node(1), node(2)];
        let targets = st.forward_targets(&hash(99), &peers);
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn record_targets_adds_to_seen() {
        let mut st = SeenTable::new();
        st.record_sender(&hash(1), &node(1));
        st.record_targets(&hash(1), &[node(2), node(3)]);
        let targets = st.forward_targets(&hash(1), &[node(1), node(2), node(3), node(4)]);
        assert_eq!(targets, vec![node(4)]);
    }

    #[test]
    fn evict_removes_expired() {
        let mut st = SeenTable::new();
        // Insert with artificially old timestamp
        st.entries.insert(
            hash(1),
            SeenEntry {
                peers: HashSet::new(),
                first_seen: Instant::now() - std::time::Duration::from_secs(700),
            },
        );
        st.entries.insert(
            hash(2),
            SeenEntry {
                peers: HashSet::new(),
                first_seen: Instant::now(),
            },
        );
        assert_eq!(st.len(), 2);
        st.evict();
        assert_eq!(st.len(), 1);
        assert!(st.entries.contains_key(&hash(2)));
    }

    #[test]
    fn evict_caps_over_capacity() {
        let mut st = SeenTable::new();
        // Insert SEEN_TABLE_MAX + 10 entries
        let max = cordelia_core::protocol::SEEN_TABLE_MAX;
        for i in 0..(max + 10) {
            let mut h = [0u8; 32];
            h[0] = (i & 0xFF) as u8;
            h[1] = ((i >> 8) & 0xFF) as u8;
            st.entries.insert(h, SeenEntry {
                peers: HashSet::new(),
                first_seen: Instant::now(),
            });
        }
        assert!(st.len() > max);
        st.evict();
        assert_eq!(st.len(), max);
    }

    #[test]
    fn first_seen_not_refreshed() {
        let mut st = SeenTable::new();
        st.record_sender(&hash(1), &node(1));
        let t1 = st.entries.get(&hash(1)).unwrap().first_seen;
        // Small delay to ensure different Instant
        std::thread::sleep(std::time::Duration::from_millis(1));
        st.record_sender(&hash(1), &node(2));
        let t2 = st.entries.get(&hash(1)).unwrap().first_seen;
        assert_eq!(t1, t2);
    }

    #[test]
    fn full_flow() {
        let mut st = SeenTable::new();
        let peers = vec![node(1), node(2), node(3), node(4)];

        // Sender pushes item
        st.record_sender(&hash(1), &node(1));

        // Compute targets: everyone except sender
        let targets = st.forward_targets(&hash(1), &peers);
        assert_eq!(targets.len(), 3);

        // Record targets before sending
        st.record_targets(&hash(1), &targets);

        // Second forward attempt: no new targets
        let targets2 = st.forward_targets(&hash(1), &peers);
        assert!(targets2.is_empty());

        // New peer joins: should get item
        let expanded = vec![node(1), node(2), node(3), node(4), node(5)];
        let targets3 = st.forward_targets(&hash(1), &expanded);
        assert_eq!(targets3, vec![node(5)]);
    }
}
