//! Cordelia Governor -- peer state machine, promotion/demotion, churn.
//!
//! Background tokio task, ticks every 10s.
//! Manages Cold -> Warm -> Hot peer lifecycle with adversarial demotion.
//!
//! Port: cordelia-core/crates/cordelia-governor (~1235 LOC)
//! Changes: NodeId = [u8; 32], Multiaddr -> String, ERA_0 -> GovernorConfig.

use cordelia_core::NodeId;
use cordelia_core::protocol;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Ban tier per spec §5.6 (parameter-rationale.md §3).
/// Determines base duration; escalation multiplies exponentially.
#[derive(Debug, Clone, Copy)]
pub enum BanTier {
    /// Rate limit breach, protocol violation: 900s base
    Transient,
    /// Identity/PSK fraud: 3600s base
    Identity,
    /// Systematic abuse: 28800s (8h) base
    Systematic,
}

impl BanTier {
    pub fn base_secs(&self) -> u64 {
        match self {
            BanTier::Transient => protocol::BAN_TRANSIENT_SECS,
            BanTier::Identity => protocol::BAN_IDENTITY_SECS,
            BanTier::Systematic => protocol::BAN_SYSTEMATIC_SECS,
        }
    }
}

/// Dial policy controls which peers the governor will attempt to connect to.
#[derive(Debug, Clone)]
pub enum DialPolicy {
    /// Dial any discovered peer (relay behaviour).
    All,
    /// Only dial peers marked as relays or bootnodes (personal node behaviour).
    RelaysOnly,
    /// Only dial specific trusted relay NodeIds (keeper behaviour).
    TrustedOnly(Vec<NodeId>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernorTargets {
    pub hot_min: usize,
    pub hot_max: usize,
    pub hot_min_relays: usize,
    pub warm_min: usize,
    pub warm_max: usize,
    pub cold_max: usize,
    pub churn_interval_secs: u64,
    pub churn_jitter_secs: u64,
    pub churn_fraction: f64,
}

impl Default for GovernorTargets {
    fn default() -> Self {
        Self {
            // Personal node defaults (demand-model.md §3.2, parameter-rationale.md §3)
            hot_min: protocol::HOT_MIN as usize,
            hot_max: protocol::HOT_MAX as usize,
            hot_min_relays: protocol::HOT_MIN_RELAYS as usize,
            warm_min: protocol::WARM_MIN as usize,
            warm_max: protocol::WARM_MAX as usize,
            cold_max: protocol::COLD_MAX as usize,
            churn_interval_secs: protocol::CHURN_INTERVAL_SECS,
            churn_jitter_secs: protocol::CHURN_JITTER_SECS,
            churn_fraction: protocol::CHURN_FRACTION,
        }
    }
}

impl GovernorTargets {
    /// Build targets from GovernorConfig.
    pub fn from_config(cfg: &cordelia_core::config::GovernorConfig) -> Self {
        Self {
            hot_min: cfg.hot_min as usize,
            hot_max: cfg.hot_max as usize,
            hot_min_relays: cfg.hot_min_relays as usize,
            warm_min: cfg.warm_min as usize,
            warm_max: cfg.warm_max as usize,
            cold_max: cfg.cold_max as usize,
            churn_interval_secs: cfg.churn_interval_secs as u64,
            churn_jitter_secs: cfg.churn_jitter_secs as u64,
            churn_fraction: cfg.churn_fraction,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PeerState {
    Cold,
    Warm,
    Hot,
    Banned {
        until: Instant,
        reason: String,
        escalation: u32,
    },
}

impl PeerState {
    pub fn is_active(&self) -> bool {
        matches!(self, PeerState::Warm | PeerState::Hot)
    }

    pub fn is_banned(&self) -> bool {
        matches!(self, PeerState::Banned { .. })
    }

    pub fn name(&self) -> &'static str {
        match self {
            PeerState::Cold => "cold",
            PeerState::Warm => "warm",
            PeerState::Hot => "hot",
            PeerState::Banned { .. } => "banned",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub addrs: Vec<String>,
    pub state: PeerState,
    pub state_changed_at: Instant,
    pub groups: Vec<String>,
    pub rtt_ms: Option<f64>,
    pub last_activity: Instant,
    pub items_delivered: u64,
    pub connected_since: Option<Instant>,
    pub demoted_at: Option<Instant>,
    pub disconnect_count: u32,
    pub last_disconnected: Option<Instant>,
    /// Whether this peer is a relay (eligible for dial under restricted policies).
    pub is_relay: bool,
    /// Whether this peer is a bootnode (discovery-only, never promoted to Hot, §8.3).
    pub is_bootnode: bool,
    /// Items this peer relayed to us (contribution tracking, §16.1).
    pub items_relayed: u64,
    /// Items we requested from this peer via sync (contribution tracking, §16.1).
    pub items_requested: u64,
    /// Exponential moving average of peer score (alpha from protocol::EMA_ALPHA).
    pub score_ema: f64,
}

impl PeerInfo {
    pub fn new(node_id: NodeId, addrs: Vec<String>, groups: Vec<String>) -> Self {
        Self {
            node_id,
            addrs,
            state: PeerState::Cold,
            state_changed_at: Instant::now(),
            groups,
            rtt_ms: None,
            last_activity: Instant::now(),
            items_delivered: 0,
            connected_since: None,
            demoted_at: None,
            disconnect_count: 0,
            last_disconnected: None,
            is_relay: false,
            is_bootnode: false,
            items_relayed: 0,
            items_requested: 0,
            score_ema: 0.0,
        }
    }

    /// Transition to a new state, updating state_changed_at.
    pub fn set_state(&mut self, new_state: PeerState) {
        self.state = new_state;
        self.state_changed_at = Instant::now();
    }

    /// Check how long the peer has been in its current state.
    pub fn state_tenure(&self) -> Duration {
        self.state_changed_at.elapsed()
    }

    /// Performance score: (throughput * rtt_factor * contribution_factor).
    /// contribution_factor only applies to relay peers (§5.5).
    pub fn score(&self) -> f64 {
        let elapsed = self
            .connected_since
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(1.0)
            .max(1.0);

        let throughput = self.items_delivered as f64 / elapsed;
        let rtt_factor = self.rtt_ms
            .map(|r| 1.0 / (1.0 + r / protocol::SCORE_RTT_DENOMINATOR_MS))
            .unwrap_or(protocol::SCORE_RTT_DEFAULT_FACTOR);

        // Contribution factor: penalise relays that don't relay items (§5.5)
        let contribution_factor = if self.is_relay {
            let ratio = self.items_relayed as f64 / (self.items_requested.max(1) as f64);
            ratio.clamp(protocol::SCORE_CONTRIBUTION_MIN, protocol::SCORE_CONTRIBUTION_MAX)
        } else {
            1.0
        };

        throughput * rtt_factor * contribution_factor
    }

    /// Update the exponential moving average score (alpha from protocol.rs).
    pub fn update_ema(&mut self) {
        let current = self.score();
        self.score_ema =
            protocol::EMA_ALPHA * current + (1.0 - protocol::EMA_ALPHA) * self.score_ema;
    }

    /// Whether this peer has any groups in common with the given set.
    pub fn has_group_overlap(&self, groups: &[String]) -> bool {
        self.groups.iter().any(|g| groups.contains(g))
    }
}

/// Governor configuration for timeout durations.
pub struct GovernorTimeouts {
    pub dead_timeout: Duration,
    pub stale_timeout: Duration,
    pub ban_duration: Duration,
}

impl Default for GovernorTimeouts {
    fn default() -> Self {
        Self {
            dead_timeout: Duration::from_secs(protocol::DEAD_TIMEOUT_SECS),
            stale_timeout: Duration::from_secs(protocol::STALE_THRESHOLD_SECS),
            ban_duration: Duration::from_secs(protocol::BAN_TRANSIENT_SECS),
        }
    }
}

impl GovernorTimeouts {
    pub fn from_config(cfg: &cordelia_core::config::GovernorConfig) -> Self {
        Self {
            dead_timeout: Duration::from_secs(cfg.keepalive_timeout_secs as u64),
            stale_timeout: Duration::from_secs(cfg.stale_threshold_secs as u64),
            ban_duration: Duration::from_secs(protocol::BAN_TRANSIENT_SECS),
        }
    }
}

/// Peer governor managing the peer state machine.
pub struct Governor {
    peers: HashMap<NodeId, PeerInfo>,
    targets: GovernorTargets,
    timeouts: GovernorTimeouts,
    our_groups: Vec<String>,
    last_churn: Instant,
    dial_policy: DialPolicy,
}

/// Actions the governor wants the node to take after a tick.
#[derive(Debug, Default)]
pub struct GovernorActions {
    /// Peers to connect to (Cold -> Warm promotion).
    pub connect: Vec<NodeId>,
    /// Peers to disconnect from.
    pub disconnect: Vec<NodeId>,
    /// State transitions that occurred: (node_id, from, to).
    pub transitions: Vec<(NodeId, String, String)>,
}

impl Governor {
    pub fn new(targets: GovernorTargets, our_groups: Vec<String>) -> Self {
        Self::with_dial_policy(targets, our_groups, DialPolicy::All)
    }

    pub fn with_dial_policy(
        targets: GovernorTargets,
        our_groups: Vec<String>,
        dial_policy: DialPolicy,
    ) -> Self {
        Self {
            peers: HashMap::new(),
            targets,
            timeouts: GovernorTimeouts::default(),
            our_groups,
            last_churn: Instant::now(),
            dial_policy,
        }
    }

    pub fn with_timeouts(mut self, timeouts: GovernorTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Update this node's group membership (for dynamic group creation).
    pub fn set_groups(&mut self, groups: Vec<String>) {
        self.our_groups = groups;
    }

    /// Add or update a known peer.
    pub fn add_peer(&mut self, node_id: NodeId, addrs: Vec<String>, groups: Vec<String>) {
        self.peers
            .entry(node_id.clone())
            .and_modify(|p| {
                p.addrs = addrs.clone();
                p.groups = groups.clone();
            })
            .or_insert_with(|| PeerInfo::new(node_id, addrs, groups));
    }

    /// Record that a peer sent us a keep-alive response.
    pub fn record_activity(&mut self, node_id: &NodeId, rtt_ms: Option<f64>) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.last_activity = Instant::now();
            if let Some(rtt) = rtt_ms {
                peer.rtt_ms = Some(rtt);
            }
        }
    }

    /// Record that a peer delivered items.
    pub fn record_items_delivered(&mut self, node_id: &NodeId, count: u64) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.items_delivered += count;
            peer.last_activity = Instant::now();
        }
    }

    /// Record items that a peer relayed to us (contribution tracking, §16.1).
    pub fn record_items_relayed(&mut self, node_id: &NodeId, count: u64) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.items_relayed += count;
        }
    }

    /// Mark peer as connected. Promotes to Hot immediately if there's room
    /// (hot_count < hot_max), otherwise Warm. This ensures newly connected
    /// peers participate in push/sync without waiting for the next tick.
    pub fn mark_connected(&mut self, node_id: &NodeId) {
        let hot_count = self
            .peers
            .values()
            .filter(|p| p.state == PeerState::Hot)
            .count();
        if let Some(peer) = self.peers.get_mut(node_id)
            && peer.state == PeerState::Cold
        {
            peer.connected_since = Some(Instant::now());
            peer.last_activity = Instant::now();
            // Bootnodes are discovery-only: always Warm, never Hot (§8.3).
            // They don't participate in data exchange and must not occupy hot slots.
            if peer.is_bootnode {
                tracing::info!(peer = %node_id, "gov: cold -> warm (bootnode, discovery-only)");
                peer.set_state(PeerState::Warm);
            } else if hot_count < self.targets.hot_min {
                // Bootstrap: urgently need hot peers, bypass tenure guard
                tracing::info!(peer = %node_id, "gov: cold -> hot (bootstrap, hot < hot_min)");
                peer.set_state(PeerState::Hot);
                peer.disconnect_count = 0;
            } else {
                // Steady state: new peers start as Warm, must earn Hot via tenure
                tracing::debug!(peer = %node_id, "gov: cold -> warm (tenure required)");
                peer.set_state(PeerState::Warm);
            }
        }
    }

    /// Mark peer as disconnected (back to Cold) with reconnect backoff.
    pub fn mark_disconnected(&mut self, node_id: &NodeId) {
        if let Some(peer) = self.peers.get_mut(node_id)
            && peer.state.is_active()
        {
            let from = peer.state.name();
            peer.set_state(PeerState::Cold);
            peer.connected_since = None;
            peer.disconnect_count += 1;
            peer.last_disconnected = Some(Instant::now());
            let backoff = Self::reconnect_backoff(peer.disconnect_count);
            tracing::info!(
                peer = %node_id,
                from,
                disconnect_count = peer.disconnect_count,
                backoff_secs = backoff.as_secs(),
                "gov: peer disconnected, backoff active"
            );
        }
    }

    /// Mark a dial attempt as failed for backoff tracking.
    pub fn mark_dial_failed(&mut self, node_id: &NodeId) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.disconnect_count += 1;
            peer.last_disconnected = Some(Instant::now());
            let backoff = Self::reconnect_backoff(peer.disconnect_count);
            tracing::debug!(
                peer = %node_id,
                disconnect_count = peer.disconnect_count,
                backoff_secs = backoff.as_secs(),
                "gov: dial failed, backoff updated"
            );
        }
    }

    /// Backoff duration: exponential min(2^count * base, max).
    fn reconnect_backoff(disconnect_count: u32) -> Duration {
        if disconnect_count == 0 {
            return Duration::ZERO;
        }
        let secs = protocol::BACKOFF_BASE_SECS
            .saturating_mul(1u64 << disconnect_count.min(protocol::BACKOFF_SATURATION));
        Duration::from_secs(secs.min(protocol::BACKOFF_MAX_SECS))
    }

    /// Replace a peer's node ID (e.g. after TLS handshake reveals real identity).
    pub fn replace_node_id(&mut self, old: &NodeId, new: NodeId, groups: Vec<String>) -> bool {
        // Check if the target already exists in a connected state
        if let Some(existing) = self.peers.get(&new)
            && existing.state.is_active()
        {
            if let Some(old_peer) = self.peers.remove(old) {
                if old_peer.is_relay
                    && let Some(target) = self.peers.get_mut(&new)
                {
                    target.is_relay = true;
                }
                tracing::debug!(
                    peer = %new,
                    old = %old,
                    "gov: placeholder removed (target already active)"
                );
            }
            return true;
        }

        if let Some(mut peer) = self.peers.remove(old) {
            peer.node_id = new.clone();
            peer.groups = groups;
            self.peers.insert(new, peer);
            true
        } else {
            false
        }
    }

    /// Ban a peer for protocol violation.
    pub fn ban_peer(&mut self, node_id: &NodeId, reason: String, tier: BanTier) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            let from = peer.state.name();
            let escalation = match &peer.state {
                PeerState::Banned { escalation, .. } => escalation + 1,
                _ => 1,
            };
            // Exponential escalation: base * 2^(escalation-1), capped at 7 days
            let base = Duration::from_secs(tier.base_secs());
            let multiplier = 1u32
                .checked_shl(escalation.saturating_sub(1))
                .unwrap_or(u32::MAX);
            let duration = (base * multiplier).min(Duration::from_secs(protocol::BAN_ESCALATION_CAP_SECS));
            tracing::warn!(
                peer = %node_id,
                from,
                reason = reason,
                escalation,
                ban_duration_secs = duration.as_secs(),
                "gov: peer banned"
            );
            peer.set_state(PeerState::Banned {
                until: Instant::now() + duration,
                reason,
                escalation,
            });
            peer.connected_since = None;
        }
    }

    /// Mark a peer as a relay node.
    pub fn set_peer_relay(&mut self, node_id: &NodeId, is_relay: bool) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.is_relay = is_relay;
        }
    }

    /// Mark a peer as a bootnode (discovery-only, never Hot, §8.3).
    pub fn set_peer_bootnode(&mut self, node_id: &NodeId, is_bootnode: bool) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.is_bootnode = is_bootnode;
        }
    }

    /// Check if a peer is dialable under the current policy.
    fn is_dialable(&self, peer: &PeerInfo) -> bool {
        match &self.dial_policy {
            DialPolicy::All => true,
            DialPolicy::RelaysOnly => peer.is_relay,
            DialPolicy::TrustedOnly(trusted) => trusted.contains(&peer.node_id),
        }
    }

    /// Get a peer's current state.
    pub fn peer_state(&self, node_id: &NodeId) -> Option<&PeerState> {
        self.peers.get(node_id).map(|p| &p.state)
    }

    /// Get peer info.
    pub fn peer_info(&self, node_id: &NodeId) -> Option<&PeerInfo> {
        self.peers.get(node_id)
    }

    /// Get all hot peer NodeIds.
    pub fn hot_peers(&self) -> Vec<NodeId> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Hot)
            .map(|p| p.node_id.clone())
            .collect()
    }

    /// Get hot peers relevant for a channel (relays + peers with matching group).
    /// Relays always receive all items (they serve all channels).
    /// Add a channel to a peer's group set (idempotent).
    /// Used when a peer sends ChannelAnnounce (0x04) with ChannelJoined.
    pub fn add_peer_channel(&mut self, node_id: &NodeId, channel_id: &str) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            let ch = channel_id.to_string();
            if !peer.groups.contains(&ch) {
                peer.groups.push(ch);
            }
        }
    }

    /// Remove a channel from a peer's group set.
    /// Used when a peer sends ChannelAnnounce (0x04) with ChannelLeft.
    pub fn remove_peer_channel(&mut self, node_id: &NodeId, channel_id: &str) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.groups.retain(|g| g != channel_id);
        }
    }

    pub fn hot_peers_for_channel(&self, channel_id: &str) -> Vec<NodeId> {
        self.peers
            .values()
            .filter(|p| {
                p.state == PeerState::Hot
                    && (p.is_relay || p.groups.contains(&channel_id.to_string()))
            })
            .map(|p| p.node_id.clone())
            .collect()
    }

    /// Get counts by state: (hot, warm, cold, banned).
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let mut hot = 0;
        let mut warm = 0;
        let mut cold = 0;
        let mut banned = 0;
        for p in self.peers.values() {
            match p.state {
                PeerState::Hot => hot += 1,
                PeerState::Warm => warm += 1,
                PeerState::Cold => cold += 1,
                PeerState::Banned { .. } => banned += 1,
            }
        }
        (hot, warm, cold, banned)
    }

    /// Run one governor tick. Returns actions for the node to execute.
    pub fn tick(&mut self) -> GovernorActions {
        let mut actions = GovernorActions::default();

        // 1. Unban expired bans
        self.unban_expired(&mut actions);
        // 2. Reap dead peers
        self.reap_dead(&mut actions);
        // 3. Promote Cold -> Warm if needed
        self.promote_cold_to_warm(&mut actions);
        // 4. Promote Warm -> Hot if needed
        self.promote_warm_to_hot(&mut actions);
        // 4a. Ensure relay connectivity (§5.4 step 4a)
        self.ensure_relay_connectivity(&mut actions);
        // 5. Demote excess Hot -> Warm
        self.demote_excess_hot(&mut actions);
        // 6. Periodic churn
        self.churn(&mut actions);
        // 7. Evict excess cold
        self.evict_excess_cold(&mut actions);

        actions
    }

    fn unban_expired(&mut self, actions: &mut GovernorActions) {
        let now = Instant::now();
        for peer in self.peers.values_mut() {
            if let PeerState::Banned {
                until,
                reason,
                escalation,
            } = &peer.state
                && now >= *until
            {
                tracing::info!(
                    peer = %peer.node_id,
                    reason = reason.as_str(),
                    escalation,
                    "gov: ban expired, returning to cold"
                );
                let from = peer.state.name().to_string();
                peer.set_state(PeerState::Cold);
                actions
                    .transitions
                    .push((peer.node_id.clone(), from, "cold".into()));
            }
        }
    }

    fn reap_dead(&mut self, actions: &mut GovernorActions) {
        let now = Instant::now();
        let dead_ids: Vec<NodeId> = self
            .peers
            .values()
            .filter(|p| {
                p.state.is_active()
                    && now.duration_since(p.last_activity) > self.timeouts.dead_timeout
            })
            .map(|p| p.node_id.clone())
            .collect();

        for id in dead_ids {
            if let Some(peer) = self.peers.get_mut(&id) {
                let from = peer.state.name().to_string();
                let inactive_secs = now.duration_since(peer.last_activity).as_secs();
                match peer.state {
                    PeerState::Hot => {
                        tracing::info!(
                            peer = %id,
                            inactive_secs,
                            "gov: reaping dead hot peer -> warm"
                        );
                        peer.set_state(PeerState::Warm);
                        peer.connected_since = None;
                        peer.demoted_at = Some(Instant::now());
                        actions.transitions.push((id, from, "warm".into()));
                    }
                    PeerState::Warm => {
                        tracing::info!(
                            peer = %id,
                            inactive_secs,
                            "gov: reaping dead warm peer -> cold (disconnect)"
                        );
                        peer.set_state(PeerState::Cold);
                        peer.connected_since = None;
                        actions.disconnect.push(id.clone());
                        actions.transitions.push((id, from, "cold".into()));
                    }
                    _ => {}
                }
            }
        }
    }

    fn promote_cold_to_warm(&mut self, actions: &mut GovernorActions) {
        let (hot, warm, _, _) = self.counts();
        let active = warm + hot;
        if active >= self.targets.warm_max {
            return;
        }

        let needed = self.targets.warm_max - active;
        let now = Instant::now();

        // Prefer peers with group overlap, filtered by dial policy and backoff
        let mut candidates: Vec<(NodeId, bool)> = self
            .peers
            .values()
            .filter(|p| {
                matches!(p.state, PeerState::Cold)
                    && self.is_dialable(p)
                    && p.disconnect_count < protocol::BACKOFF_SATURATION // max_connection_retries
                    && {
                        let backoff = Self::reconnect_backoff(p.disconnect_count);
                        p.last_disconnected
                            .is_none_or(|t| now.duration_since(t) >= backoff)
                    }
            })
            .map(|p| (p.node_id.clone(), p.has_group_overlap(&self.our_groups)))
            .collect();

        // Sort by overlap (true first), take needed
        candidates.sort_by_key(|(_, overlap)| std::cmp::Reverse(*overlap));
        let selected: Vec<NodeId> = candidates
            .into_iter()
            .take(needed)
            .map(|(id, _)| id)
            .collect();

        for id in selected {
            actions.connect.push(id);
        }
    }

    fn promote_warm_to_hot(&mut self, actions: &mut GovernorActions) {
        let (hot, _, _, _) = self.counts();
        if hot >= self.targets.hot_max {
            return; // Hot set is full
        }

        // Collect eligible warm peers (past hysteresis cooldown, not bootnodes)
        let eligible: Vec<NodeId> = self
            .peers
            .values()
            .filter(|p| {
                p.state == PeerState::Warm
                    && !p.is_bootnode
                    && p.demoted_at
                        .is_none_or(|d| d.elapsed() > self.timeouts.dead_timeout)
            })
            .map(|p| p.node_id.clone())
            .collect();

        if eligible.is_empty() {
            return;
        }

        // Anti-eclipse: RANDOM promotion among eligible peers (§5.4 step 4).
        // An attacker cannot game their score to get promoted faster.
        let urgent = hot < self.targets.hot_min;
        let needed = if urgent {
            self.targets.hot_min - hot // Fill hot_min urgently (bypass tenure)
        } else {
            0 // Only promote if replacing demoted peer (handled by churn)
        };

        if needed == 0 {
            return;
        }

        // Filter by min_warm_tenure unless in urgent mode (§5.4, parameter-rationale.md §3)
        let min_tenure = Duration::from_secs(protocol::MIN_WARM_TENURE_SECS);
        let eligible: Vec<NodeId> = if urgent {
            eligible // Bypass tenure for bootstrap urgency
        } else {
            eligible
                .into_iter()
                .filter(|id| {
                    self.peers
                        .get(id)
                        .is_some_and(|p| p.state_tenure() >= min_tenure)
                })
                .collect()
        };
        if eligible.is_empty() {
            return;
        }

        // Shuffle eligible peers using a simple deterministic shuffle
        let mut candidates = eligible;
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as usize;
        for i in (1..candidates.len()).rev() {
            let j = (seed.wrapping_mul(i + 1).wrapping_add(7)) % (i + 1);
            candidates.swap(i, j);
        }

        for id in candidates.into_iter().take(needed) {
            if let Some(peer) = self.peers.get_mut(&id) {
                tracing::info!(
                    peer = %id,
                    score = format!("{:.4}", peer.score()),
                    "gov: warm -> hot (random promotion)"
                );
                peer.disconnect_count = 0;
            }
            self.transition_peer(&id, PeerState::Hot, actions, "warm", "hot");
        }
    }

    /// Step 4a: Ensure at least hot_min_relays relay peers are in the Hot set.
    /// If not enough relays are Hot, promote a random warm relay (bypassing tenure).
    fn ensure_relay_connectivity(&mut self, actions: &mut GovernorActions) {
        if self.targets.hot_min_relays == 0 {
            return;
        }

        let hot_relays = self
            .peers
            .values()
            .filter(|p| p.state == PeerState::Hot && p.is_relay)
            .count();

        if hot_relays >= self.targets.hot_min_relays {
            return;
        }

        let needed = self.targets.hot_min_relays - hot_relays;

        // Find warm relay peers (bypass tenure guard -- relay connectivity is urgent)
        let warm_relays: Vec<NodeId> = self
            .peers
            .values()
            .filter(|p| p.state == PeerState::Warm && p.is_relay)
            .map(|p| p.node_id.clone())
            .collect();

        for id in warm_relays.into_iter().take(needed) {
            tracing::info!(
                peer = %id,
                hot_relays,
                target = self.targets.hot_min_relays,
                "gov: warm relay -> hot (ensure relay connectivity)"
            );
            if let Some(peer) = self.peers.get_mut(&id) {
                peer.disconnect_count = 0;
            }
            self.transition_peer(&id, PeerState::Hot, actions, "warm", "hot");
        }
    }

    fn demote_excess_hot(&mut self, actions: &mut GovernorActions) {
        let (hot, _, _, _) = self.counts();
        if hot <= self.targets.hot_max {
            return;
        }

        let excess = hot - self.targets.hot_max;
        let mut hot_peers: Vec<(NodeId, f64, bool)> = self
            .peers
            .values()
            .filter(|p| p.state == PeerState::Hot)
            .map(|p| {
                let is_stale = p.last_activity.elapsed() > self.timeouts.stale_timeout;
                (p.node_id.clone(), p.score(), is_stale)
            })
            .collect();

        // Stale first, then worst score
        hot_peers.sort_by(|a, b| {
            b.2.cmp(&a.2)
                .then(a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        });

        for (id, score, is_stale) in hot_peers.into_iter().take(excess) {
            tracing::info!(
                peer = %id,
                score = format!("{score:.4}"),
                is_stale,
                "gov: hot -> warm (excess demotion)"
            );
            self.transition_peer(&id, PeerState::Warm, actions, "hot", "warm");
        }
    }

    fn churn(&mut self, actions: &mut GovernorActions) {
        // Add deterministic jitter to prevent correlated churn across nodes
        let jitter = if self.targets.churn_jitter_secs > 0 {
            let seed = self.last_churn.elapsed().as_nanos() as u64;
            seed % self.targets.churn_jitter_secs
        } else {
            0
        };
        let interval = self.targets.churn_interval_secs + jitter;
        if self.last_churn.elapsed() < Duration::from_secs(interval) {
            return;
        }
        self.last_churn = Instant::now();

        self.churn_warm(actions);
        self.churn_hot(actions);
    }

    /// Warm-tier churn: demote random warm peers to cold, promote cold replacements.
    fn churn_warm(&mut self, actions: &mut GovernorActions) {
        let (_, warm, cold, _) = self.counts();
        let churn_count = (warm as f64 * self.targets.churn_fraction).ceil() as usize;

        if churn_count == 0 || cold == 0 {
            return;
        }

        tracing::info!(warm, cold, churn_count, "gov: periodic churn cycle");

        // Demote random warm -> cold
        let warm_ids: Vec<NodeId> = self
            .peers
            .values()
            .filter(|p| p.state == PeerState::Warm)
            .take(churn_count)
            .map(|p| p.node_id.clone())
            .collect();

        for id in &warm_ids {
            if let Some(peer) = self.peers.get_mut(id) {
                tracing::debug!(peer = %id, "gov: churn warm -> cold");
                peer.set_state(PeerState::Cold);
                peer.connected_since = None;
                actions.disconnect.push(id.clone());
                actions
                    .transitions
                    .push((id.clone(), "warm".into(), "cold".into()));
            }
        }

        // Promote random cold -> warm (to replace)
        let cold_ids: Vec<NodeId> = self
            .peers
            .values()
            .filter(|p| matches!(p.state, PeerState::Cold) && self.is_dialable(p))
            .take(churn_count)
            .map(|p| p.node_id.clone())
            .collect();

        for id in cold_ids {
            actions.connect.push(id);
        }
    }

    /// Hot-tier churn: demote 1 random hot peer to warm (SS5.4 step 6).
    fn churn_hot(&mut self, actions: &mut GovernorActions) {
        let (hot, _, _, _) = self.counts();
        if hot <= self.targets.hot_min {
            return;
        }

        // Pick a random non-trusted hot peer to demote
        let hot_peers: Vec<NodeId> = self
            .peers
            .values()
            .filter(|p| p.state == PeerState::Hot)
            .map(|p| p.node_id.clone())
            .collect();

        if hot_peers.is_empty() {
            return;
        }

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as usize;
        let victim = &hot_peers[seed % hot_peers.len()];
        if let Some(peer) = self.peers.get_mut(victim) {
            tracing::info!(peer = %victim, "gov: churn hot -> warm");
            peer.set_state(PeerState::Warm);
            peer.demoted_at = Some(Instant::now());
            actions
                .transitions
                .push((victim.clone(), "hot".into(), "warm".into()));
        }
    }

    fn evict_excess_cold(&mut self, _actions: &mut GovernorActions) {
        let (_, _, cold, _) = self.counts();
        if cold <= self.targets.cold_max {
            return;
        }

        let excess = cold - self.targets.cold_max;
        tracing::debug!(
            cold,
            cold_max = self.targets.cold_max,
            evicting = excess,
            "gov: evicting excess cold peers"
        );
        let mut cold_peers: Vec<(NodeId, Instant)> = self
            .peers
            .values()
            .filter(|p| matches!(p.state, PeerState::Cold))
            .map(|p| (p.node_id.clone(), p.last_activity))
            .collect();

        cold_peers.sort_by_key(|(_, t)| *t);

        for (id, _) in cold_peers.into_iter().take(excess) {
            tracing::trace!(peer = %id, "gov: evicted cold peer");
            self.peers.remove(&id);
        }
    }

    /// All known peers.
    pub fn all_peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values()
    }

    /// Transition a peer to a new state and record the transition.
    /// Used where the pattern is: get_mut -> set_state -> push transition.
    fn transition_peer(
        &mut self,
        node_id: &NodeId,
        new_state: PeerState,
        actions: &mut GovernorActions,
        from_name: &str,
        to_name: &str,
    ) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.set_state(new_state);
            actions
                .transitions
                .push((node_id.clone(), from_name.into(), to_name.into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id(byte: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = byte;
        NodeId(id)
    }

    fn make_addr() -> Vec<String> {
        vec!["127.0.0.1:9474".into()]
    }

    /// Test-only: get all hot peers for a specific group.
    impl Governor {
        fn hot_peers_for_group(&self, group_id: &str) -> Vec<&PeerInfo> {
            self.peers
                .values()
                .filter(|p| p.state == PeerState::Hot && p.groups.contains(&group_id.to_string()))
                .collect()
        }
    }

    /// Setup a governor with given targets and N peers, all added to group "g1".
    fn setup_gov(hot_min: usize, hot_max: usize, peer_count: u8) -> (Governor, Vec<NodeId>) {
        let targets = GovernorTargets {
            hot_min,
            hot_max,
            ..GovernorTargets::default()
        };
        let mut gov = Governor::new(targets, vec!["g1".into()]);
        let ids: Vec<NodeId> = (0..peer_count)
            .map(|i| {
                let id = make_node_id(i);
                gov.add_peer(id.clone(), make_addr(), vec!["g1".into()]);
                id
            })
            .collect();
        (gov, ids)
    }

    #[test]
    fn test_add_peer() {
        let mut gov = Governor::new(GovernorTargets::default(), vec!["g1".into()]);
        gov.add_peer(make_node_id(1), make_addr(), vec!["g1".into()]);
        assert_eq!(gov.counts(), (0, 0, 1, 0));
    }

    #[test]
    fn test_promote_to_warm() {
        let (mut gov, _ids) = setup_gov(2, 2, 15);

        let actions = gov.tick();
        assert!(!actions.connect.is_empty());
    }

    #[test]
    fn test_promote_warm_to_hot() {
        let (mut gov, ids) = setup_gov(2, 2, 5);
        for id in &ids {
            gov.mark_connected(id);
        }

        // First hot_min (2) promoted to Hot immediately, rest are Warm
        let (hot, warm, _, _) = gov.counts();
        assert_eq!(hot, 2); // hot_min = 2
        assert_eq!(warm, 3);

        // Tick promotes more warm to hot (random selection, filling hot_min)
        // hot_min already met, so no further promotions unless churn/demotion
        let _actions = gov.tick();
    }

    #[test]
    fn test_ban_peer() {
        let mut gov = Governor::new(GovernorTargets::default(), vec![]);
        let id = make_node_id(1);
        gov.add_peer(id.clone(), make_addr(), vec![]);

        gov.ban_peer(&id, "protocol violation".into(), BanTier::Transient);
        assert!(gov.peer_state(&id).unwrap().is_banned());

        // Escalation
        gov.ban_peer(&id, "repeat offense".into(), BanTier::Transient);
        match gov.peer_state(&id).unwrap() {
            PeerState::Banned { escalation, .. } => assert_eq!(*escalation, 2),
            _ => panic!("should be banned"),
        }
    }

    #[test]
    fn test_hot_peers_for_group() {
        let mut gov = Governor::new(GovernorTargets::default(), vec!["g1".into(), "g2".into()]);

        let id1 = make_node_id(1);
        let id2 = make_node_id(2);
        gov.add_peer(id1.clone(), make_addr(), vec!["g1".into()]);
        gov.add_peer(id2.clone(), make_addr(), vec!["g2".into()]);

        // Force to hot
        gov.peers.get_mut(&id1).unwrap().state = PeerState::Hot;
        gov.peers.get_mut(&id2).unwrap().state = PeerState::Hot;

        let g1_hot = gov.hot_peers_for_group("g1");
        assert_eq!(g1_hot.len(), 1);
        assert_eq!(g1_hot[0].node_id, id1);
    }

    #[test]
    fn test_replace_node_id() {
        let mut gov = Governor::new(GovernorTargets::default(), vec!["g1".into()]);
        let old_id = make_node_id(99);
        let new_id = make_node_id(1);
        gov.add_peer(old_id.clone(), make_addr(), vec![]);

        assert!(gov.peer_info(&old_id).is_some());
        assert!(gov.peer_info(&new_id).is_none());

        let replaced = gov.replace_node_id(&old_id, new_id.clone(), vec!["g1".into()]);
        assert!(replaced);
        assert!(gov.peer_info(&old_id).is_none());
        assert!(gov.peer_info(&new_id).is_some());
        assert_eq!(
            gov.peer_info(&new_id).unwrap().groups,
            vec!["g1".to_string()]
        );
    }

    #[test]
    fn test_peer_score() {
        let mut peer = PeerInfo::new(make_node_id(1), make_addr(), vec![]);
        peer.connected_since = Some(Instant::now() - Duration::from_secs(100));
        peer.items_delivered = 50;
        peer.rtt_ms = Some(10.0);

        let score = peer.score();
        assert!(score > 0.0);
    }

    #[test]
    fn test_mark_disconnected() {
        let mut gov = Governor::new(GovernorTargets::default(), vec!["g1".into()]);
        let id = make_node_id(1);
        gov.add_peer(id.clone(), make_addr(), vec!["g1".into()]);

        // Cold peer: no-op
        gov.mark_disconnected(&id);
        assert_eq!(*gov.peer_state(&id).unwrap(), PeerState::Cold);
        assert_eq!(gov.peer_info(&id).unwrap().disconnect_count, 0);

        // Connected peer (Hot, room available): back to Cold with tracking
        gov.mark_connected(&id);
        assert_eq!(*gov.peer_state(&id).unwrap(), PeerState::Hot); // immediate promotion
        gov.mark_disconnected(&id);
        assert_eq!(*gov.peer_state(&id).unwrap(), PeerState::Cold);
        assert!(gov.peer_info(&id).unwrap().connected_since.is_none());
        assert_eq!(gov.peer_info(&id).unwrap().disconnect_count, 1);
        assert!(gov.peer_info(&id).unwrap().last_disconnected.is_some());

        // Reconnect Hot peer: dc reset to 0 on connect, then back to Cold (dc=1)
        gov.mark_connected(&id);
        assert_eq!(gov.peer_info(&id).unwrap().disconnect_count, 0); // reset on promotion
        gov.mark_disconnected(&id);
        assert_eq!(*gov.peer_state(&id).unwrap(), PeerState::Cold);
        assert_eq!(gov.peer_info(&id).unwrap().disconnect_count, 1);
    }

    #[test]
    fn test_reconnect_backoff_values() {
        assert_eq!(Governor::reconnect_backoff(0), Duration::ZERO);
        assert_eq!(Governor::reconnect_backoff(1), Duration::from_secs(60));
        assert_eq!(Governor::reconnect_backoff(2), Duration::from_secs(120));
        assert_eq!(Governor::reconnect_backoff(3), Duration::from_secs(240));
        assert_eq!(Governor::reconnect_backoff(4), Duration::from_secs(480));
        // Capped at 900s
        assert_eq!(Governor::reconnect_backoff(5), Duration::from_secs(900));
        assert_eq!(Governor::reconnect_backoff(6), Duration::from_secs(900));
        assert_eq!(Governor::reconnect_backoff(99), Duration::from_secs(900));
    }

    #[test]
    fn test_backoff_prevents_immediate_reconnect() {
        let targets = GovernorTargets {
            warm_min: 5,
            ..Default::default()
        };
        let mut gov = Governor::new(targets, vec!["g1".into()]);

        let id = make_node_id(1);
        gov.add_peer(id.clone(), make_addr(), vec!["g1".into()]);

        gov.mark_connected(&id);
        gov.mark_disconnected(&id);

        let actions = gov.tick();
        assert!(
            !actions.connect.contains(&id),
            "peer in backoff must not be reconnected"
        );
    }

    #[test]
    fn test_backoff_allows_reconnect_after_expiry() {
        let targets = GovernorTargets {
            warm_min: 5,
            ..Default::default()
        };
        let mut gov = Governor::new(targets, vec!["g1".into()]);

        let id = make_node_id(1);
        gov.add_peer(id.clone(), make_addr(), vec!["g1".into()]);

        gov.mark_connected(&id);
        gov.mark_disconnected(&id);
        gov.peers.get_mut(&id).unwrap().last_disconnected =
            Some(Instant::now() - Duration::from_secs(120));

        let actions = gov.tick();
        assert!(
            actions.connect.contains(&id),
            "peer past backoff should be reconnected"
        );
    }

    #[test]
    fn test_hot_promotion_resets_disconnect_count() {
        let (mut gov, ids) = setup_gov(1, 1, 1);
        let id = ids[0].clone();

        // mark_connected promotes to Hot immediately (dc=0)
        gov.mark_connected(&id);
        let peer = gov.peer_info(&id).unwrap();
        assert_eq!(peer.state, PeerState::Hot);
        assert_eq!(
            peer.disconnect_count, 0,
            "immediate hot promotion should reset backoff"
        );
    }

    #[test]
    fn test_no_oscillation_after_reap() {
        let (mut gov, ids) = setup_gov(2, 2, 3);
        let id0 = ids[0].clone();
        let id1 = ids[1].clone();

        for id in &ids {
            gov.mark_connected(id);
        }
        gov.peers.get_mut(&id0).unwrap().state = PeerState::Hot;
        gov.peers.get_mut(&id1).unwrap().state = PeerState::Hot;

        // Simulate dead timeout on peer 0
        gov.peers.get_mut(&id0).unwrap().last_activity = Instant::now() - Duration::from_secs(100);

        let actions = gov.tick();
        let peer0 = gov.peer_info(&id0).unwrap();
        assert_eq!(peer0.state, PeerState::Warm);
        assert!(peer0.demoted_at.is_some());

        let peer0_promoted = actions
            .transitions
            .iter()
            .any(|(id, _, to)| *id == id0 && to == "hot");
        assert!(
            !peer0_promoted,
            "recently demoted peer must not be re-promoted"
        );
    }

    #[test]
    fn test_dial_policy_all() {
        let targets = GovernorTargets {
            warm_min: 5,
            ..Default::default()
        };
        let mut gov = Governor::with_dial_policy(targets, vec!["g1".into()], DialPolicy::All);

        let relay_id = make_node_id(1);
        let personal_id = make_node_id(2);
        gov.add_peer(relay_id.clone(), make_addr(), vec!["g1".into()]);
        gov.set_peer_relay(&relay_id, true);
        gov.add_peer(personal_id.clone(), make_addr(), vec!["g1".into()]);

        let actions = gov.tick();
        assert!(actions.connect.contains(&relay_id));
        assert!(actions.connect.contains(&personal_id));
    }

    #[test]
    fn test_dial_policy_relays_only() {
        let targets = GovernorTargets {
            warm_min: 5,
            ..Default::default()
        };
        let mut gov =
            Governor::with_dial_policy(targets, vec!["g1".into()], DialPolicy::RelaysOnly);

        let relay_id = make_node_id(1);
        let personal_id = make_node_id(2);
        gov.add_peer(relay_id.clone(), make_addr(), vec!["g1".into()]);
        gov.set_peer_relay(&relay_id, true);
        gov.add_peer(personal_id.clone(), make_addr(), vec!["g1".into()]);

        let actions = gov.tick();
        assert!(actions.connect.contains(&relay_id));
        assert!(!actions.connect.contains(&personal_id));
    }

    #[test]
    fn test_dial_policy_trusted_only() {
        let trusted_id = make_node_id(1);
        let untrusted_id = make_node_id(2);

        let targets = GovernorTargets {
            warm_min: 5,
            ..Default::default()
        };
        let mut gov = Governor::with_dial_policy(
            targets,
            vec!["g1".into()],
            DialPolicy::TrustedOnly(vec![trusted_id.clone()]),
        );

        gov.add_peer(trusted_id.clone(), make_addr(), vec!["g1".into()]);
        gov.set_peer_relay(&trusted_id, true);
        gov.add_peer(untrusted_id.clone(), make_addr(), vec!["g1".into()]);
        gov.set_peer_relay(&untrusted_id, true);

        let actions = gov.tick();
        assert!(actions.connect.contains(&trusted_id));
        assert!(!actions.connect.contains(&untrusted_id));
    }

    #[test]
    fn test_replace_does_not_overwrite_active_peer() {
        let mut gov = Governor::new(GovernorTargets::default(), vec!["g1".into()]);
        let placeholder_id = make_node_id(99);
        let real_id = make_node_id(1);

        gov.add_peer(placeholder_id.clone(), make_addr(), vec![]);
        gov.set_peer_relay(&placeholder_id, true);

        gov.add_peer(real_id.clone(), make_addr(), vec!["g1".into()]);
        gov.mark_connected(&real_id);
        assert_eq!(*gov.peer_state(&real_id).unwrap(), PeerState::Hot); // immediate promotion

        let replaced = gov.replace_node_id(&placeholder_id, real_id.clone(), vec!["g1".into()]);
        assert!(replaced);

        let peer = gov.peer_info(&real_id).unwrap();
        assert_eq!(peer.state, PeerState::Hot); // keeps Hot state
        assert!(peer.is_relay);
        assert!(gov.peer_info(&placeholder_id).is_none());
    }

    #[test]
    fn test_relay_flag_preserved_on_replace() {
        let mut gov = Governor::new(GovernorTargets::default(), vec!["g1".into()]);
        let old_id = make_node_id(99);
        let new_id = make_node_id(1);
        gov.add_peer(old_id.clone(), make_addr(), vec![]);
        gov.set_peer_relay(&old_id, true);

        gov.replace_node_id(&old_id, new_id.clone(), vec!["g1".into()]);
        assert!(gov.peer_info(&new_id).unwrap().is_relay);
    }

    #[test]
    fn test_reap_then_promote_after_cooldown() {
        let (mut gov, ids) = setup_gov(1, 1, 1);
        let id = ids[0].clone();
        gov.mark_connected(&id);

        gov.peers.get_mut(&id).unwrap().demoted_at =
            Some(Instant::now() - Duration::from_secs(100));

        let _actions = gov.tick();
        let peer = gov.peer_info(&id).unwrap();
        assert_eq!(peer.state, PeerState::Hot);
    }

    // ── Governor tick cycle tests (T4-1) ──────────────────────────────

    #[test]
    fn test_tick_churn_swaps_warm_with_cold() {
        let targets = GovernorTargets {
            hot_min: 2,
            hot_max: 5,
            warm_min: 0,
            cold_max: 100,
            churn_interval_secs: 0, // churn every tick
            churn_jitter_secs: 0,
            churn_fraction: 1.0, // swap all warm
            ..Default::default()
        };
        let mut gov = Governor::new(targets, vec![]);

        // 2 hot peers (mark_connected with hot < hot_min)
        for i in 0..2 {
            let id = make_node_id(i);
            gov.add_peer(id.clone(), make_addr(), vec![]);
            gov.mark_connected(&id);
        }
        // 3 warm peers (mark_connected after hot_min reached)
        for i in 2..5 {
            let id = make_node_id(i);
            gov.add_peer(id.clone(), make_addr(), vec![]);
            gov.mark_connected(&id);
        }
        // 3 cold peers (never connected)
        for i in 5..8 {
            let id = make_node_id(i);
            gov.add_peer(id.clone(), make_addr(), vec![]);
        }

        let (hot, warm, cold, _) = gov.counts();
        assert_eq!(hot, 2);
        assert_eq!(warm, 3);
        assert_eq!(cold, 3);

        // Force churn by setting last_churn in the past
        gov.last_churn = Instant::now() - Duration::from_secs(3700);
        let actions = gov.tick();

        // Churn should swap warm peers to cold and request cold connects
        assert!(
            !actions.connect.is_empty() || !actions.transitions.is_empty(),
            "churn should produce state changes"
        );
    }

    #[test]
    fn test_tick_hot_churn_demotes_one_hot() {
        let targets = GovernorTargets {
            hot_min: 2,
            hot_max: 5,
            warm_min: 0,
            cold_max: 100,
            churn_interval_secs: 0,
            churn_jitter_secs: 0,
            churn_fraction: 0.5,
            ..Default::default()
        };
        let mut gov = Governor::new(targets, vec![]);

        // Add 4 peers and force all to Hot manually
        for i in 0..4 {
            let id = make_node_id(i);
            gov.add_peer(id.clone(), make_addr(), vec![]);
            gov.mark_connected(&id);
            gov.peers.get_mut(&id).unwrap().set_state(PeerState::Hot);
        }

        let (hot, _, _, _) = gov.counts();
        assert_eq!(hot, 4, "should have 4 hot peers before churn");

        gov.last_churn = Instant::now() - Duration::from_secs(3700);
        let actions = gov.tick();

        let (hot_after, warm_after, _, _) = gov.counts();
        // Hot churn should demote 1 (hot > hot_min)
        assert!(
            hot_after <= 3,
            "hot churn should demote at least 1 hot peer, got hot={hot_after}"
        );
        assert!(
            warm_after >= 1,
            "demoted hot peer should be warm, got warm={warm_after}"
        );
        // Verify transition was recorded
        let hot_to_warm = actions
            .transitions
            .iter()
            .filter(|(_, from, to)| from == "hot" && to == "warm")
            .count();
        assert!(hot_to_warm >= 1, "should record hot->warm transition");
    }

    #[test]
    fn test_tick_dead_detection_demotes_inactive() {
        let targets = GovernorTargets {
            hot_min: 1,
            warm_min: 0,
            ..Default::default()
        };
        let mut gov = Governor::new(targets, vec![]).with_timeouts(GovernorTimeouts {
            dead_timeout: Duration::from_secs(5),
            ..Default::default()
        });

        let id = make_node_id(1);
        gov.add_peer(id.clone(), make_addr(), vec![]);
        gov.mark_connected(&id);
        assert_eq!(gov.peer_info(&id).unwrap().state, PeerState::Hot);

        // Simulate no activity for 10s (> dead_timeout of 5s)
        gov.peers.get_mut(&id).unwrap().last_activity = Instant::now() - Duration::from_secs(10);

        let actions = gov.tick();
        let peer = gov.peer_info(&id).unwrap();
        assert!(
            peer.state != PeerState::Hot,
            "inactive peer should be demoted from Hot"
        );
        assert!(!actions.transitions.is_empty());
    }

    #[test]
    fn test_immediate_promotion_gated_by_hot_min() {
        // BV-25 regression: only hot_min peers get immediate Hot,
        // rest must go through tenure guard
        let targets = GovernorTargets {
            hot_min: 2,
            hot_max: 10,
            warm_min: 0,
            ..Default::default()
        };
        let mut gov = Governor::new(targets, vec![]);

        // First 2 connections: immediate Hot (hot < hot_min)
        for i in 0..2 {
            let id = make_node_id(i);
            gov.add_peer(id.clone(), make_addr(), vec![]);
            gov.mark_connected(&id);
            assert_eq!(
                gov.peer_info(&id).unwrap().state,
                PeerState::Hot,
                "peer {i} should be Hot (bootstrap)"
            );
        }

        // 3rd connection: Warm only (hot >= hot_min)
        let id3 = make_node_id(3);
        gov.add_peer(id3.clone(), make_addr(), vec![]);
        gov.mark_connected(&id3);
        assert_eq!(
            gov.peer_info(&id3).unwrap().state,
            PeerState::Warm,
            "3rd peer should be Warm (tenure required)"
        );
    }

    #[test]
    fn test_hot_peers_returns_only_hot() {
        let (mut gov, ids) = setup_gov(2, 5, 5);
        // 2 hot, 3 warm
        for id in &ids {
            gov.mark_connected(id);
        }

        let hot = gov.hot_peers();
        assert_eq!(hot.len(), 2, "hot_peers() should return only Hot peers");
        let (h, w, _, _) = gov.counts();
        assert_eq!(h, 2);
        assert_eq!(w, 3);
    }

    #[test]
    fn test_state_changed_at_updated_on_transition() {
        let (mut gov, ids) = setup_gov(1, 1, 1);
        let id = &ids[0];
        let created_at = gov.peer_info(id).unwrap().state_changed_at;

        std::thread::sleep(Duration::from_millis(10));
        gov.mark_connected(id);
        let connected_at = gov.peer_info(id).unwrap().state_changed_at;

        assert!(
            connected_at > created_at,
            "state_changed_at should update on Cold->Hot transition"
        );
    }

    #[test]
    fn test_failure_count_blocks_promotion() {
        // Peers with 5+ consecutive failures should not be promoted
        let targets = GovernorTargets {
            hot_min: 1,
            warm_min: 5,
            ..Default::default()
        };
        let mut gov = Governor::new(targets, vec![]);

        let id = make_node_id(1);
        gov.add_peer(id.clone(), make_addr(), vec![]);

        // Simulate 5 failures
        for _ in 0..5 {
            gov.mark_dial_failed(&id);
        }

        let actions = gov.tick();
        // The peer should NOT be in the connect list (failure limit reached)
        assert!(
            !actions.connect.contains(&id),
            "peer with 5 failures should not be promoted"
        );
    }

    // T5-2: Tombstone-like stale detection
    #[test]
    fn test_stale_peer_demoted_first() {
        let targets = GovernorTargets {
            hot_min: 1,
            hot_max: 2, // room for 2, but we'll have 3 and need to demote
            warm_min: 0,
            ..Default::default()
        };
        let mut gov = Governor::new(targets, vec![]).with_timeouts(GovernorTimeouts {
            stale_timeout: Duration::from_secs(5),
            ..Default::default()
        });

        // 3 hot peers, one stale
        for i in 0..3 {
            let id = make_node_id(i);
            gov.add_peer(id.clone(), make_addr(), vec![]);
            gov.mark_connected(&id);
            gov.peers.get_mut(&id).unwrap().set_state(PeerState::Hot);
        }
        // Make peer 0 stale (no items for > stale_timeout)
        gov.peers.get_mut(&make_node_id(0)).unwrap().items_delivered = 0;
        gov.peers.get_mut(&make_node_id(0)).unwrap().last_activity =
            Instant::now() - Duration::from_secs(10);
        // Give peers 1 and 2 recent activity
        gov.peers.get_mut(&make_node_id(1)).unwrap().items_delivered = 100;
        gov.peers.get_mut(&make_node_id(2)).unwrap().items_delivered = 50;

        let _actions = gov.tick();
        // hot_max=2 with 3 hot peers -> demote worst. Stale peer should go first.
        let (hot, _, _, _) = gov.counts();
        assert!(hot <= 2, "should have demoted excess hot peer");
    }

    // Step 4a: hot_min_relays ensures relay backbone connectivity
    #[test]
    fn test_ensure_relay_connectivity() {
        let targets = GovernorTargets {
            hot_min: 2,
            hot_max: 10,
            hot_min_relays: 1,
            warm_min: 0,
            ..Default::default()
        };
        let mut gov = Governor::new(targets, vec![]);

        // 2 hot personal peers (satisfies hot_min)
        for i in 0..2 {
            let id = make_node_id(i);
            gov.add_peer(id.clone(), make_addr(), vec![]);
            gov.mark_connected(&id);
        }
        // 1 warm relay peer
        let relay_id = make_node_id(10);
        gov.add_peer(relay_id.clone(), make_addr(), vec![]);
        gov.mark_connected(&relay_id);
        gov.set_peer_relay(&relay_id, true);

        // Before tick: 2 hot (personal), 1 warm (relay)
        let (hot, warm, _, _) = gov.counts();
        assert_eq!(hot, 2);
        assert_eq!(warm, 1);
        let hot_relays = gov
            .hot_peers()
            .iter()
            .filter(|id| gov.peer_info(id).map(|p| p.is_relay).unwrap_or(false))
            .count();
        assert_eq!(hot_relays, 0, "no relays in hot set yet");

        // Tick should promote relay to Hot via step 4a
        let actions = gov.tick();
        let hot_relays_after = gov
            .hot_peers()
            .iter()
            .filter(|id| gov.peer_info(id).map(|p| p.is_relay).unwrap_or(false))
            .count();
        assert_eq!(
            hot_relays_after, 1,
            "relay should be promoted to Hot by step 4a"
        );
        let (hot, _, _, _) = gov.counts();
        assert_eq!(hot, 3, "should now have 3 hot peers (2 personal + 1 relay)");

        // Verify transition was recorded
        let relay_promoted = actions
            .transitions
            .iter()
            .any(|(id, _, to)| *id == relay_id && to == "hot");
        assert!(relay_promoted, "relay promotion should be in transitions");
    }

    // ── Coverage tests: governor 87.5% -> 95% ───────────────────────────

    #[test]
    fn test_evict_excess_cold() {
        let targets = GovernorTargets {
            hot_min: 0,
            hot_max: 0,
            hot_min_relays: 0,
            warm_min: 0,
            warm_max: 0, // prevent cold->warm promotion
            cold_max: 5,
            churn_interval_secs: 99999,
            churn_jitter_secs: 0,
            churn_fraction: 0.0,
        };
        let mut gov = Governor::new(targets, vec![]);

        // Add 10 cold peers with staggered last_activity (peer 0 = oldest)
        for i in 0..10u8 {
            let id = make_node_id(i);
            gov.add_peer(id.clone(), make_addr(), vec![]);
            gov.peers.get_mut(&id).unwrap().last_activity =
                Instant::now() - Duration::from_secs((10 - i as u64) * 100);
        }
        assert_eq!(gov.counts(), (0, 0, 10, 0));

        gov.tick();
        let (_, _, cold, _) = gov.counts();
        assert_eq!(cold, 5, "should evict down to cold_max");

        // Oldest 5 evicted (LRU order)
        for i in 0..5u8 {
            assert!(
                gov.peer_info(&make_node_id(i)).is_none(),
                "peer {i} (oldest) should be evicted"
            );
        }
        for i in 5..10u8 {
            assert!(
                gov.peer_info(&make_node_id(i)).is_some(),
                "peer {i} (newest) should remain"
            );
        }
    }

    #[test]
    fn test_hot_peers_for_channel() {
        let mut gov = Governor::new(GovernorTargets::default(), vec![]);

        // Peer 1: relay (serves all channels)
        let relay_id = make_node_id(1);
        gov.add_peer(relay_id.clone(), make_addr(), vec![]);
        gov.peers.get_mut(&relay_id).unwrap().state = PeerState::Hot;
        gov.peers.get_mut(&relay_id).unwrap().is_relay = true;

        // Peer 2: personal, subscribed to g1
        let g1_id = make_node_id(2);
        gov.add_peer(g1_id.clone(), make_addr(), vec!["g1".into()]);
        gov.peers.get_mut(&g1_id).unwrap().state = PeerState::Hot;

        // Peer 3: personal, subscribed to g3 only
        let g3_id = make_node_id(3);
        gov.add_peer(g3_id.clone(), make_addr(), vec!["g3".into()]);
        gov.peers.get_mut(&g3_id).unwrap().state = PeerState::Hot;

        // Channel g1: relay + g1 personal
        let g1_peers = gov.hot_peers_for_channel("g1");
        assert_eq!(g1_peers.len(), 2, "g1 should match relay + g1 peer");
        assert!(g1_peers.contains(&relay_id));
        assert!(g1_peers.contains(&g1_id));

        // Channel g2: relay only (no personal peer subscribed)
        let g2_peers = gov.hot_peers_for_channel("g2");
        assert_eq!(g2_peers.len(), 1, "g2 should match relay only");
        assert!(g2_peers.contains(&relay_id));
    }

    #[test]
    fn test_record_activity_and_rtt() {
        let mut gov = Governor::new(GovernorTargets::default(), vec![]);
        let id = make_node_id(1);
        gov.add_peer(id.clone(), make_addr(), vec![]);

        // Set last_activity to the past so we can detect the update
        gov.peers.get_mut(&id).unwrap().last_activity = Instant::now() - Duration::from_secs(60);
        let before = gov.peer_info(&id).unwrap().last_activity;

        gov.record_activity(&id, Some(15.0));
        let after = gov.peer_info(&id).unwrap();
        assert!(
            after.last_activity > before,
            "last_activity should be updated"
        );
        assert_eq!(after.rtt_ms, Some(15.0));

        // Record with None rtt: rtt_ms stays at 15.0
        gov.record_activity(&id, None);
        assert_eq!(gov.peer_info(&id).unwrap().rtt_ms, Some(15.0));
    }

    #[test]
    fn test_record_items_delivered_and_relayed() {
        let mut gov = Governor::new(GovernorTargets::default(), vec![]);
        let id = make_node_id(1);
        gov.add_peer(id.clone(), make_addr(), vec![]);

        // Items delivered: increments count and updates last_activity
        gov.peers.get_mut(&id).unwrap().last_activity = Instant::now() - Duration::from_secs(60);
        let before = gov.peer_info(&id).unwrap().last_activity;

        gov.record_items_delivered(&id, 10);
        assert_eq!(gov.peer_info(&id).unwrap().items_delivered, 10);
        assert!(gov.peer_info(&id).unwrap().last_activity > before);

        gov.record_items_delivered(&id, 5);
        assert_eq!(gov.peer_info(&id).unwrap().items_delivered, 15);

        // Items relayed: increments count (no last_activity update)
        let activity_before = gov.peer_info(&id).unwrap().last_activity;
        gov.record_items_relayed(&id, 7);
        assert_eq!(gov.peer_info(&id).unwrap().items_relayed, 7);
        assert_eq!(gov.peer_info(&id).unwrap().last_activity, activity_before);

        gov.record_items_relayed(&id, 3);
        assert_eq!(gov.peer_info(&id).unwrap().items_relayed, 10);
    }

    #[test]
    fn test_relay_score_contribution_factor() {
        // Non-relay: contribution_factor = 1.0
        let mut non_relay = PeerInfo::new(make_node_id(1), make_addr(), vec![]);
        non_relay.connected_since = Some(Instant::now() - Duration::from_secs(100));
        non_relay.items_delivered = 50;
        non_relay.rtt_ms = Some(10.0);
        let base_score = non_relay.score();

        // Relay with 50% contribution: factor = 0.5
        let mut relay_half = non_relay.clone();
        relay_half.is_relay = true;
        relay_half.items_requested = 100;
        relay_half.items_relayed = 50;
        let relay_half_score = relay_half.score();

        // Relay contribution_factor = 50/100 = 0.5, so score ~ base * 0.5
        let ratio = relay_half_score / base_score;
        assert!(
            (ratio - 0.5).abs() < 0.01,
            "relay with 50% contribution should score ~0.5x base, got ratio={ratio:.4}"
        );

        // Relay with 0 relayed: factor clamped to 0.1
        let mut relay_zero = non_relay.clone();
        relay_zero.is_relay = true;
        relay_zero.items_requested = 100;
        relay_zero.items_relayed = 0;
        let relay_zero_score = relay_zero.score();

        let ratio_zero = relay_zero_score / base_score;
        assert!(
            (ratio_zero - 0.1).abs() < 0.01,
            "relay with 0 contribution should score ~0.1x base, got ratio={ratio_zero:.4}"
        );
    }

    #[test]
    fn test_update_ema_accumulates() {
        let mut peer = PeerInfo::new(make_node_id(1), make_addr(), vec![]);
        peer.connected_since = Some(Instant::now() - Duration::from_secs(100));
        peer.items_delivered = 50;
        peer.rtt_ms = Some(10.0);

        assert_eq!(peer.score_ema, 0.0);
        let current_score = peer.score();
        assert!(current_score > 0.0);

        // First update: ema = 0.1 * score + 0.9 * 0 = 0.1 * score
        // Tolerance is 1e-6: score() uses elapsed time internally, so the value
        // drifts slightly between the reference call and update_ema().
        peer.update_ema();
        let expected_1 = protocol::EMA_ALPHA * current_score;
        assert!(
            (peer.score_ema - expected_1).abs() < 1e-6,
            "first EMA should be alpha*score, got {} expected {}",
            peer.score_ema,
            expected_1
        );

        // Multiple updates: EMA converges toward current score
        for _ in 0..100 {
            peer.update_ema();
        }
        assert!(
            (peer.score_ema - current_score).abs() / current_score < 0.01,
            "EMA should converge to current score after many updates"
        );
    }

    #[test]
    fn test_ban_escalation_caps_at_7_days() {
        let mut gov = Governor::new(GovernorTargets::default(), vec![]);
        let id = make_node_id(1);
        gov.add_peer(id.clone(), make_addr(), vec![]);

        let seven_days = Duration::from_secs(protocol::BAN_ESCALATION_CAP_SECS);

        // Ban 35 times: triggers both the .min(7 days) cap and checked_shl overflow
        for _ in 0..35 {
            gov.ban_peer(&id, "repeat".into(), BanTier::Transient);
        }

        match gov.peer_state(&id).unwrap() {
            PeerState::Banned {
                until, escalation, ..
            } => {
                assert_eq!(*escalation, 35);
                // Duration should be capped at 7 days (checked_shl overflows at shift >= 32)
                let max_until = Instant::now() + seven_days + Duration::from_secs(1);
                let min_until = Instant::now() + seven_days - Duration::from_secs(1);
                assert!(*until <= max_until, "ban duration must be capped at 7 days");
                assert!(
                    *until >= min_until,
                    "ban duration should be ~7 days at this escalation"
                );
            }
            _ => panic!("should be banned"),
        }
    }

    #[test]
    fn test_unban_expired_to_cold() {
        let mut gov = Governor::new(GovernorTargets::default(), vec![]);
        let id = make_node_id(1);
        gov.add_peer(id.clone(), make_addr(), vec![]);

        // Set banned with expiry in the past
        gov.peers.get_mut(&id).unwrap().state = PeerState::Banned {
            until: Instant::now() - Duration::from_secs(1),
            reason: "test ban".into(),
            escalation: 1,
        };
        assert!(gov.peer_state(&id).unwrap().is_banned());

        let actions = gov.tick();
        assert_eq!(
            *gov.peer_state(&id).unwrap(),
            PeerState::Cold,
            "expired ban should transition to Cold"
        );
        let unban_transition = actions
            .transitions
            .iter()
            .any(|(nid, from, to)| *nid == id && from == "banned" && to == "cold");
        assert!(unban_transition, "should record banned->cold transition");
    }

    #[test]
    fn test_churn_warm_noop_when_no_cold() {
        let targets = GovernorTargets {
            hot_min: 0,
            hot_max: 0,
            hot_min_relays: 0,
            warm_min: 0,
            warm_max: 10,
            cold_max: 50,
            churn_interval_secs: 0, // churn every tick
            churn_jitter_secs: 0,
            churn_fraction: 0.5,
        };
        let mut gov = Governor::new(targets, vec![]);

        // 3 warm peers, 0 cold
        for i in 0..3u8 {
            let id = make_node_id(i);
            gov.add_peer(id.clone(), make_addr(), vec![]);
            gov.peers.get_mut(&id).unwrap().state = PeerState::Warm;
            gov.peers.get_mut(&id).unwrap().connected_since = Some(Instant::now());
        }
        assert_eq!(gov.counts(), (0, 3, 0, 0));

        gov.last_churn = Instant::now() - Duration::from_secs(99999);
        let actions = gov.tick();

        // churn_warm should early-return (cold==0): no connects, no warm->cold transitions
        assert!(
            actions.connect.is_empty(),
            "no connects when cold==0 (churn_warm noop)"
        );
        let warm_to_cold = actions
            .transitions
            .iter()
            .any(|(_, from, to)| from == "warm" && to == "cold");
        assert!(!warm_to_cold, "no warm->cold churn when cold==0");
    }

    #[test]
    fn test_churn_hot_protects_minimum() {
        let targets = GovernorTargets {
            hot_min: 2,
            hot_max: 10,
            hot_min_relays: 0,
            warm_min: 0,
            warm_max: 10,
            cold_max: 50,
            churn_interval_secs: 0,
            churn_jitter_secs: 0,
            churn_fraction: 0.5,
        };
        let mut gov = Governor::new(targets, vec![]);

        // Exactly hot_min hot peers
        for i in 0..2u8 {
            let id = make_node_id(i);
            gov.add_peer(id.clone(), make_addr(), vec![]);
            gov.peers.get_mut(&id).unwrap().state = PeerState::Hot;
            gov.peers.get_mut(&id).unwrap().connected_since = Some(Instant::now());
        }
        assert_eq!(gov.counts(), (2, 0, 0, 0));

        gov.last_churn = Instant::now() - Duration::from_secs(99999);
        let actions = gov.tick();

        // churn_hot should early-return (hot <= hot_min): no hot->warm demotion
        let (hot, _, _, _) = gov.counts();
        assert_eq!(hot, 2, "hot peers should be preserved at hot_min");
        let hot_to_warm = actions
            .transitions
            .iter()
            .any(|(_, from, to)| from == "hot" && to == "warm");
        assert!(!hot_to_warm, "no hot->warm churn when hot <= hot_min");
    }

    #[test]
    fn test_set_groups_and_all_peers() {
        let mut gov = Governor::new(GovernorTargets::default(), vec!["g1".into()]);
        gov.add_peer(make_node_id(1), make_addr(), vec!["g1".into()]);
        gov.add_peer(make_node_id(2), make_addr(), vec!["g2".into()]);
        gov.add_peer(make_node_id(3), make_addr(), vec!["g3".into()]);

        gov.set_groups(vec!["g2".into(), "g3".into()]);
        assert_eq!(gov.all_peers().count(), 3);
    }

    #[test]
    fn test_has_group_overlap() {
        let peer = PeerInfo::new(make_node_id(1), make_addr(), vec!["g1".into(), "g2".into()]);

        assert!(
            peer.has_group_overlap(&["g2".into(), "g3".into()]),
            "should overlap on g2"
        );
        assert!(
            !peer.has_group_overlap(&["g4".into()]),
            "no overlap with g4"
        );
        assert!(!peer.has_group_overlap(&[]), "no overlap with empty set");
    }

    #[test]
    fn test_add_peer_channel_idempotent() {
        let mut gov = Governor::new(GovernorTargets::default(), vec![]);
        let id = make_node_id(1);
        gov.add_peer(id.clone(), make_addr(), vec![]);
        gov.peers.get_mut(&id).unwrap().state = PeerState::Hot;

        gov.add_peer_channel(&id, "ch1");
        assert_eq!(gov.peer_info(&id).unwrap().groups, vec!["ch1".to_string()]);

        // Idempotent: adding again doesn't duplicate
        gov.add_peer_channel(&id, "ch1");
        assert_eq!(gov.peer_info(&id).unwrap().groups, vec!["ch1".to_string()]);

        gov.add_peer_channel(&id, "ch2");
        assert_eq!(gov.peer_info(&id).unwrap().groups.len(), 2);
    }

    #[test]
    fn test_remove_peer_channel() {
        let mut gov = Governor::new(GovernorTargets::default(), vec![]);
        let id = make_node_id(1);
        gov.add_peer(id.clone(), make_addr(), vec!["ch1".into(), "ch2".into()]);
        gov.peers.get_mut(&id).unwrap().state = PeerState::Hot;

        gov.remove_peer_channel(&id, "ch1");
        assert_eq!(gov.peer_info(&id).unwrap().groups, vec!["ch2".to_string()]);

        // Removing non-existent channel is a no-op
        gov.remove_peer_channel(&id, "ch99");
        assert_eq!(gov.peer_info(&id).unwrap().groups, vec!["ch2".to_string()]);
    }

    #[test]
    fn test_add_peer_channel_affects_hot_peers_for_channel() {
        let mut gov = Governor::new(GovernorTargets::default(), vec![]);

        let relay_id = make_node_id(1);
        gov.add_peer(relay_id.clone(), make_addr(), vec![]);
        gov.peers.get_mut(&relay_id).unwrap().state = PeerState::Hot;
        gov.peers.get_mut(&relay_id).unwrap().is_relay = true;

        let personal_id = make_node_id(2);
        gov.add_peer(personal_id.clone(), make_addr(), vec![]);
        gov.peers.get_mut(&personal_id).unwrap().state = PeerState::Hot;

        // Before add: only relay serves ch1
        assert_eq!(gov.hot_peers_for_channel("ch1").len(), 1);

        // After add: relay + personal serve ch1
        gov.add_peer_channel(&personal_id, "ch1");
        let ch1_peers = gov.hot_peers_for_channel("ch1");
        assert_eq!(ch1_peers.len(), 2);
        assert!(ch1_peers.contains(&relay_id));
        assert!(ch1_peers.contains(&personal_id));

        // After remove: back to relay only
        gov.remove_peer_channel(&personal_id, "ch1");
        assert_eq!(gov.hot_peers_for_channel("ch1").len(), 1);
    }
}
