//! Configuration parsing for config.toml.
//!
//! Spec: seed-drill/specs/configuration.md
//! All parameters have defaults -- an empty config file is valid.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::CordeliaError;

/// Top-level configuration (mirrors config.toml structure).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub identity: IdentityConfig,
    pub node: NodeConfig,
    pub network: NetworkConfig,
    pub governor: GovernorConfig,
    pub replication: ReplicationConfig,
    pub limits: LimitsConfig,
    pub history: HistoryConfig,
    pub messages: MessagesConfig,
    pub api: ApiConfig,
    pub logging: LoggingConfig,
    pub swarm: SwarmConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    pub entity_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    pub http_port: u16,
    pub p2p_port: u16,
    pub data_dir: String,
    pub max_storage_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub role: String,
    pub push_policy: String,
    /// No longer used: a node learns of no relay from DNS. Kept so that
    /// configurations that set it still load.
    pub dns_discovery: String,
    #[serde(default)]
    pub bootnodes: Vec<BootnodeConfig>,
    /// Trusted peers for Personal Area Network (§8.2.2).
    /// Swarm nodes use dial_policy=trusted_only and connect only to these peers.
    /// Lead nodes accept inbound from these peers (exception to outbound-only).
    #[serde(default)]
    pub trusted_peers: Vec<TrustedPeerConfig>,
    /// Allow private/RFC-1918 addresses in peer sharing (for Docker/test envs).
    #[serde(default)]
    pub allow_private_addresses: bool,
    /// Whether to accept inbound connections. Unset, a personal node does
    /// not, and has no listening socket (decision 2026-09-30 §4.6); every
    /// other role does. Set it on a personal node that others dial
    /// directly, such as a swarm lead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<bool>,
}

impl NetworkConfig {
    /// Whether this node listens for inbound connections. A personal node
    /// only dials out, unless it is told to listen or has trusted peers
    /// (§8.2.2), which may dial it.
    pub fn accepts_inbound(&self) -> bool {
        self.listen
            .unwrap_or(self.role != "personal" || !self.trusted_peers.is_empty())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootnodeConfig {
    /// Where the relay is dialled: `host:port`.
    pub addr: String,
    /// The relay's public key (`cordelia_pk1...`). When set, any other key
    /// answering at `addr` is refused. The default relays' keys are
    /// compiled in and need not be given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// Trusted peer for Personal Area Network (§8.2.2).
/// Swarm nodes connect only to trusted peers. Lead nodes accept
/// inbound from trusted peers (exception to outbound-only rule).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeerConfig {
    /// Ed25519 public key in Bech32 format (cordelia_pk1...).
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GovernorConfig {
    pub hot_min: u32,
    pub hot_max: u32,
    pub hot_min_relays: u32,
    pub warm_min: u32,
    pub warm_max: u32,
    pub cold_max: u32,
    pub tick_interval_secs: u32,
    pub churn_interval_secs: u32,
    pub churn_jitter_secs: u32,
    pub churn_fraction: f64,
    pub min_warm_tenure_secs: u32,
    pub hysteresis_secs: u32,
    pub keepalive_timeout_secs: u32,
    pub stale_threshold_secs: u32,
    pub ema_alpha: f64,
    pub max_connection_retries: u32,
    pub clear_failure_delay_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplicationConfig {
    pub sync_interval_realtime_secs: u32,
    pub sync_interval_batch_secs: u32,
    pub tombstone_retention_days: u32,
    pub max_batch_size: u32,
    /// How long a relay waits before it asks a device again which channels
    /// it holds, and before it takes again a channel it dropped.
    pub relay_ask_again_secs: u64,
}

/// Local history: the text of a memory file as it was before sync replaced
/// or removed it (decision 2026-09-30 §4.5b). Read when the node starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HistoryConfig {
    /// How long a kept text stays. 0 turns history off and removes what
    /// is kept.
    pub days: u32,
    /// The most that is kept. Over it, the oldest records go first.
    pub max_bytes: u64,
}

/// Messages between the person's own agents (decision 2026-10-09 §6).
/// Read when the node starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MessagesConfig {
    /// The most messages the agent of one folder sends in an hour. It may
    /// lower AGENT_MESSAGES_PER_FOLDER_PER_HOUR and may not raise it: the
    /// device's limit and the ring are sized on that. 0 turns sending off
    /// for every folder of the device. Over it, the configuration is
    /// refused when it is loaded.
    pub per_folder_per_hour: u32,
}

impl MessagesConfig {
    /// Refuse a limit above the protocol's own (decision 2026-10-09 §6).
    fn check(&self) -> Result<(), CordeliaError> {
        if self.per_folder_per_hour as usize > protocol::AGENT_MESSAGES_PER_FOLDER_PER_HOUR {
            return Err(CordeliaError::Config(format!(
                "[messages] per_folder_per_hour is {}: it may be from 0 to {}, and may lower \
                 a folder's limit but not raise it",
                self.per_folder_per_hour,
                protocol::AGENT_MESSAGES_PER_FOLDER_PER_HOUR
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub max_inbound_connections: u32,
    pub max_connections_per_ip: u32,
    pub max_item_bytes: u64,
    pub writes_per_channel_per_minute: u32,
    /// The most channels whose keys one connection proves: what a relay
    /// remembers for a connection, and what a device sends on one. It
    /// can only be set lower than MAX_CHANNELS_PROVED_ON_A_CONNECTION,
    /// which is what both ends go by. No deployment sets it: a test
    /// lowers it, on a relay and on its devices alike.
    pub channels_proved_on_a_connection: u32,
}

impl LimitsConfig {
    /// The most channels whose keys one connection proves, as it is
    /// used: what is configured, no fewer than 2 and no more than the
    /// protocol's own bound.
    pub fn most_proved_on_a_connection(&self) -> usize {
        (self.channels_proved_on_a_connection as usize)
            .clamp(2, protocol::MAX_CHANNELS_PROVED_ON_A_CONNECTION)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub bind_address: String,
    pub token_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub output: String,
}

/// Swarm / Personal Area Network configuration (§8.2.2).
///
/// Set by `cordelia swarm-init` for child nodes. Lead nodes leave this empty.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SwarmConfig {
    /// HKDF derivation index for this swarm node's identity.
    /// None means this is not a swarm child node.
    pub swarm_index: Option<u32>,
    /// Path to the lead node's identity.key (used for derivation verification).
    pub lead_identity_path: Option<String>,
    /// Entity ID of the lead node (used for persistent swarm channel name).
    pub lead_entity_id: Option<String>,
}

// ── Defaults (configuration.md §3, sourced from protocol.rs) ───────

use crate::protocol;

// Config and IdentityConfig use #[derive(Default)] -- all fields have Default impls.

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            http_port: protocol::HTTP_PORT,
            p2p_port: protocol::P2P_PORT,
            data_dir: "~/.cordelia".into(),
            max_storage_bytes: protocol::MAX_STORAGE_BYTES,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: format!("0.0.0.0:{}", protocol::P2P_PORT),
            role: "personal".into(),
            push_policy: "subscribers_only".into(),
            dns_discovery: String::new(),
            bootnodes: protocol::FALLBACK_PEERS
                .iter()
                .zip(protocol::FALLBACK_PEER_KEYS)
                .map(|(addr, key)| BootnodeConfig {
                    addr: (*addr).into(),
                    key: Some((*key).into()),
                })
                .collect(),
            trusted_peers: Vec::new(),
            allow_private_addresses: false,
            listen: None,
        }
    }
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            hot_min: protocol::HOT_MIN,
            hot_max: protocol::HOT_MAX,
            hot_min_relays: protocol::HOT_MIN_RELAYS,
            warm_min: protocol::WARM_MIN,
            warm_max: protocol::WARM_MAX,
            cold_max: protocol::COLD_MAX,
            tick_interval_secs: protocol::TICK_INTERVAL_SECS as u32,
            churn_interval_secs: protocol::CHURN_INTERVAL_SECS as u32,
            churn_jitter_secs: protocol::CHURN_JITTER_SECS as u32,
            churn_fraction: protocol::CHURN_FRACTION,
            min_warm_tenure_secs: protocol::MIN_WARM_TENURE_SECS as u32,
            hysteresis_secs: protocol::HYSTERESIS_SECS as u32,
            keepalive_timeout_secs: protocol::DEAD_TIMEOUT_SECS as u32,
            stale_threshold_secs: protocol::STALE_THRESHOLD_SECS as u32,
            ema_alpha: protocol::EMA_ALPHA,
            max_connection_retries: protocol::MAX_CONNECTION_RETRIES,
            clear_failure_delay_secs: protocol::CLEAR_FAILURE_DELAY_SECS as u32,
        }
    }
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            sync_interval_realtime_secs: protocol::REALTIME_SYNC_INTERVAL_SECS as u32,
            sync_interval_batch_secs: protocol::BATCH_SYNC_INTERVAL_SECS as u32,
            tombstone_retention_days: protocol::TOMBSTONE_RETENTION_DAYS,
            max_batch_size: protocol::MAX_BATCH_SIZE as u32,
            relay_ask_again_secs: protocol::RELAY_ASK_AGAIN_SECS,
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_inbound_connections: protocol::MAX_INBOUND_CONNECTIONS as u32,
            max_connections_per_ip: protocol::MAX_CONNECTIONS_PER_IP as u32,
            max_item_bytes: protocol::MAX_ITEM_BYTES as u64,
            writes_per_channel_per_minute: protocol::WRITES_PER_CHANNEL_PER_MINUTE,
            channels_proved_on_a_connection: protocol::MAX_CHANNELS_PROVED_ON_A_CONNECTION as u32,
        }
    }
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            days: protocol::HISTORY_DAYS,
            max_bytes: protocol::HISTORY_MAX_BYTES,
        }
    }
}

impl Default for MessagesConfig {
    fn default() -> Self {
        Self {
            per_folder_per_hour: protocol::AGENT_MESSAGES_PER_FOLDER_PER_HOUR as u32,
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".into(),
            token_path: "~/.cordelia/node-token".into(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: "text".into(),
            output: "stderr".into(),
        }
    }
}

// ── Loading and saving ─────────────────────────────────────────────

impl Config {
    /// Load config from a TOML file. Returns defaults if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self, CordeliaError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| CordeliaError::Config(format!("parse config: {e}")))?;
        config.messages.check()?;
        Ok(config)
    }

    /// Save config to a TOML file.
    pub fn save(&self, path: &Path) -> Result<(), CordeliaError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| CordeliaError::Config(format!("serialize config: {e}")))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Apply environment variable overrides (configuration.md §4).
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("CORDELIA_HTTP_PORT")
            && let Ok(port) = v.parse()
        {
            self.node.http_port = port;
        }
        if let Ok(v) = std::env::var("CORDELIA_P2P_PORT")
            && let Ok(port) = v.parse()
        {
            self.node.p2p_port = port;
        }
        if let Ok(v) = std::env::var("CORDELIA_DATA_DIR") {
            self.node.data_dir = v;
        }
        if let Ok(v) = std::env::var("CORDELIA_LOG_LEVEL") {
            self.logging.level = v;
        }
        if let Ok(v) = std::env::var("CORDELIA_LOG_FORMAT") {
            self.logging.format = v;
        }
        if let Ok(v) = std::env::var("CORDELIA_LISTEN_ADDR") {
            self.network.listen_addr = v;
        }
        if let Ok(v) = std::env::var("CORDELIA_BIND_ADDRESS") {
            self.api.bind_address = v;
        }
        if let Ok(v) = std::env::var("CORDELIA_SWARM_INDEX")
            && let Ok(idx) = v.parse()
        {
            self.swarm.swarm_index = Some(idx);
        }
        if let Ok(v) = std::env::var("CORDELIA_LEAD_IDENTITY_PATH") {
            self.swarm.lead_identity_path = Some(v);
        }
        if let Ok(v) = std::env::var("CORDELIA_LEAD_ENTITY_ID") {
            self.swarm.lead_entity_id = Some(v);
        }
    }

    /// Resolve the data directory, expanding tilde.
    pub fn data_dir(&self) -> PathBuf {
        expand_tilde(&self.node.data_dir)
    }

    /// Resolve the token file path.
    ///
    /// If token_path is the default ("~/.cordelia/node-token"), resolve
    /// relative to data_dir so that overriding data_dir moves everything.
    pub fn token_path(&self) -> PathBuf {
        if self.api.token_path == "~/.cordelia/node-token" {
            self.data_dir().join("node-token")
        } else {
            expand_tilde(&self.api.token_path)
        }
    }
}

/// Expand `~` to the user's home directory.
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    if path == "~"
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home);
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.node.http_port, protocol::HTTP_PORT);
        assert_eq!(config.node.p2p_port, protocol::P2P_PORT);
        assert_eq!(config.api.bind_address, "127.0.0.1");
        assert_eq!(config.logging.level, "info");
        // max_item_bytes follows the protocol constant (64 KB)
        assert_eq!(
            config.limits.max_item_bytes,
            protocol::MAX_ITEM_BYTES as u64
        );
        // D4 fix: hot_max = 2 (was 20)
        assert_eq!(config.governor.hot_max, protocol::HOT_MAX);
        // D5 fix: warm_min = 3 (was 10), warm_max = 10 (was 50)
        assert_eq!(config.governor.warm_min, protocol::WARM_MIN);
        assert_eq!(config.governor.warm_max, protocol::WARM_MAX);
        // D6 fix: cold_max = 50 (was 200)
        assert_eq!(config.governor.cold_max, protocol::COLD_MAX);
    }

    /// The most channels whose keys one connection proves is the
    /// protocol's own bound, and can only be set lower: what is set
    /// higher, or to less than two, is taken as the nearest.
    #[test]
    fn test_the_proofs_on_a_connection_can_only_be_set_lower() {
        let most = |set: u32| {
            let mut config = Config::default();
            config.limits.channels_proved_on_a_connection = set;
            config.limits.most_proved_on_a_connection()
        };
        assert_eq!(
            Config::default().limits.most_proved_on_a_connection(),
            1_024
        );
        assert_eq!(most(16), 16);
        assert_eq!(most(1_023), 1_023);
        assert_eq!(most(1_025), 1_024);
        assert_eq!(most(u32::MAX), 1_024);
        assert_eq!(most(2), 2);
        assert_eq!(most(1), 2);
        assert_eq!(most(0), 2);
        let set: Config =
            toml::from_str("[limits]\nchannels_proved_on_a_connection = 16\n").unwrap();
        assert_eq!(set.limits.most_proved_on_a_connection(), 16);
    }

    #[test]
    fn test_round_trip_toml() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.node.http_port, protocol::HTTP_PORT);
    }

    #[test]
    fn test_partial_config() {
        let partial = r#"
[node]
http_port = 8080
"#;
        let config: Config = toml::from_str(partial).unwrap();
        assert_eq!(config.node.http_port, 8080);
        assert_eq!(config.node.p2p_port, protocol::P2P_PORT); // default preserved
    }

    /// Local history is on unless it is turned off: 30 days and 256 MB,
    /// each of which can be set by itself. 0 days is read as it is given,
    /// and turns history off.
    #[test]
    fn test_history_is_on_by_default_and_can_be_set() {
        let of = |toml: &str| -> (u32, u64) {
            let config: Config = toml::from_str(toml).unwrap();
            (config.history.days, config.history.max_bytes)
        };
        assert_eq!(of(""), (30, 256 * 1024 * 1024));
        assert_eq!(
            of(""),
            (protocol::HISTORY_DAYS, protocol::HISTORY_MAX_BYTES)
        );
        assert_eq!(of("[history]\ndays = 7\n"), (7, 256 * 1024 * 1024));
        assert_eq!(of("[history]\nmax_bytes = 1024\n"), (30, 1024));
        assert_eq!(of("[history]\ndays = 0\nmax_bytes = 0\n"), (0, 0));
        // And it is written out with the rest.
        let written = toml::to_string_pretty(&Config::default()).unwrap();
        assert!(written.contains("[history]\ndays = 30\n"), "{written}");
    }

    /// A folder's limit of messages in an hour is 20 where it is not set,
    /// can be set from 0 to 20, and a configuration that sets it over 20
    /// is refused when it is loaded (decision 2026-10-09 §6).
    #[test]
    fn test_a_folders_limit_of_messages_is_from_0_to_20() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let loaded = |toml: &str| {
            std::fs::write(&path, toml).unwrap();
            Config::load(&path).map(|config| config.messages.per_folder_per_hour)
        };
        assert_eq!(loaded("").unwrap(), 20);
        assert_eq!(
            loaded("").unwrap() as usize,
            protocol::AGENT_MESSAGES_PER_FOLDER_PER_HOUR
        );
        assert_eq!(loaded("[messages]\nper_folder_per_hour = 0\n").unwrap(), 0);
        assert_eq!(loaded("[messages]\nper_folder_per_hour = 7\n").unwrap(), 7);
        assert_eq!(
            loaded("[messages]\nper_folder_per_hour = 20\n").unwrap(),
            20
        );
        let over = loaded("[messages]\nper_folder_per_hour = 21\n").unwrap_err();
        assert!(
            over.to_string().contains("per_folder_per_hour is 21"),
            "{over}"
        );
        assert!(loaded("[messages]\nper_folder_per_hour = -1\n").is_err());
        // And it is written out with the rest.
        let written = toml::to_string_pretty(&Config::default()).unwrap();
        assert!(
            written.contains("[messages]\nper_folder_per_hour = 20\n"),
            "{written}"
        );
    }

    #[test]
    fn test_only_personal_nodes_do_not_listen() {
        let with = |toml: &str| -> bool {
            let config: Config = toml::from_str(toml).unwrap();
            config.network.accepts_inbound()
        };
        // The default role is personal: it dials out and does not listen.
        assert!(!with(""));
        assert!(!with("[network]\nrole = \"personal\"\n"));
        for role in ["relay", "bootnode", "keeper"] {
            assert!(with(&format!("[network]\nrole = \"{role}\"\n")), "{role}");
        }
        // A personal node listens when told to, or when it has trusted
        // peers, which may dial it.
        assert!(with("[network]\nlisten = true\n"));
        assert!(with(
            "[[network.trusted_peers]]\npublic_key = \"cordelia_pk1x\"\n"
        ));
        assert!(!with(
            "[network]\nlisten = false\n[[network.trusted_peers]]\npublic_key = \"cordelia_pk1x\"\n"
        ));
        // And any role can be kept from listening.
        assert!(!with("[network]\nrole = \"relay\"\nlisten = false\n"));

        // The option is not written to a config that does not set it.
        let written = toml::to_string_pretty(&Config::default()).unwrap();
        assert!(!written.contains("listen ="), "{written}");
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let config = Config::load(Path::new("/nonexistent/config.toml")).unwrap();
        assert_eq!(config.node.http_port, protocol::HTTP_PORT);
    }

    #[test]
    fn test_swarm_config_defaults_to_none() {
        let config = Config::default();
        assert!(config.swarm.swarm_index.is_none());
        assert!(config.swarm.lead_identity_path.is_none());
        assert!(config.swarm.lead_entity_id.is_none());
    }

    #[test]
    fn test_swarm_config_round_trip() {
        let partial = r#"
[swarm]
swarm_index = 7
lead_identity_path = "/tmp/lead/identity.key"
lead_entity_id = "lead_a1b2"
"#;
        let config: Config = toml::from_str(partial).unwrap();
        assert_eq!(config.swarm.swarm_index, Some(7));
        assert_eq!(
            config.swarm.lead_identity_path.as_deref(),
            Some("/tmp/lead/identity.key")
        );
        assert_eq!(config.swarm.lead_entity_id.as_deref(), Some("lead_a1b2"));

        // Round-trip
        let serialized = toml::to_string_pretty(&config).unwrap();
        let reparsed: Config = toml::from_str(&serialized).unwrap();
        assert_eq!(reparsed.swarm.swarm_index, Some(7));
    }

    #[test]
    fn test_swarm_config_env_override() {
        let mut config = Config::default();
        // SAFETY: test-only, single-threaded test
        unsafe {
            std::env::set_var("CORDELIA_SWARM_INDEX", "3");
            std::env::set_var("CORDELIA_LEAD_ENTITY_ID", "lead_test");
        }
        config.apply_env_overrides();
        assert_eq!(config.swarm.swarm_index, Some(3));
        assert_eq!(config.swarm.lead_entity_id.as_deref(), Some("lead_test"));
        unsafe {
            std::env::remove_var("CORDELIA_SWARM_INDEX");
            std::env::remove_var("CORDELIA_LEAD_ENTITY_ID");
        }
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let mut config = Config::default();
        config.identity.entity_id = "test_a1b2".into();
        config.save(&path).unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.identity.entity_id, "test_a1b2");
    }
}
