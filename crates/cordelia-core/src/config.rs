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
    pub api: ApiConfig,
    pub logging: LoggingConfig,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootnodeConfig {
    pub addr: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub max_inbound_connections: u32,
    pub max_connections_per_ip: u32,
    pub max_item_bytes: u64,
    pub writes_per_channel_per_minute: u32,
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
            dns_discovery: protocol::SRV_RECORD.into(),
            bootnodes: protocol::FALLBACK_PEERS
                .iter()
                .map(|addr| BootnodeConfig {
                    addr: (*addr).into(),
                })
                .collect(),
            trusted_peers: Vec::new(),
            allow_private_addresses: false,
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
        // D2 fix: max_item_bytes = 256KB (was 1MB)
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

    #[test]
    fn test_load_nonexistent_returns_default() {
        let config = Config::load(Path::new("/nonexistent/config.toml")).unwrap();
        assert_eq!(config.node.http_port, protocol::HTTP_PORT);
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
