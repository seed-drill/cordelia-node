//! Configuration parsing for config.toml.
//!
//! Spec: seed-drill/specs/configuration.md
//! All parameters have defaults -- an empty config file is valid.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::CordeliaError;

/// Top-level configuration (mirrors config.toml structure).
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Allow private/RFC-1918 addresses in peer sharing (for Docker/test envs).
    #[serde(default)]
    pub allow_private_addresses: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootnodeConfig {
    pub addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GovernorConfig {
    pub hot_min: u32,
    pub hot_max: u32,
    pub warm_min: u32,
    pub warm_max: u32,
    pub cold_max: u32,
    pub tick_interval_secs: u32,
    pub churn_interval_secs: u32,
    pub churn_fraction: f64,
    pub min_warm_tenure_secs: u32,
    pub hysteresis_secs: u32,
    pub keepalive_timeout_secs: u32,
    pub stale_threshold_secs: u32,
    pub ema_alpha: f64,
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

// ── Defaults (configuration.md §3) ─────────────────────────────────

impl Default for Config {
    fn default() -> Self {
        Self {
            identity: IdentityConfig::default(),
            node: NodeConfig::default(),
            network: NetworkConfig::default(),
            governor: GovernorConfig::default(),
            replication: ReplicationConfig::default(),
            limits: LimitsConfig::default(),
            api: ApiConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            entity_id: String::new(),
            public_key: String::new(),
        }
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            http_port: 9473,
            p2p_port: 9474,
            data_dir: "~/.cordelia".into(),
            max_storage_bytes: 1_073_741_824, // 1 GB
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:9474".into(),
            role: "personal".into(),
            push_policy: "subscribers_only".into(),
            dns_discovery: "_cordelia._udp.seeddrill.ai".into(),
            bootnodes: vec![
                BootnodeConfig {
                    addr: "boot1.cordelia.seeddrill.ai:9474".into(),
                },
                BootnodeConfig {
                    addr: "boot2.cordelia.seeddrill.ai:9474".into(),
                },
            ],
            allow_private_addresses: false,
        }
    }
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            hot_min: 2,
            hot_max: 20,
            warm_min: 10,
            warm_max: 50,
            cold_max: 100,
            tick_interval_secs: 10,
            churn_interval_secs: 3600,
            churn_fraction: 0.2,
            min_warm_tenure_secs: 300,
            hysteresis_secs: 90,
            keepalive_timeout_secs: 90,
            stale_threshold_secs: 1800,
            ema_alpha: 0.1,
        }
    }
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            sync_interval_realtime_secs: 60,
            sync_interval_batch_secs: 900,
            tombstone_retention_days: 7,
            max_batch_size: 100,
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_inbound_connections: 200,
            max_connections_per_ip: 5,
            max_item_bytes: 1_048_576, // 1 MB
            writes_per_channel_per_minute: 100,
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
        if let Ok(v) = std::env::var("CORDELIA_HTTP_PORT") {
            if let Ok(port) = v.parse() {
                self.node.http_port = port;
            }
        }
        if let Ok(v) = std::env::var("CORDELIA_P2P_PORT") {
            if let Ok(port) = v.parse() {
                self.node.p2p_port = port;
            }
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
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.node.http_port, 9473);
        assert_eq!(config.node.p2p_port, 9474);
        assert_eq!(config.api.bind_address, "127.0.0.1");
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn test_round_trip_toml() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.node.http_port, 9473);
    }

    #[test]
    fn test_partial_config() {
        let partial = r#"
[node]
http_port = 8080
"#;
        let config: Config = toml::from_str(partial).unwrap();
        assert_eq!(config.node.http_port, 8080);
        assert_eq!(config.node.p2p_port, 9474); // default preserved
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let config = Config::load(Path::new("/nonexistent/config.toml")).unwrap();
        assert_eq!(config.node.http_port, 9473);
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
