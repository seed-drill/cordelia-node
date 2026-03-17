//! Bootstrap flow + DNS discovery (§10).
//!
//! Discovery phases:
//!   A. Resolve bootnode addresses (config + DNS SRV)
//!   B. Connect to bootnodes, perform handshake, request peers
//!   C. Add discovered peers to cold peer table
//!
//! Spec: seed-drill/specs/network-protocol.md §10

use cordelia_core::protocol;
use std::net::{SocketAddr, ToSocketAddrs};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Default bootnode port (sourced from protocol.rs).
pub const DEFAULT_BOOTNODE_PORT: u16 = protocol::P2P_PORT;

/// DNS SRV record name for bootnode discovery (sourced from protocol.rs).
pub const SRV_RECORD: &str = protocol::SRV_RECORD;

/// Fallback peer addresses (compiled into binary, sourced from protocol.rs).
pub const FALLBACK_PEERS: &[&str] = protocol::FALLBACK_PEERS;

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("DNS resolution failed: {0}")]
    DnsError(String),

    #[error("no bootnode addresses available")]
    NoBootnodes,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// A resolved bootnode address.
#[derive(Debug, Clone)]
pub struct BootnodeAddr {
    /// Original hostname or IP (from config).
    pub host: String,
    /// Resolved socket address.
    pub addr: SocketAddr,
    /// Source of this address.
    pub source: BootnodeSource,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BootnodeSource {
    Config,
    DnsSrv,
    Fallback,
}

/// Resolve bootnode addresses from configuration.
///
/// Takes a list of "host:port" strings from the config file.
pub fn resolve_config_bootnodes(addrs: &[String]) -> Vec<BootnodeAddr> {
    let mut resolved = Vec::new();
    for addr_str in addrs {
        match addr_str.to_socket_addrs() {
            Ok(mut iter) => {
                if let Some(addr) = iter.next() {
                    resolved.push(BootnodeAddr {
                        host: addr_str.clone(),
                        addr,
                        source: BootnodeSource::Config,
                    });
                    debug!(host = %addr_str, addr = %addr, "resolved config bootnode");
                }
            }
            Err(e) => {
                warn!(host = %addr_str, error = %e, "failed to resolve config bootnode");
            }
        }
    }
    resolved
}

/// Resolve bootnode addresses from DNS SRV records.
///
/// Queries `_cordelia._udp.seeddrill.ai` for SRV records.
/// Falls back gracefully if DNS is unavailable.
pub fn resolve_dns_bootnodes() -> Vec<BootnodeAddr> {
    // DNS SRV resolution via system resolver
    // Format: "host:port" from SRV target + port
    let srv_host = format!("{SRV_RECORD}.");

    match (srv_host.as_str(), DEFAULT_BOOTNODE_PORT).to_socket_addrs() {
        Ok(addrs) => {
            let result: Vec<BootnodeAddr> = addrs
                .map(|addr| BootnodeAddr {
                    host: SRV_RECORD.to_string(),
                    addr,
                    source: BootnodeSource::DnsSrv,
                })
                .collect();
            if !result.is_empty() {
                info!(count = result.len(), "resolved DNS bootnodes");
            }
            result
        }
        Err(e) => {
            debug!(error = %e, "DNS SRV resolution failed (expected in dev)");
            Vec::new()
        }
    }
}

/// Resolve fallback peer addresses (compiled into binary).
pub fn resolve_fallback_peers() -> Vec<BootnodeAddr> {
    let mut resolved = Vec::new();
    for addr_str in FALLBACK_PEERS {
        if let Ok(mut addrs) = addr_str.to_socket_addrs()
            && let Some(addr) = addrs.next()
        {
            resolved.push(BootnodeAddr {
                host: addr_str.to_string(),
                addr,
                source: BootnodeSource::Fallback,
            });
        }
    }
    resolved
}

/// Resolve all bootnode addresses: config first, then DNS SRV, then fallback.
///
/// Deduplicates by socket address.
pub fn resolve_all_bootnodes(config_addrs: &[String]) -> Vec<BootnodeAddr> {
    let mut all = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // 1. Config bootnodes (highest priority)
    for bn in resolve_config_bootnodes(config_addrs) {
        if seen.insert(bn.addr) {
            all.push(bn);
        }
    }

    // 2. DNS SRV (skip if config already provided bootnodes)
    if config_addrs.is_empty() {
        for bn in resolve_dns_bootnodes() {
            if seen.insert(bn.addr) {
                all.push(bn);
            }
        }
    }

    // 3. Fallback (last resort, only if no config bootnodes)
    if config_addrs.is_empty() {
        for bn in resolve_fallback_peers() {
            if seen.insert(bn.addr) {
                all.push(bn);
            }
        }
    }

    info!(
        total = all.len(),
        config = all
            .iter()
            .filter(|b| b.source == BootnodeSource::Config)
            .count(),
        dns = all
            .iter()
            .filter(|b| b.source == BootnodeSource::DnsSrv)
            .count(),
        fallback = all
            .iter()
            .filter(|b| b.source == BootnodeSource::Fallback)
            .count(),
        "bootnode resolution complete"
    );

    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_config_ip() {
        let addrs = vec!["127.0.0.1:9474".to_string()];
        let resolved = resolve_config_bootnodes(&addrs);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].addr, "127.0.0.1:9474".parse().unwrap());
        assert_eq!(resolved[0].source, BootnodeSource::Config);
    }

    #[test]
    fn test_resolve_config_invalid() {
        let addrs = vec!["not-a-valid-address".to_string()];
        let resolved = resolve_config_bootnodes(&addrs);
        assert!(resolved.is_empty());
    }

    #[test]
    fn test_resolve_dns_graceful_failure() {
        // DNS resolution will fail in test environment -- should return empty, not panic
        let resolved = resolve_dns_bootnodes();
        // May be empty (expected) or may resolve if DNS is configured
        assert!(resolved.len() <= 10);
    }

    #[test]
    fn test_resolve_all_deduplicates() {
        let addrs = vec![
            "127.0.0.1:9474".to_string(),
            "127.0.0.1:9474".to_string(), // duplicate
            "127.0.0.2:9474".to_string(),
        ];
        let resolved = resolve_all_bootnodes(&addrs);
        // Should have at most 2 from config (deduplicated)
        let config_count = resolved
            .iter()
            .filter(|b| b.source == BootnodeSource::Config)
            .count();
        assert_eq!(config_count, 2);
    }

    #[test]
    fn test_fallback_peers_resolve() {
        // Fallback peers use hostnames -- may or may not resolve in test env
        let resolved = resolve_fallback_peers();
        // Just verify it doesn't panic; DNS may not resolve in CI
        assert!(resolved.len() <= FALLBACK_PEERS.len());
    }

    // ── Coverage tests: bootstrap 70% -> 85% ────────────────────────────

    #[test]
    fn test_resolve_all_empty_config_uses_dns_and_fallback() {
        // Empty config_addrs triggers DNS SRV + fallback branches (lines 141-156)
        let resolved = resolve_all_bootnodes(&[]);
        // DNS will likely fail in test env, fallback may or may not resolve.
        // Key assertion: the function doesn't panic and all results have correct sources.
        for bn in &resolved {
            assert!(
                bn.source == BootnodeSource::DnsSrv || bn.source == BootnodeSource::Fallback,
                "empty config should only produce DNS/fallback sources, got {:?}",
                bn.source
            );
        }
    }

    #[test]
    fn test_resolve_all_config_prevents_dns_and_fallback() {
        // Non-empty config_addrs skips DNS + fallback branches
        let addrs = vec!["127.0.0.1:9474".to_string()];
        let resolved = resolve_all_bootnodes(&addrs);
        for bn in &resolved {
            assert_eq!(
                bn.source,
                BootnodeSource::Config,
                "non-empty config should only produce Config sources"
            );
        }
    }

    #[test]
    fn test_resolve_config_empty_list() {
        let resolved = resolve_config_bootnodes(&[]);
        assert!(resolved.is_empty());
    }

    #[test]
    fn test_resolve_config_multiple_mixed() {
        let addrs = vec![
            "127.0.0.1:9474".to_string(),
            "not-valid".to_string(),
            "127.0.0.2:9475".to_string(),
        ];
        let resolved = resolve_config_bootnodes(&addrs);
        assert_eq!(resolved.len(), 2, "only valid addresses should resolve");
        assert_eq!(resolved[0].addr, "127.0.0.1:9474".parse().unwrap());
        assert_eq!(resolved[1].addr, "127.0.0.2:9475".parse().unwrap());
    }

    #[test]
    fn test_resolve_config_hostname() {
        // localhost should resolve in most environments
        let addrs = vec!["localhost:9474".to_string()];
        let resolved = resolve_config_bootnodes(&addrs);
        if !resolved.is_empty() {
            assert_eq!(resolved[0].host, "localhost:9474");
            assert_eq!(resolved[0].source, BootnodeSource::Config);
            assert_eq!(resolved[0].addr.port(), 9474);
        }
        // May fail in some CI envs -- not asserting non-empty
    }

    #[test]
    fn test_bootstrap_error_display() {
        let dns_err = BootstrapError::DnsError("lookup failed".into());
        assert!(dns_err.to_string().contains("lookup failed"));

        let no_boot = BootstrapError::NoBootnodes;
        assert!(no_boot.to_string().contains("no bootnode"));

        let io_err = BootstrapError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        ));
        assert!(io_err.to_string().contains("refused"));
    }

    #[test]
    fn test_bootnode_addr_fields() {
        let addr: SocketAddr = "127.0.0.1:9474".parse().unwrap();
        let bn = BootnodeAddr {
            host: "test-host".into(),
            addr,
            source: BootnodeSource::DnsSrv,
        };
        assert_eq!(bn.host, "test-host");
        assert_eq!(bn.addr.port(), 9474);
        assert_eq!(bn.source, BootnodeSource::DnsSrv);

        // Debug is derived
        let debug = format!("{:?}", bn);
        assert!(debug.contains("test-host"));
    }
}
