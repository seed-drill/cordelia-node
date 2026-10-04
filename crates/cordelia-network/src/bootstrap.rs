//! The relays a node was configured with, and their addresses.
//!
//! A relay is a name and a key: the name says where to dial, and the key is
//! what must answer there. A node dials only the relays it was configured
//! with (the two default relays, for a personal node that names none), and
//! refuses any other key at a relay's address. It learns of no relay from
//! DNS or from another peer.

use std::net::{SocketAddr, ToSocketAddrs};

use cordelia_core::protocol;
use tracing::{debug, warn};

/// The default relays' names (compiled into the binary).
pub const FALLBACK_PEERS: &[&str] = protocol::FALLBACK_PEERS;

/// A relay this node was configured with: the `host:port` it is dialled at
/// and the key that must answer there. A relay configured without a key is
/// accepted with whichever key answers, as before keys could be configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    pub host: String,
    pub key: Option<[u8; 32]>,
}

/// A configured relay with its name resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAddr {
    pub host: String,
    pub addr: SocketAddr,
    pub key: Option<[u8; 32]>,
}

/// The key of a default relay, by the name it is dialled at.
pub fn default_relay_key(host: &str) -> Option<[u8; 32]> {
    let at = protocol::FALLBACK_PEERS.iter().position(|h| *h == host)?;
    cordelia_crypto::bech32::decode_public_key(protocol::FALLBACK_PEER_KEYS[at]).ok()
}

/// The relays a node dials: those in its configuration (`host:port` and an
/// optional `cordelia_pk1...` key each) or, with `use_defaults` and none
/// configured, the default relays.
///
/// - A default relay named without a key gets the key compiled into the
///   binary, so configurations written before keys existed are covered.
/// - Only personal nodes use the defaults: a relay given none stands
///   alone, and never dials relays it was not told about.
/// - A key that does not parse is an error. Dialling without the check the
///   operator asked for would be worse than not starting.
pub fn configured_relays(
    configured: &[(String, Option<String>)],
    use_defaults: bool,
) -> Result<Vec<Relay>, String> {
    relays_from(configured, use_defaults)
}

/// The relays a node of `role` dials, given the relays its configuration
/// names. This is the one place that says so: the node asks it when it
/// starts, and so does whatever needs to know beforehand where a node
/// will dial.
///
/// - A bootnode dials no relay, whatever it names. (It dials the addresses
///   its peers share.)
/// - A personal node dials the relays it names, or the default ones where
///   it names none.
/// - Any other node dials the relays it names, and none where it names
///   none.
pub fn relays_dialled(
    role: &str,
    configured: &[(String, Option<String>)],
) -> Result<Vec<Relay>, String> {
    if role == "bootnode" {
        return Ok(Vec::new());
    }
    relays_from(configured, role == "personal")
}

fn relays_from(
    configured: &[(String, Option<String>)],
    use_defaults: bool,
) -> Result<Vec<Relay>, String> {
    if configured.is_empty() {
        if !use_defaults {
            return Ok(Vec::new());
        }
        return Ok(protocol::FALLBACK_PEERS
            .iter()
            .map(|host| Relay {
                host: (*host).to_string(),
                key: default_relay_key(host),
            })
            .collect());
    }
    configured
        .iter()
        .map(|(host, key)| {
            let key = match key {
                Some(text) => Some(cordelia_crypto::bech32::decode_public_key(text).map_err(
                    |e| format!("the key given for relay {host} is not a public key: {e}"),
                )?),
                None => default_relay_key(host),
            };
            Ok(Relay {
                host: host.clone(),
                key,
            })
        })
        .collect()
}

/// Resolve the relays' names now, with the system resolver, one address
/// per name. Names that do not resolve are skipped with a warning. Blocks;
/// for startup.
pub fn resolve_relays_now(relays: &[Relay]) -> Vec<RelayAddr> {
    let mut resolved: Vec<RelayAddr> = Vec::new();
    for relay in relays {
        match relay.host.to_socket_addrs() {
            Ok(addrs) => {
                let addrs: Vec<SocketAddr> = addrs.collect();
                match pick(&addrs) {
                    Some(addr) if !resolved.iter().any(|r| r.addr == addr) => {
                        debug!(host = %relay.host, %addr, "resolved relay");
                        resolved.push(RelayAddr {
                            host: relay.host.clone(),
                            addr,
                            key: relay.key,
                        });
                    }
                    _ => {}
                }
            }
            Err(e) => warn!(host = %relay.host, error = %e, "relay name did not resolve"),
        }
    }
    resolved
}

/// Resolve the relays' names with the system resolver (so `/etc/hosts`
/// applies), one address per name. Names that do not resolve are skipped;
/// that is expected while offline.
pub async fn resolve_relays(relays: &[Relay]) -> Vec<RelayAddr> {
    let timeout = std::time::Duration::from_secs(protocol::STREAM_TIMEOUT_SECS);
    let mut resolved: Vec<RelayAddr> = Vec::new();
    for relay in relays {
        match tokio::time::timeout(timeout, tokio::net::lookup_host(relay.host.as_str())).await {
            Ok(Ok(addrs)) => {
                let addrs: Vec<SocketAddr> = addrs.collect();
                if let Some(addr) = pick(&addrs)
                    && !resolved.iter().any(|r| r.addr == addr)
                {
                    resolved.push(RelayAddr {
                        host: relay.host.clone(),
                        addr,
                        key: relay.key,
                    });
                }
            }
            Ok(Err(e)) => debug!(host = %relay.host, error = %e, "relay name did not resolve"),
            Err(_) => debug!(host = %relay.host, "relay lookup timed out"),
        }
    }
    resolved
}

/// One address for a name, IPv4 first: the P2P endpoint binds IPv4.
fn pick(addrs: &[SocketAddr]) -> Option<SocketAddr> {
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> ([u8; 32], String) {
        let id = cordelia_crypto::identity::NodeIdentity::from_seed([n; 32]).unwrap();
        let pk = id.public_key();
        (pk, cordelia_crypto::bech32::encode_public_key(&pk).unwrap())
    }

    /// The keys compiled in for the default relays are public keys, one for
    /// each name.
    #[test]
    fn the_default_relays_have_keys() {
        assert_eq!(
            protocol::FALLBACK_PEERS.len(),
            protocol::FALLBACK_PEER_KEYS.len()
        );
        for host in protocol::FALLBACK_PEERS {
            assert!(
                default_relay_key(host).is_some(),
                "{host} has no usable key"
            );
        }
        assert_eq!(default_relay_key("relay.example.org:9474"), None);
    }

    #[test]
    fn a_personal_node_that_names_no_relays_gets_the_defaults_with_their_keys() {
        let relays = configured_relays(&[], true).unwrap();
        assert_eq!(relays.len(), protocol::FALLBACK_PEERS.len());
        for (relay, host) in relays.iter().zip(protocol::FALLBACK_PEERS) {
            assert_eq!(relay.host, *host);
            assert!(relay.key.is_some());
        }
        // A relay given none stands alone.
        assert!(configured_relays(&[], false).unwrap().is_empty());
    }

    /// Which relays a node dials goes by its role: a personal node that
    /// names none dials the default ones, and is the only one that does; a
    /// bootnode dials none, whatever it names; any other node dials the
    /// ones it names.
    #[test]
    fn the_relays_a_node_dials_go_by_its_role() {
        let hosts = |role: &str, named: &[&str]| -> Vec<String> {
            let named: Vec<(String, Option<String>)> =
                named.iter().map(|host| (host.to_string(), None)).collect();
            let relays = relays_dialled(role, &named).unwrap();
            relays.into_iter().map(|relay| relay.host).collect()
        };
        let one = ["relay.example.org:9474"];
        assert_eq!(hosts("personal", &[]), protocol::FALLBACK_PEERS);
        assert_eq!(hosts("personal", &one), one);
        for role in ["relay", "keeper", ""] {
            assert!(hosts(role, &[]).is_empty(), "{role}");
            assert_eq!(hosts(role, &one), one, "{role}");
        }
        assert!(hosts("bootnode", &[]).is_empty());
        assert!(hosts("bootnode", &one).is_empty());
        // A key that does not parse is an error for a node that would
        // dial the relay it is given for.
        let bad = [(one[0].to_string(), Some("not a key".to_string()))];
        assert!(relays_dialled("relay", &bad).is_err());
    }

    /// T19. A configured relay keeps the key it was given; a default relay
    /// named without one gets the compiled-in key; any other relay named
    /// without one has none.
    #[test]
    fn a_configured_relay_has_the_key_it_was_given_or_the_default_one() {
        let (pk, text) = key(7);
        let own = "relay.example.org:9474".to_string();
        let default = protocol::FALLBACK_PEERS[0].to_string();
        let relays = configured_relays(
            &[
                (own.clone(), Some(text.clone())),
                (default.clone(), None),
                ("other.example.org:9474".into(), None),
                // A key given for a default relay's name wins over the
                // compiled-in one: the operator said what they expect.
                (protocol::FALLBACK_PEERS[1].to_string(), Some(text)),
            ],
            true,
        )
        .unwrap();
        assert_eq!(
            relays[0],
            Relay {
                host: own,
                key: Some(pk)
            }
        );
        assert_eq!(relays[1].key, default_relay_key(&default));
        assert!(relays[1].key.is_some());
        assert_eq!(relays[2].key, None);
        assert_eq!(relays[3].key, Some(pk));
    }

    #[test]
    fn a_key_that_does_not_parse_is_an_error() {
        let err = configured_relays(
            &[("relay.example.org:9474".into(), Some("not-a-key".into()))],
            true,
        )
        .unwrap_err();
        assert!(err.contains("relay.example.org:9474"), "{err}");
        assert!(err.contains("not a public key"), "{err}");
    }

    #[test]
    fn names_resolve_to_one_address_each_and_bad_names_are_skipped() {
        let (pk, _) = key(9);
        let relays = vec![
            Relay {
                host: "127.0.0.1:9474".into(),
                key: Some(pk),
            },
            Relay {
                host: "127.0.0.1:9474".into(),
                key: None,
            }, // same address again
            Relay {
                host: "not-a-valid-address".into(),
                key: None,
            },
            Relay {
                host: "127.0.0.2:9475".into(),
                key: None,
            },
        ];
        let resolved = resolve_relays_now(&relays);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].addr, "127.0.0.1:9474".parse().unwrap());
        assert_eq!(resolved[0].key, Some(pk));
        assert_eq!(resolved[1].addr, "127.0.0.2:9475".parse().unwrap());
        assert_eq!(resolved[1].key, None);
    }

    #[tokio::test]
    async fn names_resolve_without_blocking() {
        let relays = vec![
            Relay {
                host: "127.0.0.1:9474".into(),
                key: None,
            },
            Relay {
                host: "no-such-host.invalid:9474".into(),
                key: None,
            },
        ];
        let resolved = resolve_relays(&relays).await;
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].host, "127.0.0.1:9474");
        assert_eq!(resolved[0].addr, "127.0.0.1:9474".parse().unwrap());
    }
}
