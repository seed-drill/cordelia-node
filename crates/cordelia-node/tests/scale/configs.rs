//! The configurations the harness writes (decision 2026-10-22 §4.3, rules
//! 1 and 2): each node is given the settings it has in R1, and every
//! setting beyond its defaults is listed for the summary. No address
//! outside 127.0.0.0/8 is written, and a configuration that would hold one
//! is refused before anything starts.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// The governor of `deploy/relay/relay1.toml`, which a relay is given.
pub const RELAY_GOVERNOR: [(&str, u32); 5] = [
    ("hot_min", 1),
    ("hot_max", 50),
    ("warm_min", 1),
    ("warm_max", 50),
    ("cold_max", 200),
];

/// The relays listen here, and on nothing else (rule 5 of §2.2).
pub const RELAY_ADDRESS: Ipv4Addr = Ipv4Addr::LOCALHOST;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Relay,
    Device,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Relay => "relay",
            Role::Device => "personal",
        }
    }
}

/// What one node is given.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub name: String,
    pub role: Role,
    pub http: u16,
    pub p2p: u16,
    /// The address it binds: 127.0.0.1 for a relay; the person's, or the
    /// office's, for a device.
    pub listen: IpAddr,
    /// Its relays, by address and key.
    pub relays: Vec<(SocketAddr, String)>,
    /// The relays' churn interval, where the run sets one (test 4 alone).
    pub churn_secs: Option<u64>,
    pub data_dir: PathBuf,
}

/// Whether `ip` is in 127.0.0.0/8.
pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 127,
        IpAddr::V6(_) => false,
    }
}

impl Settings {
    /// Refused where it would hold an address outside 127.0.0.0/8, or a
    /// relay with no key.
    pub fn check(&self) -> Result<(), String> {
        if !is_loopback(self.listen) {
            return Err(format!(
                "{}: it would bind {}, which is not in 127.0.0.0/8",
                self.name, self.listen
            ));
        }
        for (addr, key) in &self.relays {
            if !is_loopback(addr.ip()) {
                return Err(format!(
                    "{}: it would dial {addr}, which is not in 127.0.0.0/8",
                    self.name
                ));
            }
            if key.is_empty() {
                return Err(format!("{}: its relay {addr} is given no key", self.name));
            }
        }
        if self.role == Role::Relay && self.listen != IpAddr::V4(RELAY_ADDRESS) {
            return Err(format!(
                "{}: a relay listens on {RELAY_ADDRESS} and nothing else",
                self.name
            ));
        }
        Ok(())
    }

    /// The configuration file.
    pub fn render(&self) -> String {
        let relays: String = self
            .relays
            .iter()
            .map(|(addr, key)| {
                format!("[[network.bootnodes]]\naddr = \"{addr}\"\nkey = \"{key}\"\n\n")
            })
            .collect();
        let governor = match self.role {
            Role::Device => String::new(),
            Role::Relay => {
                let mut g: String = RELAY_GOVERNOR
                    .iter()
                    .map(|(k, v)| format!("{k} = {v}\n"))
                    .collect();
                if let Some(secs) = self.churn_secs {
                    g.push_str(&format!(
                        "churn_interval_secs = {secs}\nchurn_jitter_secs = 0\n"
                    ));
                }
                format!("[governor]\n{g}\n")
            }
        };
        format!(
            "[identity]\nentity_id = \"{name}\"\n\n\
             [node]\nhttp_port = {http}\np2p_port = {p2p}\ndata_dir = \"{data}\"\n\n\
             [network]\nlisten_addr = \"{listen}:{p2p}\"\nrole = \"{role}\"\n\
             allow_private_addresses = true\ndns_discovery = \"\"\n\n\
             {relays}{governor}\
             [api]\nbind_address = \"127.0.0.1\"\n\n\
             [logging]\nlevel = \"info\"\n",
            name = self.name,
            http = self.http,
            p2p = self.p2p,
            data = self.data_dir.display(),
            listen = self.listen,
            role = self.role.name(),
        )
    }

    /// Every setting beyond the defaults, for the summary: by kind of
    /// node, so that the summary says it once for each.
    pub fn beyond_defaults(&self) -> Vec<String> {
        let mut said = vec![
            match self.role {
                Role::Relay => format!("listen_addr: {RELAY_ADDRESS} and a port of its own"),
                Role::Device => {
                    "listen_addr: the person's address (the office's in the window) and a port"
                        .to_string()
                }
            },
            "its relays, each by address on 127.0.0.1 and by key ([[network.bootnodes]] with key)"
                .to_string(),
            "dns_discovery = \"\"".to_string(),
            "allow_private_addresses = true (without it a node dials no address on loopback)"
                .to_string(),
            "the log level, info (the default, written out)".to_string(),
            "its data directory, its HTTP port and its P2P port".to_string(),
            "the local API on 127.0.0.1 (the default, written out)".to_string(),
        ];
        if self.role == Role::Relay {
            let g: Vec<String> = RELAY_GOVERNOR
                .iter()
                .map(|(k, v)| format!("{k} {v}"))
                .collect();
            said.push(format!(
                "the governor of deploy/relay/relay1.toml: {}",
                g.join(", ")
            ));
            if let Some(secs) = self.churn_secs {
                said.push(format!(
                    "churn_interval_secs = {secs}, churn_jitter_secs = 0"
                ));
            }
        }
        said
    }
}

/// Every address the configuration at `text` holds is in 127.0.0.0/8:
/// read with the node's own reader, so that a file the harness did not
/// mean to write is refused as well.
pub fn check_written(path: &std::path::Path) -> Result<(), String> {
    let config = cordelia_core::config::Config::load(path)
        .map_err(|e| format!("{}: cannot be read: {e}", path.display()))?;
    let listen: SocketAddr = config
        .network
        .listen_addr
        .parse()
        .map_err(|_| format!("{}: listen_addr is no address", path.display()))?;
    if !is_loopback(listen.ip()) {
        return Err(format!(
            "{}: it would bind {listen}, which is not in 127.0.0.0/8",
            path.display()
        ));
    }
    for bootnode in &config.network.bootnodes {
        let addr: SocketAddr = bootnode
            .addr
            .parse()
            .map_err(|_| format!("{}: {} is no address", path.display(), bootnode.addr))?;
        if !is_loopback(addr.ip()) {
            return Err(format!(
                "{}: it would dial {addr}, which is not in 127.0.0.0/8",
                path.display()
            ));
        }
    }
    if config.network.dns_discovery.is_empty() && config.api.bind_address == "127.0.0.1" {
        Ok(())
    } else {
        Err(format!(
            "{}: it looks up relays by name, or its API is not on 127.0.0.1",
            path.display()
        ))
    }
}
