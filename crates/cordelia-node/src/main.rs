//! Cordelia node binary: CLI, daemon lifecycle, signal handling.
//!
//! Spec: seed-drill/specs/operations.md

use std::sync::Mutex;

use actix_web::{App, HttpServer, web};
use clap::Parser;

use cordelia_core::config::{self, Config};
use cordelia_crypto::bech32::{HRP_X25519_PK, encode_public_key};
use cordelia_crypto::identity::NodeIdentity;

mod indicator;
mod p2p;

#[derive(Parser)]
#[command(name = "cordelia", version, about = "Encrypted pub/sub for AI agents")]
struct Cli {
    /// Path to config file (accepted before or after the subcommand)
    #[arg(
        long,
        global = true,
        env = "CORDELIA_CONFIG",
        default_value = "~/.cordelia/config.toml"
    )]
    config: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Initialise a new node (generate keypair, create database)
    Init {
        /// Entity name (defaults to OS username)
        #[arg(long)]
        name: Option<String>,

        /// Skip interactive prompts
        #[arg(long)]
        non_interactive: bool,

        /// Force re-initialisation (overwrites existing identity)
        #[arg(long)]
        force: bool,

        /// Show secrets (node token) in output
        #[arg(long)]
        show_secrets: bool,
    },
    /// Show node status (`--line` for a status bar, `--json` for tools)
    Status {
        /// One line for a status bar, e.g. Claude Code's status line
        #[arg(long, conflicts_with = "json")]
        line: bool,
        /// Machine-readable state, for widgets and scripts
        #[arg(long)]
        json: bool,
    },
    /// Start the node daemon
    Start,
    /// Stop the node daemon
    Stop,
    /// Show how many peers the running node is connected to
    Peers,
    /// List subscribed channels
    Channels,
    /// Show detailed metrics
    Stats,
    /// Print this device's public key (give it to `add-device` elsewhere)
    #[command(alias = "pubkey")]
    Id,
    /// Add another of your devices; then run `cordelia accept` on it
    AddDevice {
        /// The other device's key, from `cordelia id` on that device
        key: String,
        /// A name for the device, e.g. "imac"
        #[arg(long)]
        name: Option<String>,
    },
    /// Trust the device that added this one with `add-device`
    Accept {
        /// The key printed by `add-device` on the other device
        key: String,
        /// A name for the device, e.g. "macbook"
        #[arg(long)]
        name: Option<String>,
    },
    /// Remove one of your devices and rotate the keys it held
    RemoveDevice {
        /// The device's key
        key: String,
    },
    /// List your devices
    Devices,
    /// List invites waiting for `accept`
    Invites,
    /// Sync an agent's memory across your devices
    Sync {
        #[command(subcommand)]
        what: SyncCommand,
    },
    /// Initialise a swarm child node (derive identity from lead, create channels)
    SwarmInit {
        /// HKDF derivation index for this child's identity
        #[arg(long)]
        index: u32,

        /// Path to the lead node's identity.key
        #[arg(long)]
        lead_identity: String,

        /// Entity ID of the lead node (for swarm channel naming)
        #[arg(long)]
        lead_entity_id: String,
    },
}

#[derive(clap::Subcommand)]
enum SyncCommand {
    /// Sync Claude Code's memory (home and project folders)
    Claude {
        /// Claude Code directory (default: ~/.claude)
        #[arg(long)]
        dir: Option<String>,
        /// Never sync this project from this device (its git remote, e.g.
        /// github.com/client-co/app, or a prefix ending in *). Repeatable;
        /// replaces the current list.
        #[arg(long)]
        exclude: Vec<String>,
        /// Do not sync home-folder memory on this device
        #[arg(long)]
        no_home: bool,
    },
    /// Stop syncing (files already synced are left in place)
    Off,
    /// Show what is syncing, and what is not
    Status,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init {
            name,
            non_interactive,
            force,
            show_secrets,
        }) => cmd_init(&cli.config, name, non_interactive, force, show_secrets),
        Some(Commands::Status { line, json }) => cmd_status(&cli.config, line, json),
        Some(Commands::Start) => cmd_start(&cli.config),
        Some(Commands::Stop) => {
            println!("cordelia stop: not yet implemented (requires PID file / signal)");
            Ok(())
        }
        Some(Commands::Peers) => cmd_peers(&cli.config),
        Some(Commands::Channels) => cmd_channels(&cli.config),
        Some(Commands::Stats) => cmd_stats(&cli.config),
        Some(Commands::Id) => cmd_pubkey(&cli.config),
        Some(Commands::AddDevice { key, name }) => cmd_add_device(&cli.config, &key, name),
        Some(Commands::Accept { key, name }) => cmd_accept(&cli.config, &key, name),
        Some(Commands::RemoveDevice { key }) => cmd_remove_device(&cli.config, &key),
        Some(Commands::Devices) => cmd_devices(&cli.config),
        Some(Commands::Invites) => cmd_invites(&cli.config),
        Some(Commands::Sync { what }) => cmd_sync(&cli.config, what),
        Some(Commands::SwarmInit {
            index,
            lead_identity,
            lead_entity_id,
        }) => cmd_swarm_init(&cli.config, index, &lead_identity, &lead_entity_id),
        None => {
            println!("Cordelia v{}", env!("CARGO_PKG_VERSION"));
            println!("Encrypted pub/sub for AI agents");
            println!();
            println!("Run `cordelia --help` for usage.");
            Ok(())
        }
    }
}

// ── cordelia init ──────────────────────────────────────────────────

fn cmd_init(
    config_path: &str,
    name: Option<String>,
    _non_interactive: bool,
    force: bool,
    show_secrets: bool,
) -> anyhow::Result<()> {
    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file).unwrap_or_default();
    config.apply_env_overrides();
    let data_dir = config.data_dir();

    // 1. Generate or load Ed25519 identity
    let identity_path = data_dir.join("identity.key");
    let identity = if identity_path.exists() && !force {
        println!("Identity exists at {}", identity_path.display());
        NodeIdentity::from_file(&identity_path)?
    } else {
        println!("Generating Ed25519 keypair...");
        let id = NodeIdentity::load_or_create(&identity_path)?;
        println!("  done.");
        id
    };

    let pk = identity.public_key();
    let pk_bech32 = encode_public_key(&pk)?;
    let x_pub = identity.x25519_public_key();
    let x_bech32 = cordelia_crypto::bech32::bech32_encode(HRP_X25519_PK, &x_pub)?;

    // 2. Derive entity ID
    let entity_name = name.unwrap_or_else(default_entity_name);
    let suffix = identity.entity_id_suffix();
    let entity_id = format!("{entity_name}_{suffix}");

    // 3. Generate node token (32 bytes CSPRNG, hex-encoded)
    let token_path = config.token_path();
    let token_hex = if token_path.exists() && !force {
        println!("Node token exists at {}", token_path.display());
        std::fs::read_to_string(&token_path)?.trim().to_string()
    } else {
        println!("Generating node token...");
        let token_bytes = cordelia_crypto::generate_psk()?; // 32 random bytes
        let hex_str = hex::encode(token_bytes);
        if let Some(parent) = token_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&token_path, &hex_str)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
        }
        println!("  written to {}", token_path.display());
        hex_str
    };

    // 4. Create database
    let db_path = data_dir.join("cordelia.db");
    if !db_path.exists() || force {
        println!("Creating database...");
        let _conn = cordelia_storage::db::open(&db_path)?;
        println!("  done.");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600))?;
        }
    } else {
        println!("Database exists at {}", db_path.display());
    }

    // 5. Create channel-keys directory
    let keys_dir = data_dir.join("channel-keys");
    if !keys_dir.exists() {
        std::fs::create_dir_all(&keys_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    // The personal channel is created on first use (`add-device`), as a
    // group channel shared by all of a person's devices (decision
    // 2026-09-30-agent-memory-sync §4.1).

    // 6. Write config
    config.identity.entity_id = entity_id.clone();
    config.identity.public_key = pk_bech32.clone();
    if !config_file.exists() || force {
        config.save(&config_file)?;
        println!("Config written to {}", config_file.display());
    }

    // Output
    println!();
    println!("Your identity:");
    println!("  Entity ID:  {entity_id}");
    println!("  Public key: {pk_bech32}");
    println!("  X25519 key: {x_bech32}");

    if show_secrets {
        println!("  Node token: {token_hex}");
    } else {
        println!("  Node token: <written to {}>", token_path.display());
    }

    println!();
    println!("Node is ready. Run `cordelia start` to begin.");

    Ok(())
}

/// Default entity name: OS username, lowercased, non-alnum replaced with hyphens.
fn default_entity_name() -> String {
    let raw = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "node".into());

    let cleaned: String = raw
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();

    // Ensure it starts with a letter
    if cleaned.starts_with(|c: char| c.is_ascii_lowercase()) {
        cleaned
    } else {
        format!("node-{cleaned}")
    }
}

// ── cordelia status ────────────────────────────────────────────────

fn cmd_status(config_path: &str, line: bool, json: bool) -> anyhow::Result<()> {
    let status = gather_status(config_path);
    let (state, summary) = indicator::derive(&status.facts);

    if line {
        let color = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
        let text = indicator::line(state, &summary, color);
        if !text.is_empty() {
            println!("{text}");
        }
        return Ok(());
    }
    if json {
        let mut out = serde_json::json!({
            "state": state.as_str(),
            "summary": summary,
            "version": env!("CARGO_PKG_VERSION"),
            "running": status.facts.running,
        });
        if let Some(device) = &status.device {
            out["device"] = device.clone().into();
            out["role"] = status.facts.role.clone().into();
        }
        if let Some(live) = &status.live {
            out["uptime_secs"] = live["uptime_secs"].clone();
            out["peers"] = serde_json::json!({
                "hot": live["peers_hot"],
                "warm": live["peers_warm"],
            });
            out["outbox_waiting"] = live["outbox_waiting"].clone();
        }
        if let Some(sync) = &status.sync {
            let report = &sync["report"];
            out["sync"] = serde_json::json!({
                "enabled": sync["enabled"],
                "last_cycle_at": report["at"],
                "last_change_at": sync["last_change_at"],
                "folders": report["folders"].as_array().map_or(0, Vec::len),
                "projects_waiting": status.facts.projects_waiting,
                "conflicts": status.facts.conflicts,
                "unsynced": report["unsynced"],
                "excluded": report["excluded"],
                "errors": status.facts.errors,
            });
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file)?;
    config.apply_env_overrides();
    let data_dir = config.data_dir();

    let identity_path = data_dir.join("identity.key");
    if !identity_path.exists() {
        println!("Node not initialised. Run `cordelia init` first.");
        return Ok(());
    }

    let identity = NodeIdentity::from_file(&identity_path)?;
    let pk = identity.public_key();
    let pk_bech32 = encode_public_key(&pk)?;

    println!("Cordelia v{}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Identity:");
    println!("  Entity ID:  {}", config.identity.entity_id);
    println!("  Public key: {pk_bech32}");
    println!("  Data dir:   {}", data_dir.display());

    // DB stats
    let db_path = data_dir.join("cordelia.db");
    if db_path.exists() {
        let conn = cordelia_storage::db::open(&db_path)?;
        let channels = cordelia_storage::channels::list_for_entity(&conn, &pk)?;
        let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);

        println!();
        println!("Storage:");
        println!("  Channels:  {}", channels.len());
        println!("  DB size:   {} KB", db_size / 1024);
    }

    println!();
    println!("Config:");
    println!("  HTTP port: {}", config.node.http_port);
    println!("  P2P port:  {}", config.node.p2p_port);
    println!("  Role:      {}", config.network.role);

    println!();
    println!("Node:");
    match &status.live {
        Some(live) => {
            let n = |k: &str| live[k].as_u64().unwrap_or(0);
            println!("  Running:   yes, up {}", format_uptime(n("uptime_secs")));
            println!(
                "  Peers:     {} hot, {} warm",
                n("peers_hot"),
                n("peers_warm")
            );
            println!("  Sync errors: {}", n("sync_errors"));
            if config.network.role == "personal" {
                println!("  Memory:    {summary}");
                for c in &status.facts.conflicts {
                    println!("    conflict: {c}");
                }
                for e in &status.facts.errors {
                    println!("    error:    {e}");
                }
            }
        }
        None => println!("  Running:   no (start it with `cordelia start`)"),
    }

    Ok(())
}

/// What `cordelia status` knows about this device and its running node.
struct GatheredStatus {
    facts: indicator::Facts,
    /// This device's public key (bech32), once initialised.
    device: Option<String>,
    /// `GET /api/v1/status` from the running node.
    live: Option<serde_json::Value>,
    /// `POST /api/v1/sync/status` from the running node.
    sync: Option<serde_json::Value>,
}

/// Collect the facts for [`indicator::derive`] without failing: a missing
/// config, an uninitialised device or a stopped node are states to report,
/// not errors. Status bars call this often, so the node gets a short
/// timeout.
fn gather_status(config_path: &str) -> GatheredStatus {
    let mut out = GatheredStatus {
        facts: indicator::Facts::default(),
        device: None,
        live: None,
        sync: None,
    };
    let Ok(mut config) = Config::load(&config::expand_tilde(config_path)) else {
        return out;
    };
    config.apply_env_overrides();
    out.facts.role = config.network.role.clone();
    let Ok(identity) = NodeIdentity::from_file(&config.data_dir().join("identity.key")) else {
        return out;
    };
    out.facts.initialised = true;
    out.device = encode_public_key(&identity.public_key()).ok();

    let timeout = std::time::Duration::from_secs(1);
    let Ok(live) = local_api(&config, false, "/api/v1/status", timeout) else {
        return out;
    };
    out.facts.running = true;
    out.facts.peers_hot = live["peers_hot"].as_u64().unwrap_or(0);
    out.facts.outbox_waiting = live["outbox_waiting"].as_u64().unwrap_or(0);
    out.live = Some(live);

    if let Ok(sync) = local_api(&config, true, "/api/v1/sync/status", timeout) {
        let report = &sync["report"];
        out.facts.sync_enabled = sync["enabled"].as_bool().unwrap_or(false);
        out.facts.report_age_secs = report["at"]
            .as_str()
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
            .map(|at| (chrono::Utc::now() - at.with_timezone(&chrono::Utc)).num_seconds());
        let strings = |v: &serde_json::Value| -> Vec<String> {
            v.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        out.facts.errors = strings(&report["errors"]);
        if let Some(folders) = report["folders"].as_array() {
            for f in folders {
                out.facts.conflicts.extend(strings(&f["conflict_files"]));
                if f["waiting"].as_bool().unwrap_or(false) {
                    out.facts.projects_waiting += 1;
                }
            }
        }
        out.sync = Some(sync);
    }
    out
}

/// `3h 12m`, `4m 05s`, `40s`.
fn format_uptime(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

// ── cordelia start ─────────────────────────────────────────────────

fn cmd_start(config_path: &str) -> anyhow::Result<()> {
    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file)?;
    config.apply_env_overrides();
    let data_dir = config.data_dir();

    // Verify init has been run
    let identity_path = data_dir.join("identity.key");
    if !identity_path.exists() {
        anyhow::bail!("Node not initialised. Run `cordelia init` first.");
    }

    let identity = NodeIdentity::from_file(&identity_path)?;
    let pk_bech32 = encode_public_key(&identity.public_key())?;

    // Load bearer token
    let token_path = config.token_path();
    let bearer_token = std::fs::read_to_string(&token_path)
        .map_err(|e| anyhow::anyhow!("read node token: {e}"))?
        .trim()
        .to_string();

    // Open database
    let db_path = data_dir.join("cordelia.db");
    let conn = cordelia_storage::db::open(&db_path)?;

    // Auto-create persistent swarm channel for lead nodes (§8.2.2).
    // Only personal nodes can be swarm leads (not bootnodes or relays).
    if config.swarm.swarm_index.is_none() && config.network.role == "personal" {
        let entity_id = &config.identity.entity_id;
        if !entity_id.is_empty() {
            let swarm_ch_id = cordelia_storage::naming::swarm_channel_id(entity_id);
            let now = chrono::Utc::now().to_rfc3339();
            let pk = identity.public_key();
            // Generate PSK and store it alongside the channel
            let swarm_psk = cordelia_crypto::generate_psk()?;
            let swarm_psk_hash = cordelia_crypto::sha256(&swarm_psk);
            let _ = conn.execute(
                "INSERT OR IGNORE INTO channels (channel_id, channel_type, mode, access, scope, creator_id, psk_hash, created_at, updated_at)
                 VALUES (?1, 'named', 'realtime', 'invite_only', 'network', ?2, ?3, ?4, ?5)",
                rusqlite::params![swarm_ch_id, pk.as_slice(), swarm_psk_hash.as_slice(), now, now],
            );
            let _ = conn.execute(
                "INSERT OR IGNORE INTO channel_members (channel_id, entity_key, role, joined_at)
                 VALUES (?1, ?2, 'owner', ?3)",
                rusqlite::params![swarm_ch_id, pk.as_slice(), now],
            );
            // Save PSK using standard psk module (handles path encoding + 0600 permissions)
            if !cordelia_storage::psk::has_psk(&data_dir, &swarm_ch_id) {
                let _ = cordelia_storage::psk::write_psk(&data_dir, &swarm_ch_id, &swarm_psk);
            }
        }
    }

    // Validate bind address is loopback
    let bind_addr = &config.api.bind_address;
    if bind_addr != "127.0.0.1" && bind_addr != "::1" && bind_addr != "localhost" {
        anyhow::bail!(
            "API bind_address must be loopback (127.0.0.1), got '{bind_addr}'. \
             Non-loopback binding is not supported in Phase 1."
        );
    }

    let http_port = config.node.http_port;
    let listen_addr = format!("{bind_addr}:{http_port}");
    let p2p_port = config.node.p2p_port;

    // Set up logging
    init_tracing(&config.logging.level);

    let version = env!("CARGO_PKG_VERSION");
    let role = &config.network.role;
    let log_level = &config.logging.level;
    let hot_min = config.governor.hot_min;
    let hot_max = config.governor.hot_max;
    let warm_min = config.governor.warm_min;
    let warm_max = config.governor.warm_max;

    println!("Cordelia v{version}");
    println!("  Entity:    {}", config.identity.entity_id);
    println!("  Public key: {pk_bech32}");
    println!("  HTTP API:  http://{listen_addr}/api/v1/channels/");
    println!("  P2P port:  {p2p_port}/UDP");
    println!("  Role:      {role}");
    println!();

    tracing::info!(
        version,
        %role,
        %log_level,
        hot_min,
        hot_max,
        warm_min,
        warm_max,
        "node starting"
    );

    // Build app state
    let identity_arc = std::sync::Arc::new(identity);
    let (push_tx, push_rx) = tokio::sync::mpsc::unbounded_channel();
    let (announce_tx, announce_rx) = tokio::sync::mpsc::unbounded_channel();

    let state = web::Data::new(cordelia_api::state::AppState {
        db: Mutex::new(conn),
        identity: NodeIdentity::from_seed(*identity_arc.seed())?,
        bearer_token,
        home_dir: data_dir,
        started_at: std::time::Instant::now(),
        sync_errors: std::sync::atomic::AtomicU64::new(0),
        peers_hot: std::sync::atomic::AtomicU64::new(0),
        peers_warm: std::sync::atomic::AtomicU64::new(0),
        push_tx: Some(push_tx),
        announce_tx: Some(announce_tx),
    });

    // Personal nodes receive invites and channel states in an inbox channel
    // derived from their key (decision 2026-09-30 §4.1).
    if config.network.role == "personal" {
        let inbox = cordelia_api::membership::ensure_own_inbox(&state)?;
        tracing::info!(%inbox, "inbox ready");
    }

    // Start the tokio/actix runtime with graceful shutdown
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        tracing::info!(%listen_addr, p2p_port, "starting node");

        // ── P2P transport ──────────────────────────────────────────
        let p2p_bind = p2p_bind_addr(&config.network.listen_addr, p2p_port)?;
        let endpoint = cordelia_network::transport::create_endpoint(&identity_arc, p2p_bind)
            .map_err(|e| anyhow::anyhow!("P2P transport: {e}"))?;
        let p2p_local = endpoint.local_addr()?;
        tracing::info!(%p2p_local, "P2P endpoint listening");

        // ── Connection manager ─────────────────────────────────────
        let roles = vec![config.network.role.clone()];
        let allow_private = config.network.allow_private_addresses;
        let is_bootnode = config.network.role == "bootnode";
        let mut conn_mgr = cordelia_network::connection::ConnectionManager::new(
            identity_arc.clone(),
            endpoint,
            vec![], // channel IDs loaded later from DB
            roles,
            p2p_port as u16,
        );

        // ── Bootstrap: resolve and connect to bootnodes ──────────────
        // Bootnodes skip this step (they are the bootstrap target).
        if !is_bootnode {
            let bootnode_addrs: Vec<String> = config
                .network
                .bootnodes
                .iter()
                .map(|b| b.addr.clone())
                .collect();
            let bootnodes = cordelia_network::bootstrap::resolve_all_bootnodes(&bootnode_addrs);
            tracing::info!(count = bootnodes.len(), "bootnodes resolved");

            for bn in &bootnodes {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(cordelia_core::protocol::STREAM_TIMEOUT_SECS),
                    conn_mgr.connect_to(bn.addr),
                ).await {
                    Ok(Ok(node_id)) => {
                        tracing::info!(bootnode = %bn.host, peer = %node_id, "connected to bootnode");
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(bootnode = %bn.host, error = %e, "failed to connect to bootnode");
                    }
                    Err(_) => {
                        tracing::warn!(bootnode = %bn.host, "bootnode connection timed out (10s)");
                    }
                }
            }
        } else {
            tracing::info!("bootnode role: skipping bootstrap");
        }

        // Update peer counts in shared state
        let hot_count = conn_mgr.connection_count() as u64;
        state.peers_hot.store(hot_count, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(peers = hot_count, "bootstrap complete");

        // ── P2P background loop ─────────────────────────────────────
        // Owns the ConnectionManager. Accepts inbound connections and
        // updates peer counts in the shared AppState atomics.
        let p2p_state = state.clone();
        let p2p_shutdown = tokio::sync::watch::channel(false);
        let mut p2p_shutdown_rx = p2p_shutdown.1.clone();
        let role_for_p2p = config.network.role.clone();
        // Parse trusted peers for PAN (§8.2.2)
        let trusted_peer_ids: Vec<cordelia_core::NodeId> = config.network.trusted_peers.iter()
            .filter_map(|tp| {
                cordelia_crypto::bech32::decode_public_key(&tp.public_key)
                    .map(cordelia_core::NodeId)
                    .map_err(|e| tracing::warn!(key = %tp.public_key, error = %e, "invalid trusted_peer key"))
                    .ok()
            })
            .collect();
        if !trusted_peer_ids.is_empty() {
            tracing::info!(count = trusted_peer_ids.len(), "trusted peers configured (PAN §8.2.2)");
        }

        // ── Sync adapter (decision 2026-09-30 §4.5) ─────────────────
        // Runs while a Claude Code directory is configured; `cordelia sync
        // claude` / `cordelia sync off` take effect on the next cycle.
        if config.network.role == "personal" {
            tokio::spawn(run_sync_loop(state.clone()));
        }

        // Bootnodes are names (the defaults are relay1/relay2 by DNS), so
        // they are resolved again while the node runs, not only at startup.
        let bootstrap_addrs = p2p::BootstrapAddrs::default();
        if !is_bootnode {
            let names: Vec<String> = config.network.bootnodes.iter().map(|b| b.addr.clone()).collect();
            tokio::spawn(p2p::keep_bootnodes_resolved(
                cordelia_network::bootstrap::bootstrap_hosts(&names),
                bootstrap_addrs.clone(),
            ));
        }

        let p2p_handle = tokio::spawn(async move {
            p2p::p2p_loop(conn_mgr, p2p_state, push_rx, announce_rx, &mut p2p_shutdown_rx, allow_private, role_for_p2p, config.governor.clone(), bootstrap_addrs, trusted_peer_ids).await;
        });

        // ── HTTP API ───────────────────────────────────────────────
        let server = HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .configure(cordelia_api::configure_routes)
        })
        .bind(&listen_addr)?
        .run();

        let server_handle = server.handle();

        // Spawn signal handler for graceful shutdown
        let p2p_shutdown_tx = p2p_shutdown.0;
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received, stopping");
            let _ = p2p_shutdown_tx.send(true);
            server_handle.stop(true).await;
        });

        tracing::info!("P2P layer ready, accepting connections");

        let result = server.await.map_err(|e| anyhow::anyhow!(e));

        // Wait for P2P loop to finish
        let _ = p2p_handle.await;
        tracing::info!("P2P shutdown complete");

        result
    })
}

/// The address to bind the P2P (QUIC) socket to: the host of
/// `network.listen_addr` (resolved, so a name like Fly's
/// `fly-global-services` works) with the node's P2P port. The port always
/// comes from `node.p2p_port` so CORDELIA_P2P_PORT keeps working.
fn p2p_bind_addr(listen_addr: &str, p2p_port: u16) -> anyhow::Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    let host = match listen_addr.rsplit_once(':') {
        Some((host, _port)) if !host.is_empty() => host,
        _ => "0.0.0.0",
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (host, p2p_port)
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("resolve listen_addr host {host:?}: {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("listen_addr host {host:?} resolved to no address"))
}

// ── Sync adapter loop ──────────────────────────────────────────────

/// Every `CYCLE_SECS`, if sync is on, run one adapter cycle off the async
/// runtime and store its report for `cordelia sync status`.
async fn run_sync_loop(state: web::Data<cordelia_api::state::AppState>) {
    use cordelia_storage::meta;
    use cordelia_sync::claude::ClaudeAdapter;

    let adapter: std::sync::Arc<Mutex<Option<(std::path::PathBuf, ClaudeAdapter)>>> =
        std::sync::Arc::new(Mutex::new(None));
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        cordelia_sync::claude::CYCLE_SECS,
    ));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        let state = state.clone();
        let adapter = adapter.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let dir = match state.db.lock() {
                Ok(db) => meta::get(&db, meta::SYNC_CLAUDE_DIR).ok().flatten(),
                Err(_) => return,
            };
            let Ok(mut slot) = adapter.lock() else { return };
            let Some(dir) = dir.map(std::path::PathBuf::from) else {
                *slot = None;
                return;
            };
            if slot.as_ref().is_none_or(|(d, _)| *d != dir) {
                let home = std::env::var_os("HOME")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_default();
                let pk = state.identity.public_key();
                *slot = Some((dir.clone(), ClaudeAdapter::new(dir, home, &pk)));
                tracing::info!("sync adapter started");
            }
            let Some((_, running)) = slot.as_mut() else {
                return;
            };
            let report = running.run_cycle(&state);
            for e in &report.errors {
                tracing::warn!(error = %e, "sync cycle error");
            }
            let now = chrono::Utc::now().to_rfc3339();
            let changed = report.folders.iter().any(|f| f.published + f.pulled > 0);
            let mut json = serde_json::to_value(&report).unwrap_or_default();
            json["at"] = serde_json::Value::String(now.clone());
            if let Ok(db) = state.db.lock() {
                let _ = meta::set(&db, meta::SYNC_CLAUDE_REPORT, &json.to_string());
                if changed {
                    let _ = meta::set(&db, meta::SYNC_CLAUDE_LAST_CHANGE, &now);
                }
            }
        })
        .await;
    }
}

// ── cordelia peers ─────────────────────────────────────────────────

fn cmd_peers(config_path: &str) -> anyhow::Result<()> {
    let live = api_get(config_path, "/api/v1/status")?;
    let n = |k: &str| live[k].as_u64().unwrap_or(0);
    println!(
        "Connected peers: {} hot, {} warm.",
        n("peers_hot"),
        n("peers_warm")
    );
    println!("(A per-peer list is not available yet.)");
    Ok(())
}

// ── cordelia channels ─────────────────────────────────────────────

fn cmd_channels(config_path: &str) -> anyhow::Result<()> {
    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file)?;
    config.apply_env_overrides();
    let data_dir = config.data_dir();

    let identity_path = data_dir.join("identity.key");
    if !identity_path.exists() {
        anyhow::bail!("Node not initialised. Run `cordelia init` first.");
    }

    let identity = NodeIdentity::from_file(&identity_path)?;
    let pk = identity.public_key();
    let db_path = data_dir.join("cordelia.db");
    let conn = cordelia_storage::db::open(&db_path)?;

    let all = cordelia_storage::channels::list_for_entity(&conn, &pk)?;

    println!(
        "{:<24} {:<10} {:>6}   {:<20} TYPE",
        "CHANNEL", "MODE", "ITEMS", "LAST ACTIVITY"
    );
    for ch in &all {
        let name = ch
            .channel_name
            .as_deref()
            .unwrap_or(&ch.channel_id[..ch.channel_id.len().min(16)]);
        let count = cordelia_storage::items::count_for_channel(&conn, &ch.channel_id)?;
        let activity = cordelia_storage::items::last_activity(&conn, &ch.channel_id)?
            .unwrap_or_else(|| "-".into());

        println!(
            "{:<24} {:<10} {:>6}   {:<20} {}",
            name, ch.mode, count, activity, ch.channel_type
        );
    }

    if all.is_empty() {
        println!("No channels. Subscribe with `cordelia subscribe <channel>`.");
    }

    Ok(())
}

// ── cordelia stats ────────────────────────────────────────────────

fn cmd_stats(config_path: &str) -> anyhow::Result<()> {
    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file)?;
    config.apply_env_overrides();
    let data_dir = config.data_dir();

    let identity_path = data_dir.join("identity.key");
    if !identity_path.exists() {
        anyhow::bail!("Node not initialised. Run `cordelia init` first.");
    }

    let identity = NodeIdentity::from_file(&identity_path)?;
    let pk = identity.public_key();
    let db_path = data_dir.join("cordelia.db");
    let conn = cordelia_storage::db::open(&db_path)?;

    let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
    let channels = cordelia_storage::channels::list_for_entity(&conn, &pk)?;

    let mut total_items: i64 = 0;
    for ch in &channels {
        total_items += cordelia_storage::items::count_for_channel(&conn, &ch.channel_id)?;
    }

    let size_str = if db_size > 1_048_576 {
        format!("{:.1} MB", db_size as f64 / 1_048_576.0)
    } else {
        format!("{:.1} KB", db_size as f64 / 1024.0)
    };

    println!("Storage:        {size_str}");
    println!("Channels:       {}", channels.len());
    println!("Total items:    {total_items}");
    println!("Sync errors:    0");
    println!("Peers:          0 (P2P not yet implemented)");

    Ok(())
}

// ── cordelia swarm-init ────────────────────────────────────────────

fn cmd_swarm_init(
    config_path: &str,
    index: u32,
    lead_identity_path: &str,
    lead_entity_id: &str,
) -> anyhow::Result<()> {
    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file)?;
    config.apply_env_overrides();
    let data_dir = config.data_dir();

    // Load lead identity and derive child
    let lead_path = config::expand_tilde(lead_identity_path);
    let lead = NodeIdentity::from_file(&lead_path)?;
    let child = lead.derive_child(index)?;

    let child_pk = child.public_key();
    let child_pk_bech32 = encode_public_key(&child_pk)?;
    let child_suffix = child.entity_id_suffix();
    let entity_id = format!("swarm{index}_{child_suffix}");

    // Write child identity
    std::fs::create_dir_all(&data_dir)?;
    let identity_path = data_dir.join("identity.key");
    if identity_path.exists() {
        anyhow::bail!(
            "Identity already exists at {}. Use --force with `cordelia init` to overwrite.",
            identity_path.display()
        );
    }
    std::fs::write(&identity_path, child.seed())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Generate node token
    let token = cordelia_crypto::generate_psk()?;
    let token_hex = hex::encode(token);
    let token_path = data_dir.join("node-token");
    std::fs::write(&token_path, &token_hex)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Create database
    let db_path = data_dir.join("cordelia.db");
    let conn = cordelia_storage::db::open(&db_path)?;

    // Create channel-keys directory
    std::fs::create_dir_all(data_dir.join("channel-keys"))?;

    // Create persistent swarm channel
    let swarm_ch_id = cordelia_storage::naming::swarm_channel_id(lead_entity_id);
    let psk = cordelia_crypto::generate_psk()?;
    let psk_hash = cordelia_crypto::sha256(&psk);
    let now = chrono::Utc::now().to_rfc3339();
    // Insert as protocol-type channel (scope=network)
    let _ = conn.execute(
        "INSERT OR IGNORE INTO channels (channel_id, channel_type, mode, access, scope, creator_id, psk_hash, created_at, updated_at)
         VALUES (?1, 'named', 'realtime', 'invite_only', 'network', ?2, ?3, ?4, ?5)",
        rusqlite::params![swarm_ch_id, child_pk.as_slice(), psk_hash.as_slice(), now, now],
    );
    let _ = conn.execute(
        "INSERT OR IGNORE INTO channel_members (channel_id, entity_key, role, joined_at)
         VALUES (?1, ?2, 'owner', ?3)",
        rusqlite::params![swarm_ch_id, child_pk.as_slice(), now],
    );

    // Save PSK using the standard psk module (handles path encoding + 0600 permissions)
    cordelia_storage::psk::write_psk(&data_dir, &swarm_ch_id, &psk)?;

    // Create default ephemeral local channel
    let local_ch_id = format!("cordelia:local:{}", uuid::Uuid::new_v4());
    let local_psk = cordelia_crypto::generate_psk()?;
    cordelia_storage::channels::create_local(&conn, &local_ch_id, &child_pk, Some(&local_psk))?;

    // Save local PSK
    cordelia_storage::psk::write_psk(&data_dir, &local_ch_id, &local_psk)?;

    // Update config with swarm fields
    config.identity.entity_id = entity_id.clone();
    config.identity.public_key = child_pk_bech32.clone();
    config.swarm.swarm_index = Some(index);
    config.swarm.lead_identity_path = Some(lead_identity_path.to_string());
    config.swarm.lead_entity_id = Some(lead_entity_id.to_string());
    config.save(&config_file)?;

    println!("Swarm node initialised:");
    println!("  Entity:           {entity_id}");
    println!("  Public key:       {child_pk_bech32}");
    println!("  Derivation index: {index}");
    println!("  Lead entity:      {lead_entity_id}");
    println!("  Swarm channel:    {swarm_ch_id}");
    println!("  Local channel:    {local_ch_id}");
    println!("  Data directory:   {}", data_dir.display());

    Ok(())
}

fn cmd_pubkey(config_path: &str) -> anyhow::Result<()> {
    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file)?;
    config.apply_env_overrides();
    let data_dir = config.data_dir();

    let identity_path = data_dir.join("identity.key");
    if !identity_path.exists() {
        anyhow::bail!("Node not initialised. Run `cordelia init` first.");
    }

    let identity = NodeIdentity::from_file(&identity_path)?;
    let pk_bech32 = cordelia_crypto::bech32::encode_public_key(&identity.public_key())?;
    println!("{pk_bech32}");
    Ok(())
}

// ── Device commands (decision 2026-09-30-agent-memory-sync §3) ────
//
// Thin clients of the running node's local API: all logic lives in the
// node (cordelia_api::membership), which must be started first.

/// POST `body` to the local node's API and return the JSON response.
/// GET a local API endpoint of the running node; errors if it isn't running.
fn api_get(config_path: &str, path: &str) -> anyhow::Result<serde_json::Value> {
    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file)?;
    config.apply_env_overrides();
    local_api(&config, false, path, std::time::Duration::from_secs(3))
}

/// Call the running node's local API (GET, or POST with an empty body)
/// with the node token, failing after `timeout`.
fn local_api(
    config: &Config,
    post: bool,
    path: &str,
    timeout: std::time::Duration,
) -> anyhow::Result<serde_json::Value> {
    let token = std::fs::read_to_string(config.token_path())?;
    let url = format!(
        "http://{}:{}{path}",
        config.api.bind_address, config.node.http_port
    );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build()
        .into();
    let auth = format!("Bearer {}", token.trim());
    let resp = if post {
        agent
            .post(&url)
            .header("Authorization", &auth)
            .send_json(serde_json::json!({}))
    } else {
        agent.get(&url).header("Authorization", &auth).call()
    };
    let json = resp
        .map_err(|e| {
            anyhow::anyhow!(
                "cannot reach the local node at {url} ({e}). Start it with `cordelia start`."
            )
        })?
        .body_mut()
        .read_json()?;
    Ok(json)
}

fn api_post(
    config_path: &str,
    path: &str,
    body: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file)?;
    config.apply_env_overrides();

    let token_path = config.token_path();
    let token = std::fs::read_to_string(&token_path).map_err(|e| {
        anyhow::anyhow!(
            "read node token {}: {e}. Run `cordelia init` first.",
            token_path.display()
        )
    })?;
    let url = format!(
        "http://{}:{}{path}",
        config.api.bind_address, config.node.http_port
    );

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .into();
    let mut resp = agent
        .post(&url)
        .header("Authorization", &format!("Bearer {}", token.trim()))
        .send_json(&body)
        .map_err(|e| {
            anyhow::anyhow!(
                "cannot reach the local node at {url} ({e}). Start it with `cordelia start`."
            )
        })?;

    let status = resp.status();
    let json: serde_json::Value = resp
        .body_mut()
        .read_json()
        .unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        let message = json["error"]["message"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("HTTP {status}"));
        anyhow::bail!("{message}");
    }
    Ok(json)
}

fn cmd_add_device(config_path: &str, key: &str, name: Option<String>) -> anyhow::Result<()> {
    let resp = api_post(
        config_path,
        "/api/v1/devices/add",
        serde_json::json!({ "device": key, "name": name }),
    )?;
    let channels = resp["channels"].as_array().map(Vec::len).unwrap_or(0);
    let this_device = resp["this_device"].as_str().unwrap_or_default();
    println!(
        "Added {} to {channels} channel{}.",
        name.as_deref().unwrap_or(key),
        if channels == 1 { "" } else { "s" }
    );
    println!();
    println!("On the other device, run:");
    println!("  cordelia accept {this_device}");
    Ok(())
}

fn cmd_accept(config_path: &str, key: &str, name: Option<String>) -> anyhow::Result<()> {
    let resp = api_post(
        config_path,
        "/api/v1/devices/accept",
        serde_json::json!({ "key": key, "name": name }),
    )?;
    let joined = resp["applied"].as_array().map(Vec::len).unwrap_or(0);
    println!("Trusted {}.", name.as_deref().unwrap_or(key));
    if joined > 0 {
        println!(
            "Joined {joined} channel{}.",
            if joined == 1 { "" } else { "s" }
        );
    } else {
        println!("Its invites have not arrived yet; they will be applied as they do.");
    }
    Ok(())
}

fn cmd_remove_device(config_path: &str, key: &str) -> anyhow::Result<()> {
    let resp = api_post(
        config_path,
        "/api/v1/devices/remove",
        serde_json::json!({ "device": key }),
    )?;
    let rotated = resp["channels_rotated"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    println!(
        "Removed {key} from {rotated} channel{} and rotated {}.",
        if rotated == 1 { "" } else { "s" },
        if rotated == 1 {
            "its key"
        } else {
            "their keys"
        }
    );
    Ok(())
}

fn cmd_devices(config_path: &str) -> anyhow::Result<()> {
    let resp = api_post(config_path, "/api/v1/devices/list", serde_json::json!({}))?;
    for d in resp["devices"].as_array().into_iter().flatten() {
        let key = d["key"].as_str().unwrap_or_default();
        let name = d["name"].as_str().unwrap_or("");
        let marker = if d["this_device"].as_bool() == Some(true) {
            "  (this device)"
        } else if d["in_personal_channel"].as_bool() != Some(true) {
            "  (waiting to join)"
        } else {
            ""
        };
        println!("{key}  {name}{marker}");
    }
    Ok(())
}

fn cmd_invites(config_path: &str) -> anyhow::Result<()> {
    let resp = api_post(config_path, "/api/v1/invites/list", serde_json::json!({}))?;
    let pending = resp["pending"].as_array().cloned().unwrap_or_default();
    if pending.is_empty() {
        println!("No invites waiting.");
        return Ok(());
    }
    for p in &pending {
        println!(
            "{}  from {}  ({})",
            p["channel_id"].as_str().unwrap_or_default(),
            p["from"].as_str().unwrap_or_default(),
            p["received_at"].as_str().unwrap_or_default()
        );
    }
    println!();
    println!("To join, trust the sender: cordelia accept <from>");
    Ok(())
}

fn cmd_sync(config_path: &str, what: SyncCommand) -> anyhow::Result<()> {
    let resp = match what {
        SyncCommand::Claude {
            dir,
            exclude,
            no_home,
        } => {
            let dir = dir.map(|d| {
                std::fs::canonicalize(&d)
                    .map(|p| p.display().to_string())
                    .unwrap_or(d)
            });
            let mut body = serde_json::json!({ "enabled": true, "dir": dir, "home": !no_home });
            if !exclude.is_empty() {
                body["exclude"] = serde_json::json!(exclude);
            }
            let resp = api_post(config_path, "/api/v1/sync/claude", body)?;
            println!(
                "Syncing Claude Code memory in {}.",
                resp["dir"].as_str().unwrap_or("~/.claude")
            );
            if resp["home"].as_bool() == Some(false) {
                println!("Home-folder memory is not synced on this device.");
            }
            for e in resp["exclude"].as_array().into_iter().flatten() {
                println!(
                    "Never synced from this device: {}",
                    e.as_str().unwrap_or_default()
                );
            }
            println!("Run `cordelia sync status` in a few seconds to see what is syncing.");
            return Ok(());
        }
        SyncCommand::Off => {
            api_post(
                config_path,
                "/api/v1/sync/claude",
                serde_json::json!({ "enabled": false }),
            )?;
            println!("Sync is off. Files already synced stay where they are.");
            return Ok(());
        }
        SyncCommand::Status => api_post(config_path, "/api/v1/sync/status", serde_json::json!({}))?,
    };

    if resp["enabled"].as_bool() != Some(true) {
        println!("Sync is off. Turn it on with `cordelia sync claude`.");
        return Ok(());
    }
    println!(
        "Syncing Claude Code memory in {}",
        resp["dir"].as_str().unwrap_or_default()
    );
    let report = &resp["report"];
    if report.is_null() {
        println!("  (first cycle not run yet)");
        return Ok(());
    }
    println!(
        "  last cycle: {}",
        report["at"].as_str().unwrap_or_default()
    );
    for f in report["folders"].as_array().into_iter().flatten() {
        let state = if f["waiting"].as_bool() == Some(true) {
            "waiting to join".to_string()
        } else {
            "syncing".to_string()
        };
        println!(
            "  {:<45} {} ({})",
            f["project"].as_str().unwrap_or_default(),
            state,
            f["folder"].as_str().unwrap_or_default()
        );
        for s in f["skipped"].as_array().into_iter().flatten() {
            println!("      skipped: {}", s.as_str().unwrap_or_default());
        }
    }
    for e in report["excluded"].as_array().into_iter().flatten() {
        println!(
            "  {:<45} excluded on this device",
            e.as_str().unwrap_or_default()
        );
    }
    let unsynced = report["unsynced"].as_array().cloned().unwrap_or_default();
    if !unsynced.is_empty() {
        println!("  not synced (no git remote):");
        for u in &unsynced {
            println!("    {}", u.as_str().unwrap_or_default());
        }
    }
    for e in report["errors"].as_array().into_iter().flatten() {
        println!("  error: {}", e.as_str().unwrap_or_default());
    }
    Ok(())
}

// ── Signal handling ───────────────────────────────────────────────

/// Wait for SIGINT (Ctrl+C) or SIGTERM (systemd/launchctl stop).
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = ctrl_c => { tracing::info!("received SIGINT"); }
            _ = sigterm.recv() => { tracing::info!("received SIGTERM"); }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for Ctrl+C");
        tracing::info!("received SIGINT");
    }
}

// ── Tracing ───────────────────────────────────────────────────────

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("cordelia={level},actix_web=warn")));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2p_bind_addr() {
        let v4 = p2p_bind_addr("0.0.0.0:9474", 9474).unwrap();
        assert_eq!(v4.to_string(), "0.0.0.0:9474");
        // The port always comes from p2p_port.
        assert_eq!(p2p_bind_addr("0.0.0.0:9474", 19474).unwrap().port(), 19474);
        // Names resolve (Fly's fly-global-services is a hosts-file name).
        assert!(
            p2p_bind_addr("localhost:9474", 9474)
                .unwrap()
                .ip()
                .is_loopback()
        );
        assert!(p2p_bind_addr("[::]:9474", 9474).unwrap().is_ipv6());
        // Missing host falls back to all interfaces.
        assert_eq!(
            p2p_bind_addr(":9474", 9474).unwrap().to_string(),
            "0.0.0.0:9474"
        );
        assert!(p2p_bind_addr("no-such-host.invalid:9474", 9474).is_err());
    }

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(40), "40s");
        assert_eq!(format_uptime(245), "4m 05s");
        assert_eq!(format_uptime(3 * 3600 + 12 * 60 + 9), "3h 12m");
    }
}
