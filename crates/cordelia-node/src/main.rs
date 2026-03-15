//! Cordelia node binary: CLI, daemon lifecycle, signal handling.
//!
//! Spec: seed-drill/specs/operations.md

use std::sync::Mutex;

use actix_web::{App, HttpServer, web};
use clap::Parser;

use cordelia_core::config::{self, Config};
use cordelia_crypto::bech32::{HRP_X25519_PK, encode_public_key};
use cordelia_crypto::identity::NodeIdentity;

#[derive(Parser)]
#[command(name = "cordelia", about = "Encrypted pub/sub for AI agents")]
struct Cli {
    /// Path to config file
    #[arg(long, default_value = "~/.cordelia/config.toml")]
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
    /// Show node status
    Status,
    /// Start the node daemon
    Start,
    /// Stop the node daemon
    Stop,
    /// List connected peers
    Peers,
    /// List subscribed channels
    Channels,
    /// Show detailed metrics
    Stats,
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
        Some(Commands::Status) => cmd_status(&cli.config),
        Some(Commands::Start) => cmd_start(&cli.config),
        Some(Commands::Stop) => {
            println!("cordelia stop: not yet implemented (requires PID file / signal)");
            Ok(())
        }
        Some(Commands::Peers) => cmd_peers(),
        Some(Commands::Channels) => cmd_channels(&cli.config),
        Some(Commands::Stats) => cmd_stats(&cli.config),
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

    // 6. Create personal channel
    let personal_channel_id = cordelia_storage::naming::personal_channel_id(&pk);
    let personal_psk_path = cordelia_storage::psk::psk_path(&data_dir, &personal_channel_id);
    if !personal_psk_path.exists() {
        println!("Creating personal channel...");
        let psk = cordelia_crypto::generate_psk()?;
        cordelia_storage::psk::write_psk(&data_dir, &personal_channel_id, &psk)?;
        println!("  done.");
    }

    // 7. Write config
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

fn cmd_status(config_path: &str) -> anyhow::Result<()> {
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

    Ok(())
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

    println!("Cordelia v{}", env!("CARGO_PKG_VERSION"));
    println!("  Entity:    {}", config.identity.entity_id);
    println!("  Public key: {pk_bech32}");
    println!("  HTTP API:  http://{listen_addr}/api/v1/channels/");
    println!("  P2P port:  {p2p_port}/UDP");
    println!("  Role:      {}", config.network.role);
    println!();

    // Build app state
    let identity_arc = std::sync::Arc::new(identity);
    let (push_tx, push_rx) = tokio::sync::mpsc::unbounded_channel();

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
    });

    // Start the tokio/actix runtime with graceful shutdown
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        tracing::info!(%listen_addr, p2p_port, "starting node");

        // ── P2P transport ──────────────────────────────────────────
        let p2p_bind: std::net::SocketAddr =
            format!("0.0.0.0:{p2p_port}").parse().unwrap();
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
                    std::time::Duration::from_secs(10),
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
        let p2p_handle = tokio::spawn(async move {
            p2p_loop(conn_mgr, p2p_state, push_rx, &mut p2p_shutdown_rx, allow_private, role_for_p2p, config.governor.clone()).await;
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

// ── P2P background loop ───────────────────────────────────────────

/// Background task that accepts incoming QUIC connections, handles
/// outbound item pushes, and manages peer lifecycle. Communicates
/// peer counts back to the HTTP API via AppState atomic counters.
async fn p2p_loop(
    mut conn_mgr: cordelia_network::connection::ConnectionManager,
    state: web::Data<cordelia_api::state::AppState>,
    mut push_rx: tokio::sync::mpsc::UnboundedReceiver<cordelia_api::state::PushItem>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    allow_private_addresses: bool,
    node_role: String,
    gov_config: cordelia_core::config::GovernorConfig,
) {
    tracing::info!(role = %node_role, "P2P loop started (accept + push + peer-sharing)");

    // Create a push sender for handle_peer_streams (relay re-push)
    // We re-use the state's push_tx for this
    let relay_push_tx: tokio::sync::mpsc::UnboundedSender<cordelia_api::state::PushItem> = state
        .push_tx
        .as_ref()
        .expect("push_tx must be set when P2P is running")
        .clone();

    // Shared peer list: updated by p2p_loop, read by per-peer stream handlers
    let shared_peers: std::sync::Arc<
        std::sync::RwLock<Vec<cordelia_network::messages::PeerAddress>>,
    > = std::sync::Arc::new(std::sync::RwLock::new(conn_mgr.known_peer_addresses()));

    // Our own node identity for filtering
    let our_node_id = cordelia_core::NodeId(state.identity.public_key());

    // Governor: manages Hot/Warm/Cold peer lifecycle (§5)
    let gov_targets = cordelia_network::governor::GovernorTargets::from_config(&gov_config);
    let gov_timeouts = cordelia_network::governor::GovernorTimeouts::from_config(&gov_config);
    let mut governor = cordelia_network::governor::Governor::new(gov_targets, vec![])
        .with_timeouts(gov_timeouts);

    // Register any peers from bootstrap as connected
    for peer_id in conn_mgr.connected_peers() {
        governor.add_peer(peer_id.clone(), vec![], vec![]);
        governor.mark_connected(&peer_id);
    }
    // Immediately promote all connected peers to Hot (small network bootstrap)
    governor.tick();

    // Peer-sharing timer: discover new peers from connected peers
    let mut peer_share_interval = tokio::time::interval(std::time::Duration::from_secs(5));
    peer_share_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    peer_share_interval.tick().await; // skip first immediate tick

    // Pull-sync timer: anti-entropy, fetch missing items from hot peers (§4.5)
    let mut sync_interval = tokio::time::interval(std::time::Duration::from_secs(10));
    sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    sync_interval.tick().await; // skip first immediate tick

    // Governor tick timer: peer promotion/demotion (§5.4)
    let mut gov_interval = tokio::time::interval(std::time::Duration::from_secs(10));
    gov_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    gov_interval.tick().await; // skip first immediate tick

    // Governor event channel: spawned tasks report events back to governor
    enum GovEvent {
        ItemsDelivered(cordelia_core::NodeId, u64),
        Activity(cordelia_core::NodeId),
    }
    let (gov_tx, mut gov_rx) = tokio::sync::mpsc::unbounded_channel::<GovEvent>();

    loop {
        tokio::select! {
            // Accept incoming connection
            result = conn_mgr.accept_incoming() => {
                match result {
                    Ok(node_id) => {
                        let count = conn_mgr.connection_count() as u64;
                        state.peers_hot.store(count, std::sync::atomic::Ordering::Relaxed);
                        tracing::info!(peer = %node_id, peers = count, "accepted inbound connection");

                        // Register with governor
                        governor.add_peer(node_id.clone(), vec![], vec![]);
                        governor.mark_connected(&node_id);

                        // Update shared peer list
                        if let Ok(mut peers) = shared_peers.write() {
                            *peers = conn_mgr.known_peer_addresses();
                        }

                        // Spawn stream handler for this peer's inbound protocol streams
                        if let Some(conn) = conn_mgr.get_connection(&node_id) {
                            let conn = conn.clone();
                            let peer_id = node_id.clone();
                            let db_state = state.clone();
                            let peers_ref = shared_peers.clone();
                            let role = node_role.clone();
                            let ptx = relay_push_tx.clone();
                            tokio::spawn(async move {
                                handle_peer_streams(conn, peer_id, db_state, peers_ref, role, ptx).await;
                            });
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "inbound connection failed");
                    }
                }
            }

            // Periodic peer-sharing: request peers from a connected peer
            _ = peer_share_interval.tick() => {
                let peers = conn_mgr.connected_peers();
                if peers.is_empty() {
                    continue;
                }
                let target = peers[0].clone();
                if let Some(conn) = conn_mgr.get_connection(&target) {
                    let conn = conn.clone();
                    // Open stream with 5s timeout (spec: debug-telemetry.md §5)
                    let (mut send, mut recv) = match tokio::time::timeout(
                        std::time::Duration::from_secs(5), conn.open_bi(),
                    ).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => { tracing::debug!(peer = %target, error = %e, "peer-share open_bi failed"); continue; }
                        Err(_) => { tracing::debug!(peer = %target, "peer-share open_bi timed out (5s)"); continue; }
                    };
                    let mut stream = tokio::io::join(&mut recv, &mut send);
                    // Request peers with 5s timeout
                    let discovered = match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        cordelia_network::peer_sharing::request_peers(&mut stream, 20),
                    ).await {
                        Ok(Ok(d)) => d,
                        Ok(Err(e)) => { tracing::debug!(peer = %target, error = %e, "peer-share request failed"); continue; }
                        Err(_) => { tracing::debug!(peer = %target, "peer-share request timed out (5s)"); continue; }
                    };
                    drop(stream); drop(send); drop(recv); // close stream promptly
                    // Filter and connect to new peers
                    let own_addr = conn_mgr.local_addr().ok();
                    let valid = if allow_private_addresses {
                        discovered
                    } else {
                        cordelia_network::peer_sharing::filter_valid_addresses(&discovered, own_addr.as_ref())
                    };
                    for peer_addr in &valid {
                        let peer_node_id = cordelia_core::NodeId(
                            peer_addr.node_id.as_slice().try_into().unwrap_or([0u8; 32])
                        );
                        if peer_node_id == our_node_id || conn_mgr.is_connected(&peer_node_id) {
                            continue;
                        }
                        if let Some(addr_str) = peer_addr.addrs.first() {
                            if let Ok(addr) = addr_str.parse() {
                                // 10s timeout per peer-share connect (spec: debug-telemetry.md §5)
                                match tokio::time::timeout(
                                    std::time::Duration::from_secs(10),
                                    conn_mgr.connect_to(addr),
                                ).await {
                                    Ok(Ok(new_id)) => {
                                        let count = conn_mgr.connection_count() as u64;
                                        state.peers_hot.store(count, std::sync::atomic::Ordering::Relaxed);
                                        tracing::info!(peer = %new_id, peers = count, "connected via peer-sharing");
                                        governor.add_peer(new_id.clone(), vec![], vec![]);
                                        governor.mark_connected(&new_id);
                                        if let Ok(mut peers) = shared_peers.write() {
                                            *peers = conn_mgr.known_peer_addresses();
                                        }
                                        if let Some(new_conn) = conn_mgr.get_connection(&new_id) {
                                            let new_conn = new_conn.clone();
                                            let peer_id = new_id;
                                            let db_state = state.clone();
                                            let peers_ref = shared_peers.clone();
                                            let role = node_role.clone();
                                            let ptx = relay_push_tx.clone();
                                            tokio::spawn(async move {
                                                handle_peer_streams(new_conn, peer_id, db_state, peers_ref, role, ptx).await;
                                            });
                                        }
                                    }
                                    Ok(Err(e)) => { tracing::debug!(addr = %addr_str, error = %e, "peer-share connect failed"); }
                                    Err(_) => { tracing::warn!(addr = %addr_str, "peer-share connect timed out (10s)"); }
                                }
                            }
                        }
                    }
                }
            }

            // Push items to hot peers
            Some(push_item) = push_rx.recv() => {
                let item = cordelia_network::messages::Item {
                    item_id: push_item.item_id.clone(),
                    channel_id: push_item.channel_id.clone(),
                    item_type: push_item.item_type,
                    encrypted_blob: push_item.encrypted_blob,
                    content_hash: push_item.content_hash,
                    content_length: 0, // computed from blob
                    author_id: push_item.author_id,
                    signature: push_item.signature,
                    key_version: push_item.key_version,
                    published_at: push_item.published_at,
                    is_tombstone: push_item.is_tombstone,
                    parent_id: push_item.parent_id,
                };

                // Push to HOT peers only (§4.6, BV-25). Skip excluded peer for relay re-push.
                let exclude = push_item.exclude_peer;
                let all_peers = governor.hot_peers();
                let mut push_count = 0u32;
                let mut skip_count = 0u32;
                for peer_id in &all_peers {
                    if exclude.as_ref() == Some(peer_id) {
                        skip_count += 1;
                        continue;
                    }
                    if let Some(conn) = conn_mgr.get_connection(peer_id) {
                        let conn = conn.clone();
                        let items = vec![item.clone()];
                        let pid = peer_id.clone();
                        push_count += 1;
                        let iid = push_item.item_id.clone();
                        tracing::debug!(peer = %pid, item = %iid, "spawning push task");
                        // Fire and forget -- don't block the loop
                        tokio::spawn(async move {
                            tracing::debug!(peer = %pid, item = %iid, "push open_bi started");
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                conn.open_bi(),
                            ).await {
                                Ok(Ok((mut send, mut recv))) => {
                                    let mut stream = tokio::io::join(&mut recv, &mut send);
                                    match cordelia_network::item_sync::send_push(&mut stream, &items).await {
                                        Ok(ack) => {
                                            tracing::debug!(
                                                peer = %pid,
                                                stored = ack.stored,
                                                "push delivered"
                                            );
                                        }
                                        Err(e) => {
                                            tracing::debug!(peer = %pid, error = %e, "push send failed");
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    tracing::debug!(peer = %pid, error = %e, "push open_bi failed");
                                }
                                Err(_) => {
                                    tracing::warn!(peer = %pid, "push open_bi timed out (10s)");
                                }
                            }
                        });
                    } else {
                        tracing::warn!(peer = %peer_id, "push skipped: get_connection returned None");
                    }
                }
                tracing::debug!(
                    channel = %push_item.channel_id,
                    item = %push_item.item_id,
                    total_peers = all_peers.len(),
                    pushed = push_count,
                    excluded = skip_count,
                    "item pushed to peers"
                );
            }

            // Periodic pull-sync: fetch missing items from connected peers
            _ = sync_interval.tick() => {
                if node_role == "bootnode" {
                    continue; // bootnodes don't store/sync items
                }
                let peers = conn_mgr.connected_peers();
                if peers.is_empty() {
                    continue;
                }
                // Get channels we're subscribed to
                let channels: Vec<String> = {
                    let db = match state.db.lock() {
                        Ok(db) => db,
                        Err(_) => continue,
                    };
                    let pk = state.identity.public_key();
                    cordelia_storage::channels::list_for_entity(&db, &pk)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|c| c.channel_id)
                        .collect()
                };

                if channels.is_empty() {
                    continue;
                }

                // Sync from HOT peers only (§4.5, BV-25). O(hot_max) per cycle.
                let hot = governor.hot_peers();
                tracing::debug!(hot_peers = hot.len(), total_peers = peers.len(), channels = channels.len(), "pull-sync cycle");
                for target in &hot {
                    if let Some(conn) = conn_mgr.get_connection(target) {
                    let conn = conn.clone();
                    let sync_state = state.clone();
                    let sync_channels = channels.clone();
                    let target = target.clone();
                    let gtx = gov_tx.clone();
                    tracing::debug!(peer = %target, channels = sync_channels.len(), "pull-sync starting");
                    tokio::spawn(async move {
                        for ch_id in &sync_channels {
                            // Open a new stream for each channel sync (10s timeout)
                            let (mut send, mut recv) = match tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                conn.open_bi(),
                            ).await {
                                Ok(Ok(s)) => s,
                                Ok(Err(e)) => { tracing::debug!(peer = %target, channel = %ch_id, error = %e, "sync open_bi failed"); break; }
                                Err(_) => { tracing::warn!(peer = %target, channel = %ch_id, "sync open_bi timed out (10s)"); break; }
                            };
                            let mut stream = tokio::io::join(&mut recv, &mut send);

                            // Send sync request (15s timeout per spec)
                            tracing::debug!(peer = %target, channel = %ch_id, "sync request sent");
                            let resp = match tokio::time::timeout(
                                std::time::Duration::from_secs(15),
                                cordelia_network::item_sync::send_sync_request(&mut stream, ch_id, None, 100),
                            ).await {
                                Ok(Ok(r)) => r,
                                Ok(Err(e)) => {
                                    tracing::debug!(peer = %target, channel = %ch_id, error = %e, "sync request failed");
                                    continue;
                                }
                                Err(_) => {
                                    tracing::warn!(peer = %target, channel = %ch_id, "sync request timed out (15s)");
                                    continue;
                                }
                            };

                            tracing::debug!(peer = %target, channel = %ch_id, headers = resp.items.len(), "sync response received");
                            if resp.items.is_empty() {
                                continue;
                            }

                            // Compare with local DB to find missing items
                            let known = {
                                let db = match sync_state.db.lock() {
                                    Ok(db) => db,
                                    Err(_) => continue,
                                };
                                let stored = cordelia_storage::items::query_listen(
                                    &db, ch_id, None, 1000,
                                ).unwrap_or_default();
                                stored.into_iter()
                                    .map(|si| (si.item_id, (si.content_hash, si.published_at)))
                                    .collect::<std::collections::HashMap<_, _>>()
                            };

                            let fetch_ids = cordelia_network::item_sync::compute_fetch_list(
                                &resp.items, &known,
                            );

                            if fetch_ids.is_empty() {
                                continue;
                            }

                            // Fetch missing items
                            if let Err(e) = cordelia_network::item_sync::send_fetch_request(
                                &mut send, &fetch_ids,
                            ).await {
                                tracing::debug!(error = %e, "fetch request failed");
                                continue;
                            }

                            let items = match tokio::time::timeout(
                                std::time::Duration::from_secs(30),
                                cordelia_network::item_sync::read_fetch_response(&mut recv),
                            ).await {
                                Ok(Ok(items)) => items,
                                Ok(Err(e)) => {
                                    tracing::debug!(peer = %target, error = %e, "fetch response failed");
                                    continue;
                                }
                                Err(_) => {
                                    tracing::warn!(peer = %target, channel = %ch_id, "fetch response timed out (30s)");
                                    continue;
                                }
                            };

                            // Store fetched items
                            let mut stored_count = 0u32;
                            {
                                let db = match sync_state.db.lock() {
                                    Ok(db) => db,
                                    Err(_) => continue,
                                };
                                for item in &items {
                                    if !cordelia_network::item_sync::verify_content_hash(item) {
                                        continue;
                                    }
                                    let author: [u8; 32] = match item.author_id.as_slice().try_into() {
                                        Ok(a) => a, Err(_) => continue,
                                    };
                                    let hash: [u8; 32] = match item.content_hash.as_slice().try_into() {
                                        Ok(h) => h, Err(_) => continue,
                                    };
                                    let sig: [u8; 64] = match item.signature.as_slice().try_into() {
                                        Ok(s) => s, Err(_) => continue,
                                    };
                                    let new_item = cordelia_storage::items::NewItem {
                                        item_id: &item.item_id,
                                        channel_id: &item.channel_id,
                                        author_id: &author,
                                        item_type: &item.item_type,
                                        published_at: &item.published_at,
                                        parent_id: item.parent_id.as_deref(),
                                        key_version: item.key_version as i64,
                                        content_hash: &hash,
                                        signature: &sig,
                                        encrypted_blob: &item.encrypted_blob,
                                    };
                                    if let Ok(true) = cordelia_storage::items::insert_item(&db, &new_item) {
                                        stored_count += 1;
                                    }
                                }
                            } // db lock dropped

                            if stored_count > 0 {
                                tracing::info!(
                                    channel = %ch_id,
                                    fetched = fetch_ids.len(),
                                    stored = stored_count,
                                    "pull-sync complete"
                                );
                                let _ = gtx.send(GovEvent::ItemsDelivered(target.clone(), stored_count as u64));
                            }
                        }
                    });
                    } // if let Some(conn)
                } // for target in peers
            }

            // Governor tick: peer promotion/demotion/churn (§5.4)
            _ = gov_interval.tick() => {
                // Drain governor event channel
                while let Ok(event) = gov_rx.try_recv() {
                    match event {
                        GovEvent::ItemsDelivered(peer_id, count) => {
                            governor.record_items_delivered(&peer_id, count);
                        }
                        GovEvent::Activity(peer_id) => {
                            governor.record_activity(&peer_id, None);
                        }
                    }
                }
                // Sync governor with connection manager
                let connected = conn_mgr.connected_peers();
                // Mark all connected peers as active (alive)
                for peer_id in &connected {
                    governor.record_activity(peer_id, None);
                }
                // Detect disconnected peers (governor knows, conn_mgr doesn't)
                let gov_active: Vec<_> = governor.hot_peers();
                for peer_id in &gov_active {
                    if !connected.contains(peer_id) {
                        governor.mark_disconnected(peer_id);
                    }
                }
                // Update hot/warm peer counts in shared state
                let (hot, warm, cold, banned) = governor.counts();
                state.peers_hot.store(hot as u64, std::sync::atomic::Ordering::Relaxed);

                let actions = governor.tick();
                if !actions.transitions.is_empty() {
                    for (node_id, from, to) in &actions.transitions {
                        tracing::info!(peer = %node_id, from, to, "gov: state transition");
                    }
                }
                // Disconnect peers the governor wants removed
                for node_id in &actions.disconnect {
                    conn_mgr.disconnect(node_id);
                }
                // Connect peers the governor wants promoted (Cold->Warm)
                for node_id in &actions.connect {
                    if let Some(peer) = governor.peer_info(node_id) {
                        if let Some(addr_str) = peer.addrs.first() {
                            if let Ok(addr) = addr_str.parse() {
                                match tokio::time::timeout(
                                    std::time::Duration::from_secs(10),
                                    conn_mgr.connect_to(addr),
                                ).await {
                                    Ok(Ok(new_id)) => {
                                        governor.mark_connected(&new_id);
                                        tracing::info!(peer = %new_id, "gov: connected (promotion)");
                                        if let Some(new_conn) = conn_mgr.get_connection(&new_id) {
                                            let new_conn = new_conn.clone();
                                            let peer_id = new_id;
                                            let db_state = state.clone();
                                            let peers_ref = shared_peers.clone();
                                            let role = node_role.clone();
                                            let ptx = relay_push_tx.clone();
                                            tokio::spawn(async move {
                                                handle_peer_streams(new_conn, peer_id, db_state, peers_ref, role, ptx).await;
                                            });
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        governor.mark_dial_failed(node_id);
                                        tracing::debug!(peer = %node_id, error = %e, "gov: connect failed");
                                    }
                                    Err(_) => {
                                        governor.mark_dial_failed(node_id);
                                        tracing::debug!(peer = %node_id, "gov: connect timed out (10s)");
                                    }
                                }
                            }
                        }
                    }
                }
                let (hot, warm, cold, banned) = governor.counts();
                state.peers_hot.store(hot as u64, std::sync::atomic::Ordering::Relaxed);
                tracing::debug!(hot, warm, cold, banned, "gov: tick complete");
            }

            // Shutdown signal
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("P2P loop shutting down");
                    conn_mgr.shutdown();
                    break;
                }
            }
        }
    }
}

/// Handle inbound protocol streams from a connected peer.
/// Runs until the connection closes.
async fn handle_peer_streams(
    conn: quinn::Connection,
    peer_id: cordelia_core::NodeId,
    state: web::Data<cordelia_api::state::AppState>,
    shared_peers: std::sync::Arc<std::sync::RwLock<Vec<cordelia_network::messages::PeerAddress>>>,
    node_role: String,
    push_tx: tokio::sync::mpsc::UnboundedSender<cordelia_api::state::PushItem>,
) {
    let mut stream_count: u64 = 0;
    loop {
        // Accept next bidirectional stream from this peer
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                let reason = match &e {
                    quinn::ConnectionError::TimedOut => "idle_timeout",
                    quinn::ConnectionError::Reset => "reset",
                    quinn::ConnectionError::ApplicationClosed(_) => "shutdown",
                    quinn::ConnectionError::LocallyClosed => "local_close",
                    _ => "error",
                };
                tracing::info!(peer = %peer_id, reason, streams = stream_count, error = %e, "peer connection closed");
                break;
            }
        };

        stream_count += 1;

        // Read protocol byte to determine handler
        let protocol = match cordelia_network::codec::read_protocol_byte(&mut recv).await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "failed to read protocol byte");
                continue;
            }
        };

        let proto_name = match protocol {
            cordelia_network::messages::Protocol::ItemPush => "item_push",
            cordelia_network::messages::Protocol::ItemSync => "item_sync",
            cordelia_network::messages::Protocol::PeerSharing => "peer_share",
            _ => "other",
        };
        tracing::debug!(peer = %peer_id, protocol = proto_name, stream = stream_count, "stream opened (inbound)");
        let stream_start = std::time::Instant::now();

        match protocol {
            cordelia_network::messages::Protocol::ItemPush => {
                // Read push payload
                let msg = match cordelia_network::codec::read_frame(&mut recv).await {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!(peer = %peer_id, error = %e, "failed to read push frame");
                        continue;
                    }
                };

                if let cordelia_network::messages::WireMessage::PushPayload(payload) = msg {
                    let mut stored = 0u32;
                    let mut dedup = 0u32;

                    // Scope the DB lock so it's dropped before the await
                    {
                        let db = match state.db.lock() {
                            Ok(db) => db,
                            Err(_) => continue,
                        };

                        for item in &payload.items {
                            if !cordelia_network::item_sync::verify_content_hash(item) {
                                tracing::warn!(item = %item.item_id, "content hash mismatch");
                                continue;
                            }

                            // Relay: ensure channel row exists (no FK violation)
                            if node_role == "relay" {
                                let _ = db.execute(
                                    "INSERT OR IGNORE INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at) VALUES (?1, 'named', 'realtime', 'open', X'00', datetime('now'), datetime('now'))",
                                    rusqlite::params![item.channel_id],
                                );
                            }

                            let author: [u8; 32] = match item.author_id.as_slice().try_into() {
                                Ok(a) => a,
                                Err(_) => continue,
                            };
                            let hash: [u8; 32] = match item.content_hash.as_slice().try_into() {
                                Ok(h) => h,
                                Err(_) => continue,
                            };
                            let sig: [u8; 64] = match item.signature.as_slice().try_into() {
                                Ok(s) => s,
                                Err(_) => continue,
                            };

                            let new_item = cordelia_storage::items::NewItem {
                                item_id: &item.item_id,
                                channel_id: &item.channel_id,
                                author_id: &author,
                                item_type: &item.item_type,
                                published_at: &item.published_at,
                                parent_id: item.parent_id.as_deref(),
                                key_version: item.key_version as i64,
                                content_hash: &hash,
                                signature: &sig,
                                encrypted_blob: &item.encrypted_blob,
                            };

                            match cordelia_storage::items::insert_item(&db, &new_item) {
                                Ok(true) => stored += 1,
                                Ok(false) => dedup += 1,
                                Err(e) => {
                                    tracing::debug!(item = %item.item_id, error = %e, "store failed");
                                }
                            }
                        }
                    } // db lock dropped here

                    tracing::debug!(
                        peer = %peer_id,
                        stored, dedup,
                        items = payload.items.len(),
                        "processed inbound push"
                    );

                    // Relay re-push: if we're a relay, forward to other peers
                    if node_role == "relay" && stored > 0 {
                        for item in &payload.items {
                            let _ = push_tx.send(cordelia_api::state::PushItem {
                                channel_id: item.channel_id.clone(),
                                item_id: item.item_id.clone(),
                                encrypted_blob: item.encrypted_blob.clone(),
                                content_hash: item.content_hash.clone(),
                                author_id: item.author_id.clone(),
                                signature: item.signature.clone(),
                                key_version: item.key_version,
                                published_at: item.published_at.clone(),
                                item_type: item.item_type.clone(),
                                is_tombstone: item.is_tombstone,
                                parent_id: item.parent_id.clone(),
                                exclude_peer: Some(peer_id.clone()), // don't push back to sender
                            });
                        }
                        tracing::debug!(
                            peer = %peer_id,
                            stored,
                            "relay re-push queued"
                        );
                    }

                    // Send ack (safe to await now, db lock is released)
                    let ack = cordelia_network::messages::WireMessage::PushAck(
                        cordelia_network::messages::PushAck {
                            stored,
                            dedup_dropped: dedup,
                            policy_rejected: 0,
                            verification_failed: 0,
                        },
                    );
                    let _ = cordelia_network::codec::write_frame(&mut send, &ack).await;
                }
            }
            cordelia_network::messages::Protocol::ItemSync => {
                // Handle sync request: return item headers from our DB
                let msg = match cordelia_network::codec::read_frame(&mut recv).await {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!(peer = %peer_id, error = %e, "sync request read failed");
                        continue;
                    }
                };
                if let cordelia_network::messages::WireMessage::SyncRequest(req) = msg {
                    let (headers, has_more) = {
                        let db = match state.db.lock() {
                            Ok(db) => db,
                            Err(_) => continue,
                        };
                        let items = cordelia_storage::items::query_listen(
                            &db,
                            &req.channel_id,
                            req.since.as_deref(),
                            req.limit,
                        )
                        .unwrap_or_default();
                        let has_more = items.len() as u32 >= req.limit;
                        let headers: Vec<cordelia_network::messages::ItemHeader> = items
                            .iter()
                            .map(|si| cordelia_network::messages::ItemHeader {
                                item_id: si.item_id.clone(),
                                channel_id: si.channel_id.clone(),
                                item_type: si.item_type.clone(),
                                content_hash: si.content_hash.clone(),
                                author_id: si.author_id.clone(),
                                signature: si.signature.clone(),
                                key_version: si.key_version as u32,
                                published_at: si.published_at.clone(),
                                is_tombstone: si.is_tombstone,
                                parent_id: si.parent_id.clone(),
                            })
                            .collect();
                        (headers, has_more)
                    }; // db lock dropped

                    let resp = cordelia_network::messages::WireMessage::SyncResponse(
                        cordelia_network::messages::SyncResponse {
                            items: headers,
                            has_more,
                        },
                    );
                    let _ = cordelia_network::codec::write_frame(&mut send, &resp).await;
                    tracing::debug!(peer = %peer_id, channel = %req.channel_id, "served sync request");

                    // Handle optional FetchRequest on same stream
                    if let Ok(fetch_msg) = cordelia_network::codec::read_frame(&mut recv).await {
                        if let cordelia_network::messages::WireMessage::FetchRequest(freq) =
                            fetch_msg
                        {
                            let fetch_items = {
                                let db = match state.db.lock() {
                                    Ok(db) => db,
                                    Err(_) => continue,
                                };
                                let items = cordelia_storage::items::query_listen(
                                    &db,
                                    &req.channel_id,
                                    None,
                                    1000,
                                )
                                .unwrap_or_default();
                                items
                                    .into_iter()
                                    .filter(|si| freq.item_ids.contains(&si.item_id))
                                    .map(|si| cordelia_network::messages::Item {
                                        item_id: si.item_id,
                                        channel_id: si.channel_id,
                                        item_type: si.item_type,
                                        encrypted_blob: si.encrypted_blob,
                                        content_hash: si.content_hash,
                                        content_length: 0,
                                        author_id: si.author_id,
                                        signature: si.signature,
                                        key_version: si.key_version as u32,
                                        published_at: si.published_at,
                                        is_tombstone: si.is_tombstone,
                                        parent_id: si.parent_id,
                                    })
                                    .collect::<Vec<_>>()
                            }; // db lock dropped
                            let fresp = cordelia_network::messages::WireMessage::FetchResponse(
                                cordelia_network::messages::FetchResponse { items: fetch_items },
                            );
                            let _ = cordelia_network::codec::write_frame(&mut send, &fresp).await;
                            tracing::debug!(peer = %peer_id, fetched = freq.item_ids.len(), "served fetch request");
                        }
                    }
                }
            }
            cordelia_network::messages::Protocol::PeerSharing => {
                // Read request, respond with current known peers
                let msg = match cordelia_network::codec::read_frame(&mut recv).await {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!(peer = %peer_id, error = %e, "peer-share read failed");
                        continue;
                    }
                };
                if let cordelia_network::messages::WireMessage::PeerShareRequest(req) = msg {
                    let max = req.max_peers as usize;
                    let current_peers = shared_peers
                        .read()
                        .map(|p| p.iter().take(max).cloned().collect::<Vec<_>>())
                        .unwrap_or_default();
                    let count = current_peers.len();
                    let resp = cordelia_network::messages::WireMessage::PeerShareResponse(
                        cordelia_network::messages::PeerShareResponse {
                            peers: current_peers,
                        },
                    );
                    let _ = cordelia_network::codec::write_frame(&mut send, &resp).await;
                    tracing::debug!(peer = %peer_id, count, "served peer-share request");
                }
            }
            other => {
                tracing::debug!(peer = %peer_id, protocol = ?other, "ignoring unhandled protocol");
            }
        }
        // Stream close logging (all protocol handlers)
        tracing::debug!(
            peer = %peer_id, protocol = proto_name, stream = stream_count,
            duration_ms = stream_start.elapsed().as_millis() as u64,
            "stream closed"
        );
        drop(send);
        drop(recv);
    }
}

// ── cordelia peers ─────────────────────────────────────────────────

fn cmd_peers() -> anyhow::Result<()> {
    println!("ENTITY          STATE   LATENCY   ADDRESS");
    println!();
    println!("No peers connected (P2P transport not yet implemented).");
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
        "{:<24} {:<10} {:>6}   {:<20} {}",
        "CHANNEL", "MODE", "ITEMS", "LAST ACTIVITY", "TYPE"
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
