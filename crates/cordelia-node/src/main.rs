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
        /// Icon, tooltip and class as JSON, for Waybar and the Omarchy bar
        #[arg(long, conflicts_with_all = ["line", "json"])]
        waybar: bool,
    },
    /// Start the node daemon
    Start,
    /// Stop the node daemon
    Stop,
    /// List the peers the running node is connected to
    Peers {
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// List subscribed channels
    Channels,
    /// Show what this node stores and has seen (counts only)
    Stats {
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
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
    /// Turn on Claude Code memory sync. Nothing syncs until you map a
    /// folder (`cordelia sync map`) or pass --all. Running it again keeps
    /// your settings.
    Claude {
        /// Claude Code directory (default: ~/.claude)
        #[arg(long)]
        dir: Option<String>,
        /// Sync everything found, now and later: home memory and every git
        /// project, as well as the folders you map
        #[arg(long)]
        all: bool,
        /// Sync only the folders you map (turns --all off)
        #[arg(long, conflicts_with = "all")]
        mapped_only: bool,
        /// With --all: never sync this project from this device (its git
        /// remote, e.g. github.com/client-co/app, or a prefix ending in *).
        /// Repeatable; replaces the current list.
        #[arg(long)]
        exclude: Vec<String>,
        /// Do not sync home-folder memory on this device (unmaps it too)
        #[arg(long)]
        no_home: bool,
        /// Back to the defaults: ~/.claude, only mapped folders, nothing
        /// excluded. Mapped folders stay mapped.
        #[arg(long)]
        reset: bool,
    },
    /// Sync Claude's memory for a folder under a name. The name is what
    /// your devices share: map the same name on each of them. For a git
    /// project it defaults to the remote (github.com/owner/repo), and for
    /// your home directory to `~`. Claude Code keeps one memory per
    /// repository, so any folder of a repository maps the whole repository.
    Map {
        /// The folder you run Claude Code in
        folder: String,
        /// The name to sync under (default: the folder's git remote; `~`
        /// for the home directory)
        name: Option<String>,
        /// Map the home directory itself: home memory, under `~` or under
        /// the name given
        #[arg(long)]
        home: bool,
    },
    /// Stop syncing a mapped folder from this device (its files stay where
    /// they are)
    Unmap {
        /// The folder, or the name it is mapped to
        folder: String,
    },
    /// Stop syncing (files already synced are left in place)
    Off,
    /// Show what syncs, what was found, and what your other devices sync
    Status,
    /// Sync home-folder memory on this device, or not
    Home {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// With --all: stop syncing one project from this device (its git
    /// remote, e.g. github.com/client-co/app, or a prefix ending in *)
    Exclude { project: String },
    /// With --all: sync a project again after `exclude`
    Include { project: String },
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
        Some(Commands::Status { line, json, waybar }) => {
            cmd_status(&cli.config, line, json, waybar)
        }
        Some(Commands::Start) => cmd_start(&cli.config),
        Some(Commands::Stop) => {
            println!("cordelia stop: not yet implemented (requires PID file / signal)");
            Ok(())
        }
        Some(Commands::Peers { json }) => cmd_peers(&cli.config, json),
        Some(Commands::Channels) => cmd_channels(&cli.config),
        Some(Commands::Stats { json }) => cmd_stats(&cli.config, json),
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

fn cmd_status(config_path: &str, line: bool, json: bool, waybar: bool) -> anyhow::Result<()> {
    let status = gather_status(config_path);
    let (state, summary) = indicator::derive(&status.facts);

    if waybar {
        let mut details = Vec::new();
        if status.facts.running {
            let relays = status.facts.peers_hot;
            details.push(match relays {
                0 => "Relays: none connected".to_string(),
                n => format!("Relays: {n} connected"),
            });
            if status.facts.outbox_waiting > 0 {
                details.push(format!("Waiting to send: {}", status.facts.outbox_waiting));
            }
            if status.facts.outbox_refused > 0 {
                details.push(format!(
                    "Not taken by a relay: {}",
                    status.facts.outbox_refused
                ));
            }
        }
        if let Some(sync) = &status.sync {
            if let Some(folders) = sync["report"]["folders"].as_array()
                && !folders.is_empty()
            {
                details.push(format!("Folders syncing: {}", folders.len()));
            }
            if let Some(at) = sync["last_change_at"]
                .as_str()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            {
                let secs = (chrono::Utc::now() - at.with_timezone(&chrono::Utc)).num_seconds();
                details.push(format!("Last change: {}", indicator::ago(secs)));
            }
        }
        for c in &status.facts.conflicts {
            details.push(format!("Conflict: {c}"));
        }
        for file in &status.facts.too_large {
            details.push(format!("Too large to sync: {file}"));
        }
        for e in &status.facts.errors {
            details.push(format!("Error: {e}"));
        }
        let text = indicator::bar(state, &summary, &details);
        if !text.is_empty() {
            println!("{text}");
        }
        return Ok(());
    }

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
            // The node's own version: `version` above is this command's.
            out["node_version"] = live["version"].clone();
            out["uptime_secs"] = live["uptime_secs"].clone();
            out["peers"] = serde_json::json!({
                "hot": live["peers_hot"],
                "warm": live["peers_warm"],
            });
            out["outbox_waiting"] = live["outbox_waiting"].clone();
            out["outbox_refused"] = live["outbox_refused"].clone();
        }
        if let Some(sync) = &status.sync {
            let report = &sync["report"];
            // One entry per synced folder: what a panel lists and toggles.
            let projects: Vec<serde_json::Value> = report["folders"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|f| {
                    serde_json::json!({
                        "project": f["project"],
                        "folder": f["folder"],
                        "cwd": f["cwd"],
                        "mapped": f["mapped"],
                        "channel": f["channel_id"],
                        "waiting": f["waiting"],
                        "last_pulled_at": f["last_pulled_at"],
                        "last_published_at": f["last_published_at"],
                        "error": f["error"],
                        "conflicts": f["conflict_files"],
                        "too_large": f["too_large"],
                    })
                })
                .collect();
            out["sync"] = serde_json::json!({
                "enabled": sync["enabled"],
                "dir": sync["dir"],
                "all": sync["all"],
                "mappings": sync["mappings"],
                "home": sync["home"],
                "home_name": sync["home_name"],
                "exclude": sync["exclude"],
                "unmapped": report["unmapped"],
                "available": report["available"],
                "last_cycle_at": report["at"],
                "last_change_at": sync["last_change_at"],
                "folders": report["folders"].as_array().map_or(0, Vec::len),
                "projects": projects,
                "projects_waiting": status.facts.projects_waiting,
                "conflicts": status.facts.conflicts,
                "unsynced": report["unsynced"],
                "excluded": report["excluded"],
                "errors": status.facts.errors,
            });
        }
        // The connected peers and this person's devices, for panels.
        if status.facts.running
            && let Ok(config) = Config::load(&config::expand_tilde(config_path)).map(|mut c| {
                c.apply_env_overrides();
                c
            })
        {
            let timeout = std::time::Duration::from_secs(1);
            if let Ok(peers) = local_api(&config, false, "/api/v1/peers", timeout) {
                out["peers"]["list"] = peers["peers"].clone();
                out["peers"]["relays"] = peers["relays"].clone();
            }
            if let Ok(devices) = local_api(&config, true, "/api/v1/devices/list", timeout) {
                out["devices"] = devices["devices"].clone();
            }
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
    if config.network.accepts_inbound() {
        println!("  P2P port:  {}", config.node.p2p_port);
    } else {
        println!("  P2P:       outbound only (no listening port)");
    }
    println!("  Role:      {}", config.network.role);

    println!();
    println!("Node:");
    match &status.live {
        Some(live) => {
            let n = |k: &str| live[k].as_u64().unwrap_or(0);
            println!("  Running:   yes, up {}", format_uptime(n("uptime_secs")));
            if let Some(note) = version_note(live["version"].as_str(), env!("CARGO_PKG_VERSION")) {
                println!("  Version:   {note}");
            }
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
    out.facts.outbox_refused = live["outbox_refused"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["refusals"].as_u64() >= Some(indicator::REFUSALS_BEFORE_ATTENTION))
        .count() as u64;
    out.live = Some(live);

    if let Ok(sync) = local_api(&config, true, "/api/v1/sync/status", timeout) {
        let report = &sync["report"];
        out.facts.sync_enabled = sync["enabled"].as_bool().unwrap_or(false);
        out.facts.sync_all = sync["all"].as_bool().unwrap_or(false);
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
            out.facts.folders = folders.len();
            for f in folders {
                out.facts.conflicts.extend(strings(&f["conflict_files"]));
                let folder = f["folder"].as_str().unwrap_or_default();
                out.facts.too_large.extend(
                    strings(&f["too_large"])
                        .into_iter()
                        .map(|name| format!("{folder}/memory/{name}")),
                );
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
    if config.network.accepts_inbound() {
        println!("  P2P port:  {p2p_port}/UDP");
    } else {
        println!("  P2P:       outbound only (no listening port)");
    }
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
        peers: Default::default(),
        relays: Default::default(),
        outbox_refused: Default::default(),
        relist: Default::default(),
        sync_control: Default::default(),
    });

    // Personal nodes receive invites and channel states in an inbox channel
    // derived from their key (decision 2026-09-30 §4.1).
    if config.network.role == "personal" {
        let inbox = cordelia_api::membership::ensure_own_inbox(&state)?;
        tracing::info!(%inbox, "inbox ready");
    }

    // Start the tokio/actix runtime with graceful shutdown
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async {
        tracing::info!(%listen_addr, p2p_port, "starting node");

        // ── P2P transport ──────────────────────────────────────────
        let p2p_bind = p2p_bind_addr(&config.network.listen_addr, p2p_port)?;
        let accepts_inbound = config.network.accepts_inbound();
        let endpoint = if accepts_inbound {
            cordelia_network::transport::create_endpoint(&identity_arc, p2p_bind)
        } else {
            // A personal node only dials out (decision 2026-09-30 §4.6):
            // no listener, and whichever port the system gives it.
            cordelia_network::transport::create_client_endpoint(&identity_arc, p2p_bind.ip())
        }
        .map_err(|e| anyhow::anyhow!("P2P transport: {e}"))?;
        let p2p_local = endpoint.local_addr()?;
        if accepts_inbound {
            tracing::info!(%p2p_local, "P2P endpoint listening");
        } else {
            tracing::info!(%p2p_local, "P2P endpoint dials out only; nothing listens");
        }
        // The port others can dial, sent in the handshake: none if this
        // node does not listen.
        let advertised_port = if accepts_inbound { p2p_port as u16 } else { 0 };

        // ── Connection manager ─────────────────────────────────────
        let roles = vec![config.network.role.clone()];
        let allow_private = config.network.allow_private_addresses;
        let is_bootnode = config.network.role == "bootnode";
        let conn_mgr = cordelia_network::connection::ConnectionManager::new(
            identity_arc.clone(),
            endpoint,
            vec![], // channel IDs loaded later from DB
            roles,
            advertised_port,
        );

        // ── The relays this node dials ───────────────────────────────
        // Its configured relays or, for a personal node that names none,
        // the default ones, each with the key that must answer (decision
        // 2026-09-30 §4.6). The P2P loop dials them and keeps trying the
        // ones that are not connected, so starting never waits on a relay
        // that is unreachable. Bootnodes dial nobody.
        let relays = if is_bootnode {
            Vec::new()
        } else {
            let configured: Vec<(String, Option<String>)> = config
                .network
                .bootnodes
                .iter()
                .map(|b| (b.addr.clone(), b.key.clone()))
                .collect();
            cordelia_network::bootstrap::configured_relays(
                &configured,
                config.network.role == "personal",
            )
            .map_err(|e| anyhow::anyhow!("network.bootnodes: {e}"))?
        };
        for relay in &relays {
            if relay.key.is_none() {
                tracing::warn!(
                    relay = %relay.host,
                    "no key is configured for this relay: whichever node answers there is accepted"
                );
            }
        }
        tracing::info!(count = relays.len(), "relays configured");

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
        // Runs while a Claude Code directory is configured. A change of
        // setting takes effect at once: it wakes the loop, and a cycle
        // that was already running stops (see `SyncControl`).
        if config.network.role == "personal" {
            if let Err(e) = cordelia_api::sync::keep_earlier_scope(&state) {
                tracing::warn!(error = %e, "sync: could not read the stored scope");
            }
            tokio::spawn(run_sync_loop(state.clone()));
        }

        // Relays are configured by name, so the names are resolved again
        // while the node runs, not only at startup.
        let relay_addrs = p2p::RelayAddrs::default();
        if !relays.is_empty() {
            tokio::spawn(p2p::keep_relays_resolved(relays, relay_addrs.clone()));
        }

        let p2p_handle = tokio::spawn(async move {
            p2p::p2p_loop(conn_mgr, p2p_state, push_rx, announce_rx, &mut p2p_shutdown_rx, allow_private, role_for_p2p, config.governor.clone(), relay_addrs, trusted_peer_ids, config.node.max_storage_bytes, std::time::Duration::from_secs(config.replication.relay_ask_again_secs.clamp(1, 86_400))).await;
        });

        // ── HTTP API ───────────────────────────────────────────────
        let server = HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .configure(cordelia_api::configure_routes)
        })
        .bind(&listen_addr)?
        // Only this node handles the signals that stop it, and it tells
        // the server to stop (below), so that one deadline covers both.
        .disable_signals()
        // A request being answered when the server is told to stop has one
        // stream timeout to finish; then its connection is closed.
        .shutdown_timeout(cordelia_core::protocol::STREAM_TIMEOUT_SECS)
        .run();

        let server_handle = server.handle();
        let p2p_shutdown_tx = p2p_shutdown.0;

        tracing::info!("P2P layer ready, accepting connections");

        // The node runs until it is told to stop, or one of its parts ends
        // by itself. Then every part is told to stop, and the node waits
        // for them a bounded time, whatever one of them is waiting for.
        let stopped = run_until_stopped(
            server,
            p2p_handle,
            async {
                shutdown_signal().await;
                tracing::info!("shutdown signal received, stopping");
            },
            move || {
                let _ = p2p_shutdown_tx.send(true);
                // Gracefully: a request being handled finishes, and what is
                // still open after one stream timeout is closed. So, as a
                // rule, the process does not end in the middle of a request.
                // actix-server before 2.9.1 could wait for ever here (#99).
                // The server's own future says when it has stopped.
                tokio::spawn(server_handle.stop(true));
            },
            std::time::Duration::from_secs(cordelia_core::protocol::NODE_STOP_TIMEOUT_SECS),
        )
        .await;

        match &stopped.server {
            None => tracing::warn!("the HTTP server did not stop in time; exiting without it"),
            Some(Err(e)) => tracing::error!(error = %e, "the HTTP server failed"),
            Some(Ok(())) => {}
        }
        match &stopped.p2p {
            None => tracing::warn!("the P2P loop did not stop in time; exiting without it"),
            Some(Err(e)) => tracing::error!(error = %e, "the P2P loop failed"),
            Some(Ok(())) => tracing::info!("P2P shutdown complete"),
        }
        stopped.result()
    });
    // Tasks still running are dropped. Work that cannot be interrupted (a
    // sync cycle, a database write) is given one stream timeout to finish,
    // and is then left as a crash would leave it.
    runtime.shutdown_timeout(std::time::Duration::from_secs(
        cordelia_core::protocol::STREAM_TIMEOUT_SECS,
    ));
    result
}

/// How a node's run ended.
struct Stopped<S, P> {
    /// Whether the node was told to stop. If it was not, one of its parts
    /// ended by itself, and that stopped the node.
    told: bool,
    /// What the HTTP server finished with, if it finished in time.
    server: Option<S>,
    /// What the peer-to-peer loop finished with, if it finished in time.
    p2p: Option<P>,
}

impl<E: std::fmt::Display, F: std::fmt::Display> Stopped<Result<(), E>, Result<(), F>> {
    /// What the node exits with: success only if it was told to stop, and
    /// both its parts stopped in time and without failing.
    ///
    /// A node that stopped because one of its parts ended has failed, and
    /// whatever runs it starts it again. One that gave up on a part did
    /// stop, but not cleanly, and says so.
    fn result(self) -> anyhow::Result<()> {
        let mut wrong = Vec::new();
        if !self.told {
            wrong
                .push("a part of the node ended, though the node was not told to stop".to_string());
        }
        match self.server {
            None => wrong.push("the HTTP server did not stop in time".into()),
            Some(Err(e)) => wrong.push(format!("the HTTP server failed: {e}")),
            Some(Ok(())) => {}
        }
        match self.p2p {
            None => wrong.push("the P2P loop did not stop in time".into()),
            Some(Err(e)) => wrong.push(format!("the P2P loop failed: {e}")),
            Some(Ok(())) => {}
        }
        if wrong.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(wrong.join("; ")))
        }
    }
}

/// Run a node's two parts until the node is told to stop (`told`), or one
/// of them ends by itself. Then tell them to stop (`stop`), and wait for
/// what is still running: `at_most` in all, and no more.
///
/// A node that waited for ever for one of its parts would never exit. One
/// did: its HTTP server never finished stopping (#99). And a node that ran
/// on without one of its parts would look alive and do nothing.
async fn run_until_stopped<S, P>(
    server: impl std::future::Future<Output = S>,
    p2p: impl std::future::Future<Output = P>,
    told: impl std::future::Future<Output = ()>,
    stop: impl FnOnce(),
    at_most: std::time::Duration,
) -> Stopped<S, P> {
    tokio::pin!(server, p2p, told);
    let (mut server_out, mut p2p_out) = (None, None);
    let was_told = tokio::select! {
        biased;
        _ = &mut told => true,
        out = &mut server => {
            server_out = Some(out);
            false
        }
        out = &mut p2p => {
            p2p_out = Some(out);
            false
        }
    };
    if !was_told {
        let part = if server_out.is_some() {
            "HTTP server"
        } else {
            "P2P loop"
        };
        tracing::error!(
            part,
            "a part of the node ended, though the node was not told to stop; stopping the node"
        );
    }
    stop();
    let out_of_time = tokio::time::sleep(at_most);
    tokio::pin!(out_of_time);
    while server_out.is_none() || p2p_out.is_none() {
        tokio::select! {
            out = &mut server, if server_out.is_none() => server_out = Some(out),
            out = &mut p2p, if p2p_out.is_none() => p2p_out = Some(out),
            _ = &mut out_of_time => break,
        }
    }
    Stopped {
        told: was_told,
        server: server_out,
        p2p: p2p_out,
    }
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

/// Every `CYCLE_SECS`, and as soon as a sync setting changes, run one
/// adapter cycle (if sync is on) off the async runtime, and store its
/// report for `cordelia sync status`.
async fn run_sync_loop(state: web::Data<cordelia_api::state::AppState>) {
    use cordelia_storage::meta;
    use cordelia_sync::claude::ClaudeAdapter;

    let adapter: std::sync::Arc<Mutex<Option<ClaudeAdapter>>> =
        std::sync::Arc::new(Mutex::new(None));
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        cordelia_sync::claude::CYCLE_SECS,
    ));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = state.sync_control.woken() => {}
        }
        let state = state.clone();
        let adapter = adapter.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let (dir, generation) = match state.db.lock() {
                Ok(db) => (
                    meta::get(&db, meta::SYNC_CLAUDE_DIR).ok().flatten(),
                    state.sync_control.generation_under(&db),
                ),
                Err(_) => return,
            };
            let Ok(mut slot) = adapter.lock() else { return };
            let Some(dir) = dir else {
                // Sync was just turned off: this person's other devices
                // stop listing what this one synced. If the settings
                // change under it, the adapter is kept, and the next turn
                // looks again.
                if slot.is_some() {
                    match cordelia_sync::claude::withdraw(&state, generation) {
                        Ok(false) => return,
                        Ok(true) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "sync: could not withdraw this device's names");
                        }
                    }
                    *slot = None;
                }
                return;
            };
            // One adapter, for the directory that is set, as it is stored:
            // a cycle of any other does nothing.
            let running = adapter_for(
                &mut slot,
                |held: &ClaudeAdapter| held.is_for(&dir),
                || {
                    let home = std::env::var_os("HOME")
                        .map(std::path::PathBuf::from)
                        .unwrap_or_default();
                    tracing::info!("sync adapter started");
                    ClaudeAdapter::new(dir.as_str().into(), home, &state.identity.public_key())
                },
            );
            // The report carries the settings count it was made under: a
            // setting changed during the cycle makes it a report from
            // before the change.
            let report = running.run_cycle(&state);
            for e in &report.errors {
                tracing::warn!(error = %e, "sync cycle error");
            }
            let now = chrono::Utc::now().to_rfc3339();
            let changed = report.folders.iter().any(|f| f.published + f.pulled > 0);
            let mut json = serde_json::to_value(&report).unwrap_or_default();
            json["at"] = serde_json::Value::String(now.clone());
            if let Ok(db) = state.db.lock() {
                if report_stands(&report, state.sync_control.generation_under(&db)) {
                    let _ = meta::set(&db, meta::SYNC_CLAUDE_REPORT, &json.to_string());
                }
                if changed {
                    let _ = meta::set(&db, meta::SYNC_CLAUDE_LAST_CHANGE, &now);
                }
            }
        })
        .await;
    }
}

/// What status says beside home memory (`~`) that other devices sync and
/// this one does not: the command that maps it here, or why there is none.
/// A home directory has one name on a device. `here` is the name this
/// device's home is mapped under, and `last` the name it last synced
/// under. Where either is another name than `~`, mapping home as `~`
/// would take it to another channel than the one it is in, or left.
fn home_memory_elsewhere(here: Option<&str>, last: Option<&str>) -> String {
    let home = cordelia_sync::claude::HOME_NAME;
    match (here, last) {
        (Some(here), _) => format!("home memory on this device syncs as {here}"),
        (None, Some(last)) if last != home => {
            format!("home memory on this device last synced as {last}")
        }
        _ => "cordelia sync map ~ --home".to_string(),
    }
}

/// Whether a cycle's report is a report of what syncs now, to be kept for
/// `cordelia sync status`. One from a cycle that stopped saw only some of
/// the folders, and one made under settings that have changed since (`now`
/// is the count of changes as it stands) saw the wrong ones. The change
/// that did either has already woken the next cycle.
fn report_stands(report: &cordelia_sync::claude::CycleReport, now: u64) -> bool {
    !report.stopped && report.generation == now
}

// ── cordelia peers ─────────────────────────────────────────────────

fn cmd_peers(config_path: &str, json: bool) -> anyhow::Result<()> {
    let resp = api_get(config_path, "/api/v1/peers")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }
    let peers = resp["peers"].as_array().cloned().unwrap_or_default();
    if peers.is_empty() {
        println!("No peers connected.");
    } else {
        println!(
            "{:<67} {:<8} {:<5} {:<22} {:>10} {:>9}",
            "KEY", "ROLE", "STATE", "ADDRESS", "CONNECTED", "IDLE"
        );
        for p in &peers {
            let text = |k: &str| p[k].as_str().unwrap_or("-");
            let secs = |k: &str| format_uptime(p[k].as_u64().unwrap_or(0));
            println!(
                "{:<67} {:<8} {:<5} {:<22} {:>10} {:>9}",
                text("key"),
                text("role"),
                text("state"),
                text("address"),
                secs("connected_secs"),
                secs("idle_secs"),
            );
        }
    }
    // A configured relay that is not connected is the answer to "why does
    // this device have fewer relays than that one".
    let missing: Vec<&serde_json::Value> = resp["relays"]
        .as_array()
        .map(|relays| {
            relays
                .iter()
                .filter(|r| r["state"] != "connected")
                .collect()
        })
        .unwrap_or_default();
    if !missing.is_empty() {
        println!("\nConfigured relays that are not connected:");
        for r in missing {
            println!("  {}", relay_line(r));
        }
    }
    Ok(())
}

/// One line saying where a configured relay stands.
fn relay_line(r: &serde_json::Value) -> String {
    let host = r["host"].as_str().unwrap_or("-");
    let ago = |k: &str| r[k].as_u64().map(format_uptime);
    let mut line = format!("{host}  {}", r["state"].as_str().unwrap_or("-"));
    if let Some(t) = ago("unreachable_secs") {
        line.push_str(&format!(" for {t}"));
    }
    if let Some(t) = ago("last_tried_secs") {
        line.push_str(&format!(", last tried {t} ago"));
    }
    if let Some(why) = r["error"].as_str() {
        line.push_str(&format!(" ({why})"));
    }
    line
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

fn cmd_stats(config_path: &str, json: bool) -> anyhow::Result<()> {
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
    let channels = cordelia_storage::channels::list_for_entity(&conn, &pk)?.len();
    let usage = cordelia_storage::usage::snapshot(&conn, chrono::Utc::now().timestamp())?;
    // What a relay's storage cap counts, and the cap: the database's pages
    // in use, which fall when a channel is dropped (the file does not
    // shrink).
    let used = cordelia_storage::db::used_bytes(&conn)?;
    let cap = config.node.max_storage_bytes;

    if json {
        let out = serde_json::json!({
            "database_bytes": db_size,
            "storage_used_bytes": used,
            "storage_max_bytes": cap,
            "channels_subscribed": channels,
            "items_stored": usage.items_stored,
            "content_bytes_stored": usage.bytes_stored,
            "peers_seen": {
                "1d": { "node": usage.peers_1d, "relay": usage.relays_1d },
                "7d": { "node": usage.peers_7d, "relay": usage.relays_7d },
            },
            "channels_active": {
                "1d": usage.channels_active_1d,
                "7d": usage.channels_active_7d,
            },
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("Database:         {}", format_bytes(db_size));
    if config.network.role == "relay" {
        println!(
            "Storage:          {} in use of {} allowed",
            format_bytes(used),
            format_bytes(cap)
        );
    }
    println!(
        "Stored:           {} items, {} of encrypted content",
        usage.items_stored,
        format_bytes(usage.bytes_stored)
    );
    println!("Channels:         {channels} subscribed");
    println!(
        "Peers seen:       {} in the last day, {} in the last week (plus {} and {} relays)",
        usage.peers_1d, usage.peers_7d, usage.relays_1d, usage.relays_7d
    );
    println!(
        "Active channels:  {} in the last day, {} in the last week",
        usage.channels_active_1d, usage.channels_active_7d
    );

    Ok(())
}

/// `1.5 MB`, `12.0 KB`.
fn format_bytes(bytes: u64) -> String {
    if bytes > 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    }
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

/// A project as the exclude list stores it: lower case, no `.git`.
fn normalise_project(project: &str) -> String {
    let lower = project.trim().to_lowercase();
    lower.trim_end_matches(".git").to_string()
}

/// What `map` offers when the home directory is named without `--home`:
/// the command that does what was asked.
///
/// - No name: `home on`, which puts home memory back under the name it
///   last had on this device.
/// - The name `~`: `map` with the flag and no name, which is `~`.
/// - A name home memory can take: `map` with the flag and that name.
/// - Anything else is `Err`, with the name: it is said to be unusable, and
///   nothing is offered that would map home under another name than the
///   one that was typed.
fn home_offer(name: Option<&str>) -> Result<String, String> {
    let Some(name) = name else {
        return Ok("cordelia sync home on".to_string());
    };
    let name = normalise_project(name);
    if name == cordelia_sync::claude::HOME_NAME {
        Ok("cordelia sync map ~ --home".to_string())
    } else if cordelia_api::sync::valid_sync_name(&name) {
        Ok(format!("cordelia sync map ~ {} --home", shell_word(&name)))
    } else {
        Err(name)
    }
}

/// The adapter for the Claude Code directory that is set, `dir`, as it is
/// stored: the one held, if it is for that directory, or a new one in its
/// place (`ClaudeAdapter::is_for`).
fn adapter_for<A>(
    slot: &mut Option<A>,
    is_for: impl Fn(&A) -> bool,
    make: impl FnOnce() -> A,
) -> &mut A {
    if !slot.as_ref().is_some_and(is_for) {
        *slot = None;
    }
    slot.get_or_insert_with(make)
}

/// The sync settings of the running node. Sync must be on.
fn sync_settings(config_path: &str) -> anyhow::Result<serde_json::Value> {
    let current = api_post(config_path, "/api/v1/sync/status", serde_json::json!({}))?;
    if current["enabled"].as_bool() != Some(true) {
        anyhow::bail!("Sync is off. Turn it on with `cordelia sync claude`.");
    }
    Ok(current)
}

/// The declared mappings in `settings`, as (folder, name).
fn declared_mappings(settings: &serde_json::Value) -> Vec<(String, String)> {
    let text = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
    settings["mappings"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| (text(&m["folder"]), text(&m["name"])))
        .collect()
}

/// The exclude list in `settings`.
fn excluded_projects(settings: &serde_json::Value) -> Vec<String> {
    settings["exclude"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e.as_str().map(String::from))
        .collect()
}

/// The home directory as Claude Code sees it: a real path.
fn real_home() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    home.canonicalize().unwrap_or(home)
}

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

/// POST `body` to the local node's API and return the JSON response.
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
        let mut message = json["error"]["message"]
            .as_str()
            .map(|m| m.strip_prefix("bad request: ").unwrap_or(m).to_string())
            .unwrap_or_else(|| format!("HTTP {status}"));
        // An install leaves the old node running until it is restarted.
        // A refusal may then mean only that the node is another version
        // than this command.
        let timeout = std::time::Duration::from_secs(3);
        if !VERSION_NOTED.load(std::sync::atomic::Ordering::Relaxed)
            && let Ok(node) = local_api(&config, false, "/api/v1/status", timeout)
            && let Some(note) = version_note(node["version"].as_str(), env!("CARGO_PKG_VERSION"))
        {
            message.push_str(&format!("\n{note}"));
        }
        anyhow::bail!("{message}");
    }
    Ok(json)
}

/// Set once this command has said that the node is another version, so that
/// it is not said again beside a refusal.
static VERSION_NOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// What to say about the running node, if it answers and is not the version
/// this command is.
fn node_version_note(config_path: &str) -> Option<String> {
    let mut config = Config::load(&config::expand_tilde(config_path)).ok()?;
    config.apply_env_overrides();
    let timeout = std::time::Duration::from_secs(3);
    let node = local_api(&config, false, "/api/v1/status", timeout).ok()?;
    version_note(node["version"].as_str(), env!("CARGO_PKG_VERSION"))
}

/// What to say when the running node is not the version this command is
/// (`own`). A node from before it reported its version reports none.
fn version_note(node: Option<&str>, own: &str) -> Option<String> {
    // Which of the two is the older is not judged: version strings are
    // not compared, only found to differ.
    let after = "They should be the same: an upgrade leaves the old node running until it \
                 is restarted.";
    match node {
        Some(node) if node == own => None,
        Some(node) => Some(format!(
            "The running node is version {node} and this command is version {own}. {after}"
        )),
        None => Some(format!(
            "The running node is from before nodes said their version, and this command \
             is version {own}. {after}"
        )),
    }
}

/// The mapping `cordelia sync unmap <word>` means, given the mapping whose
/// name the word is and the mapping whose folder it is. One word that
/// means two mappings is refused: it is not for the command to pick.
fn mapping_meant<'a>(
    word: &str,
    by_name: Option<&'a (String, String)>,
    by_folder: Option<&'a (String, String)>,
) -> anyhow::Result<&'a (String, String)> {
    match (by_name, by_folder) {
        (Some(named), Some(at)) if named.0 != at.0 => anyhow::bail!(
            "{word} is the name {} syncs under, and also a folder, which syncs as {}. \
             To unmap the folder: cordelia sync unmap {}. To unmap the other: \
             cordelia sync unmap {}.",
            short_path(&named.0),
            sync_label(&at.1),
            shell_arg(&at.0),
            shell_arg(&named.0)
        ),
        (Some(found), _) | (None, Some(found)) => Ok(found),
        (None, None) => anyhow::bail!(
            "{word} is not mapped on this device. `cordelia sync status` shows what is."
        ),
    }
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
    let notes: Vec<&str> = resp["notes"]
        .as_array()
        .map(|notes| notes.iter().filter_map(|n| n.as_str()).collect())
        .unwrap_or_default();
    println!("Trusted {}.", name.as_deref().unwrap_or(key));
    if joined > 0 {
        println!(
            "Joined {joined} channel{}.",
            if joined == 1 { "" } else { "s" }
        );
    } else if notes.is_empty() {
        println!(
            "Its invites have not arrived yet. They will be applied when they do, within the next hour."
        );
    }
    for note in notes {
        println!("{note}");
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
    if rotated > 0 {
        println!(
            "Your other devices are told through the relays, and the change is offered again \
             until each of them confirms it. `cordelia devices` shows any that has not."
        );
    }
    Ok(())
}

fn cmd_devices(config_path: &str) -> anyhow::Result<()> {
    let resp = api_post(config_path, "/api/v1/devices/list", serde_json::json!({}))?;
    for d in resp["devices"].as_array().into_iter().flatten() {
        let key = d["key"].as_str().unwrap_or_default();
        let name = d["name"].as_str().unwrap_or("");
        let marker = if d["this_device"].as_bool() == Some(true) {
            "  (this device)".to_string()
        } else if d["in_personal_channel"].as_bool() != Some(true) {
            "  (waiting to join)".to_string()
        } else {
            // A change this device made (a device added or removed) that
            // the other has not confirmed. It is offered again until it
            // does; a few minutes are normal, since it goes through a relay.
            match unconfirmed_for(&d["unconfirmed_since"]) {
                Some(secs) if secs >= UNCONFIRMED_SHOWN_AFTER_SECS => format!(
                    "  (has not confirmed a change sent {})",
                    indicator::ago(secs)
                ),
                _ => String::new(),
            }
        };
        println!("{key}  {name}{marker}");
    }
    Ok(())
}

/// How long a change may go unconfirmed before `cordelia devices` says so.
/// It travels through a relay, and the other device looks every ten
/// seconds, so a minute or two means nothing.
const UNCONFIRMED_SHOWN_AFTER_SECS: i64 = 600;

/// Seconds since the time in a device's `unconfirmed_since`, if it has one.
fn unconfirmed_for(since: &serde_json::Value) -> Option<i64> {
    let at = chrono::DateTime::parse_from_rfc3339(since.as_str()?).ok()?;
    Some((chrono::Utc::now() - at.with_timezone(&chrono::Utc)).num_seconds())
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
    println!("These are from keys this device has not accepted.");
    println!(
        "Accept one only if it is another of your own devices, and you added this device \
         from it: cordelia accept <from>"
    );
    Ok(())
}

fn cmd_sync(config_path: &str, what: SyncCommand) -> anyhow::Result<()> {
    use cordelia_sync::claude::HOME_NAME;
    use cordelia_sync::discover::{self, Project};

    // An install leaves the old node running until it is restarted. Said
    // first, and whether or not the command then works: a node of another
    // version may take a request and mean something else by it.
    if let Some(note) = node_version_note(config_path) {
        eprintln!("{note}\n");
        VERSION_NOTED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let set = |body: serde_json::Value| api_post(config_path, "/api/v1/sync/claude", body);
    // The settings generation a change left behind: the scope printed at
    // the end waits for a report made after it.
    let since: Option<u64>;
    match what {
        SyncCommand::Claude {
            dir,
            all,
            mapped_only,
            exclude,
            no_home,
            reset,
        } => {
            let mut body = serde_json::json!({ "enabled": true, "reset": reset });
            if let Some(dir) = dir {
                let path = config::expand_tilde(&dir);
                body["dir"] = std::fs::canonicalize(&path)
                    .unwrap_or(path)
                    .display()
                    .to_string()
                    .into();
            }
            if all || mapped_only {
                body["all"] = all.into();
            }
            if !exclude.is_empty() {
                body["exclude"] = serde_json::json!(exclude);
            }
            if no_home {
                body["home"] = false.into();
            }
            // Nothing changes silently: say what this run changed.
            let before = api_post(config_path, "/api/v1/sync/status", serde_json::json!({}))?;
            let after = set(body)?;
            since = after["generation"].as_u64();
            for line in setting_changes(&before, &after) {
                println!("{line}");
            }
            println!();
        }
        SyncCommand::Map { folder, name, home } => {
            let given = std::fs::canonicalize(config::expand_tilde(&folder))
                .map_err(|e| anyhow::anyhow!("{folder}: {e}"))?;
            if !given.is_dir() {
                anyhow::bail!("{folder} is not a folder");
            }
            // Claude Code keeps one memory per repository, in the folder
            // of its main working tree: that is the folder to map.
            let root = discover::memory_root(&given);
            let mapped_folder = root.display().to_string();
            let home_dir = real_home();
            let is_home = root == home_dir;
            // Mapped already, and no name given: there is nothing to
            // change, and the name it has is the answer.
            let already = match &name {
                None => declared_mappings(&sync_settings(config_path)?)
                    .into_iter()
                    .find(|(folder, _)| *folder == mapped_folder)
                    .map(|(_, name)| name),
                Some(_) => None,
            };
            if let Some(mapped) = already {
                println!(
                    "{} is already mapped to {}. Nothing changed.",
                    short_path(&mapped_folder),
                    sync_label(&mapped)
                );
                println!();
                since = None;
            } else {
                // Home memory syncs only when it is asked for, and by
                // naming the home directory itself: never by a slip, and
                // never because a folder inside it was named.
                let names_home = given == home_dir;
                // The first two refusals offer `home on`, which puts home
                // memory back under the name it last had here: the name
                // that was given, if any, was for another folder.
                if home && !names_home {
                    anyhow::bail!(
                        "--home is for the home directory itself. To sync home memory: \
                         cordelia sync home on"
                    );
                }
                if is_home && !names_home {
                    anyhow::bail!(
                        "Claude Code keeps the memory for {} with your home directory's, because \
                         your home directory is a git repository. To sync home memory: \
                         cordelia sync home on",
                        given.display()
                    );
                }
                if is_home && !home {
                    match home_offer(name.as_deref()) {
                        Ok(command) => anyhow::bail!(
                            "that is your home directory. To sync home memory: {command}"
                        ),
                        Err(name) => anyhow::bail!(
                            "that is your home directory, and {name:?} is not a name it can \
                             sync under. To sync home memory under a name (lower-case letters, \
                             digits and . _ - /): cordelia sync map ~ <name> --home"
                        ),
                    }
                }
                let name = match name {
                    Some(name) => normalise_project(&name),
                    None if is_home => HOME_NAME.to_string(),
                    None => {
                        let needs_name = |why: &str| {
                            anyhow::anyhow!(
                                "{0} {why}, so it needs a name: cordelia sync map {0} <name>\n\
                                 Use the same name on your other devices.",
                                shell_arg(&mapped_folder)
                            )
                        };
                        match discover::project_for(&root, &home_dir) {
                            Some(Project::Repo(remote))
                                if cordelia_api::sync::valid_sync_name(&remote) =>
                            {
                                remote
                            }
                            Some(Project::Repo(remote)) => {
                                return Err(needs_name(&format!(
                                    "has a remote that does not make a usable name ({remote})"
                                )));
                            }
                            _ => return Err(needs_name("is not a git project with a remote")),
                        }
                    }
                };
                let settings = api_post(
                    config_path,
                    "/api/v1/sync/map",
                    serde_json::json!({
                        "folder": mapped_folder,
                        "name": name,
                        "home": is_home,
                    }),
                )?;
                since = settings["generation"].as_u64();
                if root != given {
                    println!(
                        "Claude Code keeps one memory for a repository, shared by its folders and worktrees."
                    );
                }
                println!(
                    "Mapped {} to {}.",
                    short_path(&mapped_folder),
                    sync_label(&name)
                );
                // Say so when the folder synced may not be the one Claude Code
                // uses, rather than report "syncing" and leave it to be found.
                let claude_dir = settings["dir"].as_str().unwrap_or_default();
                if discover::memory_root_is_assumed(&given) {
                    println!(
                        "Note: this is a submodule, or a worktree of a bare repository. Where Claude \
                         Code keeps memory for those is not confirmed: check that it uses {}.",
                        discover::claude_folder(std::path::Path::new(claude_dir), &root)
                            .map(|f| short_path(&f.display().to_string()))
                            .unwrap_or_default()
                    );
                }
                if std::path::Path::new(claude_dir) != home_dir.join(".claude") {
                    println!(
                        "Note: sync uses {}, not ~/.claude: the memory is kept under that directory.",
                        short_path(claude_dir)
                    );
                }
                println!();
            }
        }
        SyncCommand::Unmap { folder } => {
            let settings = sync_settings(config_path)?;
            let mappings = declared_mappings(&settings);
            // A name; or a folder, which may be any folder of a mapped
            // repository, or one that is no longer on disk.
            let as_name = normalise_project(&folder);
            let by_name = mappings
                .iter()
                .find(|(_, name)| *name == folder || *name == as_name);
            let by_folder = {
                let trimmed = match folder.trim_end_matches('/') {
                    "" => "/",
                    other => other,
                };
                let path = config::expand_tilde(trimmed);
                let mut spellings = vec![path.display().to_string()];
                if let Ok(real) = std::fs::canonicalize(&path) {
                    spellings.push(discover::memory_root(&real).display().to_string());
                    spellings.push(real.display().to_string());
                }
                mappings.iter().find(|(f, _)| spellings.contains(f))
            };
            let (mapped, name) = mapping_meant(&folder, by_name, by_folder)?;
            let after = api_post(
                config_path,
                "/api/v1/sync/unmap",
                serde_json::json!({ "folder": mapped }),
            )?;
            since = after["generation"].as_u64();
            println!(
                "No longer synced from this device: {} ({}). Its files stay where they are.",
                short_path(mapped),
                sync_label(name)
            );
            if settings["all"].as_bool() == Some(true) {
                println!(
                    "This device syncs everything it finds; this folder now stays out until \
                     it is mapped again."
                );
            }
            println!();
        }
        SyncCommand::Off => {
            set(serde_json::json!({ "enabled": false }))?;
            println!("Sync is off. Files already synced stay where they are.");
            return Ok(());
        }
        SyncCommand::Status => since = None,
        SyncCommand::Home { state } => {
            let on = state == "on";
            // The home directory's mapping, whatever name it has.
            let home_dir = real_home().display().to_string();
            let mapped_as = |settings: &serde_json::Value| {
                declared_mappings(settings)
                    .into_iter()
                    .find(|(folder, _)| *folder == home_dir)
                    .map(|(_, name)| name)
            };
            let before = sync_settings(config_path)?;
            let after = if on && mapped_as(&before).is_none() {
                // On maps it, so that it syncs whichever scope this device
                // uses: under the name it last had here, so that off and
                // on again leaves it in the channel it was in. Mapping it
                // is also what turns the setting on, in one step.
                let name = before["home_name"].as_str().unwrap_or(HOME_NAME);
                api_post(
                    config_path,
                    "/api/v1/sync/map",
                    serde_json::json!({ "folder": home_dir, "name": name, "home": true }),
                )
                .map_err(|e| {
                    anyhow::anyhow!(
                        "home memory was not mapped as {}: {e}\nTo map it under a name: \
                         cordelia sync map ~ <name> --home",
                        sync_label(name)
                    )
                })?
            } else {
                // Off unmaps it as well.
                set(serde_json::json!({ "enabled": true, "home": on }))?
            };
            // Said from what the node holds now, not from what was asked.
            match mapped_as(&after) {
                Some(name) if on && name != HOME_NAME => println!(
                    "Home-folder memory syncs on this device, as {}.",
                    sync_label(&name)
                ),
                Some(_) if on => println!("Home-folder memory syncs on this device."),
                None if !on => println!("Home-folder memory is not synced on this device."),
                Some(name) => anyhow::bail!(
                    "home memory is still mapped on this device (as {}): the node did not \
                     unmap it. To stop it syncing: cordelia sync unmap {}",
                    sync_label(&name),
                    shell_word(&name)
                ),
                None => anyhow::bail!("home memory could not be mapped"),
            }
            return Ok(());
        }
        SyncCommand::Exclude { project } => {
            let project = exclusion(&project);
            let settings = sync_settings(config_path)?;
            if let Some((folder, name)) = declared_mappings(&settings)
                .iter()
                .find(|(folder, name)| *name == project || *folder == project)
            {
                anyhow::bail!(
                    "{} is mapped on this device. To stop syncing it: cordelia sync unmap {}",
                    short_path(folder),
                    shell_word(name)
                );
            }
            let mut exclude = excluded_projects(&settings);
            if !exclude.contains(&project) {
                exclude.push(project.clone());
            }
            set(serde_json::json!({ "enabled": true, "exclude": exclude }))?;
            println!("Not synced from this device: {}", short_path(&project));
            return Ok(());
        }
        SyncCommand::Include { project } => {
            let project = exclusion(&project);
            let settings = sync_settings(config_path)?;
            let mut exclude = excluded_projects(&settings);
            exclude.retain(|e| *e != project);
            set(serde_json::json!({ "enabled": true, "exclude": exclude }))?;
            if settings["all"].as_bool() == Some(true) {
                println!("Synced from this device again: {}", short_path(&project));
            } else {
                println!(
                    "No longer excluded: {}. Only mapped folders sync on this device: \
                     `cordelia sync map <folder>` syncs it.",
                    short_path(&project)
                );
            }
            return Ok(());
        }
    }
    print_sync_scope(config_path, since)
}

/// What `cordelia sync exclude` and `include` are given, as the exclude
/// list stores it: a project name or prefix, or a folder as the real path
/// of the repository it is in.
fn exclusion(given: &str) -> String {
    let looks_like_a_path = given.starts_with(['/', '~', '.']);
    match std::fs::canonicalize(config::expand_tilde(given)) {
        Ok(real) if looks_like_a_path => cordelia_sync::discover::memory_root(&real)
            .display()
            .to_string(),
        _ if given.starts_with('/') => given.trim_end_matches('/').to_string(),
        _ => normalise_project(given),
    }
}

/// What a run of `cordelia sync claude` changed, one line each, from the
/// settings before and after it.
fn setting_changes(before: &serde_json::Value, after: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let was_on = before["enabled"].as_bool() == Some(true);
    if !was_on {
        out.push("Sync turned on.".to_string());
    }

    let dir = |v: &serde_json::Value| v["dir"].as_str().map(short_path);
    if let Some(now) = dir(after)
        && dir(before).as_ref() != Some(&now)
    {
        out.push(match dir(before) {
            Some(was) => format!("Claude Code directory: {now} (was {was})."),
            None => format!("Claude Code directory: {now}."),
        });
    }

    let all = |v: &serde_json::Value| v["all"].as_bool() == Some(true);
    if all(after) != all(before) {
        out.push(if all(after) {
            "Scope: everything found (was mapped folders only).".to_string()
        } else {
            "Scope: mapped folders only (was everything found).".to_string()
        });
    }

    let home = |v: &serde_json::Value| v["home"].as_bool() != Some(false);
    if home(after) != home(before) {
        out.push(if home(after) {
            "Home memory: no longer kept off this device.".to_string()
        } else {
            "Home memory: kept off this device.".to_string()
        });
    }

    let (excluded, was_excluded) = (excluded_projects(after), excluded_projects(before));
    if excluded != was_excluded {
        let list = |l: &[String]| {
            if l.is_empty() {
                "nothing".to_string()
            } else {
                l.join(", ")
            }
        };
        out.push(format!(
            "Excluded: {} (was {}).",
            list(&excluded),
            list(&was_excluded)
        ));
    }

    let mapped = declared_mappings(after);
    for (folder, name) in declared_mappings(before) {
        if !mapped.iter().any(|(f, _)| *f == folder) {
            out.push(format!(
                "Unmapped: {} ({}).",
                short_path(&folder),
                sync_label(&name)
            ));
        }
    }

    if was_on && out.is_empty() {
        out.push("No settings changed.".to_string());
    }
    out
}

/// When a folder last received and last sent a memory, as people read it.
fn folder_activity(folder: &serde_json::Value) -> String {
    let ago = |v: &serde_json::Value| {
        v.as_str()
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
            .map(|at| {
                indicator::ago((chrono::Utc::now() - at.with_timezone(&chrono::Utc)).num_seconds())
            })
    };
    match (
        ago(&folder["last_pulled_at"]),
        ago(&folder["last_published_at"]),
    ) {
        (Some(received), Some(sent)) => format!("received {received}, sent {sent}"),
        (Some(received), None) => format!("received {received}"),
        (None, Some(sent)) => format!("sent {sent}"),
        (None, None) => String::new(),
    }
}

/// A sync name as people read it.
fn sync_label(name: &str) -> String {
    if name == cordelia_sync::claude::HOME_NAME {
        "home memory".to_string()
    } else {
        name.to_string()
    }
}

/// `path` with the home directory written as `~`.
fn short_path(path: &str) -> String {
    let home = real_home().display().to_string();
    match path.strip_prefix(&home) {
        Some(rest) if home.len() > 1 && (rest.is_empty() || rest.starts_with('/')) => {
            format!("~{rest}")
        }
        _ => path.to_string(),
    }
}

/// `path` as an argument to paste into a shell: with the home directory as
/// `~`, quoted where it needs to be.
fn shell_arg(path: &str) -> String {
    shell_quoted(&short_path(path))
}

/// A word as a shell argument: as it is where that is safe, quoted
/// otherwise. Names from other devices are printed inside commands to
/// copy, so nothing in one may be read by the shell.
fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && !word.starts_with('-')
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-+@%".contains(&b));
    if plain {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// A path that may start with `~/` as a shell argument. The `~/` stays
/// outside the quotes, where the shell expands it.
fn shell_quoted(path: &str) -> String {
    let plain = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-+".contains(&b))
    };
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    match path.strip_prefix("~/") {
        _ if path == "~" => path.to_string(),
        Some(rest) if plain(rest) => path.to_string(),
        Some(rest) => format!("~/{}", quote(rest)),
        None if plain(path) => path.to_string(),
        None => quote(path),
    }
}

/// Print rows in columns as wide as their widest cell, indented.
fn print_columns(rows: &[Vec<String>]) {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..columns)
        .map(|col| {
            rows.iter()
                .filter_map(|r| r.get(col))
                .map(|cell| cell.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    for row in rows {
        let line: String = row
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("  {cell:<width$}"))
            .collect();
        println!("{}", line.trim_end());
    }
}

/// Print what syncs on this device, what was found and is not syncing, and
/// what this person's other devices sync. After a change (`since` is the
/// settings generation it left), waits briefly for a report made under
/// the new settings: a cycle that was already running reports the old ones.
fn print_sync_scope(config_path: &str, since: Option<u64>) -> anyhow::Result<()> {
    let status = || api_post(config_path, "/api/v1/sync/status", serde_json::json!({}));
    let mut resp = status()?;
    if resp["enabled"].as_bool() != Some(true) {
        println!("Sync is off. Turn it on with `cordelia sync claude`.");
        return Ok(());
    }
    let fresh = |resp: &serde_json::Value| {
        !resp["report"].is_null() && resp["report"]["generation"].as_u64() >= since
    };
    for _ in 0..80 {
        if fresh(&resp) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        resp = status()?;
    }

    let text = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
    let list = |v: &serde_json::Value| v.as_array().cloned().unwrap_or_default();
    let all = resp["all"].as_bool() == Some(true);

    println!(
        "Syncing Claude Code memory in {}",
        short_path(&text(&resp["dir"]))
    );
    let report = &resp["report"];
    if !fresh(&resp) {
        println!("  (still working on it: try `cordelia sync status` in a few seconds)");
        return Ok(());
    }

    let folders = list(&report["folders"]);
    if folders.is_empty() {
        println!("  Nothing syncs yet.");
    }
    let mut rows: Vec<Vec<String>> = Vec::new();
    for f in &folders {
        let place = match f["cwd"].as_str() {
            Some(cwd) => short_path(cwd),
            None => short_path(&text(&f["folder"])),
        };
        let state = if let Some(error) = f["error"].as_str() {
            format!("error: {error}")
        } else if f["waiting"].as_bool() == Some(true) {
            "waiting for one of your other devices to let this one in".to_string()
        } else {
            "syncing".to_string()
        };
        rows.push(vec![
            place,
            sync_label(&text(&f["project"])),
            state,
            folder_activity(f),
        ]);
    }
    print_columns(&rows);
    for f in &folders {
        for s in list(&f["skipped"]) {
            println!(
                "  not synced (not a plain text file Cordelia can carry): {}/memory/{}",
                short_path(&text(&f["folder"])),
                text(&s)
            );
        }
        for s in list(&f["too_large"]) {
            println!(
                "  not synced (too large: an entry carries at most 64 KB): {}/memory/{}",
                short_path(&text(&f["folder"])),
                text(&s)
            );
        }
        for c in list(&f["conflict_files"]) {
            println!("  conflict to merge: {}", short_path(&text(&c)));
        }
    }
    let excluded: Vec<String> = list(&report["excluded"])
        .iter()
        .map(|e| sync_label(&text(e)))
        .collect();
    if !excluded.is_empty() {
        println!("  Excluded on this device: {}", excluded.join(", "));
    }

    // What the other devices sync is marked where it was found here, and
    // listed on its own only when it was not.
    let available: Vec<String> = list(&report["available"]).iter().map(text).collect();
    let unmapped = list(&report["unmapped"]);
    if !unmapped.is_empty() {
        println!();
        println!("Found on this machine, not syncing:");
        let rows: Vec<Vec<String>> = unmapped
            .iter()
            .map(|u| {
                let Some(cwd) = u["cwd"].as_str() else {
                    return vec![
                        short_path(&text(&u["folder"])),
                        "its folder is not known".to_string(),
                        "cordelia sync map <its folder> <name>".to_string(),
                    ];
                };
                // `map` takes folders in the home directory only.
                let mappable = std::path::Path::new(cwd).starts_with(real_home());
                let (mut what, command) = match u["name"].as_str() {
                    // Under the name it last had here, if it had another:
                    // mapped as `~` it would go to another channel.
                    Some(name) if name == cordelia_sync::claude::HOME_NAME => {
                        match resp["home_name"].as_str() {
                            Some(last) if last != name => (
                                format!("{} (last synced as {last})", sync_label(name)),
                                "cordelia sync home on".to_string(),
                            ),
                            _ => (sync_label(name), "cordelia sync map ~ --home".to_string()),
                        }
                    }
                    Some(name) if !mappable => (
                        name.to_string(),
                        "outside your home directory: only --all syncs it".to_string(),
                    ),
                    Some(name) => (
                        name.to_string(),
                        format!("cordelia sync map {}", shell_arg(cwd)),
                    ),
                    None if !mappable => (
                        "not a git project".to_string(),
                        "outside your home directory: it cannot be mapped".to_string(),
                    ),
                    None => (
                        "needs a name (not a git project)".to_string(),
                        format!("cordelia sync map {} <name>", shell_arg(cwd)),
                    ),
                };
                // Not said of a home that last synced under another
                // name: what the other devices sync is `~`, and turning
                // home on here would not join that.
                if u["name"]
                    .as_str()
                    .is_some_and(|n| available.iter().any(|a| a == n))
                    && !command.ends_with("sync home on")
                {
                    what.push_str(" (your other devices sync it)");
                }
                vec![short_path(cwd), what, command]
            })
            .collect();
        print_columns(&rows);
    }

    let home_dir = real_home().display().to_string();
    let home_here: Option<String> = declared_mappings(&resp)
        .into_iter()
        .find(|(folder, _)| *folder == home_dir)
        .map(|(_, name)| name);
    let elsewhere: Vec<Vec<String>> = available
        .iter()
        .filter(|name| {
            !unmapped
                .iter()
                .any(|u| u["name"].as_str() == Some(name.as_str()))
        })
        .map(|name| {
            let command = if name == cordelia_sync::claude::HOME_NAME {
                home_memory_elsewhere(home_here.as_deref(), resp["home_name"].as_str())
            } else {
                format!("cordelia sync map <folder> {}", shell_word(name))
            };
            vec![sync_label(name), command]
        })
        .collect();
    if !elsewhere.is_empty() {
        println!();
        println!("Synced by your other devices, not by this one:");
        print_columns(&elsewhere);
    }

    println!();
    if all {
        println!(
            "Scope: everything found (home memory and git projects), now and later. \
             `cordelia sync claude --mapped-only` limits it to mapped folders."
        );
    } else {
        println!(
            "Scope: mapped folders only. `cordelia sync claude --all` syncs everything \
             found (home memory and git projects), now and later."
        );
    }
    for e in list(&report["errors"]) {
        println!("error: {}", text(&e));
    }
    Ok(())
}

// ── Signal handling ───────────────────────────────────────────────

/// Wait for SIGINT (Ctrl+C), SIGTERM (systemd, launchd, Docker) or SIGQUIT.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        // SIGQUIT stops the node as the others do. Left alone it would end
        // the process with a core, and the node's keys are in its memory.
        let mut sigquit = signal(SignalKind::quit()).expect("failed to register SIGQUIT handler");

        tokio::select! {
            _ = ctrl_c => { tracing::info!("received SIGINT"); }
            _ = sigterm.recv() => { tracing::info!("received SIGTERM"); }
            _ = sigquit.recv() => { tracing::info!("received SIGQUIT"); }
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
    /// A part of a node, for these tests: it runs until it is told to stop,
    /// and then takes `to_stop` to finish, or never does.
    async fn part(
        mut stop: tokio::sync::watch::Receiver<bool>,
        to_stop: Option<std::time::Duration>,
    ) -> Result<(), String> {
        while !*stop.borrow_and_update() {
            if stop.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
        match to_stop {
            Some(time) => tokio::time::sleep(time).await,
            None => std::future::pending::<()>().await,
        }
        Ok(())
    }

    /// Run two such parts as a node does. The node is told to stop after
    /// `told_after`, if at all. The parts take `server` and `p2p` to stop.
    /// Returns how the run ended and how long it took.
    async fn run_parts(
        told_after: Option<std::time::Duration>,
        server: Option<std::time::Duration>,
        p2p: Option<std::time::Duration>,
    ) -> (
        Stopped<Result<(), String>, Result<(), String>>,
        std::time::Duration,
    ) {
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let began = tokio::time::Instant::now();
        let stopped = run_until_stopped(
            part(stop_rx.clone(), server),
            part(stop_rx, p2p),
            async {
                match told_after {
                    Some(time) => tokio::time::sleep(time).await,
                    None => std::future::pending::<()>().await,
                }
            },
            move || {
                let _ = stop_tx.send(true);
            },
            AT_MOST,
        )
        .await;
        (stopped, began.elapsed())
    }

    const AT_MOST: std::time::Duration = std::time::Duration::from_secs(30);
    const DAY: std::time::Duration = std::time::Duration::from_secs(86_400);

    fn secs(n: u64) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_secs(n))
    }

    /// A node that is told to stop exits within a bounded time, whatever
    /// one of its parts is waiting for: a part that never finishes is
    /// waited for only so long, and the node says which part it was.
    #[tokio::test(start_paused = true)]
    async fn a_node_told_to_stop_waits_for_its_parts_only_so_long() {
        // The HTTP server never finishes stopping.
        let (stopped, took) = tokio::time::timeout(DAY, run_parts(secs(5), None, secs(1)))
            .await
            .expect("a part that never finishes was waited for without end");
        assert_eq!(took, secs(5).unwrap() + AT_MOST);
        assert!(stopped.told);
        assert!(stopped.server.is_none(), "the server never finished");
        assert_eq!(stopped.p2p, Some(Ok(())));
        assert!(
            stopped.result().is_err(),
            "a node that gave up on a part did not stop cleanly"
        );

        // Nor does the peer-to-peer loop.
        let (stopped, took) = tokio::time::timeout(DAY, run_parts(secs(5), secs(1), None))
            .await
            .expect("a part that never finishes was waited for without end");
        assert_eq!(took, secs(5).unwrap() + AT_MOST);
        assert_eq!(stopped.server, Some(Ok(())));
        assert!(stopped.p2p.is_none(), "the loop never finished");

        // Parts that finish are waited for, and no longer.
        let (stopped, took) = run_parts(secs(5), secs(2), secs(1)).await;
        assert_eq!(took, secs(7).unwrap());
        assert_eq!((stopped.server, stopped.p2p), (Some(Ok(())), Some(Ok(()))));
    }

    /// The time a node waits is for both parts together, counted from when
    /// it is told to stop: a part does not get the whole of it again after
    /// the other has finished.
    #[tokio::test(start_paused = true)]
    async fn the_time_to_stop_is_for_the_whole_node() {
        let (stopped, took) = tokio::time::timeout(DAY, run_parts(secs(5), secs(20), None))
            .await
            .unwrap();
        assert_eq!(took, secs(5).unwrap() + AT_MOST);
        assert_eq!(stopped.server, Some(Ok(())));
        assert!(stopped.p2p.is_none());
    }

    /// A node that is not told to stop runs on, however long, and its parts
    /// are not told to stop.
    #[tokio::test(start_paused = true)]
    async fn a_node_that_is_not_told_to_stop_runs_on() {
        assert!(
            tokio::time::timeout(DAY, run_parts(None, secs(1), secs(1)))
                .await
                .is_err(),
            "a node stopped though it was not told to"
        );
    }

    /// A node whose part ends by itself stops: the other part is told to
    /// stop, and the node exits with a failure, so that whatever runs it
    /// starts it again. A node that ran on without its peer-to-peer loop
    /// would answer its local API and sync nothing.
    #[tokio::test(start_paused = true)]
    async fn a_node_whose_part_ends_by_itself_stops() {
        for which in ["the peer-to-peer loop", "the HTTP server"] {
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            let ends = async {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                Err::<(), String>("it broke".into())
            };
            let other = part(stop_rx.clone(), secs(1));
            let began = tokio::time::Instant::now();
            let run = async {
                let stop = move || {
                    let _ = stop_tx.send(true);
                };
                let never = std::future::pending::<()>();
                if which == "the HTTP server" {
                    run_until_stopped(ends, other, never, stop, AT_MOST).await
                } else {
                    let stopped = run_until_stopped(other, ends, never, stop, AT_MOST).await;
                    Stopped {
                        told: stopped.told,
                        server: stopped.p2p,
                        p2p: stopped.server,
                    }
                }
            };
            let stopped = tokio::time::timeout(DAY, run)
                .await
                .unwrap_or_else(|_| panic!("the node ran on though {which} had ended"));
            // The part that ended is in `server` here, whichever it was.
            assert_eq!(began.elapsed(), secs(11).unwrap(), "{which}");
            assert!(!stopped.told, "{which}");
            assert_eq!(stopped.server, Some(Err("it broke".into())), "{which}");
            assert_eq!(
                stopped.p2p,
                Some(Ok(())),
                "{which}: the other part was told to stop"
            );
            assert!(*stop_rx.borrow(), "{which}");
            assert!(
                stopped.result().is_err(),
                "{which}: the node must exit with a failure"
            );
        }
    }

    /// What a node exits with: success only if it was told to stop, and
    /// both its parts stopped in time and without failing.
    #[test]
    fn a_node_exits_with_a_failure_unless_it_stopped_cleanly() {
        type Ended = Option<Result<(), String>>;
        let stopped = |told, server: Ended, p2p: Ended| Stopped { told, server, p2p };
        let ok = || Some(Ok(()));
        let failed = || Some(Err("it broke".to_string()));
        assert!(stopped(true, ok(), ok()).result().is_ok());
        for (told, server, p2p) in [
            (false, ok(), ok()),
            (true, None, ok()),
            (true, ok(), None),
            (true, failed(), ok()),
            (true, ok(), failed()),
            (false, None, failed()),
        ] {
            let why = stopped(told, server.clone(), p2p.clone()).result();
            assert!(why.is_err(), "{told} {server:?} {p2p:?}");
        }
        // It says what went wrong.
        let why = stopped(false, failed(), ok())
            .result()
            .unwrap_err()
            .to_string();
        assert!(
            why.contains("not told to stop") && why.contains("it broke"),
            "{why}"
        );
    }

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
    fn test_what_a_run_of_sync_claude_changed() {
        let settings = |v: serde_json::Value| v;
        let off = settings(
            serde_json::json!({ "enabled": false, "all": false, "home": true,
            "exclude": [], "mappings": [] }),
        );
        let on = settings(serde_json::json!({ "enabled": true, "dir": "/srv/claude",
            "all": false, "home": true, "exclude": [], "mappings": [] }));
        assert_eq!(
            setting_changes(&off, &on),
            ["Sync turned on.", "Claude Code directory: /srv/claude."]
        );
        assert_eq!(setting_changes(&on, &on), ["No settings changed."]);

        let wider = settings(serde_json::json!({ "enabled": true, "dir": "/srv/other",
            "all": true, "home": false, "exclude": ["github.com/o/x"],
            "mappings": [{ "folder": "/srv/notes", "name": "lab-notes" }] }));
        assert_eq!(
            setting_changes(&on, &wider),
            [
                "Claude Code directory: /srv/other (was /srv/claude).",
                "Scope: everything found (was mapped folders only).",
                "Home memory: kept off this device.",
                "Excluded: github.com/o/x (was nothing).",
            ]
        );
        assert_eq!(
            setting_changes(&wider, &on),
            [
                "Claude Code directory: /srv/claude (was /srv/other).",
                "Scope: mapped folders only (was everything found).",
                "Home memory: no longer kept off this device.",
                "Excluded: nothing (was github.com/o/x).",
                "Unmapped: /srv/notes (lab-notes).",
            ]
        );
    }

    #[test]
    fn test_paths_as_shell_arguments() {
        for (path, want) in [
            ("~", "~"),
            ("~/Work/cordelia-node", "~/Work/cordelia-node"),
            ("/srv/code/app_v2", "/srv/code/app_v2"),
            // The `~/` stays outside the quotes so the shell expands it.
            ("~/My Notes", "~/'My Notes'"),
            ("/srv/My Notes", "'/srv/My Notes'"),
            ("~/it's here", "~/'it'\\''s here'"),
            ("/srv/$(touch x)", "'/srv/$(touch x)'"),
            ("/srv/a;b", "'/srv/a;b'"),
        ] {
            assert_eq!(shell_quoted(path), want);
        }
    }

    #[test]
    fn test_names_as_shell_arguments() {
        for (name, want) in [
            ("lab-notes", "lab-notes"),
            (
                "github.com/seed-drill/cordelia-node",
                "github.com/seed-drill/cordelia-node",
            ),
            ("host.example/a%20b/c+d", "host.example/a%20b/c+d"),
            // A tilde is expanded by the shell at the start of a word.
            ("git.sr.ht/~sam/proj", "'git.sr.ht/~sam/proj'"),
            ("x; rm -rf ~", "'x; rm -rf ~'"),
            ("-rf", "'-rf'"),
            ("", "''"),
        ] {
            assert_eq!(shell_word(name), want);
        }
    }

    /// An install leaves the old node running. A command says so, beside
    /// what the node answered, when the node is not the version it is.
    #[test]
    fn test_a_node_of_another_version_is_named() {
        assert_eq!(version_note(Some("0.2.0-alpha.6"), "0.2.0-alpha.6"), None);
        let other = version_note(Some("0.2.0-alpha.5"), "0.2.0-alpha.6").unwrap();
        assert!(
            other.contains("node is version 0.2.0-alpha.5")
                && other.contains("command is version 0.2.0-alpha.6")
                && other.contains("restarted"),
            "{other}"
        );
        // A node from before it said its version.
        let older = version_note(None, "0.2.0-alpha.6").unwrap();
        assert!(
            older.contains("from before nodes said their version")
                && older.contains("command is version 0.2.0-alpha.6")
                && older.contains("restarted"),
            "{older}"
        );
    }

    /// Another device's `~` is offered to this device only where its home
    /// has no other name: a home has one name on a device.
    #[test]
    fn test_home_memory_elsewhere_is_offered_only_to_a_home_without_a_name() {
        let offer = "cordelia sync map ~ --home";
        assert_eq!(home_memory_elsewhere(None, None), offer);
        assert_eq!(home_memory_elsewhere(None, Some("~")), offer);
        let mapped = home_memory_elsewhere(Some("team"), Some("team"));
        assert!(mapped.contains("syncs as team") && !mapped.contains("cordelia"));
        let off = home_memory_elsewhere(None, Some("team"));
        assert!(off.contains("last synced as team") && !off.contains("cordelia"));
    }

    /// Status shows the last report of what syncs. A report from a cycle
    /// that stopped, or from before the settings last changed, is not one.
    #[test]
    fn test_only_a_report_of_what_syncs_now_is_kept() {
        use cordelia_sync::claude::CycleReport;
        let report = |generation: u64, stopped: bool| CycleReport {
            generation,
            stopped,
            ..Default::default()
        };
        assert!(report_stands(&report(4, false), 4));
        assert!(!report_stands(&report(4, true), 4));
        assert!(!report_stands(&report(3, false), 4));
    }

    /// What `map` offers when the home directory is named without the
    /// flag does what was asked: nothing that would map home under another
    /// name than the one typed, and nothing a shell would read otherwise.
    #[test]
    fn test_what_map_offers_for_the_home_directory() {
        let offer = |name: Option<&str>| home_offer(name);
        assert_eq!(offer(None).unwrap(), "cordelia sync home on");
        assert_eq!(offer(Some("~")).unwrap(), "cordelia sync map ~ --home");
        for (typed, offered) in [
            ("team", "cordelia sync map ~ team --home"),
            ("Team", "cordelia sync map ~ team --home"),
            (
                "github.com/Owner/Repo.git",
                "cordelia sync map ~ github.com/owner/repo --home",
            ),
            ("Repo.GIT", "cordelia sync map ~ repo --home"),
        ] {
            assert_eq!(offer(Some(typed)).unwrap(), offered, "{typed}");
        }
        for not_a_name in ["my team", "a/../b", "it's", "-x", "~x", ""] {
            assert!(offer(Some(not_a_name)).is_err(), "{not_a_name:?}");
        }
        // Run as offered, a name is the name it was given as.
        assert_eq!(normalise_project(&normalise_project("Repo.GIT")), "repo");
    }

    /// The loop holds one adapter, for the Claude Code directory that is
    /// set. It keeps the one it has while that is the directory, and makes
    /// another when it is not, or when it has none.
    #[test]
    fn test_the_loop_holds_the_adapter_for_the_directory_that_is_set() {
        let made = std::cell::Cell::new(0);
        let make = |dir: &'static str| {
            made.set(made.get() + 1);
            dir
        };
        let mut slot: Option<&'static str> = None;
        // None held: one is made.
        assert_eq!(*adapter_for(&mut slot, |d| *d == "/a", || make("/a")), "/a");
        // Held, and for the directory: kept.
        assert_eq!(*adapter_for(&mut slot, |d| *d == "/a", || make("/a")), "/a");
        assert_eq!(made.get(), 1);
        // Held, for another: one is made for the new directory.
        assert_eq!(*adapter_for(&mut slot, |d| *d == "/b", || make("/b")), "/b");
        assert_eq!((made.get(), slot), (2, Some("/b")));
    }

    /// `cordelia sync unmap <word>`: a name, or a folder. A word that is
    /// one mapping's name and another mapping's folder is refused.
    #[test]
    fn test_a_word_that_means_two_mappings_is_refused() {
        let pair = |folder: &str, name: &str| (folder.to_string(), name.to_string());
        // Paths under nobody's home directory, so that none is shortened
        // to `~` wherever the tests run.
        let home = pair("/srv/agents/sam", "work");
        let folder = pair("/srv/agents/sam/work", "client");

        let said = mapping_meant("work", Some(&home), Some(&folder))
            .unwrap_err()
            .to_string();
        assert!(
            said.contains("cordelia sync unmap /srv/agents/sam/work")
                && said.contains("cordelia sync unmap /srv/agents/sam."),
            "{said}"
        );
        // One meaning, by either route or by both.
        assert_eq!(mapping_meant("work", Some(&home), None).unwrap(), &home);
        assert_eq!(mapping_meant("work", None, Some(&folder)).unwrap(), &folder);
        assert_eq!(
            mapping_meant("x", Some(&folder), Some(&folder)).unwrap(),
            &folder
        );
        let said = mapping_meant("x", None, None).unwrap_err().to_string();
        assert!(said.contains("not mapped on this device"), "{said}");
    }

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(40), "40s");
        assert_eq!(format_uptime(245), "4m 05s");
        assert_eq!(format_uptime(3 * 3600 + 12 * 60 + 9), "3h 12m");
    }
}
