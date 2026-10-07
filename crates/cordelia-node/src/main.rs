//! Cordelia node binary: CLI, daemon lifecycle, signal handling.
//!
//! Spec: seed-drill/specs/operations.md

use std::sync::Mutex;

use actix_web::{App, HttpServer, web};
use clap::Parser;

use cordelia_core::config::{self, Config};
use cordelia_crypto::bech32::{HRP_X25519_PK, encode_public_key};
use cordelia_crypto::identity::NodeIdentity;

mod history_cmd;
mod indicator;
mod p2p;
mod person_cmd;
mod relay_entries;
mod terminal;

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

        /// Give this device a new key: it leaves the devices it is with,
        /// keeps its memory folders and their mappings, and follows no
        /// recovery phrase. Asks at a terminal.
        #[arg(long, conflicts_with_all = ["name", "force", "show_secrets"])]
        new_key: bool,
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
    /// Make the recovery phrase of your devices on this one: twelve
    /// words, shown once. Asks at a terminal.
    Phrase {
        /// What your devices call this one, e.g. "laptop" (default: the
        /// machine's name)
        #[arg(long)]
        name: Option<String>,
    },
    /// Add another of your devices; then run `cordelia accept` on it,
    /// within the hour. Asks at a terminal.
    AddDevice {
        /// The other device's key, from `cordelia id` on that device
        key: String,
        /// A name for the device, e.g. "desktop"
        #[arg(long)]
        name: Option<String>,
    },
    /// Take what the device that added this one hands over. Asks at a
    /// terminal.
    Accept {
        /// The key printed by `add-device` on the other device
        key: String,
    },
    /// Remove one of your devices, with the recovery phrase. Asks at a
    /// terminal.
    RemoveDevice {
        /// The device's key, as `cordelia devices` lists it
        key: String,
    },
    /// Give the devices that stay a new secret, with the recovery
    /// phrase: of each device added since the last change, you say
    /// whether it stays. Asks at a terminal.
    Renew,
    /// Settle two changes that were made apart, with the recovery
    /// phrase, on a device that has seen both. Asks at a terminal.
    Settle,
    /// After a change is made: say what is still missing, until this
    /// machine may be closed. It is what `remove-device`, `renew` and
    /// `settle` go on to, in a process that never held the phrase.
    #[command(hide = true)]
    ChangeMade {
        /// The change's number
        number: u64,
    },
    /// List your devices, what each has applied, and what each relay
    /// holds
    Devices {
        /// Go through what this device is to tell you, and clear what
        /// you say yes to. Asks at a terminal.
        #[arg(long)]
        clear: bool,
    },
    /// Sync an agent's memory across your devices
    Sync {
        #[command(subcommand)]
        what: SyncCommand,
    },
    /// List the versions of memory files that sync replaced or removed on
    /// this device: with no argument, how much is kept and for which agents
    #[command(args_conflicts_with_subcommands = true)]
    History {
        /// An agent's name, or the folder it works in
        of: Option<String>,
        /// Only files that were removed and are still absent
        #[arg(long)]
        removed: bool,
        /// Only versions kept since a time (2026-10-03T09:00:00Z), or in
        /// the last while (30m, 2h, 3d)
        #[arg(long)]
        since: Option<String>,
        #[command(subcommand)]
        what: Option<HistoryCommand>,
    },
    /// Put kept versions of memory files back, by id (see `cordelia history`)
    Restore {
        /// The ids of the versions, each restored by itself in this order
        ids: Vec<String>,
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
enum HistoryCommand {
    /// Print one kept version
    Show {
        /// The version's id
        id: String,
    },
    /// Remove kept versions from this device, with every other kept
    /// version here that holds the same text
    Drop {
        /// An agent's name, or the folder it works in
        of: Option<String>,
        /// One file of it
        file: Option<String>,
        /// Everything kept on this device
        #[arg(long)]
        all: bool,
    },
}

#[derive(clap::Subcommand)]
enum SyncCommand {
    /// Turn on Claude Code memory sync. Nothing syncs until you map a
    /// folder (`cordelia sync map`): only mapped folders sync. Running it
    /// again keeps your settings.
    Claude {
        /// Claude Code directory (default: ~/.claude)
        #[arg(long)]
        dir: Option<String>,
        /// No more: only mapped folders sync. It is refused, and says
        /// what to do instead.
        #[arg(long, hide = true)]
        all: bool,
        /// Sync only the folders you map: the only scope there is
        #[arg(long, conflicts_with = "all")]
        mapped_only: bool,
        /// No more: there is nothing left to exclude. It is refused, and
        /// says what to do instead.
        #[arg(long, hide = true)]
        exclude: Vec<String>,
        /// Do not sync home-folder memory on this device: unmaps the home
        /// directory
        #[arg(long)]
        no_home: bool,
        /// Back to the default Claude Code directory, ~/.claude. Mapped
        /// folders stay mapped.
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
    Status {
        /// Put away the notice of the folders that stopped syncing: you
        /// have seen it
        #[arg(long)]
        seen: bool,
    },
    /// Sync home-folder memory on this device, or not: `on` maps the home
    /// directory, and `off` unmaps it
    Home {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// No more: there is nothing left to exclude. It is refused, and says
    /// what to do instead.
    #[command(hide = true)]
    Exclude { project: String },
    /// No more: there is nothing left to exclude. It is refused, and says
    /// what to do instead.
    #[command(hide = true)]
    Include { project: String },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init { new_key: true, .. }) => person_cmd::new_key(&cli.config),
        Some(Commands::Init {
            name,
            non_interactive,
            force,
            show_secrets,
            new_key: false,
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
        Some(Commands::Phrase { name }) => person_cmd::phrase(&cli.config, name),
        Some(Commands::AddDevice { key, name }) => person_cmd::add_device(&cli.config, &key, name),
        Some(Commands::Accept { key }) => person_cmd::accept(&cli.config, &key),
        Some(Commands::RemoveDevice { key }) => person_cmd::remove_device(&cli.config, &key),
        Some(Commands::Renew) => person_cmd::renew(&cli.config),
        Some(Commands::Settle) => person_cmd::settle(&cli.config),
        Some(Commands::ChangeMade { number }) => person_cmd::change_made(&cli.config, number),
        Some(Commands::Devices { clear }) => person_cmd::devices(&cli.config, clear),
        Some(Commands::Sync { what }) => cmd_sync(&cli.config, what),
        Some(Commands::History {
            of,
            removed,
            since,
            what,
        }) => match what {
            None => history_cmd::list(&cli.config, of.as_deref(), removed, since.as_deref()),
            Some(HistoryCommand::Show { id }) => history_cmd::show(&cli.config, &id),
            Some(HistoryCommand::Drop { of, file, all }) => {
                history_cmd::drop(&cli.config, of.as_deref(), file.as_deref(), all)
            }
        },
        Some(Commands::Restore { ids }) => history_cmd::restore(&cli.config, &ids),
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

/// What is said of a database from a later version than this one
/// (decision 2026-10-04 §10.1): where it is, both versions, that nothing
/// was changed, and the way on.
fn from_a_later_version(db_path: &std::path::Path, found: u32, own: u32) -> String {
    format!(
        "the database at {} is from a later version of Cordelia than this one: it is at schema \
         version {found}, and this is Cordelia {}, which knows schema version {own} and none \
         after. Nothing was changed. Install the later version again; or, to go back to this \
         one, put back the copy that the later version made, as its release notes say.",
        db_path.display(),
        env!("CARGO_PKG_VERSION"),
    )
}

/// Open the node's database, as a command that opens it itself does, with
/// the schema's steps run. **A database from a later version is refused**
/// (decision 2026-10-04 §10.1): the command names both versions, and
/// changes nothing.
fn open_database(db_path: &std::path::Path) -> anyhow::Result<rusqlite::Connection> {
    use cordelia_storage::StorageError;
    match cordelia_storage::db::open(db_path) {
        Ok(conn) => Ok(conn),
        Err(StorageError::LaterVersion { found, own }) => {
            anyhow::bail!("{}", from_a_later_version(db_path, found, own))
        }
        Err(e) => Err(e.into()),
    }
}

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

    // A database that this command would open is opened before anything
    // is written: one from a later version is refused, and nothing is
    // changed, not the node's token either (decision 2026-10-04 §10.1).
    let db_path = data_dir.join("cordelia.db");
    if db_path.exists() && force {
        drop(open_database(&db_path)?);
    }

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
    if !db_path.exists() || force {
        println!("Creating database...");
        let _conn = open_database(&db_path)?;
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

    // No channel is made here. A device's channels are made from its
    // person's secret, once it follows a recovery phrase: `cordelia
    // phrase` on the first device, `add-device` there and `accept` here
    // on each one after (decision 2026-10-04 §5, §6).

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
    // The state, the level, and what the line says: the level is worked
    // out here, in the command, and nowhere else (decision 2026-10-04
    // §10.1).
    let shown = indicator::shown(&status.facts);
    let (state, level, summary) = (shown.state, shown.level, shown.summary.clone());
    // Everything that holds beside what the line says: a tooltip and the
    // plain status list it all.
    let also: Vec<String> = shown
        .holds
        .iter()
        .filter(|holds| holds.says != summary)
        .map(indicator::Holds::detail)
        .collect();

    if waybar {
        let mut details = also.clone();
        if let Some(why) = &status.not_asked {
            details.push(format!("Not asked: {why}"));
        }
        if let Some(why) = status.held() {
            details.push(format!("Held up: {why}"));
        }
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
        // The folders that stopped syncing, with sync on or off.
        if let Some(sync) = &status.sync {
            for stopped in notice_details(&sync["notice"]) {
                details.push(format!("Stopped syncing: {stopped}"));
            }
        }
        let text = indicator::bar(state, level, &summary, &details);
        if !text.is_empty() {
            println!("{text}");
        }
        return Ok(());
    }

    if line {
        let color = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
        let text = indicator::line(state, level, &summary, color);
        if !text.is_empty() {
            println!("{text}");
        }
        return Ok(());
    }
    if json {
        let holds: Vec<serde_json::Value> = shown
            .holds
            .iter()
            .map(|holds| {
                serde_json::json!({
                    "level": holds.level.as_str(),
                    "what": holds.what,
                    "says": holds.says,
                })
            })
            .collect();
        let mut out = serde_json::json!({
            "state": state.as_str(),
            // The level: `red`, `amber`, or null where none holds. A
            // panel draws it, and works nothing out itself.
            "level": level.map(indicator::Level::as_str),
            // The first thing of that level; with no level, what the
            // state says.
            "summary": summary,
            // Everything that holds, red first, each with its level.
            "holds": holds,
            "version": env!("CARGO_PKG_VERSION"),
            "running": status.facts.running,
        });
        if let Some(device) = &status.device {
            out["device"] = device.clone().into();
            out["role"] = status.facts.role.clone().into();
        }
        // A node that was not asked is not known to be stopped, or to be
        // running: `running` says neither, and `not_asked` says why.
        if let Some(why) = &status.not_asked {
            out["running"] = serde_json::Value::Null;
            out["not_asked"] = why.clone().into();
        }
        if let Some(live) = &status.live {
            // Why the node is held up, where it is: by what, and why.
            if !live["held"].is_null() {
                out["held"] = live["held"].clone();
            }
            // Key files of an older version that were left in place.
            if live["key_files_in_place"].as_u64() > Some(0) {
                out["key_files_in_place"] = live["key_files_in_place"].clone();
            }
            // The node's own version: `version` above is this command's.
            out["node_version"] = live["version"].clone();
            out["uptime_secs"] = live["uptime_secs"].clone();
            // For how long no relay has been connected, by the node's
            // own clock: null while one is (decision 2026-10-04 §10.1).
            out["no_relay_secs"] = live["no_relay_secs"].clone();
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
                        // Files that could not be synced in the last
                        // cycle, each with why: always a list. Past the
                        // first hundred they are only counted.
                        "failed": f["failed"].as_array().cloned().unwrap_or_default(),
                        "failed_more": f["failed_more"].as_u64().unwrap_or(0),
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
                // Why nothing is published from this device, where
                // nothing is, and where it stands under a phrase.
                "publishes_nothing": report["publishes_nothing"],
                "stands": sync["stands"],
                // Whether the device took this version with what an
                // earlier one held: with no phrase it is not added yet.
                "moved_on": sync["moved_on"],
                "unsynced": report["unsynced"],
                "excluded": report["excluded"],
                "errors": status.facts.errors,
                // The notice of the folders that stopped syncing, while
                // the node stores one: null where it stores none.
                "notice": sync["notice"],
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
        }
        // What this device holds of its person, under a recovery phrase
        // (decision 2026-10-04 §8): where it stands, what it says in
        // words, and what it is to tell a person.
        if let Some(person) = &status.person {
            out["person"] = person.clone();
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
    // A database from a later version is not opened: the status says so,
    // and goes on to what the node says of itself (decision 2026-10-04
    // §10.1).
    let opened = match db_path.exists() {
        true => Some(open_database(&db_path)),
        false => None,
    };
    if let Some(Err(why)) = &opened {
        println!();
        println!("Storage:");
        println!("  Not read:  {why}");
    }
    if let Some(Ok(conn)) = opened {
        let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);

        println!();
        println!("Storage:");
        // A personal node holds names, each with its channel from the
        // person's secret. A node of another role holds channels of the
        // older kind.
        if config.network.role == "personal" {
            let names = cordelia_storage::person::names(&conn)?;
            println!("  Names:     {}", names.len());
        } else {
            let channels = cordelia_storage::channels::list_for_entity(&conn, &pk)?;
            println!("  Channels:  {}", channels.len());
        }
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
            // A node that is held up says why (decision 2026-10-04
            // §10.1).
            if let Some(why) = status.held() {
                println!("  Held up:   {why}");
            }
            // Key files of an older version that no copy holds are left
            // where they are, and said (decision 2026-10-04 §10.1).
            if let Some(files) = live["key_files_in_place"].as_u64().filter(|n| *n > 0) {
                println!(
                    "  Key files: {}",
                    cordelia_api::first_start::key_files_in_place_says(files as usize)
                );
            }
            if config.network.role == "personal" {
                println!("  Memory:    {summary}");
                for more in &also {
                    println!("    also:     {more}");
                }
                for c in &status.facts.conflicts {
                    println!("    conflict: {c}");
                }
                for e in &status.facts.errors {
                    println!("    error:    {e}");
                }
                // The folders that stopped syncing, with sync on or off
                // (decision 2026-10-04 §10.1).
                let stopped = status
                    .sync
                    .as_ref()
                    .map(|sync| notice_details(&sync["notice"]))
                    .unwrap_or_default();
                for folder in &stopped {
                    println!("    stopped:  {folder}");
                }
                if !stopped.is_empty() {
                    println!("              (`cordelia sync status` says how to map each)");
                }
                // What this device says of itself and its person's
                // devices (decision 2026-10-04 §5.1, §5.2, §8).
                let timeout = std::time::Duration::from_secs(3);
                let asked_again = || local_api(&config, true, "/api/v1/devices/list", timeout).ok();
                if let Some(person) = status.person.clone().or_else(asked_again) {
                    let (short, says) = person_cmd::status_lines(&person);
                    println!("  Devices:   {short}");
                    for line in says {
                        println!("    {line}");
                    }
                }
            }
        }
        // A node whose address is refused is not asked, and is not known
        // to be stopped.
        None => match &status.not_asked {
            None => println!("  Running:   no (start it with `cordelia start`)"),
            Some(why) => println!("  Running:   not asked: {why}"),
        },
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
    /// Why the node was not asked, where its API address is not one a
    /// command asks ([`api_host`]).
    not_asked: Option<String>,
    /// `POST /api/v1/devices/list` from the running node, where it is a
    /// personal one: what it holds of its person.
    person: Option<serde_json::Value>,
}

impl GatheredStatus {
    /// Why the running node is held up, in its own words, where it is
    /// (decision 2026-10-04 §10.1).
    fn held(&self) -> Option<&str> {
        self.live.as_ref()?["held"]["why"].as_str()
    }
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
        not_asked: None,
        person: None,
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

    let address = &config.api.bind_address;
    if api_host(address).is_none() {
        out.facts.not_asked = true;
        out.not_asked = Some(not_the_nodes_own(address));
        return out;
    }
    let timeout = std::time::Duration::from_secs(1);
    let Ok(live) = local_api(&config, false, "/api/v1/status", timeout) else {
        return out;
    };
    out.facts.running = true;
    out.facts.uptime_secs = live["uptime_secs"].as_u64();
    // By the node's own clock. A node that does not say gives none.
    out.facts.no_relay_secs = live["no_relay_secs"].as_u64();
    // Only the command knows that the node is another version than it.
    out.facts.other_version = live["version"].as_str() != Some(env!("CARGO_PKG_VERSION"));
    out.facts.held = live["held"]["by"].as_str().map(str::to_string);
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
        out.facts.mapped = sync["mappings"].as_array().map_or(0, Vec::len);
        out.facts.stands = sync["stands"].as_str().unwrap_or_default().to_string();
        out.facts.moved_on = sync["moved_on"].as_bool().unwrap_or(false);
        // The notice of what stopped syncing, while the node stores one.
        let notice = &sync["notice"];
        out.facts.notice = notice.is_object().then(|| indicator::Stopped {
            folders: notice["stopped"].as_u64().unwrap_or(0) as usize,
            not_known: notice["not_known"].as_bool() == Some(true),
        });
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
    // What the node holds of this person's devices (decision 2026-10-04
    // §8): a level goes by it.
    if out.facts.role == "personal"
        && let Ok(person) = local_api(&config, true, "/api/v1/devices/list", timeout)
    {
        out.facts.devices = devices_facts(&person, chrono::Utc::now().timestamp());
        out.person = Some(person);
    }
    out
}

/// What a status goes by of a person's devices, from the node's look at
/// them (`POST /api/v1/devices/list`) at `now`, in seconds
/// ([`indicator::Devices`]).
fn devices_facts(person: &serde_json::Value, now: i64) -> indicator::Devices {
    let list = |key: &str| person[key].as_array().into_iter().flatten();
    let ago = |at: &serde_json::Value| at.as_i64().map(|at| now.saturating_sub(at).max(0) as u64);
    let change = person["change"].as_u64();
    let applied_secs = ago(&person["applied_at"]);
    // A removal stands where the statement lists a key as removed, and
    // is not applied by a device that does not say it has applied that
    // statement.
    let removal = list("removed").next().is_some();
    let not_by_all = list("devices").any(|device| device["applied"].as_u64() != change);
    let said_left = list("devices").chain(list("added"));
    indicator::Devices {
        not_applied: person["state"] == "applied" && person["cannot_go_on"].is_string(),
        removal_not_applied_secs: applied_secs.filter(|_| removal && not_by_all),
        added_not_cleared: list("notices")
            .filter(|notice| notice["kind"] == "added")
            .count(),
        said_left: said_left.filter(|device| device["left"] == true).count(),
        without_latest_secs: list("relays")
            .filter(|relay| relay["holds_latest"] == false)
            .filter_map(|relay| relay["connected_secs"].as_u64())
            .collect(),
        no_room_secs: list("relays")
            .filter_map(|relay| ago(&relay["no_room_at"]))
            .collect(),
        // Only a name that a device which still counts had listed: one
        // that only a device which counts no longer had listed is in
        // `cordelia devices`, and in no level.
        names_not_listed: list("names_not_listed")
            .filter(|name| name["by"].as_array().is_some_and(|by| !by.is_empty()))
            .count(),
        applied_secs,
        names_to_go: person["names"]["to_go"].as_array().map_or(0, Vec::len),
        to_go_secs: ago(&person["names"]["to_go_since"]),
    }
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

/// The name of the file in a node's data directory that the node holds a
/// lock on for as long as it runs.
const NODE_LOCK: &str = "node.lock";

/// Take the lock that says a node is running on the data directory
/// `data_dir` (decision 2026-10-04 §10.1): an advisory lock on a file
/// there, which the system lets go of when the process ends, however it
/// ends. The file that is returned holds it, and is kept for the life of
/// the process.
///
/// Where another process holds it, a node is running on that directory:
/// this one says so, and has changed nothing. The file holds nothing, and
/// is left where it is when the node stops. On a volume that knows no
/// such lock the node starts, and says that it could not take one.
fn lock_data_dir(data_dir: &std::path::Path) -> anyhow::Result<std::fs::File> {
    let path = data_dir.join(NODE_LOCK);
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|e| anyhow::anyhow!("the lock on {} cannot be taken: {e}", data_dir.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
            "another node is running on the data directory {}: a data directory is one node's. \
             Nothing was changed. Stop that node first, or give this one a directory of its own.",
            data_dir.display()
        ),
        Err(std::fs::TryLockError::Error(e)) if e.kind() == std::io::ErrorKind::Unsupported => {
            tracing::warn!(
                "the volume of the data directory knows no lock: nothing stops a second node \
                 from being started on it"
            );
            Ok(file)
        }
        Err(std::fs::TryLockError::Error(e)) => {
            anyhow::bail!("the lock on {} cannot be taken: {e}", data_dir.display())
        }
    }
}

/// The free room on the volume that holds `folder`, in bytes, as far as
/// whoever runs the node may use it: what the copy of the database at a
/// first start is compared with before it is begun (decision 2026-10-04
/// §10.1). None where it cannot be learned.
fn room_on_volume(folder: &std::path::Path) -> Option<u64> {
    #[cfg(unix)]
    {
        let volume = rustix::fs::statvfs(folder).ok()?;
        Some(volume.f_bavail.saturating_mul(volume.f_frsize))
    }
    #[cfg(not(unix))]
    {
        let _ = folder;
        None
    }
}

fn cmd_start(config_path: &str) -> anyhow::Result<()> {
    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file)?;
    config.apply_env_overrides();
    let data_dir = config.data_dir();

    // Logging is set up before anything else is done, so that what the
    // schema's steps say when the database is opened is in the log.
    init_tracing(&config.logging.level);

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

    // The API listens only on this machine.
    let bind_addr = &config.api.bind_address;
    let Some(host) = api_host(bind_addr) else {
        anyhow::bail!("{}", not_the_nodes_own(bind_addr));
    };

    let http_port = config.node.http_port;
    let listen_addr = format!("{host}:{http_port}");
    let p2p_port = config.node.p2p_port;

    // The port of the local API is bound before the database is opened,
    // and so before anything is written (decision 2026-10-04 §10.1): a
    // node that cannot bind, because another is running, changes
    // nothing.
    let api_listener = std::net::TcpListener::bind(&listen_addr)
        .map_err(|e| anyhow::anyhow!("the node's API cannot listen at {listen_addr}: {e}"))?;

    // A data directory is one node's (decision 2026-10-04 §10.1): the
    // lock on it is taken before the database is opened, and is held for
    // as long as the process lives. A second node on the same directory,
    // whatever port it was given, says so here and changes nothing.
    let _one_node = lock_data_dir(&data_dir)?;

    // Open database. One from a later version is refused (decision
    // 2026-10-04 §10.1). A personal node then stays up, over a database
    // of its own in memory, and says so in its status: nothing of the
    // one on disk is read or changed, and under a service that restarts
    // what stops, stopping would be a loop. A node of any other role
    // carries what other nodes hand it, and does not start without its
    // database: it says why, and stops.
    let db_path = data_dir.join("cordelia.db");
    let (conn, later) = match cordelia_storage::db::open(&db_path) {
        Ok(conn) => (conn, None),
        Err(cordelia_storage::StorageError::LaterVersion { found, own }) => {
            let why = from_a_later_version(&db_path, found, own);
            if config.network.role != "personal" {
                anyhow::bail!("{why}");
            }
            (cordelia_storage::db::open_in_memory()?, Some(why))
        }
        Err(e) => return Err(e.into()),
    };

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

    // A personal node writes nothing of the older kind of channel: what
    // it holds of that kind goes at its first start on this version,
    // below. A node of any other role goes on carrying that kind.
    let personal = config.network.role == "personal";
    if !personal {
        // A node makes no channel that it does not use. Up to
        // 0.2.0-alpha.7 a node made a swarm channel for itself each time
        // it started, and v1 uses none. Any that this node holds is
        // removed, with its key and whatever it holds. Its ID holds a
        // name, so the log says how many went and does not say which.
        let removed = cordelia_storage::channels::remove_swarm_channels(&conn, &data_dir)?;
        if removed.any() {
            tracing::info!(
                channels = removed.channels,
                items = removed.items,
                key_files = removed.key_files,
                "removed swarm channels, which this version does not use"
            );
        }
        // A key file that could not be removed is no reason not to start.
        // The node says how many, and tries again the next time it starts.
        if removed.key_files_left > 0 {
            tracing::warn!(
                key_files = removed.key_files_left,
                "could not remove every key file of a swarm channel; they are left, and the node starts"
            );
        }
        // The guard against a new channel of the older kind is a
        // device's. A node of this role that is started on a database
        // which a personal node moved on removes it (decision 2026-10-04
        // §10.1).
        if cordelia_storage::first_start::remove_guard(&conn)? {
            tracing::info!(
                "removed the guard that a personal node set on this database: a node of this \
                 role takes channels of the older kind"
            );
        }
    }

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
        own_channels: Default::default(),
        held: Default::default(),
        history: Default::default(),
    });

    // A personal node makes its first start on this version here
    // (decision 2026-10-04 §10.1): after the port of its local API is
    // bound, before its sync loop and its first pass are started, and
    // before anything else is written. Where a copy of the database is
    // to be made, the node is held up here and the copy is made by the
    // first turn of its sync loop, which runs no cycle before the step
    // has succeeded: its server answers meanwhile, and its status says
    // that a copy is being made. A relay and a bootnode make no copy and
    // take no step: their databases are stepped as any version steps
    // them, at the opening.
    //
    // A node whose database is from a later version makes none: it is
    // held up for as long as it runs, and touches nothing.
    match &later {
        Some(why) => {
            tracing::error!("{why}");
            state
                .held
                .hold(cordelia_api::state::Held::LaterDatabase(why.clone()));
        }
        None if personal => {
            cordelia_api::first_start::take_at_start(&state, version, &room_on_volume);
        }
        None => {}
    }

    // A personal node keeps local history of what sync replaces. It holds
    // no channel of the older kind: no inbox is made for it, and nothing
    // of that kind is read (decision 2026-10-04 §10).
    if personal && later.is_none() {
        start_history(&state, &config.history);
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
        // 2026-09-30 §4.6); none for a bootnode. The P2P loop dials them
        // and keeps trying the ones that are not connected, so starting
        // never waits on a relay that is unreachable.
        let configured: Vec<(String, Option<String>)> = config
            .network
            .bootnodes
            .iter()
            .map(|b| (b.addr.clone(), b.key.clone()))
            .collect();
        let relays =
            cordelia_network::bootstrap::relays_dialled(&config.network.role, &configured)
                .map_err(|e| anyhow::anyhow!("network.bootnodes: {e}"))?;
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
            // The stored scope is off whenever sync is on (decision
            // 2026-10-04 §10.1): it is written so at every start with
            // sync on. Nothing is written of the settings while the
            // first start is still to be made: the step reads the scope
            // as it is stored, and writes it off itself.
            if state.held.why().is_none() {
                scope_off(&state);
            }
            tokio::spawn(run_sync_loop(state.clone()));
        }

        // Relays are configured by name, so the names are resolved again
        // while the node runs, not only at startup.
        let relay_addrs = p2p::RelayAddrs::default();
        // The relays as the configuration names them, whether or not a
        // name resolves: what the node is set up with.
        let relays_set_up = relays.clone();
        if !relays.is_empty() {
            tokio::spawn(p2p::keep_relays_resolved(relays, relay_addrs.clone()));
        }

        let p2p_handle = tokio::spawn(async move {
            p2p::p2p_loop(conn_mgr, p2p_state, push_rx, announce_rx, &mut p2p_shutdown_rx, allow_private, role_for_p2p, config.governor.clone(), relays_set_up, relay_addrs, trusted_peer_ids, config.node.max_storage_bytes, std::time::Duration::from_secs(config.replication.relay_ask_again_secs.clamp(1, 86_400))).await;
        });

        // ── HTTP API ───────────────────────────────────────────────
        // A personal node serves the local API of a device, and no
        // Channels API of the older kind (decision 2026-10-04 §10).
        let serves_a_device = config.network.role == "personal";
        let server = HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .configure(match serves_a_device {
                    true => cordelia_api::configure_device_routes,
                    false => cordelia_api::configure_routes,
                })
        })
        // On the port that was bound before anything was written.
        .listen(api_listener)?
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

// ── Local history ──────────────────────────────────────────────────

/// Set up local history as the configuration has it (decision 2026-09-30
/// §4.5b). Turned off, what was kept is removed. Otherwise the records
/// that were pending when the node last stopped are marked, and what is
/// too old or over the size is dropped.
///
/// A store that cannot be prepared is still set: it keeps nothing, so the
/// sync adapter makes no change that needs a text kept, and says why.
fn start_history(state: &cordelia_api::state::AppState, config: &config::HistoryConfig) {
    use cordelia_storage::history::{Start, Store};
    let now = chrono::Utc::now();
    let (store, interrupted, swept) = match Store::start(
        &state.home_dir,
        config.days,
        config.max_bytes,
        now,
    ) {
        Start::Off(removed) => {
            match removed {
                Ok(()) => tracing::info!("history: turned off"),
                Err(e) => {
                    tracing::warn!(error = %e, "history: turned off, but what was kept could not be removed")
                }
            }
            return;
        }
        Start::On {
            store,
            interrupted,
            swept,
        } => (store, interrupted, swept),
    };
    match interrupted {
        Ok(0) => {}
        Ok(interrupted) => tracing::warn!(
            records = interrupted,
            "history: the node stopped part-way through these changes; their texts are kept"
        ),
        Err(e) => {
            tracing::error!(error = %e, "history: cannot be written; sync replaces nothing until it can")
        }
    }
    match swept {
        Ok(swept) if swept.aged + swept.over > 0 => tracing::info!(
            aged = swept.aged,
            over = swept.over,
            "history: dropped old records"
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "history: could not drop old records"),
    }
    state.history.open(Some(store));
}

// ── Sync adapter loop ──────────────────────────────────────────────

/// The one adapter the sync loop holds: the one in `slot` while `is_for`
/// says it is for the Claude Code directory that is set, and otherwise a
/// new one from `make`, in its place.
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

/// What is done once in every `every`: when it was last due, or when the
/// count began.
struct Every {
    since: std::time::Instant,
    every: std::time::Duration,
}

impl Every {
    fn from(since: std::time::Instant, every: std::time::Duration) -> Self {
        Self { since, every }
    }

    /// Whether it is due at `now`: `every` has passed since it last was.
    /// Asked again before another has passed, it is not.
    fn is_due(&mut self, now: std::time::Instant) -> bool {
        let due = now.duration_since(self.since) >= self.every;
        if due {
            self.since = now;
        }
        due
    }
}

/// Write the stored scope off, where sync is on and it is not stored so
/// ([`cordelia_api::sync::scope_off_at_start`]): what a personal node
/// does when it starts, once its first start on this version is done.
fn scope_off(state: &cordelia_api::state::AppState) {
    if let Err(e) = cordelia_api::sync::scope_off_at_start(state) {
        tracing::warn!(error = %e, "sync: could not write the stored scope off");
    }
}

/// Whether the node may run a cycle now (decision 2026-10-04 §10.1). A
/// node whose first start on this version is not done runs none: it
/// tries the first start again when a cycle would have run, after a wait
/// that doubles with each try that fails, and goes on only once that is
/// done. A node whose database is from a later version runs none for as
/// long as it runs.
fn may_cycle(state: &cordelia_api::state::AppState) -> bool {
    use cordelia_api::state::Held;
    match state.held.why() {
        None => true,
        Some(Held::FirstStart(_)) => {
            let done =
                cordelia_api::first_start::take(state, env!("CARGO_PKG_VERSION"), &room_on_volume);
            // The start that was held up is made now: the scope is
            // written off as at any start with sync on.
            if done {
                scope_off(state);
            }
            done
        }
        // Nothing is tried on a database from a later version.
        Some(Held::LaterDatabase(_)) => false,
    }
}

/// Every `CYCLE_SECS`, and as soon as a sync setting changes, run one
/// adapter cycle (if sync is on) off the async runtime, and store its
/// report for `cordelia sync status`. Once in every
/// `HISTORY_SWEEP_INTERVAL_SECS` it sweeps local history first.
///
/// A node that is held up runs no cycle ([`may_cycle`]).
async fn run_sync_loop(state: web::Data<cordelia_api::state::AppState>) {
    use cordelia_storage::meta;
    use cordelia_sync::claude::ClaudeAdapter;

    let adapter: std::sync::Arc<Mutex<Option<ClaudeAdapter>>> =
        std::sync::Arc::new(Mutex::new(None));
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        cordelia_sync::claude::CYCLE_SECS,
    ));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut sweep = Every::from(
        std::time::Instant::now(),
        std::time::Duration::from_secs(cordelia_core::protocol::HISTORY_SWEEP_INTERVAL_SECS),
    );

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = state.sync_control.woken() => {}
        }
        let state = state.clone();
        let adapter = adapter.clone();
        let sweep = sweep.is_due(std::time::Instant::now());
        // Each turn of the loop is counted as it begins and as it ends,
        // whether or not sync is on: a command that asks for a cycle
        // waits for one that began after it asked (decision 2026-10-04
        // §7.1, step 1).
        let cycle = state.sync_control.cycle_begins();
        let counted = state.clone();
        // Whether the turn went to its end: a cycle that stopped where
        // the settings changed under it, or that could not be run, did
        // not, and a command that waited for it is told so (decision
        // 2026-10-04 §7.1, step 1).
        let to_its_end = tokio::task::spawn_blocking(move || {
            // In its own turn, whether or not sync is on: history ages
            // either way.
            if sweep {
                state.history.sweep(chrono::Utc::now());
            }
            if !may_cycle(&state) {
                return false;
            }
            let (dir, generation) = match state.db.lock() {
                Ok(db) => (
                    meta::get(&db, meta::SYNC_CLAUDE_DIR).ok().flatten(),
                    state.sync_control.generation_under(&db),
                ),
                Err(_) => return false,
            };
            let Ok(mut slot) = adapter.lock() else {
                return false;
            };
            let Some(dir) = dir else {
                // Sync was just turned off: this person's other devices
                // stop listing what this one synced. If the settings
                // change under it, the adapter is kept, and the next turn
                // looks again.
                if slot.is_some() {
                    match cordelia_sync::claude::withdraw(&state, generation) {
                        Ok(false) => return false,
                        Ok(true) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "sync: could not withdraw this device's names");
                        }
                    }
                    *slot = None;
                }
                return true;
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
            !report.stopped
        })
        .await
        .unwrap_or(false);
        if !to_its_end {
            counted.sync_control.cycle_was_cut_short(cycle);
        }
        counted.sync_control.cycle_ended(cycle);
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
    let conn = open_database(&db_path)?;

    // A personal node carries no channel of the older kind (decision
    // 2026-10-04 §10): what it has is the names that it holds, each with
    // its channel from the person's secret. Nothing of the older kind is
    // read.
    if config.network.role == "personal" {
        for line in names_held(&conn)? {
            println!("{line}");
        }
        return Ok(());
    }

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

/// What `cordelia channels` says on a personal node: the names that the
/// device holds, each with how many entries it stores of the name's
/// channel and when it stored the last; or, where it holds none, the way
/// to hold one.
fn names_held(conn: &rusqlite::Connection) -> anyhow::Result<Vec<String>> {
    let names = cordelia_storage::person::names(conn)?;
    if names.is_empty() {
        return Ok(vec![
            "No names. A device holds a name once it follows a recovery phrase and a folder \
             is mapped to it (`cordelia sync map <folder> <name>`)."
                .to_string(),
        ]);
    }
    let mut lines = vec![format!("{:<40} {:>8}   LAST STORED", "NAME", "ENTRIES")];
    for held in names {
        let (entries, last) = cordelia_storage::usage::stored_of_channel(conn, &held.channel)?;
        let last = last
            .and_then(|at| chrono::DateTime::from_timestamp(at, 0))
            .map_or_else(|| "-".to_string(), |at| at.to_rfc3339());
        lines.push(format!("{:<40} {:>8}   {last}", held.name, entries));
    }
    Ok(lines)
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
    let conn = open_database(&db_path)?;

    let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
    // A personal node carries no channel of the older kind (decision
    // 2026-10-04 §10): its channels are the names it holds, and what it
    // stores is the entries of its own channels. Nothing of the older
    // kind is read.
    let personal = config.network.role == "personal";
    let now = chrono::Utc::now().timestamp();
    let (channels, usage) = match personal {
        true => (
            cordelia_storage::person::names(&conn)?.len(),
            cordelia_storage::usage::snapshot_of_a_device(&conn, now)?,
        ),
        false => (
            cordelia_storage::channels::list_for_entity(&conn, &pk)?.len(),
            cordelia_storage::usage::snapshot(&conn, now)?,
        ),
    };
    // What a relay's storage cap counts, and the cap: what its items are
    // counted at, each its content and what an entry takes beyond it. It
    // falls when a channel is dropped (the file does not shrink).
    let used = cordelia_storage::items::stored_cost(&conn)?;
    let cap = config.node.max_storage_bytes;
    // What a node that carries both kinds holds of the channels from
    // their secrets: they are counted apart, by what their entries are
    // counted at, against a cap of their own of the same size (decision
    // 2026-10-04 §2.5). An operator sees the room of each kind.
    let of_entries = match personal {
        true => None,
        false => {
            let (entries, content_bytes) = cordelia_storage::usage::stored_of_own(&conn)?;
            Some(EntriesHeld {
                used: cordelia_storage::relay::used_bytes(&conn)?,
                channels: cordelia_storage::relay::count_held(&conn)?,
                entries,
                content_bytes,
            })
        }
    };

    if json {
        let mut out = serde_json::json!({
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
        if let Some(held) = &of_entries {
            out["entries"] = serde_json::json!({
                "storage_used_bytes": held.used,
                "storage_max_bytes": cap,
                "channels_held": held.channels,
                "entries_stored": held.entries,
                "content_bytes_stored": held.content_bytes,
            });
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("Database:         {}", format_bytes(db_size));
    if config.network.role == "relay" {
        for line in storage_lines(used, cap, of_entries.as_ref()) {
            println!("{line}");
        }
    }
    println!(
        "Stored:           {} {}, {} of encrypted content",
        usage.items_stored,
        if personal { "entries" } else { "items" },
        format_bytes(usage.bytes_stored)
    );
    match personal {
        true => println!("Names:            {channels} held"),
        false => println!("Channels:         {channels} subscribed"),
    }
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

/// What a node that carries both kinds of channel holds of the channels
/// from their secrets (decision 2026-10-04 §2.5).
struct EntriesHeld {
    /// What its entries are counted at: what this kind's cap is set
    /// against.
    used: u64,
    /// How many channels it holds.
    channels: u64,
    /// How many entries, and the bytes of their content.
    entries: u64,
    content_bytes: u64,
}

/// What `cordelia stats` says of a relay's room: each kind of channel
/// against its cap, which is of one size for both (decision 2026-10-04
/// §2.5). `used` is what the older kind holds.
fn storage_lines(used: u64, cap: u64, of_entries: Option<&EntriesHeld>) -> Vec<String> {
    let mut lines = vec![format!(
        "Storage:          {} in use of {} allowed, by channels of the older kind",
        format_bytes(used),
        format_bytes(cap)
    )];
    if let Some(held) = of_entries {
        lines.push(format!(
            "                  {} in use of {} allowed, by channels from their secrets ({} held, \
             {} {})",
            format_bytes(held.used),
            format_bytes(cap),
            held.channels,
            held.entries,
            if held.entries == 1 {
                "entry"
            } else {
                "entries"
            },
        ));
    }
    lines
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

/// What `cordelia swarm-init` says where the node's role is `personal`.
const NO_SWARM_ON_A_PERSONAL_NODE: &str = "a personal node carries no swarm channel in this \
    version, and nothing was set up. A device's channels come from its recovery phrase: \
    `cordelia phrase` on the first device, and `cordelia add-device` and `cordelia accept` \
    for each one after.";

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

    // A personal node carries no channel of the older kind (decision
    // 2026-10-04 §10), and a swarm channel is one: this command would
    // write rows and key files that such a node never reads, and that
    // its first start on this version copies and removes. It is refused
    // there, before anything is written.
    if config.network.role == "personal" {
        anyhow::bail!(NO_SWARM_ON_A_PERSONAL_NODE);
    }

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
    // The database is opened before anything is written: one from a
    // later version is refused, and nothing is changed (decision
    // 2026-10-04 §10.1).
    let db_path = data_dir.join("cordelia.db");
    let conn = open_database(&db_path)?;
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

/// A project's name in its one spelling: as a name's channel is made
/// from it, and as a project is found from its remote.
fn normalise_project(project: &str) -> String {
    cordelia_core::sync_name::tidy(project)
}

/// The name `map` was given, as it is sent to the node. A shell hands an
/// unquoted `~` over as the home directory's path, in whatever spelling
/// `$HOME` has (it may reach the directory through a link), so that path
/// is taken for `~`.
fn name_given(typed: &str, home_dir: &std::path::Path) -> String {
    let typed = typed.trim();
    let path = std::path::Path::new(typed);
    let is_home = path == home_dir
        || (path.is_absolute() && std::fs::canonicalize(path).is_ok_and(|real| real == home_dir));
    if is_home {
        cordelia_sync::claude::HOME_NAME.to_string()
    } else {
        normalise_project(typed)
    }
}

/// Whether the name `map` was given is the name the folder is mapped
/// under: none was given, or it is that name as it would be sent, or it
/// is that name as it is stored. (A name stored by an earlier version can
/// end in `.git`, which is taken off a name that is sent.)
fn is_the_name_it_has(typed: Option<&str>, home_dir: &std::path::Path, mapped: &str) -> bool {
    typed.is_none_or(|typed| {
        name_given(typed, home_dir) == mapped || typed.trim().to_lowercase() == mapped
    })
}

/// What `map` offers when the home directory is named with a name and
/// without `--home`: the command that was typed, with the flag.
///
/// - The name `~`, however a shell handed it over (see [`name_given`]):
///   `map` with the flag and no name, which is `~`.
/// - A name home memory can take: `map` with the flag and the name as it
///   was typed, quoted for a shell where it needs to be. Run, it maps
///   home under the name the typed command would have.
/// - Anything else is `Err`, with the name as typed: it is said to be
///   unusable, and no name is offered in its place.
fn home_offer(typed: &str, home_dir: &std::path::Path) -> Result<String, String> {
    let typed = typed.trim();
    let sent = name_given(typed, home_dir);
    if sent == cordelia_sync::claude::HOME_NAME {
        Ok("cordelia sync map ~ --home".to_string())
    } else if cordelia_api::sync::valid_sync_name(&sent) {
        Ok(format!("cordelia sync map ~ {} --home", shell_word(typed)))
    } else {
        Err(typed.to_string())
    }
}

/// The mapping a word names, if it names one: by the name as it is
/// stored, or else in its one spelling. (An earlier version could store a
/// name that ends in `.git`, which the one spelling takes off. Where one
/// mapping is stored as `x.git` and another as `x`, `x.git` names the
/// first.)
///
/// A word that ends in `/` is a folder, as a shell completes one, and
/// names no mapping.
fn mapping_named<'a>(mappings: &'a [(String, String)], word: &str) -> Option<&'a (String, String)> {
    let word = word.trim();
    if word.ends_with('/') {
        return None;
    }
    let as_stored = word.to_lowercase();
    let as_name = normalise_project(word);
    [as_stored, as_name]
        .iter()
        .find_map(|spelt| mappings.iter().find(|(_, name)| name == spelt))
}

/// The mapping of a folder, given the folder's spellings in the order
/// they are meant: the first spelling that is a mapping's folder decides.
/// So a folder that is mapped is found before the repository it is in,
/// whichever of the two was mapped first.
fn mapping_at<'a>(
    mappings: &'a [(String, String)],
    spellings: &[String],
) -> Option<&'a (String, String)> {
    spellings
        .iter()
        .find_map(|spelt| mappings.iter().find(|(folder, _)| folder == spelt))
}

/// The mappings as the node's own check takes them.
fn as_mappings(mappings: &[(String, String)]) -> Vec<cordelia_api::types::SyncMapping> {
    mappings
        .iter()
        .map(|(folder, name)| cordelia_api::types::SyncMapping {
            folder: folder.clone(),
            name: name.clone(),
        })
        .collect()
}

/// What a refusal of `map` says about syncing home memory, where no name
/// was given for it: `home on`, which puts home memory back under the name
/// it last had on this device, if the node would take that; and how to map
/// it under a name if it would not (another folder has that name now).
fn home_on_offer(
    last_name: Option<&str>,
    home_dir: &std::path::Path,
    mappings: &[(String, String)],
) -> String {
    let name = last_name.unwrap_or(cordelia_sync::claude::HOME_NAME);
    let request = cordelia_api::types::SyncMapRequest {
        folder: home_dir.display().to_string(),
        name: name.to_string(),
        home: true,
    };
    match cordelia_api::sync::check_mapping(&request, home_dir, &as_mappings(mappings)) {
        Ok(_) => "To sync home memory: cordelia sync home on".to_string(),
        Err(why) => format!(
            "Home memory cannot be put back as {} ({why}). To sync it under a name: \
             cordelia sync map ~ <name> --home",
            sync_label(name)
        ),
    }
}

/// What `map` does about a folder that is not already mapped as asked.
#[derive(Debug, PartialEq)]
enum MapStep {
    /// Ask the node. It takes the request, or refuses it for a reason
    /// that unmapping the folder would not change.
    Send,
    /// The folder is mapped under another name, and nothing else stands
    /// in the way: unmapping it first is the way.
    UnmapFirst(String),
}

/// Whether to advise an unmap. `request` is what would be sent, and
/// `mappings` what the node holds.
///
/// Unmapping is not free: the folder stops syncing, and forgets what it
/// agreed. So it is advised only when the request would be taken
/// once the folder was unmapped, which is asked of the node's own check
/// (`cordelia_api::sync::check_mapping`) with the folder's mapping left
/// out. A request that would be refused anyway is sent, and the node says
/// why.
fn map_step(
    request: &cordelia_api::types::SyncMapRequest,
    home_dir: &std::path::Path,
    mappings: &[(String, String)],
) -> MapStep {
    let Some((_, mapped)) = mappings
        .iter()
        .find(|(folder, _)| *folder == request.folder)
    else {
        return MapStep::Send;
    };
    let others: Vec<(String, String)> = mappings
        .iter()
        .filter(|(folder, _)| *folder != request.folder)
        .cloned()
        .collect();
    match cordelia_api::sync::check_mapping(request, home_dir, &as_mappings(&others)) {
        Ok(_) => MapStep::UnmapFirst(mapped.clone()),
        Err(_) => MapStep::Send,
    }
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

/// The host of the node's API as it is written before a port, where
/// `address` is one of the two that the API may have: `127.0.0.1`, or
/// `::1`, which is written in brackets there. `None` for anything else.
/// The node starts with no other, and a command asks no other.
///
/// Only those two, written so. A name is not taken, `localhost` included:
/// what a name stands for is the resolver's answer, and whatever then
/// binds or connects asks for it again. Where that answer was another
/// machine, the node's token would go there.
fn api_host(address: &str) -> Option<&'static str> {
    match address {
        "127.0.0.1" => Some("127.0.0.1"),
        "::1" => Some("[::1]"),
        _ => None,
    }
}

/// What is said of an API address that [`api_host`] does not take: by the
/// node, which does not start, and by a command, which does not ask. It
/// names the address, the two it may be, and where it is set.
fn not_the_nodes_own(address: &str) -> String {
    // The one value that an earlier version took and this one does not.
    let was_taken = match address {
        "localhost" => " (Up to 0.2.0-alpha.6 the name `localhost` was taken: write `127.0.0.1`.)",
        _ => "",
    };
    format!(
        "the node's API address is set to '{address}', which is neither `127.0.0.1` nor \
         `::1`, written so.{was_taken} The API of a node of this version listens at one of \
         those two and at no other, and a command sends the node's token nowhere else. See \
         `bind_address` under `[api]` in the configuration, and CORDELIA_BIND_ADDRESS."
    )
}

/// How a command reaches its own node: the client, which waits for an
/// answer for `limit` or, with none, for as long as it takes, and the
/// address of `path` there. A request carries the node's token, so it goes to the
/// node's own address and nowhere else:
///
/// - **To no other address.** The node's API listens at one of two
///   addresses of this machine ([`api_host`]). An API address that a
///   setting, or `CORDELIA_BIND_ADDRESS`, has made another is refused
///   here, before anything is sent.
/// - **Through no proxy.** The HTTP client's default takes one from the
///   environment (`ALL_PROXY`, `HTTP_PROXY` and the rest). A proxy is for
///   the network, and a request to this machine is not sent to one.
/// - **Following no redirect.** The node's API sends none, so an answer
///   that is one did not come from the node. It is not followed, and
///   [`local_api`] and [`api_post`] do not read it as the node's.
fn to_this_machine(
    config: &Config,
    path: &str,
    limit: Option<std::time::Duration>,
) -> anyhow::Result<(
    ureq::config::ConfigBuilder<ureq::typestate::AgentScope>,
    String,
)> {
    let address = &config.api.bind_address;
    let host = api_host(address).ok_or_else(|| anyhow::anyhow!(not_the_nodes_own(address)))?;
    let client = ureq::Agent::config_builder()
        .proxy(None)
        .max_redirects(0)
        .timeout_global(limit);
    let url = format!("http://{host}:{}{path}", config.node.http_port);
    Ok((client, url))
}

/// Call the running node's local API (GET, or POST with an empty body)
/// with the node token, failing after `timeout`.
fn local_api(
    config: &Config,
    post: bool,
    path: &str,
    timeout: std::time::Duration,
) -> anyhow::Result<serde_json::Value> {
    let (client, url) = to_this_machine(config, path, Some(timeout))?;
    let token = std::fs::read_to_string(config.token_path())?;
    let agent: ureq::Agent = client.build().into();
    let auth = format!("Bearer {}", token.trim());
    let resp = if post {
        agent
            .post(&url)
            .header("Authorization", &auth)
            .send_json(serde_json::json!({}))
    } else {
        agent.get(&url).header("Authorization", &auth).call()
    };
    let mut resp = resp.map_err(|e| {
        anyhow::anyhow!(
            "cannot reach the local node at {url} ({e}). Start it with `cordelia start`."
        )
    })?;
    // A failure is an error already. What is left that is no success is
    // an answer the node's API never gives (a redirect, say).
    if !resp.status().is_success() {
        anyhow::bail!(
            "what answered at {url} is not the node (HTTP {})",
            resp.status()
        );
    }
    Ok(resp.body_mut().read_json()?)
}

/// POST `body` to the local node's API and return the JSON response.
fn api_post(
    config_path: &str,
    path: &str,
    body: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    api_post_within(
        config_path,
        path,
        body,
        Some(std::time::Duration::from_secs(30)),
    )
}

/// How long a command that waits without a limit waits before it says so:
/// a little longer than the node waits for its turn before it answers
/// that it is busy, so that the answer comes first, and this is not said
/// a moment ahead of it. (The command's wait begins before the request is
/// sent, and the node's when it takes the request up.) A wait longer
/// than this is for work the node has begun.
const STILL_WAITING_AFTER: std::time::Duration =
    std::time::Duration::from_secs(cordelia_core::protocol::HISTORY_TURN_WAIT_SECS + 2);

/// When a command that waits for the node says that it is still waiting:
/// only where it waits with no limit of its own, and then once
/// [`STILL_WAITING_AFTER`] is up.
fn said_after(limit: Option<std::time::Duration>) -> Option<std::time::Duration> {
    limit.is_none().then_some(STILL_WAITING_AFTER)
}

/// Run `say` if nothing has come on `done`, and its other end is still
/// held, when `wait` is up. The other end is dropped when the node has
/// answered.
fn say_if_not_done(
    done: std::sync::mpsc::Receiver<()>,
    wait: std::time::Duration,
    say: impl FnOnce(),
) {
    if done.recv_timeout(wait) == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
        say();
    }
}

/// Do `work`, and run `say` once, from another thread, if it is still
/// going when `wait` is up. With no `wait` nothing is said: `say` is let
/// go of before the work begins.
fn saying_if_long<T>(
    wait: Option<std::time::Duration>,
    say: impl FnOnce() + Send + 'static,
    work: impl FnOnce() -> T,
) -> T {
    let (answered, done) = std::sync::mpsc::channel::<()>();
    match wait {
        Some(wait) => {
            std::thread::spawn(move || say_if_not_done(done, wait, say));
        }
        None => drop(say),
    }
    let out = work();
    drop(answered);
    out
}

/// What a command says while it waits for the node with no limit. A
/// person who sees nothing may interrupt it, and that takes nothing back.
fn still_waiting() {
    eprintln!(
        "Still waiting for the node, which finishes what it has begun. Interrupting this \
         command does not take back what it asked for: `cordelia history` shows what was done."
    );
}

/// [`api_post`], waiting for the answer for `limit`, or for as long as it
/// takes: what the node carries out to the end whether or not anyone
/// waits (a restore) is waited for, so that the command says what it did.
/// With no limit it says, once, that it is still waiting.
fn api_post_within(
    config_path: &str,
    path: &str,
    body: serde_json::Value,
    limit: Option<std::time::Duration>,
) -> anyhow::Result<serde_json::Value> {
    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file)?;
    config.apply_env_overrides();

    let (client, url) = to_this_machine(&config, path, limit)?;
    let token_path = config.token_path();
    let token = std::fs::read_to_string(&token_path).map_err(|e| {
        anyhow::anyhow!(
            "read node token {}: {e}. Run `cordelia init` first.",
            token_path.display()
        )
    })?;

    let agent: ureq::Agent = client.http_status_as_error(false).build().into();
    let sent = saying_if_long(said_after(limit), still_waiting, || {
        agent
            .post(&url)
            .header("Authorization", &format!("Bearer {}", token.trim()))
            .send_json(&body)
    });
    let mut resp = sent.map_err(|e| {
        anyhow::anyhow!(
            "cannot reach the local node at {url} ({e}). Start it with `cordelia start`."
        )
    })?;

    let status = resp.status();
    // A redirect did not come from the node: nothing of it is read.
    if status.is_redirection() {
        anyhow::bail!("what answered at {url} is not the node (HTTP {status})");
    }
    let json: serde_json::Value = resp
        .body_mut()
        .read_json()
        .unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        let mut message = json["error"]["message"]
            .as_str()
            .map(|m| m.strip_prefix("bad request: ").unwrap_or(m).to_string())
            .unwrap_or_else(|| format!("HTTP {status}"));
        // A node goes on running the version it was started as until it
        // is restarted. A refusal may then mean only that the node is
        // another version than this command.
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

/// What the node answered a command.
pub(crate) enum Told {
    /// It did what was asked, and says this.
    Yes(serde_json::Value),
    /// It refused: the HTTP status, and why, in its words.
    No { status: u16, message: String },
}

/// POST `body` to the local node's API, waiting for `limit`, and give
/// back what it answered, a refusal among it: for a command that does
/// something else where the node refuses for one reason than where it
/// refuses for another. A node that is not reached, or an answer that is
/// not the node's, is an error.
pub(crate) fn api_post_told(
    config_path: &str,
    path: &str,
    body: serde_json::Value,
    limit: Option<std::time::Duration>,
) -> anyhow::Result<Told> {
    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file)?;
    config.apply_env_overrides();
    let (client, url) = to_this_machine(&config, path, limit)?;
    let token_path = config.token_path();
    let token = std::fs::read_to_string(&token_path).map_err(|e| {
        anyhow::anyhow!(
            "read node token {}: {e}. Run `cordelia init` first.",
            token_path.display()
        )
    })?;
    let agent: ureq::Agent = client.http_status_as_error(false).build().into();
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
    if status.is_redirection() {
        anyhow::bail!("what answered at {url} is not the node (HTTP {status})");
    }
    let json: serde_json::Value = resp
        .body_mut()
        .read_json()
        .unwrap_or(serde_json::Value::Null);
    if status.is_success() {
        return Ok(Told::Yes(json));
    }
    let message = json["error"]["message"]
        .as_str()
        .map(|said| {
            let said = said.strip_prefix("bad request: ").unwrap_or(said);
            said.strip_prefix("conflict: ").unwrap_or(said).to_string()
        })
        .unwrap_or_else(|| format!("HTTP {status}"));
    Ok(Told::No {
        status: status.as_u16(),
        message,
    })
}

/// Set once this command has said that the node is another version, so that
/// it is not said again beside a refusal.
static VERSION_NOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The running node's status, as it answers a command that asks within
/// `timeout`, or why it could not be had.
fn node_status(
    config_path: &str,
    timeout: std::time::Duration,
) -> anyhow::Result<serde_json::Value> {
    let mut config = Config::load(&config::expand_tilde(config_path))?;
    config.apply_env_overrides();
    local_api(&config, false, "/api/v1/status", timeout)
}

/// What to say about the running node, if it answers and is not the version
/// this command is.
fn node_version_note(config_path: &str) -> Option<String> {
    let node = node_status(config_path, std::time::Duration::from_secs(3)).ok()?;
    version_note(node["version"].as_str(), env!("CARGO_PKG_VERSION"))
}

/// What a command that changes anything says of a node of another
/// version, after the note that says how to restart it.
const NOT_SENT_TO_ANOTHER_VERSION: &str = "This command changes something, and is not sent to a \
                                           node of another version: nothing was done.";

/// What a command that changes anything says where the node did not say
/// which version it is, after why.
const VERSION_NOT_LEARNED: &str = "The running node's version could not be learned. This command \
                                   changes something, and is sent only to a node of its own \
                                   version: nothing was done.";

/// What a command that makes or asks for a recovery phrase says of a
/// node that is held up, after why the node is.
const NOT_WHILE_HELD_UP: &str = "The node is held up, and would refuse what this command hands \
                                 it in the end: no recovery phrase was shown or asked for, and \
                                 nothing was done.";

/// How long a command that changes something waits for the node to say
/// which version it is: as long as it waits for the node to do what it
/// asks. A node that is busy answers late, and is not taken for one that
/// does not answer.
const VERSION_ASKED_FOR: std::time::Duration = std::time::Duration::from_secs(30);

/// Refuse a running node of another version than this command (decision
/// 2026-10-04 §10.1, rule 6; §16). A command that changes anything is
/// sent only to a node of its own version: a route of the same name may
/// mean another thing in another. The refusal is the note that says how
/// to restart the node.
///
/// The commands that change something are every `sync` command but
/// `status` (its `--seen` included) and `off`, `restore`, `history
/// drop`, `init --new-key`, and
/// each command of a person's devices but `devices` with no act. Turning
/// sync off is sent to any node, and what only shows is answered beside
/// one, with the note ([`note_another_version`]).
///
/// **Where the node's version could not be learned, the command is
/// refused too:** the node did not answer, or what answered was no
/// status. A command that changes something is not sent to a node that
/// may be of any version.
pub(crate) fn refuse_another_version(config_path: &str) -> anyhow::Result<()> {
    refuse_by_version(&node_status(config_path, VERSION_ASKED_FOR))
}

/// [`refuse_another_version`], given what the node answered when it was
/// asked its status.
fn refuse_by_version(status: &anyhow::Result<serde_json::Value>) -> anyhow::Result<()> {
    let node = match status {
        Ok(node) => node,
        Err(why) => anyhow::bail!("{why}\n{VERSION_NOT_LEARNED}"),
    };
    match version_note(node["version"].as_str(), env!("CARGO_PKG_VERSION")) {
        None => Ok(()),
        Some(note) => {
            VERSION_NOTED.store(true, std::sync::atomic::Ordering::Relaxed);
            anyhow::bail!("{note}\n{NOT_SENT_TO_ANOTHER_VERSION}")
        }
    }
}

/// [`refuse_another_version`], and then refuse a node that is held up:
/// for a command that makes, shows or asks for a recovery phrase
/// (decision 2026-10-04 §10.1). A node that is held up refuses what such
/// a command hands it in the end, so the command asks how the node stands
/// first: no word of a phrase is shown, and none is asked for, where the
/// node would then refuse.
pub(crate) fn refuse_before_a_phrase(config_path: &str) -> anyhow::Result<()> {
    refuse_by_how_it_stands(&node_status(config_path, VERSION_ASKED_FOR))
}

/// [`refuse_before_a_phrase`], given what the node answered when it was
/// asked its status.
fn refuse_by_how_it_stands(status: &anyhow::Result<serde_json::Value>) -> anyhow::Result<()> {
    refuse_by_version(status)?;
    let held = status.as_ref().ok().and_then(|node| node.get("held"));
    match held {
        None | Some(serde_json::Value::Null) => Ok(()),
        Some(held) => {
            let why = held["why"].as_str().unwrap_or("it does not say why");
            anyhow::bail!("{why}\n{NOT_WHILE_HELD_UP}")
        }
    }
}

/// Say, where the running node is another version than this command, that
/// it is, and how to restart it: for a command that only shows, or that
/// turns sync off, which is answered beside such a node all the same
/// (decision 2026-10-04 §10.1, rule 6).
pub(crate) fn note_another_version(config_path: &str) {
    if let Some(note) = node_version_note(config_path) {
        eprintln!("{note}\n");
        VERSION_NOTED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The command that restarts a node which runs as the service that the
/// install script sets up, on the system named (`std::env::consts::OS`).
/// The script prints the same one.
fn restart_command(os: &str) -> &'static str {
    match os {
        "macos" => "launchctl kickstart -k gui/$(id -u)/ai.seeddrill.cordelia",
        _ => "systemctl --user daemon-reload && systemctl --user restart cordelia",
    }
}

/// What to say when the running node is not the version this command is
/// (`own`). A node from before it reported its version reports none.
fn version_note(node: Option<&str>, own: &str) -> Option<String> {
    // Which of the two is the older is not judged: version strings are
    // not compared, only found to differ.
    let after = format!(
        "They should be the same: a node goes on running the version it was started as \
         until it is restarted. Where it runs as the service that the install script \
         set up, restart it with `{}`; otherwise stop it and start it again.",
        restart_command(std::env::consts::OS)
    );
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

fn cmd_sync(config_path: &str, what: SyncCommand) -> anyhow::Result<()> {
    use cordelia_sync::claude::HOME_NAME;
    use cordelia_sync::discover::{self, Project};

    // What is no more is refused here, before anything is sent, and
    // before the node is asked anything at all (decision 2026-10-04
    // §10.1).
    if let Some(no_more) = refused_before_sending(&what) {
        anyhow::bail!("{no_more}");
    }
    // A node goes on running the version it was started as until it is
    // restarted, and a node of another version may take a request and
    // mean something else by it. So a command that changes anything is
    // not sent to one (decision 2026-10-04 §10.1, rule 6). Turning sync
    // off is sent to any node, and what only shows is answered beside
    // one: each with the note, said first.
    match &what {
        SyncCommand::Off | SyncCommand::Status { .. } => note_another_version(config_path),
        _ => refuse_another_version(config_path)?,
    }
    let set = |body: serde_json::Value| api_post(config_path, "/api/v1/sync/claude", body);
    // The settings generation a change left behind: the scope printed at
    // the end waits for a report made after it.
    let since: Option<u64>;
    match what {
        SyncCommand::Claude {
            dir,
            mapped_only,
            no_home,
            reset,
            // Refused above, where either was given.
            all: _,
            exclude: _,
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
            // The only scope there is: sent as it always was, for a node
            // to store.
            if mapped_only {
                body["all"] = false.into();
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
            if mapped_only {
                println!("{ONLY_MAPPED_FOLDERS_SYNC}");
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
            let settings = sync_settings(config_path)?;
            let mappings = declared_mappings(&settings);
            let home_on = || home_on_offer(settings["home_name"].as_str(), &home_dir, &mappings);
            let mapped = mappings
                .iter()
                .find(|(folder, _)| *folder == mapped_folder)
                .map(|(_, name)| name.clone());
            // The name asked for, as it would be sent.
            let asked = name.as_deref().map(|typed| name_given(typed, &home_dir));
            // Mapped already, and no name given, or the name it has: there
            // is nothing to change, and the name it has is the answer. It
            // is never refused, not for a flag left out either.
            let already = mapped
                .clone()
                .filter(|mapped| is_the_name_it_has(name.as_deref(), &home_dir, mapped));
            // What is said of a folder mapped under another name, once
            // nothing else stands in the way of the request.
            let unmap_first = |mapped: &str| {
                anyhow::anyhow!(
                    "{0} is already mapped to {1}. To sync it under another name, unmap it \
                     first: cordelia sync unmap {2}",
                    short_path(&mapped_folder),
                    sync_label(mapped),
                    shell_arg(&mapped_folder)
                )
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
                // `map` checks when it is run: it is not sent where it
                // would sync another folder than one that was found
                // (decision 2026-10-04 §10.1).
                if let Some(why) = map_would_sync_another(&given, &root, &settings) {
                    anyhow::bail!("{why}");
                }
                // Home memory syncs only when it is asked for, and by
                // naming the home directory itself: never by a slip, and
                // never because a folder inside it was named.
                let names_home = given == home_dir;
                // The first two refusals say how to sync home memory
                // under the name it last had here: the name that was
                // given, if any, was for another folder.
                if home && !names_home {
                    anyhow::bail!("--home is for the home directory itself. {}", home_on());
                }
                if is_home && !names_home {
                    anyhow::bail!(
                        "Claude Code keeps the memory for {} with your home directory's, because \
                         your home directory is a git repository. {}",
                        given.display(),
                        home_on()
                    );
                }
                if is_home && !home {
                    // No name: the name home memory last had on this
                    // device.
                    let Some(typed) = name.as_deref() else {
                        anyhow::bail!("that is your home directory. {}", home_on());
                    };
                    let command = home_offer(typed, &home_dir).map_err(|name| {
                        anyhow::anyhow!(
                            "that is your home directory, and {name:?} is not a name it can \
                             sync under: use lower-case letters, digits and . _ - / ~ + % @, \
                             and do not start it with - or ~. To sync home memory under a \
                             name: cordelia sync map ~ <name> --home"
                        )
                    })?;
                    // The command offered is one the node would take: it
                    // is asked here, of the same check, with the flag.
                    let with_flag = cordelia_api::types::SyncMapRequest {
                        folder: mapped_folder.clone(),
                        name: asked.clone().unwrap_or_default(),
                        home: true,
                    };
                    // Mapped under another name, and nothing else in the
                    // way. The command as typed would be refused for the
                    // flag once home was unmapped, so both steps are said
                    // at once, after saying that this is the home
                    // directory: if naming it was a slip, nothing is
                    // unmapped for it.
                    if let MapStep::UnmapFirst(mapped) = map_step(&with_flag, &home_dir, &mappings)
                    {
                        anyhow::bail!(
                            "that is your home directory, and it is already mapped to {}. To \
                             sync home memory under another name, unmap it and then map it \
                             with --home:\n  cordelia sync unmap {}\n  {command}",
                            sync_label(&mapped),
                            shell_arg(&mapped_folder)
                        );
                    }
                    let held = as_mappings(&mappings);
                    match cordelia_api::sync::check_mapping(&with_flag, &home_dir, &held) {
                        Ok(_) => anyhow::bail!(
                            "that is your home directory. To sync home memory: {command}"
                        ),
                        Err(why) => anyhow::bail!(
                            "that is your home directory, and it cannot sync under that \
                             name: {why}"
                        ),
                    }
                }
                let name = match asked {
                    Some(name) => name,
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
                let request = cordelia_api::types::SyncMapRequest {
                    folder: mapped_folder.clone(),
                    name: name.clone(),
                    home: is_home,
                };
                if let MapStep::UnmapFirst(mapped) = map_step(&request, &home_dir, &mappings) {
                    return Err(unmap_first(&mapped));
                }
                let settings = api_post(
                    config_path,
                    "/api/v1/sync/map",
                    serde_json::json!({
                        "folder": request.folder,
                        "name": request.name,
                        "home": request.home,
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
            let by_name = mapping_named(&mappings, &folder);
            let by_folder = {
                let trimmed = match folder.trim_end_matches('/') {
                    "" => "/",
                    other => other,
                };
                let path = config::expand_tilde(trimmed);
                // The folder as typed, then its real path, then the
                // repository it is in.
                let mut spellings = vec![path.display().to_string()];
                if let Ok(real) = std::fs::canonicalize(&path) {
                    spellings.push(real.display().to_string());
                    spellings.push(discover::memory_root(&real).display().to_string());
                }
                mapping_at(&mappings, &spellings)
            };
            // A word that ends in `/` is a folder. If it is not a mapped
            // one, and is a mapping's name without the `/`, say so.
            if by_folder.is_none()
                && let Some((named, name)) =
                    mapping_named(&mappings, folder.trim().trim_end_matches('/'))
                && by_name.is_none()
            {
                anyhow::bail!(
                    "{folder} is taken for a folder, and it is not mapped on this device. To \
                     unmap {}, which syncs as {}: cordelia sync unmap {}",
                    short_path(named),
                    sync_label(name),
                    shell_word(name)
                );
            }
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
            println!();
        }
        SyncCommand::Off => {
            set(serde_json::json!({ "enabled": false }))?;
            println!("Sync is off. Files already synced stay where they are.");
            return Ok(());
        }
        SyncCommand::Status { seen } => {
            // The one act that takes the notice away: a request of its
            // own, which changes no setting (decision 2026-10-04 §10.1).
            if seen {
                match api_post_told(
                    config_path,
                    "/api/v1/sync/seen",
                    serde_json::json!({}),
                    None,
                )? {
                    Told::Yes(_) => println!("{NOTICE_SEEN}\n"),
                    // A node that has no such request is another
                    // version: it must be restarted first.
                    Told::No { status: 404, .. } => anyhow::bail!("{}", seen_is_not_known()),
                    Told::No { message, .. } => anyhow::bail!("{message}"),
                }
            }
            since = None;
        }
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
                // On maps it: under the name it last had here, so that
                // off and on again leaves it in the channel it was in.
                // Mapping it is also what turns the setting on, in one
                // step.
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
        // Refused above, before anything was sent.
        SyncCommand::Exclude { .. } | SyncCommand::Include { .. } => return Ok(()),
    }
    print_sync_scope(config_path, since)
}

/// What `cordelia sync status --seen` says once the node has put the
/// notice away, or had none.
const NOTICE_SEEN: &str = "The notice of the folders that stopped syncing is put away.";

/// What `cordelia sync status --seen` says of a node that has no such
/// request: it runs another version, and must be restarted first.
fn seen_is_not_known() -> String {
    format!(
        "the running node has no such request: it is another version than this command, and \
         must be restarted first. Where it runs as the service that the install script set up, \
         restart it with `{}`; otherwise stop it and start it again.",
        restart_command(std::env::consts::OS)
    )
}

/// One folder that the notice names, as `cordelia sync status` prints
/// it: the command that maps it, or why no command does (decision
/// 2026-10-04 §10.1). `None` for a folder that is mapped since: nothing
/// is printed for it.
///
/// **A command is printed only where it maps the folder that stopped,**
/// and it carries the folder's name, the one it synced under: `map` with
/// no name takes the remote as it is now, which may be another. For a
/// tree laid out by hand there is no command: the row says that the
/// layout no longer syncs, where the memory is, and the name it synced
/// under. A folder that is not under the Claude Code directory which
/// sync is set to has none either, and says which directory it synced
/// under.
fn notice_row(named: &serde_json::Value) -> Option<Vec<String>> {
    use cordelia_sync::claude::HOME_NAME;
    let is = |key: &str| named[key].as_bool() == Some(true);
    if is("mapped") {
        return None;
    }
    let folder = named["folder"].as_str().unwrap_or_default();
    let name = named["name"].as_str();
    let says = named["says"].as_str();
    let synced_as = match name {
        Some(name) => format!("synced as {}", sync_label(name)),
        None => "synced under no name that was kept".to_string(),
    };
    let Some(cwd) = named["cwd"].as_str().filter(|_| is("mappable")) else {
        let directory = named["directory"].as_str().or(named["cwd"].as_str());
        let place = directory.map_or_else(|| short_path(folder), short_path);
        return Some(match named["why_not"].as_str() {
            Some("laid_out_by_hand") => vec![
                format!("{}/memory", short_path(folder)),
                synced_as,
                "this layout no longer syncs, and no command maps it".to_string(),
            ],
            Some("another_claude_dir") => vec![
                place,
                synced_as,
                match named["synced_under"].as_str() {
                    Some(under) => format!(
                        "it synced under {}, which sync is not set to",
                        short_path(under)
                    ),
                    None => "it synced under another Claude Code directory".to_string(),
                },
            ],
            _ => vec![
                place,
                synced_as,
                says.unwrap_or("the node does not say whether `cordelia sync map` would sync it")
                    .to_string(),
            ],
        });
    };
    // In its one spelling, as `map` sends a name that is typed.
    let tidied = name.map(cordelia_core::sync_name::tidy);
    let (what, command) = if is("home") {
        let command = match tidied.as_deref() {
            None | Some(HOME_NAME) => "cordelia sync map ~ --home".to_string(),
            Some(name) => format!("cordelia sync map ~ {} --home", shell_word(name)),
        };
        (synced_as, command)
    } else if is("needs_name") {
        (
            says.unwrap_or("needs a name").to_string(),
            format!("cordelia sync map {} <name>", shell_arg(cwd)),
        )
    } else {
        let name = tidied.unwrap_or_default();
        (
            synced_as,
            format!("cordelia sync map {} {}", shell_arg(cwd), shell_word(&name)),
        )
    };
    Some(vec![short_path(cwd), what, command])
}

/// The day of a time written as RFC 3339, for a person to read.
fn day_of(at: &str) -> &str {
    at.get(..10).unwrap_or(at)
}

/// What `cordelia sync status` says of the notice, first, with sync on
/// and with it off (decision 2026-10-04 §10.1): each folder it names
/// that is not mapped now, in rows ([`notice_row`]), with what is said
/// before them and after. Empty where the node carries none.
fn notice_lines(
    notice: &serde_json::Value,
    sync_on: bool,
) -> (Vec<String>, Vec<Vec<String>>, Vec<String>) {
    let Some(named) = notice["folders"].as_array() else {
        return Default::default();
    };
    let rows: Vec<Vec<String>> = named.iter().filter_map(notice_row).collect();
    let not_known = notice["not_known"].as_bool() == Some(true);
    let mut before = Vec::new();
    let mut after = Vec::new();
    if rows.is_empty() && !not_known {
        before.push(
            "Every folder that stopped syncing on this device is mapped again. To put this \
             notice away: cordelia sync status --seen"
                .to_string(),
        );
        return (before, rows, after);
    }
    let since = notice["records"][0]["at"]
        .as_str()
        .map(day_of)
        .unwrap_or("an earlier day");
    match rows.len() {
        0 => before.push(format!(
            "Folders stopped syncing on this device ({since}): only mapped folders sync, and \
             they had synced because everything found did."
        )),
        1 => before.push(format!(
            "1 folder stopped syncing on this device ({since}): only mapped folders sync, and \
             it had synced because everything found did."
        )),
        n => before.push(format!(
            "{n} folders stopped syncing on this device ({since}): only mapped folders sync, \
             and they had synced because everything found did."
        )),
    }
    if !rows.is_empty() {
        before.push(
            "These synced in the last whole cycle before that; a folder that had synced \
             earlier, and not then, is not listed. To sync one again, map it:"
                .to_string(),
        );
    }
    if not_known {
        let days: Vec<&str> = notice["records"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|record| record["folders"].as_u64().unwrap_or(0) == 0)
            .filter_map(|record| record["at"].as_str().map(day_of))
            .collect();
        after.push(format!(
            "What stopped on {} is not known: no report of the last cycle was kept. What is \
             found on this machine is listed {}, with the command that maps each folder.",
            match days.is_empty() {
                true => "one day".to_string(),
                false => days.join(" and on "),
            },
            match sync_on {
                true => "below",
                false => "by `cordelia sync status` once sync is on",
            }
        ));
    }
    if !sync_on {
        after.push(
            "Sync is off: turn it on first (`cordelia sync claude`). `cordelia sync map` is \
             refused until then."
                .to_string(),
        );
    }
    after.push("Once you have seen this: cordelia sync status --seen".to_string());
    (before, rows, after)
}

/// Print the notice of what stopped syncing, where the node carries one
/// ([`notice_lines`]).
fn print_notice(status: &serde_json::Value) {
    let sync_on = status["enabled"].as_bool() == Some(true);
    let (before, rows, after) = notice_lines(&status["notice"], sync_on);
    if before.is_empty() && rows.is_empty() && after.is_empty() {
        return;
    }
    for line in &before {
        println!("{line}");
    }
    print_columns(&rows);
    for line in &after {
        println!("{line}");
    }
    println!();
}

/// What a status says of the notice in a list of what holds: each folder
/// that stopped syncing and is not mapped now, and that some are not
/// known, where a record names none. For plain `cordelia status` and for
/// a bar's tooltip.
fn notice_details(notice: &serde_json::Value) -> Vec<String> {
    let mut out: Vec<String> = notice["folders"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|named| named["mapped"].as_bool() != Some(true))
        .map(|named| {
            let place = named["cwd"]
                .as_str()
                .or(named["directory"].as_str())
                .or(named["folder"].as_str())
                .unwrap_or_default();
            match named["name"].as_str() {
                Some(name) => format!("{} ({})", short_path(place), sync_label(name)),
                None => short_path(place),
            }
        })
        .collect();
    if notice["not_known"].as_bool() == Some(true) {
        out.push("folders that are not known (no report of the last cycle was kept)".to_string());
    }
    out
}

/// What `--mapped-only` says: it is taken, and changes nothing that syncs.
const ONLY_MAPPED_FOLDERS_SYNC: &str = "Only mapped folders sync: that is the only scope there is.";

/// What is said in the place of an exclusion, where one is asked for.
const NOTHING_LEFT_TO_EXCLUDE: &str = "there is nothing left to exclude: only mapped folders \
    sync, and nothing was changed. To stop a mapped folder syncing: cordelia sync unmap \
    <folder>. To sync one: cordelia sync map <folder>.";

/// What a `sync` command asks for that is no more, where it does
/// (decision 2026-10-04 §10.1): the words it is refused with, before
/// anything is sent to the node. Everything found no longer syncs, so
/// `--all` is refused; and with nothing synced that is not mapped, there
/// is nothing to exclude or to include.
fn refused_before_sending(what: &SyncCommand) -> Option<&'static str> {
    match what {
        SyncCommand::Claude { all: true, .. } => {
            Some(cordelia_api::sync::EVERYTHING_FOUND_IS_REFUSED)
        }
        SyncCommand::Claude { exclude, .. } if !exclude.is_empty() => Some(NOTHING_LEFT_TO_EXCLUDE),
        SyncCommand::Exclude { .. } | SyncCommand::Include { .. } => Some(NOTHING_LEFT_TO_EXCLUDE),
        _ => None,
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

    let home = |v: &serde_json::Value| v["home"].as_bool() != Some(false);
    if home(after) != home(before) {
        out.push(if home(after) {
            "Home memory: no longer kept off this device.".to_string()
        } else {
            "Home memory: kept off this device.".to_string()
        });
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
            .all(|b| b.is_ascii_alphanumeric() || b"/._-+@".contains(&b));
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

/// The command that maps a folder which was found, or a reason in its
/// place: one row of the list of what is found and not syncing, from the
/// entry as the node carries it (decision 2026-10-04 §10.1).
///
/// **A command is printed only where it maps what was found:** where the
/// entry says that `cordelia sync map`, given its directory, would sync
/// that folder. Otherwise the reason stands in its place. For a memory
/// tree laid out by hand there is no command at all: the row says that
/// the layout cannot be mapped, and where the memory is.
///
/// `home_name` is the name home memory last had on this device, and
/// `available` the names that this person's other devices sync.
fn found_row(
    found: &serde_json::Value,
    home_name: Option<&str>,
    available: &[String],
) -> Vec<String> {
    use cordelia_sync::claude::HOME_NAME;
    let folder = found["folder"].as_str().unwrap_or_default();
    let name = found["name"].as_str();
    let says = found["says"].as_str();
    let is = |key: &str| found[key].as_bool() == Some(true);
    let Some(cwd) = found["cwd"].as_str().filter(|_| is("mappable")) else {
        if found["why_not"].as_str() == Some("laid_out_by_hand") {
            return vec![
                format!("{}/memory", short_path(folder)),
                "this layout cannot be mapped".to_string(),
            ];
        }
        // An entry that says nothing of whether it can be mapped is from
        // a node that does not say: no command is made up for it.
        let reason = says.unwrap_or(
            "the node does not say whether `cordelia sync map` would sync it: restart the node",
        );
        return match found["directory"].as_str().or(found["cwd"].as_str()) {
            Some(directory) => vec![
                short_path(directory),
                name.map_or_else(|| "not a git project".to_string(), sync_label),
                reason.to_string(),
            ],
            None => vec![short_path(folder), reason.to_string()],
        };
    };
    let (mut what, command) = if is("home") {
        // Under the name it last had here, if it had another: mapped as
        // `~` it would go to another channel.
        match home_name {
            Some(last) if last != HOME_NAME => (
                format!("{} (last synced as {last})", sync_label(HOME_NAME)),
                "cordelia sync home on".to_string(),
            ),
            _ => (
                sync_label(HOME_NAME),
                "cordelia sync map ~ --home".to_string(),
            ),
        }
    } else if is("needs_name") {
        (
            says.unwrap_or("needs a name").to_string(),
            format!("cordelia sync map {} <name>", shell_arg(cwd)),
        )
    } else {
        (
            name.unwrap_or_default().to_string(),
            format!("cordelia sync map {}", shell_arg(cwd)),
        )
    };
    // Not said of a home that last synced under another name: what the
    // other devices sync is `~`, and turning home on here would not join
    // that.
    if name.is_some_and(|name| available.iter().any(|other| other == name))
        && !command.ends_with("sync home on")
    {
        what.push_str(" (your other devices sync it)");
    }
    vec![short_path(cwd), what, command]
}

/// The folders that the node lists as found and not syncing, and those
/// that its notice names, from its status: each as Claude Code's folder,
/// its directory, and the reason that stands in the place of a command
/// for it, where it has one. An entry's directory is under `cwd` where
/// `cordelia sync map` would sync its folder, and under `directory`
/// where it would not.
fn found_and_named(status: &serde_json::Value) -> Vec<(&str, &str, Option<&str>)> {
    let found = status["report"]["unmapped"].as_array();
    let named = status["notice"]["folders"].as_array();
    found
        .into_iter()
        .chain(named)
        .flatten()
        .filter_map(|entry| {
            let directory = entry["cwd"].as_str().or(entry["directory"].as_str())?;
            Some((entry["folder"].as_str()?, directory, entry["says"].as_str()))
        })
        .collect()
}

/// Why `cordelia sync map` is not sent, where it would sync another
/// folder than one that was found (decision 2026-10-04 §10.1). `map`
/// checks whenever it is run, however the command was come by: it reads
/// what the node lists as found and what its notice names, and where one
/// of them has the directory that was given (`given`, or `root`, the
/// directory whose folder holds its memory), and a Claude Code folder
/// other than the one `map` would sync, it is refused with the reason.
///
/// A command copied from earlier output, or typed from memory, would
/// otherwise map another folder: Claude Code's own folder for the
/// directory of a tree laid out by hand, or the folder of a repository
/// that has appeared above the directory since it was found.
fn map_would_sync_another(
    given: &std::path::Path,
    root: &std::path::Path,
    status: &serde_json::Value,
) -> Option<String> {
    use cordelia_api::found;
    let claude_dir = std::path::Path::new(status["dir"].as_str()?);
    let would_sync = found::claude_folder(claude_dir, root)?;
    let listed = found_and_named(status);
    let pairs = || {
        listed
            .iter()
            .map(|(folder, directory, _)| (*folder, *directory))
    };
    let (asked, folder) = [given, root].into_iter().find_map(|asked| {
        found::in_the_way(asked, &would_sync, pairs()).map(|folder| (asked, folder))
    })?;
    // Where the folder was found for the directory that was given, and
    // Claude Code now keeps that directory's memory with a repository
    // that contains it, that is the reason: what the node said of the
    // folder was said before. Otherwise, the reason the node gave.
    let reason = match asked == given && root != given {
        true => Some(found::WhyNot::MemoryElsewhere(root.to_path_buf()).says()),
        false => listed
            .iter()
            .find(|(of, directory, _)| *of == folder && std::path::Path::new(directory) == asked)
            .and_then(|(_, _, says)| *says)
            .map(str::to_string),
    };
    Some(found::map_refused(
        asked,
        &would_sync,
        folder,
        reason.as_deref(),
    ))
}

/// Print what syncs on this device, what was found and is not syncing, and
/// what this person's other devices sync. After a change (`since` is the
/// settings generation it left), waits briefly for a report made under
/// the new settings: a cycle that was already running reports the old ones.
fn print_sync_scope(config_path: &str, since: Option<u64>) -> anyhow::Result<()> {
    let status = || api_post(config_path, "/api/v1/sync/status", serde_json::json!({}));
    let mut resp = status()?;
    // What stopped syncing is said first, with sync on or off.
    print_notice(&resp);
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

    println!(
        "Syncing Claude Code memory in {}",
        short_path(&text(&resp["dir"]))
    );
    let report = &resp["report"];
    if !fresh(&resp) {
        println!("  (still working on it: try `cordelia sync status` in a few seconds)");
        return Ok(());
    }

    // A device that follows no recovery phrase, or has stopped, publishes
    // nothing: its folders are listed, and what is in them stays here.
    let stays_here = report["publishes_nothing"].as_str();
    if let Some(why) = stays_here {
        println!("  Nothing is sent from this device: {why}");
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
        rows.push(vec![
            place,
            sync_label(&text(&f["project"])),
            match stays_here {
                Some(_) => "stays on this machine".to_string(),
                None => folder_state(f),
            },
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
                "  not synced (too large: a file's name and its text may together be 60 KB): \
                 {}/memory/{}",
                short_path(&text(&f["folder"])),
                text(&s)
            );
        }
        for c in list(&f["conflict_files"]) {
            println!("  conflict to merge: {}", short_path(&text(&c)));
        }
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
            .map(|found| found_row(found, resp["home_name"].as_str(), &available))
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
    println!("Only mapped folders sync. `cordelia sync map <folder>` syncs one.");
    for e in list(&report["errors"]) {
        println!("error: {}", text(&e));
    }
    Ok(())
}

/// What a folder's row in `cordelia sync status` says of it, from its
/// report: why it does not sync, or that it does, and how many of its
/// files could not be synced in the last cycle. (The first five are
/// named, each with why, among the errors at the end, and the rest are
/// counted there.)
fn folder_state(folder: &serde_json::Value) -> String {
    if let Some(error) = folder["error"].as_str() {
        return format!("error: {error}");
    }
    if folder["waiting"].as_bool() == Some(true) {
        return "waiting for its channel to be fetched from a relay".to_string();
    }
    let listed = folder["failed"].as_array().map_or(0, Vec::len) as u64;
    match listed + folder["failed_more"].as_u64().unwrap_or(0) {
        0 => "syncing".to_string(),
        1 => "syncing, but 1 file could not be synced".to_string(),
        n => format!("syncing, but {n} files could not be synced"),
    }
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
    /// A folder's row says why it does not sync, or that it does and how
    /// many of its files failed in the last cycle: those listed, and those
    /// only counted.
    #[test]
    fn test_a_folders_row_says_how_many_files_failed() {
        use serde_json::json;
        let state = |folder: serde_json::Value| super::folder_state(&folder);
        assert_eq!(state(json!({})), "syncing");
        assert_eq!(state(json!({ "failed": [], "failed_more": 0 })), "syncing");
        let one = json!({ "name": "a.md", "error": "why" });
        assert_eq!(
            state(json!({ "failed": [one] })),
            "syncing, but 1 file could not be synced"
        );
        assert_eq!(
            state(json!({ "failed": [one, one], "failed_more": 3 })),
            "syncing, but 5 files could not be synced"
        );
        // Why the folder does not sync at all comes first.
        assert_eq!(
            state(json!({ "error": "it is gone", "failed": [one] })),
            "error: it is gone"
        );
        assert_eq!(
            state(json!({ "waiting": true })),
            "waiting for its channel to be fetched from a relay"
        );
    }

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

    /// On a personal node `cordelia channels` says the names that the
    /// device holds, each with what it stores of the name's channel, and
    /// nothing of the older kind of channel (decision 2026-10-04 §10):
    /// with none held, it says how one comes to be held.
    #[test]
    fn test_channels_on_a_device_lists_the_names_it_holds() {
        let conn = cordelia_storage::db::open_in_memory().unwrap();
        let none = names_held(&conn).unwrap();
        assert_eq!(none.len(), 1, "{none:?}");
        assert!(none[0].starts_with("No names."), "{none:?}");
        assert!(none[0].contains("cordelia sync map"), "{none:?}");

        let identity = NodeIdentity::generate().unwrap();
        let phrase = cordelia_crypto::phrase::Phrase::generate().unwrap();
        let now = 1_790_000_000;
        cordelia_api::person::first_statement(&conn, &identity, &phrase, "desktop", now).unwrap();
        cordelia_api::person::hold_name(&conn, "team", now).unwrap();
        cordelia_api::person::hold_name(&conn, "lab", now).unwrap();
        // A channel of the older kind in the same database is not listed.
        conn.execute(
            "INSERT INTO channels (channel_id, channel_name, channel_type, mode, access,
                                   creator_id, created_at, updated_at)
             VALUES ('older', 'older', 'named', 'realtime', 'open', X'AA', '2026-10-01',
                     '2026-10-01')",
            [],
        )
        .unwrap();
        let listed = names_held(&conn).unwrap();
        assert_eq!(listed.len(), 3, "{listed:?}");
        assert!(listed[0].starts_with("NAME"), "{listed:?}");
        assert!(
            listed[1].starts_with("lab ") && listed[1].ends_with(" -"),
            "{listed:?}"
        );
        assert!(listed[2].starts_with("team "), "{listed:?}");
        assert!(!listed.join("\n").contains("older"), "{listed:?}");
        // What it stores of a name's channel is counted.
        let team = cordelia_storage::person::channel_of_name(&conn, "team")
            .unwrap()
            .unwrap();
        assert_eq!(
            cordelia_storage::usage::stored_of_channel(&conn, &team).unwrap(),
            (0, None)
        );
    }

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

        // The scope that a node says, and the list of exclusions that it
        // stores, are no setting of the command's: nothing is said of
        // either.
        let other = settings(serde_json::json!({ "enabled": true, "dir": "/srv/other",
            "all": true, "home": false, "exclude": ["github.com/o/x"],
            "mappings": [{ "folder": "/srv/notes", "name": "lab-notes" }] }));
        assert_eq!(
            setting_changes(&on, &other),
            [
                "Claude Code directory: /srv/other (was /srv/claude).",
                "Home memory: kept off this device.",
            ]
        );
        assert_eq!(
            setting_changes(&other, &on),
            [
                "Claude Code directory: /srv/claude (was /srv/other).",
                "Home memory: no longer kept off this device.",
                "Unmapped: /srv/notes (lab-notes).",
            ]
        );
    }

    /// What is no more is refused by the command, before anything is sent
    /// (decision 2026-10-04 §10.1): `--all`, with whatever beside it;
    /// `--exclude`; and `exclude` and `include`, each with what to do
    /// instead. `--mapped-only` is taken, and so is everything else.
    #[test]
    fn test_what_is_no_more_is_refused_before_anything_is_sent() {
        use clap::Parser;
        let asked = |args: &[&str]| -> Option<&'static str> {
            let line = [&["cordelia", "sync"], args].concat();
            match super::Cli::parse_from(line).command {
                Some(super::Commands::Sync { what }) => refused_before_sending(&what),
                _ => panic!("{args:?} is no sync command"),
            }
        };
        for everything in [
            &["claude", "--all"][..],
            &["claude", "--all", "--dir", "/srv/claude"],
            &["claude", "--all", "--reset"],
            &["claude", "--all", "--no-home"],
            &["claude", "--all", "--exclude", "x"],
        ] {
            let said = asked(everything).unwrap_or_else(|| panic!("{everything:?} is sent"));
            assert!(said.contains("only mapped folders sync"), "{said}");
            assert!(said.contains("nothing was changed"), "{said}");
            assert!(said.contains("cordelia sync map <folder>"), "{said}");
        }
        for exclusion in [
            &["claude", "--exclude", "github.com/client-co/app"][..],
            &["claude", "--exclude", "a", "--exclude", "b", "--reset"],
            &["exclude", "github.com/client-co/app"],
            &["include", "github.com/client-co/app"],
        ] {
            let said = asked(exclusion).unwrap_or_else(|| panic!("{exclusion:?} is sent"));
            assert!(said.contains("nothing left to exclude"), "{said}");
            assert!(said.contains("cordelia sync unmap <folder>"), "{said}");
            assert!(said.contains("cordelia sync map <folder>"), "{said}");
        }
        for sent in [
            &["claude"][..],
            &["claude", "--mapped-only"],
            &["claude", "--dir", "/srv/claude", "--no-home", "--reset"],
            &["map", "/srv/notes", "lab"],
            &["unmap", "lab"],
            &["home", "on"],
            &["home", "off"],
            &["off"],
            &["status"],
        ] {
            assert_eq!(asked(sent), None, "{sent:?}");
        }
        assert!(ONLY_MAPPED_FOLDERS_SYNC.contains("the only scope there is"));
    }

    /// The list of what is found prints `cordelia sync map` only where it
    /// maps what was found, and the reason in its place otherwise
    /// (decision 2026-10-04 §10.1): from the entry as the node carries
    /// it, for each kind of folder.
    #[test]
    fn test_a_map_command_is_printed_only_where_it_maps_what_was_found() {
        let home = real_home().display().to_string();
        let row = |found: serde_json::Value| found_row(&found, None, &[]);
        let json = |text: &str| serde_json::from_str::<serde_json::Value>(text).unwrap();
        let claude = format!("{home}/.claude/projects");

        // What `map` would sync: the command, with its directory.
        let project = serde_json::json!({
            "folder": format!("{claude}/-x-Work-cn"), "cwd": format!("{home}/Work/cn"),
            "name": "github.com/o/cn", "mappable": true,
        });
        assert_eq!(
            row(project.clone()),
            [
                "~/Work/cn",
                "github.com/o/cn",
                "cordelia sync map ~/Work/cn"
            ]
        );
        // One that needs a name: the command asks for one, and says why.
        let needs = serde_json::json!({
            "folder": format!("{claude}/-x-notes"), "cwd": format!("{home}/notes"), "name": null,
            "mappable": true, "needs_name": true, "says": "needs a name (not a git project)",
        });
        assert_eq!(
            row(needs),
            [
                "~/notes",
                "needs a name (not a git project)",
                "cordelia sync map ~/notes <name>"
            ]
        );
        let taken = serde_json::json!({
            "folder": format!("{claude}/-x-src-cn"), "cwd": format!("{home}/src/cn"),
            "name": "github.com/o/cn", "mappable": true, "needs_name": true,
            "says": "needs another name (its own is mapped from /x/Work/cn)",
        });
        assert_eq!(
            row(taken)[1..],
            [
                "needs another name (its own is mapped from /x/Work/cn)",
                "cordelia sync map ~/src/cn <name>"
            ]
        );
        // The home directory's own entry, with what maps it: as `~`, or
        // under the name it last had here.
        let home_entry = serde_json::json!({
            "folder": format!("{claude}/-x"), "cwd": home, "name": "~",
            "mappable": true, "home": true,
        });
        assert_eq!(
            row(home_entry.clone()),
            ["~", "home memory", "cordelia sync map ~ --home"]
        );
        assert_eq!(
            found_row(&home_entry, Some("team"), &[]),
            [
                "~",
                "home memory (last synced as team)",
                "cordelia sync home on"
            ]
        );
        // What the other devices sync is marked.
        let others = ["github.com/o/cn".to_string(), "~".to_string()];
        assert_eq!(
            found_row(&project, None, &others)[1],
            "github.com/o/cn (your other devices sync it)"
        );
        assert_eq!(
            found_row(&home_entry, Some("team"), &others)[1],
            "home memory (last synced as team)"
        );

        // What `map` would not sync: no command, and the reason in its
        // place, for each reason there is.
        for (why, says) in [
            (
                "outside_home",
                "outside your home directory: it cannot be mapped",
            ),
            ("directory_gone", "its directory is gone"),
            (
                "home_not_set",
                "HOME is not set for the node: nothing can be mapped until it is",
            ),
            ("git_not_run", "the node cannot run git"),
            (
                "memory_elsewhere",
                "Claude Code now keeps its memory with /x, a git repository",
            ),
            ("path_too_long", "its path is longer than 200 characters"),
            (
                "another_claude_dir",
                "it is not under the Claude Code directory",
            ),
        ] {
            let cannot = serde_json::json!({
                "folder": format!("{claude}/-srv-app"), "cwd": null, "directory": "/srv/app",
                "name": "github.com/o/app", "mappable": false, "why_not": why, "says": says,
            });
            let printed = row(cannot);
            assert_eq!(printed, ["/srv/app", "github.com/o/app", says], "{why}");
            assert!(!printed.join(" ").contains("cordelia sync map"), "{why}");
        }
        let no_name = json(
            r#"{"folder":"/c/projects/-srv-n","cwd":null,"directory":"/srv/n","name":null,
                "mappable":false,"why_not":"outside_home","says":"outside your home directory"}"#,
        );
        assert_eq!(
            row(no_name),
            ["/srv/n", "not a git project", "outside your home directory"]
        );
        // No directory known: the folder, and that.
        let unknown = json(
            r#"{"folder":"/c/projects/-gone","cwd":null,"name":null,"mappable":false,
                "why_not":"no_directory","says":"its directory is not known"}"#,
        );
        assert_eq!(
            row(unknown),
            ["/c/projects/-gone", "its directory is not known"]
        );
        // A tree laid out by hand: no command at all, only that the
        // layout cannot be mapped, and where the memory is. Not its
        // directory, and not the home directory's command where that is
        // what its transcripts record.
        let by_hand = serde_json::json!({
            "folder": "/c/projects/workspace", "cwd": null, "directory": home, "name": "~",
            "mappable": false, "why_not": "laid_out_by_hand",
            "says": "this layout cannot be mapped: Claude Code did not name the folder after \
                     its directory",
        });
        assert_eq!(
            row(by_hand),
            [
                "/c/projects/workspace/memory",
                "this layout cannot be mapped"
            ]
        );
        // An entry whose directory is under `cwd` and that is not said
        // to be mappable gets no command: nothing is made up for it.
        let unsaid = json(r#"{"folder":"/c/projects/-x-old","cwd":"/x/old","name":"old"}"#);
        let printed = row(unsaid);
        assert_eq!(printed[..2], ["/x/old", "old"]);
        assert!(
            printed[2].starts_with("the node does not say"),
            "{printed:?}"
        );
        let not_mappable = json(
            r#"{"folder":"/c/projects/-x-old","cwd":"/x/old","name":"old","mappable":false,
                "says":"its directory is gone"}"#,
        );
        assert_eq!(
            row(not_mappable),
            ["/x/old", "old", "its directory is gone"]
        );
    }

    /// `cordelia sync map` checks when it is run (decision 2026-10-04
    /// §10.1): where the node lists a folder as found, or names one in
    /// its notice, with the directory that was given and another Claude
    /// Code folder than the one `map` would sync, nothing is sent, and
    /// the reason is said. For a folder that it would sync, it goes on.
    #[test]
    fn test_map_is_not_sent_where_it_would_sync_another_folder_than_was_found() {
        use std::path::Path;
        let status = |found: serde_json::Value, named: serde_json::Value| {
            serde_json::json!({
                "enabled": true,
                "dir": "/home/sam/.claude",
                "report": { "unmapped": found },
                "notice": { "folders": named },
            })
        };
        let none = serde_json::json!([]);
        let own = "/home/sam/.claude/projects/-home-sam-Work-cn";
        let cn = Path::new("/home/sam/Work/cn");

        // The folder that `map` would sync was found: it is sent.
        let found = serde_json::json!([
            { "folder": own, "cwd": "/home/sam/Work/cn", "name": "github.com/o/cn", "mappable": true },
        ]);
        assert_eq!(
            map_would_sync_another(cn, cn, &status(found, none.clone())),
            None
        );
        // Nothing found, and sync off (the node then refuses): it is sent.
        assert_eq!(
            map_would_sync_another(cn, cn, &status(none.clone(), none.clone())),
            None
        );
        assert_eq!(
            map_would_sync_another(cn, cn, &serde_json::json!({ "enabled": false })),
            None
        );

        // The directory of a tree laid out by hand.
        let by_hand = serde_json::json!([
            { "folder": "/home/sam/.claude/projects/workspace", "cwd": null,
              "directory": "/home/sam/Work/cn", "name": "github.com/o/cn", "mappable": false,
              "why_not": "laid_out_by_hand", "says": "this layout cannot be mapped" },
        ]);
        for listed in [
            status(by_hand.clone(), none.clone()),
            status(none.clone(), by_hand.clone()),
        ] {
            let why = map_would_sync_another(cn, cn, &listed).expect("refused");
            assert!(
                why.contains("/home/sam/.claude/projects/workspace"),
                "{why}"
            );
            assert!(why.contains("(this layout cannot be mapped)"), "{why}");
            assert!(why.contains(own), "{why}");
            assert!(why.contains("nothing was mapped"), "{why}");
            // Given one of its subdirectories, whose memory is the
            // repository's: refused as well.
            let sub = Path::new("/home/sam/Work/cn/src");
            assert!(map_would_sync_another(sub, cn, &listed).is_some());
        }

        // A directory that a repository has appeared above since it was
        // found: `map` would sync the repository's folder.
        let notes = Path::new("/home/sam/notes");
        let above = Path::new("/home/sam");
        let found = serde_json::json!([
            { "folder": "/home/sam/.claude/projects/-home-sam-notes", "cwd": "/home/sam/notes",
              "name": null, "mappable": true, "needs_name": true,
              "says": "needs a name (not a git project)" },
        ]);
        let listed = status(found, none.clone());
        assert_eq!(map_would_sync_another(notes, notes, &listed), None);
        let why = map_would_sync_another(notes, above, &listed).expect("refused");
        assert!(
            why.contains("/home/sam/.claude/projects/-home-sam-notes"),
            "{why}"
        );
        assert!(
            why.contains("/home/sam/.claude/projects/-home-sam)"),
            "{why}"
        );
        // The reason is the repository, and not what was said of the
        // folder when it was found.
        assert!(
            why.contains("(Claude Code now keeps its memory with /home/sam, a git repository"),
            "{why}"
        );
        assert!(!why.contains("needs a name"), "{why}");
        // An entry of another directory is not in the way.
        let other = Path::new("/home/sam/other");
        assert_eq!(map_would_sync_another(other, other, &listed), None);

        // A folder that the notice names, which synced under another
        // Claude Code directory.
        let named = serde_json::json!([
            { "folder": "/home/sam/.other/projects/-home-sam-Work-cn", "cwd": null,
              "directory": "/home/sam/Work/cn", "name": "github.com/o/cn", "mappable": false,
              "why_not": "another_claude_dir",
              "says": "it is not under the Claude Code directory that sync is set to" },
        ]);
        let why = map_would_sync_another(cn, cn, &status(none, named)).expect("refused");
        assert!(
            why.contains("it is not under the Claude Code directory"),
            "{why}"
        );
    }

    /// What `cordelia sync status` prints for the notice (decision
    /// 2026-10-04 §10.1): a `map` command for each folder that can be
    /// mapped, with the name it synced under; none for one that cannot,
    /// with why; nothing for a folder that is mapped since; and with sync
    /// off, to turn sync on first.
    #[test]
    fn test_the_notice_offers_map_for_each_folder_that_can_be_mapped() {
        let home = real_home().display().to_string();
        let claude = format!("{home}/.claude");
        let folder = |name: &str| format!("{claude}/projects/{name}");
        let named = serde_json::json!([
            // Can be mapped: its command carries its name, tidied as
            // `map` would send it.
            { "folder": folder("-x-Work-cn"), "cwd": format!("{home}/Work/cn"),
              "name": "github.com/o/cn.git", "mappable": true, "synced_under": claude,
              "at": "2026-10-05T10:00:00Z" },
            // Mapped since: nothing is printed for it.
            { "folder": folder("-x-notes"), "cwd": null, "directory": format!("{home}/notes"),
              "name": "lab", "mappable": false, "mapped": true },
            // Needs a name: another folder is mapped under its own.
            { "folder": folder("-x-src-cn"), "cwd": format!("{home}/src/cn"),
              "name": "github.com/o/two", "mappable": true, "needs_name": true,
              "says": "needs another name (its own is mapped from /x/two)" },
            // The home directory's own folder, as `~` and under a name.
            { "folder": folder("-x"), "cwd": home, "name": "~", "mappable": true, "home": true },
            // A tree laid out by hand.
            { "folder": folder("workspace"), "cwd": null, "directory": format!("{home}/Work/app"),
              "name": "github.com/o/app", "mappable": false, "why_not": "laid_out_by_hand",
              "says": "this layout cannot be mapped" },
            // Under another Claude Code directory.
            { "folder": "/srv/other/projects/-x-old", "cwd": null,
              "directory": format!("{home}/old"), "name": "old", "mappable": false,
              "why_not": "another_claude_dir", "synced_under": "/srv/other",
              "says": "it is not under the Claude Code directory that sync is set to" },
            // From a report of before mappings: no directory.
            { "folder": folder("-x-before"), "cwd": null, "name": "github.com/o/before",
              "mappable": false, "why_not": "no_directory", "says": "its directory is not known" },
            // Its directory is gone.
            { "folder": folder("-x-gone"), "cwd": null, "directory": format!("{home}/gone"),
              "name": null, "mappable": false, "why_not": "directory_gone",
              "says": "its directory is gone" },
        ]);
        let rows: Vec<Vec<String>> = named
            .as_array()
            .unwrap()
            .iter()
            .filter_map(notice_row)
            .collect();
        let want: Vec<Vec<&str>> = vec![
            vec![
                "~/Work/cn",
                "synced as github.com/o/cn.git",
                "cordelia sync map ~/Work/cn github.com/o/cn",
            ],
            vec![
                "~/src/cn",
                "needs another name (its own is mapped from /x/two)",
                "cordelia sync map ~/src/cn <name>",
            ],
            vec!["~", "synced as home memory", "cordelia sync map ~ --home"],
            vec![
                "~/.claude/projects/workspace/memory",
                "synced as github.com/o/app",
                "this layout no longer syncs, and no command maps it",
            ],
            vec![
                "~/old",
                "synced as old",
                "it synced under /srv/other, which sync is not set to",
            ],
            vec![
                "~/.claude/projects/-x-before",
                "synced as github.com/o/before",
                "its directory is not known",
            ],
            vec![
                "~/gone",
                "synced under no name that was kept",
                "its directory is gone",
            ],
        ];
        assert_eq!(rows, want);
        // Home under a name of its own: the command carries it.
        let home_as = serde_json::json!({
            "folder": folder("-x"), "cwd": home, "name": "team", "mappable": true, "home": true,
        });
        assert_eq!(
            notice_row(&home_as).unwrap()[2],
            "cordelia sync map ~ team --home"
        );
        // A name that a shell would read is quoted.
        let odd = serde_json::json!({
            "folder": folder("-x-odd"), "cwd": format!("{home}/odd"), "name": "a%b",
            "mappable": true,
        });
        assert_eq!(
            notice_row(&odd).unwrap()[2],
            "cordelia sync map ~/odd 'a%b'"
        );

        // The whole of what is printed, with sync on.
        let notice = serde_json::json!({
            "records": [
                { "at": "2026-10-05T10:00:00Z", "dir": claude, "folders": 8 },
            ],
            "not_known": false,
            "dir": claude,
            "stopped": 7,
            "folders": named,
        });
        let (before, printed, after) = notice_lines(&notice, true);
        assert!(
            before[0].starts_with("7 folders stopped syncing on this device (2026-10-05)"),
            "{before:?}"
        );
        assert!(before[1].contains("in the last whole cycle"), "{before:?}");
        assert_eq!(printed, rows);
        assert_eq!(
            after,
            ["Once you have seen this: cordelia sync status --seen"]
        );
        // With sync off: to turn sync on first, since `map` is refused.
        let (_, printed, after) = notice_lines(&notice, false);
        assert_eq!(printed, rows);
        assert!(
            after[0].starts_with("Sync is off: turn it on first"),
            "{after:?}"
        );
        assert!(after[1].ends_with("cordelia sync status --seen"));

        // A record with the date alone: what stopped is not known, and
        // what is found is listed for it.
        let unknown = serde_json::json!({
            "records": [{ "at": "2026-10-05T10:00:00Z", "dir": claude, "folders": null }],
            "not_known": true, "dir": claude, "stopped": 0, "folders": [],
        });
        let (before, printed, after) = notice_lines(&unknown, true);
        assert!(
            before[0].starts_with("Folders stopped syncing on this device"),
            "{before:?}"
        );
        assert_eq!(before.len(), 1);
        assert!(printed.is_empty());
        assert!(
            after[0].starts_with("What stopped on 2026-10-05 is not known"),
            "{after:?}"
        );
        assert!(after[0].contains("listed below"), "{after:?}");
        let (_, _, after) = notice_lines(&unknown, false);
        assert!(after[0].contains("once sync is on"), "{after:?}");

        // Every folder mapped since: only how to put it away.
        let all_mapped = serde_json::json!({
            "records": [{ "at": "2026-10-05T10:00:00Z", "dir": claude, "folders": 1 }],
            "not_known": false, "dir": claude, "stopped": 0,
            "folders": [{ "folder": folder("-x-notes"), "cwd": null, "name": "lab",
                          "mappable": false, "mapped": true }],
        });
        let (before, printed, after) = notice_lines(&all_mapped, true);
        assert!(printed.is_empty() && after.is_empty());
        assert!(before[0].contains("is mapped again"), "{before:?}");
        assert!(before[0].ends_with("cordelia sync status --seen"));
        // One folder is said as one.
        let one = serde_json::json!({
            "records": [{ "at": "2026-10-05T10:00:00Z", "dir": claude, "folders": 1 }],
            "not_known": false, "dir": claude, "stopped": 1, "folders": [odd],
        });
        assert!(notice_lines(&one, true).0[0].starts_with("1 folder stopped syncing"));
        // No notice: nothing.
        let none = notice_lines(&serde_json::Value::Null, true);
        assert!(none.0.is_empty() && none.1.is_empty() && none.2.is_empty());

        // Plain `cordelia status` and a bar's tooltip name each folder
        // that is not mapped now, and say where some are not known.
        let details = notice_details(&notice);
        assert_eq!(details.len(), 7, "{details:?}");
        assert_eq!(details[0], "~/Work/cn (github.com/o/cn.git)");
        assert_eq!(details[2], "~ (home memory)");
        assert_eq!(details[6], "~/gone");
        assert!(!details.iter().any(|line| line.contains("~/notes")));
        let details = notice_details(&unknown);
        assert_eq!(details.len(), 1);
        assert!(details[0].starts_with("folders that are not known"));
        assert!(notice_details(&all_mapped).is_empty());
        assert!(notice_details(&serde_json::Value::Null).is_empty());
    }

    /// `cordelia sync status --seen` beside a node that has no such
    /// request says that the node must be restarted, and how.
    #[test]
    fn test_seen_says_to_restart_a_node_that_has_no_such_request() {
        let said = seen_is_not_known();
        assert!(said.contains("has no such request"), "{said}");
        assert!(said.contains("must be restarted first"), "{said}");
        assert!(
            said.contains(restart_command(std::env::consts::OS)),
            "{said}"
        );
    }

    /// What a status goes by of a person's devices, from the node's look
    /// at them (decision 2026-10-04 §8, §10.1): each thing as the look
    /// gives it, and nothing where the look says nothing.
    #[test]
    fn test_what_a_status_goes_by_of_a_persons_devices() {
        let now = 1_000_000;
        assert_eq!(
            devices_facts(&serde_json::json!({}), now),
            indicator::Devices::default()
        );
        // A device that follows no phrase: nothing holds.
        let alone = serde_json::json!({
            "state": "no_phrase", "change": null, "devices": [], "added": [], "removed": [],
            "notices": [], "relays": [{ "relay": "a", "holds_latest": null, "connected_secs": 900,
            "no_room_at": null }], "names_not_listed": [], "names": { "sent": [], "to_go": [],
            "to_go_since": null }, "cannot_go_on": "no recovery phrase yet",
        });
        assert_eq!(devices_facts(&alone, now), indicator::Devices::default());

        let look = serde_json::json!({
            "state": "applied",
            "change": 3,
            "applied_at": now - 3_600,
            "cannot_go_on": null,
            "devices": [
                { "this_device": true, "applied": 3, "left": false },
                { "this_device": false, "applied": null, "left": false },
                { "this_device": false, "applied": 3, "left": true },
            ],
            "added": [{ "applied": 3, "left": true }, { "applied": 3, "left": false }],
            "removed": [{ "key": "k" }],
            "notices": [
                { "id": "1", "kind": "added" },
                { "id": "2", "kind": "left" },
                { "id": "3", "kind": "added" },
                { "id": "4", "kind": "left_out" },
            ],
            "relays": [
                { "relay": "a", "holds_latest": false, "connected_secs": 400, "no_room_at": null },
                { "relay": "b", "holds_latest": true, "connected_secs": 900, "no_room_at": now - 60 },
                { "relay": "c", "holds_latest": false, "connected_secs": null, "no_room_at": null },
                { "relay": "d", "holds_latest": null, "connected_secs": 700, "no_room_at": now + 5 },
            ],
            // Two that a device which still counts had listed, and one
            // that only a device which counts no longer had.
            "names_not_listed": [
                { "name": "lab", "by": [{ "key": "a" }], "by_gone": [] },
                { "name": "old", "by": [], "by_gone": [{ "key": "g" }] },
                { "name": "team", "by": [{ "key": "a" }], "by_gone": [{ "key": "g" }] },
            ],
            "names": { "sent": ["x"], "to_go": ["lab"], "to_go_since": now - 30 },
        });
        assert_eq!(
            devices_facts(&look, now),
            indicator::Devices {
                not_applied: false,
                removal_not_applied_secs: Some(3_600),
                added_not_cleared: 2,
                said_left: 2,
                // Only a relay that is connected and says that it does
                // not hold it.
                without_latest_secs: vec![400],
                // A refusal in the clock's future was a moment ago.
                no_room_secs: vec![60, 0],
                names_not_listed: 2,
                applied_secs: Some(3_600),
                names_to_go: 1,
                to_go_secs: Some(30),
            }
        );

        let edit = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut look = look.clone();
            change(&mut look);
            devices_facts(&look, now)
        };
        // A removal that every device has applied is none; nor is a
        // change that some device has not applied and that removes none;
        // nor one of which this device does not know when it applied it.
        let all_applied = edit(&|look| look["devices"][1]["applied"] = 3.into());
        assert_eq!(all_applied.removal_not_applied_secs, None);
        let none_removed = edit(&|look| look["removed"] = serde_json::json!([]));
        assert_eq!(none_removed.removal_not_applied_secs, None);
        let not_known = edit(&|look| look["applied_at"] = serde_json::Value::Null);
        assert_eq!(not_known.removal_not_applied_secs, None);
        assert_eq!(not_known.applied_secs, None);
        // A device that says it has applied another change has not
        // applied this one.
        let another = edit(&|look| {
            look["devices"][1]["applied"] = 2.into();
        });
        assert_eq!(another.removal_not_applied_secs, Some(3_600));
        // Answered with a change that it could not apply.
        let not_applied = edit(&|look| look["cannot_go_on"] = "it could not".into());
        assert!(not_applied.not_applied);
        // A device that has stopped says why it cannot go on, and that
        // is said of where it stands, not here.
        let removed = edit(&|look| {
            look["state"] = "removed".into();
            look["cannot_go_on"] = "this device was removed".into();
        });
        assert!(!removed.not_applied);
        // A name that only a device which counts no longer had listed is
        // in no level; nor is one of which the node does not say who had.
        let gone = edit(&|look| {
            look["names_not_listed"] = serde_json::json!([
                { "name": "old", "by": [], "by_gone": [{ "key": "g" }] },
                { "name": "bare" },
            ]);
        });
        assert_eq!(gone.names_not_listed, 0);
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
            ("host.example/a/c+d", "host.example/a/c+d"),
            // A tilde is expanded by the shell at the start of a word.
            ("git.sr.ht/~sam/proj", "'git.sr.ht/~sam/proj'"),
            // fish expands `%self`; a percent sign is quoted wherever it is.
            ("%self", "'%self'"),
            ("host.example/a%20b", "'host.example/a%20b'"),
            ("x; rm -rf ~", "'x; rm -rf ~'"),
            ("-rf", "'-rf'"),
            ("", "''"),
        ] {
            assert_eq!(shell_word(name), want);
        }
    }

    /// A node can be another version than the command. A command says so,
    /// beside what the node answered, and says how to restart the node.
    #[test]
    fn test_a_node_of_another_version_is_named() {
        assert_eq!(version_note(Some("0.2.0-alpha.6"), "0.2.0-alpha.6"), None);
        let other = version_note(Some("0.2.0-alpha.5"), "0.2.0-alpha.6").unwrap();
        // It names the command that restarts the node on this system.
        let restart = restart_command(std::env::consts::OS);
        assert!(
            other.contains("node is version 0.2.0-alpha.5")
                && other.contains("command is version 0.2.0-alpha.6")
                && other.contains(&format!("restart it with `{restart}`")),
            "{other}"
        );
        // A node from before it said its version.
        let older = version_note(None, "0.2.0-alpha.6").unwrap();
        assert!(
            older.contains("from before nodes said their version")
                && older.contains("command is version 0.2.0-alpha.6")
                && older.contains(&format!("restart it with `{restart}`")),
            "{older}"
        );
    }

    /// A command that changes something is refused where the node's
    /// version could not be learned, as it is where the node is of
    /// another version (decision 2026-10-04 §10.1, rule 6): the node did
    /// not answer, or what answered was no status. It says why, and that
    /// nothing was done. A node of the command's own version is not
    /// refused.
    #[test]
    fn test_a_node_whose_version_is_not_learned_is_refused() {
        let own = env!("CARGO_PKG_VERSION");
        let of_this_version = Ok(serde_json::json!({ "version": own }));
        assert!(refuse_by_version(&of_this_version).is_ok());

        let not_reached: anyhow::Result<serde_json::Value> = Err(anyhow::anyhow!(
            "cannot reach the local node at the address"
        ));
        let refused = refuse_by_version(&not_reached).unwrap_err().to_string();
        assert!(
            refused.starts_with("cannot reach the local node at the address\n"),
            "{refused}"
        );
        assert!(
            refused.contains("The running node's version could not be learned."),
            "{refused}"
        );
        assert!(refused.ends_with("nothing was done."), "{refused}");

        let another = Ok(serde_json::json!({ "version": "0.0.0-another" }));
        let refused = refuse_by_version(&another).unwrap_err().to_string();
        assert!(
            refused.contains("The running node is version 0.0.0-another"),
            "{refused}"
        );
        assert!(
            refused.contains("is not sent to a node of another version"),
            "{refused}"
        );
        // What answers and says no version is a node from before nodes
        // said theirs.
        let says_none = Ok(serde_json::json!({ "status": "running" }));
        let refused = refuse_by_version(&says_none).unwrap_err().to_string();
        assert!(
            refused.contains("from before nodes said their version"),
            "{refused}"
        );
    }

    /// A command that makes or asks for a recovery phrase asks how the
    /// node stands first, and is refused where the node is held up, with
    /// why the node is (decision 2026-10-04 §10.1): before any word is
    /// shown. It is refused for the node's version as any command that
    /// changes something is, and that is said first.
    #[test]
    fn test_a_command_of_a_phrase_is_refused_by_a_node_that_is_held_up() {
        let own = env!("CARGO_PKG_VERSION");
        let stands = |held: serde_json::Value| -> anyhow::Result<serde_json::Value> {
            Ok(serde_json::json!({ "version": own, "held": held }))
        };
        assert!(refuse_by_how_it_stands(&stands(serde_json::Value::Null)).is_ok());
        assert!(refuse_by_how_it_stands(&Ok(serde_json::json!({ "version": own }))).is_ok());

        let why = "the first start on this version is not done: no room";
        let held = stands(serde_json::json!({ "by": "first_start", "why": why }));
        let refused = refuse_by_how_it_stands(&held).unwrap_err().to_string();
        assert!(refused.starts_with(&format!("{why}\n")), "{refused}");
        assert!(
            refused.contains("no recovery phrase was shown or asked for"),
            "{refused}"
        );
        // Held up, and saying nothing of why.
        let held = stands(serde_json::json!({ "by": "something" }));
        let refused = refuse_by_how_it_stands(&held).unwrap_err().to_string();
        assert!(refused.contains("The node is held up"), "{refused}");

        // The version comes first.
        let another = Ok(serde_json::json!({
            "version": "0.0.0-another",
            "held": { "by": "first_start", "why": why },
        }));
        let refused = refuse_by_how_it_stands(&another).unwrap_err().to_string();
        assert!(
            refused.contains("is not sent to a node of another version"),
            "{refused}"
        );
        assert!(!refused.contains("The node is held up"), "{refused}");
        let not_reached: anyhow::Result<serde_json::Value> = Err(anyhow::anyhow!("not reached"));
        let refused = refuse_by_how_it_stands(&not_reached)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("could not be learned"), "{refused}");
    }

    /// `cordelia stats` on a relay says the room of each kind of channel
    /// against its cap, which is of one size for both (decision
    /// 2026-10-04 §2.5): the older kind first, and then the channels from
    /// their secrets, with how many it holds.
    #[test]
    fn test_stats_says_the_room_of_each_kind_of_channel() {
        let held = EntriesHeld {
            used: 3 * 1_048_576,
            channels: 2,
            entries: 1,
            content_bytes: 7,
        };
        assert_eq!(
            storage_lines(2048, 16 * 1_048_576, Some(&held)),
            [
                "Storage:          2.0 KB in use of 16.0 MB allowed, by channels of the older kind",
                "                  3.0 MB in use of 16.0 MB allowed, by channels from their \
                 secrets (2 held, 1 entry)",
            ]
        );
        let more = EntriesHeld { entries: 5, ..held };
        assert!(storage_lines(0, 1024, Some(&more))[1].ends_with("(2 held, 5 entries)"));
        // A node that holds none of the new kind's tables says the one.
        assert_eq!(storage_lines(2048, 4096, None).len(), 1);
    }

    /// Each system's service is restarted by its own command, as the
    /// install script restarts it.
    #[test]
    fn test_the_restart_command_is_the_systems_own() {
        assert_eq!(
            restart_command("linux"),
            "systemctl --user daemon-reload && systemctl --user restart cordelia"
        );
        assert_eq!(
            restart_command("macos"),
            "launchctl kickstart -k gui/$(id -u)/ai.seeddrill.cordelia"
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

    /// What `map` offers when the home directory is named, with a name and
    /// without the flag, is the command that was typed, with the flag: the
    /// name as typed, so that it maps home under the name that command
    /// would have, and quoted where a shell would read it otherwise.
    #[test]
    fn test_what_map_offers_for_the_home_directory() {
        let home = std::path::Path::new("/home/sam");
        let offer = |name: &str| home_offer(name, home);
        // `~`, quoted or as a shell hands it over.
        for home_itself in ["~", " ~ ", "/home/sam"] {
            assert_eq!(
                offer(home_itself).unwrap(),
                "cordelia sync map ~ --home",
                "{home_itself:?}"
            );
        }
        for (typed, offered) in [
            ("team", "cordelia sync map ~ team --home"),
            (" team ", "cordelia sync map ~ team --home"),
            ("Team", "cordelia sync map ~ Team --home"),
            (
                "github.com/Owner/Repo.git",
                "cordelia sync map ~ github.com/Owner/Repo.git --home",
            ),
            // An ending in capitals, and one with a space before it: the
            // typed command would map `repo` and `team`, which are names.
            ("Repo.GIT", "cordelia sync map ~ Repo.GIT --home"),
            ("team .git", "cordelia sync map ~ 'team .git' --home"),
            (
                "git.sr.ht/~sam/proj",
                "cordelia sync map ~ 'git.sr.ht/~sam/proj' --home",
            ),
            ("100%mine", "cordelia sync map ~ '100%mine' --home"),
        ] {
            assert_eq!(offer(typed).unwrap(), offered, "{typed}");
        }
        // Not a name. It is said as it was typed, not as it was tidied.
        for not_a_name in [
            "my team",
            "My Team",
            "a/../b",
            "it's",
            "-x",
            "~x",
            "",
            ".git",
            "/home/sam/x",
        ] {
            assert_eq!(offer(not_a_name).unwrap_err(), not_a_name, "{not_a_name:?}");
        }
    }

    /// The name `map` sends: in its one spelling, and `~` for the home
    /// directory's path, which is what a shell makes of an unquoted `~`.
    #[test]
    fn test_the_name_map_sends() {
        let home = std::path::Path::new("/home/sam");
        for (typed, sent) in [
            ("~", "~"),
            (" ~ ", "~"),
            ("/home/sam", "~"),
            ("/home/sam/", "~"),
            ("Team", "team"),
            ("Repo.GIT", "repo"),
            ("team .git", "team"),
            // Another path is no name, and is sent as it is to be refused.
            ("/home/sam/x", "/home/sam/x"),
            ("/home/samantha", "/home/samantha"),
        ] {
            assert_eq!(name_given(typed, home), sent, "{typed:?}");
        }
    }

    /// `$HOME` may reach the home directory through a link. A shell hands
    /// that spelling over for an unquoted `~`, and the home directory is
    /// known by its real path: it is still `~`.
    #[cfg(unix)]
    #[test]
    fn test_the_home_directory_by_another_spelling_is_still_home() {
        let dir = tempfile::tempdir().unwrap();
        let within = dir.path().canonicalize().unwrap();
        let (real, other, link) = (
            within.join("real"),
            within.join("other"),
            within.join("link"),
        );
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&other).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let link = link.to_str().unwrap();
        assert_eq!(name_given(link, &real), "~");
        assert_eq!(
            home_offer(link, &real).unwrap(),
            "cordelia sync map ~ --home"
        );
        // A directory that is not the home directory is not.
        assert_ne!(name_given(other.to_str().unwrap(), &real), "~");
        // Nor a path that does not exist.
        assert_ne!(
            name_given(within.join("gone").to_str().unwrap(), &real),
            "~"
        );
        // Nor a word that happens to lead there from where the command is
        // run: a shell makes an absolute path of `~`.
        let here = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert_eq!(name_given(".", &here), ".");
    }

    /// `map` changes nothing when it is given the name the folder has, or
    /// none: the name as it would be sent, or as it is stored.
    #[test]
    fn test_the_name_a_folder_has_is_no_change() {
        let home = std::path::Path::new("/home/sam");
        for (typed, mapped) in [
            (None, "team"),
            (Some("team"), "team"),
            (Some(" Team "), "team"),
            (Some("team.git"), "team"),
            (Some("~"), "~"),
            // An unquoted `~`, as a shell hands it over.
            (Some("/home/sam"), "~"),
            // A name an earlier version stored with its ending, typed as
            // it is stored.
            (Some("x.git"), "x.git"),
            (Some("X.GIT"), "x.git"),
        ] {
            assert!(
                is_the_name_it_has(typed, home, mapped),
                "{typed:?} {mapped}"
            );
        }
        for (typed, mapped) in [
            ("other", "team"),
            ("x", "x.git"),
            ("~", "team"),
            ("/home/sam", "team"),
            ("team", "~"),
        ] {
            assert!(
                !is_the_name_it_has(Some(typed), home, mapped),
                "{typed} {mapped}"
            );
        }
    }

    /// A folder mapped under another name is told to unmap first only when
    /// that would help: when the request would be taken once it was
    /// unmapped. Unmapping is not free, so a request that would be refused
    /// anyway is sent, and the node says why.
    #[test]
    fn test_an_unmap_is_advised_only_when_it_would_help() {
        let home = std::path::Path::new("/home/sam");
        let pair = |folder: &str, name: &str| (folder.to_string(), name.to_string());
        let mappings = [
            pair("/home/sam", "team"),
            pair("/home/sam/notes", "lab-notes"),
            pair("/home/sam/Work", "work"),
        ];
        let step = |folder: &str, name: &str, flag: bool| {
            let request = cordelia_api::types::SyncMapRequest {
                folder: folder.into(),
                name: name.into(),
                home: flag,
            };
            map_step(&request, home, &mappings)
        };
        // Mapped under another name, and nothing else stands in the way.
        assert_eq!(
            step("/home/sam/notes", "other", false),
            MapStep::UnmapFirst("lab-notes".into())
        );
        assert_eq!(
            step("/home/sam", "other", true),
            MapStep::UnmapFirst("team".into())
        );
        // Mapped under another name, and refused whatever is unmapped.
        for (folder, name, flag, why) in [
            ("/home/sam/notes", "lab notes", false, "not a usable name"),
            ("/home/sam/notes", "~", false, "the name of home memory"),
            (
                "/home/sam/notes",
                "work",
                false,
                "another folder has the name",
            ),
            ("/home/sam/notes", "other", true, "the flag is for home"),
            ("/home/sam", "my team", true, "not a usable name"),
            ("/home/sam", "work", true, "another folder has the name"),
            ("/home/sam", "other", false, "home, without the flag"),
        ] {
            assert_eq!(step(folder, name, flag), MapStep::Send, "{why}");
        }
        // Not mapped at all.
        assert_eq!(step("/home/sam/new", "new", false), MapStep::Send);
        assert_eq!(step("/home/sam/new", "work", false), MapStep::Send);
    }

    /// One adapter is held, for the Claude Code directory that is set: the
    /// one there is while it is for that directory, and another when it is
    /// not, or when there is none. (The loop passes `ClaudeAdapter::is_for`
    /// as the question; that call is not under test here.)
    #[test]
    fn test_an_adapter_is_kept_only_while_it_is_for_the_directory() {
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

    /// A word names a mapping as the name is stored, or else in its one
    /// spelling. An earlier version could store a name that ends in
    /// `.git`: the one spelling takes that off, so such a name is found as
    /// it is stored, in whatever case it is typed, and before a mapping
    /// that has the name without the ending.
    #[test]
    fn test_a_mapping_is_named_as_stored_or_tidied() {
        let pair = |folder: &str, name: &str| (folder.to_string(), name.to_string());
        // The mapping with the shorter name comes first, so that taking
        // the first that matches in any spelling would take the wrong one.
        let mappings = [
            pair("/home/sam/c", "old"),
            pair("/home/sam/a", "team"),
            pair("/home/sam/b", "old.git"),
            pair("/home/sam", "~"),
        ];
        for (word, folder) in [
            ("team", "/home/sam/a"),
            (" Team ", "/home/sam/a"),
            ("team.git", "/home/sam/a"),
            ("old.git", "/home/sam/b"),
            ("OLD.GIT", "/home/sam/b"),
            (" Old.Git ", "/home/sam/b"),
            ("old", "/home/sam/c"),
            ("old.git.git", "/home/sam/c"),
            ("~", "/home/sam"),
        ] {
            let found = mapping_named(&mappings, word).map(|(folder, _)| folder.as_str());
            assert_eq!(found, Some(folder), "{word:?}");
        }
        // A word that ends in `/` is a folder, and names nothing.
        for word in ["other", "/home/sam/a", "", "team/", "old.git/", " team/ "] {
            assert_eq!(mapping_named(&mappings, word), None, "{word:?}");
        }
    }

    /// `cordelia sync unmap <folder>` means the mapping of that folder
    /// before the mapping of the repository it is in, whichever of the two
    /// was mapped first.
    #[test]
    fn test_unmap_takes_the_folder_named_before_the_repository_it_is_in() {
        let pair = |folder: &str, name: &str| (folder.to_string(), name.to_string());
        let list =
            |items: &[&str]| -> Vec<String> { items.iter().map(|s| s.to_string()).collect() };
        // Home was mapped first, then a folder in it; later the home
        // directory became a git repository, so it is the repository the
        // folder is in.
        let mappings = [pair("/home/sam", "~"), pair("/home/sam/notes", "lab")];
        let folder = |spellings: &[&str]| {
            mapping_at(&mappings, &list(spellings)).map(|(folder, _)| folder.as_str())
        };
        // As typed, its real path, the repository.
        let notes = ["notes", "/home/sam/notes", "/home/sam"];
        assert_eq!(folder(&notes), Some("/home/sam/notes"));
        // A folder that is not mapped means the repository it is in.
        let other = ["other", "/home/sam/other", "/home/sam"];
        assert_eq!(folder(&other), Some("/home/sam"));
        assert_eq!(folder(&["/elsewhere"]), None);
        assert_eq!(folder(&[]), None);
    }

    /// A refusal that points at `home on` says so only where the node
    /// would take it. `home on` puts home memory back under the name it
    /// last had on this device, and another folder may have that name now.
    #[test]
    fn test_home_on_is_offered_only_where_the_node_would_take_it() {
        let home = std::path::Path::new("/home/sam");
        let pair = |folder: &str, name: &str| (folder.to_string(), name.to_string());
        let on = "To sync home memory: cordelia sync home on";
        // Never mapped; mapped before under a name that is free; mapped now.
        assert_eq!(home_on_offer(None, home, &[]), on);
        let others = [pair("/home/sam/notes", "lab")];
        assert_eq!(home_on_offer(Some("team"), home, &others), on);
        let mapped = [pair("/home/sam", "team")];
        assert_eq!(home_on_offer(Some("team"), home, &mapped), on);
        // The name it last had is another folder's now.
        let taken = [pair("/home/sam/Work", "team")];
        let said = home_on_offer(Some("team"), home, &taken);
        assert!(!said.contains("home on"), "{said}");
        assert!(
            said.contains("cannot be put back as team")
                && said.contains("already mapped from /home/sam/Work")
                && said.ends_with("cordelia sync map ~ <name> --home"),
            "{said}"
        );
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

    /// A command asks the node only at one of the two addresses that the
    /// node itself starts with, written as it is there. Any other is
    /// refused before a client is made, so the node's token is sent
    /// nowhere else.
    #[test]
    fn test_a_command_asks_only_at_one_of_the_nodes_two_addresses() {
        assert_eq!(api_host("127.0.0.1"), Some("127.0.0.1"));
        // An IPv6 address is written in brackets before a port.
        assert_eq!(api_host("::1"), Some("[::1]"));
        // Anything else, this machine's or not: a name (what it stands
        // for is asked again by whatever connects), another address of
        // this machine, another way of writing one of the two.
        for other in [
            "localhost",
            "LOCALHOST",
            "192.0.2.1",
            "0.0.0.0",
            "127.0.0.2",
            "[::1]",
            "0:0:0:0:0:0:0:1",
            "::ffff:127.0.0.1",
            " 127.0.0.1",
            "127.0.0.1 ",
            "example.org",
            "127.0.0.1.example.org",
            "",
        ] {
            assert_eq!(api_host(other), None, "{other}");
        }
        let mut config = Config::default();
        let limit = Some(std::time::Duration::from_secs(1));
        let port = config.node.http_port;
        let url_for = |config: &Config| {
            let (_, url) = to_this_machine(config, "/api/v1/status", limit)
                .ok()
                .unwrap();
            url
        };
        assert_eq!(
            url_for(&config),
            format!("http://127.0.0.1:{port}/api/v1/status")
        );
        config.api.bind_address = "::1".into();
        assert_eq!(
            url_for(&config),
            format!("http://[::1]:{port}/api/v1/status")
        );
        config.api.bind_address = "192.0.2.1".into();
        let refused = to_this_machine(&config, "/api/v1/status", limit)
            .err()
            .unwrap()
            .to_string();
        assert_eq!(refused, not_the_nodes_own("192.0.2.1"));
        // Only the name that an earlier version took is said to have been.
        assert!(!refused.contains("0.2.0-alpha.6"), "{refused}");
        let was_taken = not_the_nodes_own("localhost");
        assert!(
            was_taken.contains("0.2.0-alpha.6") && was_taken.contains("write `127.0.0.1`"),
            "{was_taken}"
        );
        assert!(!not_the_nodes_own("LOCALHOST").contains("0.2.0-alpha.6"));
        assert!(
            refused.contains("'192.0.2.1'")
                && refused.contains("nowhere else")
                && refused.contains("CORDELIA_BIND_ADDRESS"),
            "{refused}"
        );
    }

    /// A command that waits for the node with no limit says so once, if
    /// the answer has not come by then, and says nothing if it has.
    #[test]
    fn test_a_long_wait_is_said_once_and_a_short_one_is_not() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let said = AtomicUsize::new(0);
        let say = || {
            said.fetch_add(1, Ordering::SeqCst);
        };
        let soon = std::time::Duration::from_millis(20);
        // Still waiting when the time is up, and not before it is.
        let (answered, done) = std::sync::mpsc::channel::<()>();
        let began = std::time::Instant::now();
        say_if_not_done(done, soon, say);
        assert!(began.elapsed() >= soon, "said before the wait was up");
        assert_eq!(said.load(Ordering::SeqCst), 1);
        drop(answered);
        // Answered before it is.
        let (answered, done) = std::sync::mpsc::channel::<()>();
        drop(answered);
        say_if_not_done(done, std::time::Duration::from_secs(60), say);
        assert_eq!(said.load(Ordering::SeqCst), 1);
        // And it waits longer than the node waits for its turn: a node
        // that is busy says so first.
        assert!(STILL_WAITING_AFTER.as_secs() > cordelia_core::protocol::HISTORY_TURN_WAIT_SECS);
    }

    /// Work that takes long is said to, once, while it goes on, and its
    /// answer is what comes back. Work that is done in time has nothing
    /// said of it, and nor has any where no wait is given.
    ///
    /// Nothing here has to happen inside a stretch of time. What says it
    /// holds something that is let go of with it, so the test learns when
    /// nobody can say it any more. The ten seconds and the ten minutes
    /// below are limits on a failure: a pass waits the twenty
    /// milliseconds of its first case, and no longer.
    #[test]
    fn test_work_that_takes_long_is_said_to() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, mpsc};
        let limit = std::time::Duration::from_secs(10);
        let said = Arc::new(AtomicUsize::new(0));
        let say = || {
            let said = said.clone();
            let (held, gone) = mpsc::channel::<()>();
            let say = move || {
                let _held = held;
                said.fetch_add(1, Ordering::SeqCst);
            };
            (say, gone)
        };
        // Nobody holds what says it any more, within the limit.
        let let_go = |gone: &mpsc::Receiver<()>| {
            gone.recv_timeout(limit) == Err(mpsc::RecvTimeoutError::Disconnected)
        };

        // Work that goes on until it is said to: it is said to, once.
        let (saying, gone) = say();
        let counted = said.clone();
        let slow = move || {
            let began = std::time::Instant::now();
            while counted.load(Ordering::SeqCst) == 0 && began.elapsed() < limit {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            7
        };
        let soon = std::time::Duration::from_millis(20);
        let began = std::time::Instant::now();
        assert_eq!(saying_if_long(Some(soon), saying, slow), 7);
        // Not before the wait that was given.
        assert!(began.elapsed() >= soon);
        assert!(let_go(&gone));
        assert_eq!(said.load(Ordering::SeqCst), 1);

        // Done in time: the one who would have said it finds the work
        // over, and says nothing.
        let (saying, gone) = say();
        let long = std::time::Duration::from_secs(600);
        assert_eq!(saying_if_long(Some(long), saying, || 8), 8);
        assert!(let_go(&gone));
        assert_eq!(said.load(Ordering::SeqCst), 1);

        // With no wait there is nobody to say it, however long the work
        // takes: what says it is let go of before the work begins, and
        // this work goes on until it has been.
        let (saying, gone) = say();
        let until_let_go = move || let_go(&gone);
        assert!(saying_if_long(None, saying, until_let_go));
        assert_eq!(said.load(Ordering::SeqCst), 1);
    }

    /// A command says that it is still waiting only where it waits with
    /// no limit of its own: a restore and a drop, which the node carries
    /// out to the end. (That those two are the ones that wait so, and
    /// that this is what they are given, is not under test here.)
    #[test]
    fn test_only_a_wait_with_no_limit_is_said() {
        assert_eq!(said_after(None), Some(STILL_WAITING_AFTER));
        let limit = Some(std::time::Duration::from_secs(30));
        assert_eq!(said_after(limit), None);
    }

    /// What is done once in each hour (the sweep of local history) is due
    /// once in each: not before one has passed, and not again until
    /// another has. (That the node's loop sweeps when it is due is not
    /// under test here.)
    #[test]
    fn test_what_is_done_each_hour_is_due_once_in_each() {
        let start = std::time::Instant::now();
        let hour =
            std::time::Duration::from_secs(cordelia_core::protocol::HISTORY_SWEEP_INTERVAL_SECS);
        let second = std::time::Duration::from_secs(1);
        let mut sweep = Every::from(start, hour);
        assert!(!sweep.is_due(start));
        assert!(!sweep.is_due(start + hour - second));
        assert!(sweep.is_due(start + hour));
        assert!(!sweep.is_due(start + hour + second));
        assert!(!sweep.is_due(start + hour * 2 - second));
        assert!(sweep.is_due(start + hour * 2));
    }

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(40), "40s");
        assert_eq!(format_uptime(245), "4m 05s");
        assert_eq!(format_uptime(3 * 3600 + 12 * 60 + 9), "3h 12m");
    }
}
