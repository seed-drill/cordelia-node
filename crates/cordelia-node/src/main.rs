//! Cordelia node binary: CLI, daemon lifecycle, signal handling.
//!
//! Spec: seed-drill/specs/operations.md

use std::sync::Mutex;

use actix_web::{web, App, HttpServer};
use clap::Parser;

use cordelia_core::config::{self, Config};
use cordelia_crypto::bech32::{encode_public_key, HRP_X25519_PK};
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
    let personal_channel_id =
        cordelia_storage::naming::personal_channel_id(&pk);
    let personal_psk_path =
        cordelia_storage::psk::psk_path(&data_dir, &personal_channel_id);
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

    // Set up logging
    init_tracing(&config.logging.level);

    println!("Cordelia v{}", env!("CARGO_PKG_VERSION"));
    println!("  Entity:    {}", config.identity.entity_id);
    println!("  Public key: {pk_bech32}");
    println!("  HTTP API:  http://{listen_addr}/api/v1/channels/");
    println!();

    // Build app state
    let state = web::Data::new(cordelia_api::state::AppState {
        db: Mutex::new(conn),
        identity,
        bearer_token,
        home_dir: data_dir,
    });

    // Start the tokio/actix runtime
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        tracing::info!(%listen_addr, "starting HTTP server");

        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .configure(cordelia_api::configure_routes)
        })
        .bind(&listen_addr)?
        .run()
        .await
        .map_err(|e| anyhow::anyhow!(e))
    })
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("cordelia={level},actix_web=warn")));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
