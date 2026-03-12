//! Cordelia node binary: CLI, daemon lifecycle, signal handling.
//!
//! Spec: seed-drill/specs/operations.md

use clap::Parser;

#[derive(Parser)]
#[command(name = "cordelia", about = "Encrypted pub/sub for AI agents")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Initialise a new node (generate keypair, create database)
    Init,
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
        Some(Commands::Init) => {
            println!("cordelia init: not yet implemented (WP5)");
        }
        Some(Commands::Status) => {
            println!("cordelia status: not yet implemented");
        }
        Some(Commands::Start) => {
            println!("cordelia start: not yet implemented");
        }
        Some(Commands::Stop) => {
            println!("cordelia stop: not yet implemented");
        }
        None => {
            println!("Cordelia v{}", env!("CARGO_PKG_VERSION"));
            println!("Encrypted pub/sub for AI agents");
            println!();
            println!("Run `cordelia --help` for usage.");
        }
    }

    Ok(())
}
