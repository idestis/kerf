//! `kerf` — diff-aware, KMS-first encryption for structured secret files.
//!
//! This binary is the user-facing surface. The command tree mirrors SPEC § 7;
//! subcommands are stubbed until the corresponding `kerf-core` / `kerf-kms`
//! pieces land. Real implementations must preserve the on-disk byte-identity
//! invariant described in CLAUDE.md and SPEC § 6.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Exit codes — stable contract, see SPEC § 7.6.
mod exit {
    pub const GENERIC: u8 = 1;
    pub const USAGE: u8 = 2;
}

#[derive(Parser, Debug)]
#[command(
    name = "kerf",
    version,
    about = "Diff-aware, KMS-first encryption for structured secret files.",
    long_about = None,
)]
struct Cli {
    /// Increase log verbosity (repeat for more detail).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a `.kerf.yaml` config at the repository root.
    Init {
        /// Recipient(s) to record in the config.
        #[arg(long = "recipient", value_name = "KEY")]
        recipients: Vec<String>,
    },
    /// Encrypt a plaintext file. Minimal-diff re-encryption if output exists.
    Encrypt {
        /// Plaintext input file.
        file: PathBuf,
        /// Destination. If omitted, an in-place encrypt is performed.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Encrypt in place, replacing the input file atomically.
        #[arg(long, conflicts_with = "output")]
        in_place: bool,
    },
    /// Decrypt to stdout or to a file.
    Decrypt {
        /// Encrypted file.
        file: PathBuf,
        /// Destination. Stdout if omitted.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// MAC + AAD integrity check. Does not produce decrypted output.
    Verify {
        /// Encrypted file.
        file: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("kerf: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn run(cmd: Command) -> Result<(), CliError> {
    match cmd {
        Command::Init { .. }
        | Command::Encrypt { .. }
        | Command::Decrypt { .. }
        | Command::Verify { .. } => Err(CliError::Unimplemented),
    }
}

fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("not yet implemented")]
    Unimplemented,
    #[allow(dead_code)] // wired up as real commands land
    #[error("usage: {0}")]
    Usage(String),
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Unimplemented => exit::GENERIC,
            Self::Usage(_) => exit::USAGE,
        }
    }
}
