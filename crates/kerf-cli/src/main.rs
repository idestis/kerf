//! `kerf` — diff-aware, KMS-first encryption for structured secret files.
//!
//! v0.1 ships age recipients only; KMS provider flags are accepted at the
//! CLI level but error with "not yet implemented" until the corresponding
//! `kerf-kms` backend lands.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

mod exit {
    pub const GENERIC: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const NO_RECIPIENT: u8 = 10;
    pub const MAC_FAIL: u8 = 11;
    pub const AAD_FAIL: u8 = 12;
    pub const UNWRAP_FAIL: u8 = 13;
    pub const BAD_INPUT: u8 = 20;
}

mod io;
mod recipients;
mod run;

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

/// Recipient flags — accepted on both `encrypt` and (where relevant) other
/// commands that take a recipient set. Mirrors SOPS's flag names so muscle
/// memory carries over.
#[derive(Args, Debug, Clone, Default)]
pub struct RecipientFlags {
    /// age recipient (`age1…`). May be repeated.
    #[arg(long = "age", value_name = "RECIPIENT")]
    pub age: Vec<String>,

    /// AWS KMS key ARN. May be repeated.
    #[arg(long = "kms", value_name = "ARN")]
    pub kms: Vec<String>,

    /// GCP Cloud KMS crypto-key resource id. May be repeated.
    #[arg(long = "gcp-kms", value_name = "ID")]
    pub gcp_kms: Vec<String>,

    /// Azure Key Vault key URL (`https://<vault>/keys/<name>[/<version>]`).
    /// May be repeated.
    #[arg(long = "azure-kv", value_name = "URL")]
    pub azure_kv: Vec<String>,
}

/// Identity flags — required only on `decrypt`.
#[derive(Args, Debug, Clone, Default)]
pub struct IdentityFlags {
    /// Path to an age identity file. Env: `KERF_AGE_KEY_FILE` / `SOPS_AGE_KEY_FILE`.
    #[arg(long = "identity-file", value_name = "PATH")]
    pub identity_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Encrypt a plaintext file. Minimal-diff re-encryption if output exists.
    Encrypt {
        /// Plaintext input file (YAML or JSON).
        file: PathBuf,
        /// Destination. If omitted, requires --in-place.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Replace the input file atomically with its encrypted form.
        #[arg(long, conflicts_with = "output")]
        in_place: bool,
        /// Override the default encrypted-key regex.
        #[arg(long, value_name = "REGEX")]
        encrypted_regex: Option<String>,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
        #[command(flatten)]
        recipients: RecipientFlags,
    },
    /// Decrypt to stdout or to a file.
    Decrypt {
        /// Encrypted file.
        file: PathBuf,
        /// Destination. Stdout if omitted.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
        #[command(flatten)]
        identity: IdentityFlags,
    },
    /// Verify file integrity: per-value AAD binding + whole-file MAC.
    /// Produces no plaintext. Exit 0 on integrity, non-zero otherwise
    /// (SPEC § 7.6: 11 = MAC, 12 = AAD, 10/13 = recipient).
    Verify {
        /// Encrypted file.
        file: PathBuf,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
        #[command(flatten)]
        identity: IdentityFlags,
    },
    /// Initialise a `.kerf.yaml` config (planned).
    Init {
        /// Recipient(s) to record.
        #[arg(long = "recipient", value_name = "KEY")]
        recipients: Vec<String>,
    },
    /// Generate a fresh age keypair. Writes the secret key to disk (0600)
    /// and prints the public recipient to stdout so it can be piped or
    /// recorded in `.kerf.yaml`.
    Keygen {
        /// Path to write the secret key. Refuses to overwrite an existing file.
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let result = match cli.command {
        Command::Encrypt {
            file,
            output,
            in_place,
            encrypted_regex,
            format,
            recipients,
        } => run::encrypt(run::EncryptArgs {
            file,
            output,
            in_place,
            encrypted_regex,
            format,
            recipients,
        }),
        Command::Decrypt {
            file,
            output,
            format,
            identity,
        } => run::decrypt(run::DecryptArgs {
            file,
            output,
            format,
            identity,
        }),
        Command::Keygen { output } => run::keygen(output),
        Command::Verify {
            file,
            format,
            identity,
        } => run::verify(run::VerifyArgs {
            file,
            format,
            identity,
        }),
        Command::Init { .. } => Err(CliError::Unimplemented),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("kerf: {err}");
            ExitCode::from(err.exit_code())
        }
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

/// CLI-layer error type. Each variant carries enough information to
/// produce a specific exit code (SPEC § 7.6).
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("not yet implemented")]
    Unimplemented,

    #[error("{0}")]
    Usage(String),

    #[error("{0}")]
    BadInput(String),

    #[error("no usable recipient: {0}")]
    NoRecipient(String),

    #[error("mac verification failed")]
    MacFail,

    #[error("aad mismatch at {0}")]
    AadFail(String),

    #[error("recipient unwrap failed: {0}")]
    UnwrapFail(String),

    #[error("{0}")]
    Other(String),
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Unimplemented | Self::Other(_) => exit::GENERIC,
            Self::Usage(_) => exit::USAGE,
            Self::BadInput(_) => exit::BAD_INPUT,
            Self::NoRecipient(_) => exit::NO_RECIPIENT,
            Self::MacFail => exit::MAC_FAIL,
            Self::AadFail(_) => exit::AAD_FAIL,
            Self::UnwrapFail(_) => exit::UNWRAP_FAIL,
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<kerf_core::Error> for CliError {
    fn from(e: kerf_core::Error) -> Self {
        match e {
            kerf_core::Error::Yaml(err) => Self::BadInput(format!("yaml: {err}")),
            kerf_core::Error::AadMismatch(p) => Self::AadFail(p),
            kerf_core::Error::Decrypt => Self::MacFail,
            other => Self::Other(other.to_string()),
        }
    }
}

impl From<kerf_kms::Error> for CliError {
    fn from(e: kerf_kms::Error) -> Self {
        Self::UnwrapFail(e.to_string())
    }
}
