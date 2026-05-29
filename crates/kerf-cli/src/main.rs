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

mod config;
mod io;
mod keys;
mod path;
mod plumbing;
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

    /// Global identity (see `IdentityFlags`). Inherited by every subcommand.
    #[command(flatten)]
    identity: IdentityFlags,

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

/// Identity flags — global, since unwrapping a DEK is cross-cutting: every
/// command that decrypts (decrypt, verify, view, set, unset, rotate, keys
/// add, mac) reads the same credential, with one meaning. Commands that don't
/// decrypt simply ignore it. Defined once on `Cli` and inherited.
#[derive(Args, Debug, Clone, Default)]
pub struct IdentityFlags {
    /// Path to an age identity file. Env: `KERF_AGE_KEY_FILE` / `SOPS_AGE_KEY_FILE`.
    #[arg(long = "identity-file", value_name = "PATH", global = true)]
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
    },
    /// Initialise a `.kerf.yaml` config with a single creation rule.
    ///
    /// Recipients are given as `<type>:<value>` — e.g.
    /// `aws-kms:arn:aws:kms:…`, `gcp-kms:projects/…`,
    /// `azure-kv:https://…`, or `age:age1…` (a bare `age1…` also works).
    Init {
        /// Recipient(s) to record. Repeatable. At least one required.
        #[arg(long = "recipient", value_name = "KEY")]
        recipients: Vec<String>,
        /// Destination path. Defaults to `./.kerf.yaml`.
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Override the rule's path matcher (default: any `*.kerf.*` file).
        #[arg(long, value_name = "REGEX")]
        path_regex: Option<String>,
        /// Override which keys get encrypted (default: the built-in regex).
        #[arg(long, value_name = "REGEX")]
        encrypted_regex: Option<String>,
        /// MAC over all leaves, not just encrypted ones (more diff churn;
        /// catches changes to non-secret config). Default: encrypted only.
        #[arg(long)]
        mac_all: bool,
    },
    /// Generate a fresh age keypair. Writes the secret key to disk (0600)
    /// and prints the public recipient to stdout so it can be piped or
    /// recorded in `.kerf.yaml`.
    Keygen {
        /// Path to write the secret key. Refuses to overwrite an existing file.
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Rotate the DEK: fresh key, re-encrypt every value, re-wrap for the
    /// same recipients. The one command that rewrites the whole file.
    Rotate {
        /// Encrypted file (mutated in place).
        file: PathBuf,
        /// Audit note for why the rotation happened (logged, not yet stored).
        #[arg(long, value_name = "MSG")]
        reason: Option<String>,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
    },
    /// Manage recipients without rotating the DEK (add / remove / list).
    /// Body ciphertexts and the MAC stay byte-identical.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Read-only decrypt to stdout. With --path, print just one value.
    View {
        /// Encrypted file.
        file: PathBuf,
        /// Dotted path to extract (e.g. `db.password`). Whole file if omitted.
        #[arg(long, value_name = "PATH")]
        path: Option<String>,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
    },
    /// Set one value (read from stdin) through the diff-aware encrypt path.
    /// Value never appears in argv. Mutates the file in place.
    Set {
        /// Encrypted file (mutated in place).
        file: PathBuf,
        /// Dotted path to set (e.g. `db.password`).
        path: String,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
    },
    /// Remove one value through the diff-aware encrypt path. Mutates in place.
    Unset {
        /// Encrypted file (mutated in place).
        file: PathBuf,
        /// Dotted path to remove (e.g. `db.password`).
        path: String,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
    },
    /// [plumbing] Print the `kerf:` block (without DEKs) as JSON.
    Metadata {
        /// Encrypted file.
        file: PathBuf,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
    },
    /// [plumbing] Print the recipient list (without DEKs) as JSON.
    Recipients {
        /// Encrypted file.
        file: PathBuf,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
    },
    /// [plumbing] Exit 0 if `path`'s leaf key is encrypted per the file's
    /// regex, exit 1 otherwise. Quiet — the exit code is the signal.
    PathEncrypted {
        /// Encrypted file.
        file: PathBuf,
        /// Dotted path to test (e.g. `db.password`).
        path: String,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
    },
    /// [plumbing] Whole-file MAC operations.
    Mac {
        /// Encrypted file.
        file: PathBuf,
        /// Verify the MAC. Currently the only mode; required.
        #[arg(long)]
        verify: bool,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
    },
}

/// `kerf keys` subcommands. Recipient management never touches the DEK.
#[derive(Subcommand, Debug)]
enum KeysCommand {
    /// Wrap the existing DEK for new recipient(s) and append them.
    Add {
        /// Encrypted file (mutated in place).
        file: PathBuf,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
        #[command(flatten)]
        recipients: RecipientFlags,
    },
    /// Remove matching recipient(s). Refuses to remove the last one.
    Remove {
        /// Encrypted file (mutated in place).
        file: PathBuf,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
        #[command(flatten)]
        recipients: RecipientFlags,
    },
    /// List the file's recipients (no DEKs).
    List {
        /// Encrypted file.
        file: PathBuf,
        /// Force the file format (overrides extension detection).
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    // `identity` is a global flag (see `IdentityFlags`); pull it out once and
    // hand it to whichever subcommand needs it. Match arms are exclusive, so
    // moving it into the chosen arm is fine.
    let Cli {
        command, identity, ..
    } = cli;

    let result = match command {
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
        } => run::decrypt(run::DecryptArgs {
            file,
            output,
            format,
            identity,
        }),
        Command::Keygen { output } => run::keygen(output),
        Command::Verify { file, format } => run::verify(run::VerifyArgs {
            file,
            format,
            identity,
        }),
        Command::Init {
            recipients,
            output,
            path_regex,
            encrypted_regex,
            mac_all,
        } => config::init(config::InitArgs {
            recipients,
            output,
            path_regex,
            encrypted_regex,
            mac_all,
        }),
        Command::Rotate {
            file,
            reason,
            format,
        } => run::rotate(run::RotateArgs {
            file,
            format,
            reason,
            identity,
        }),
        Command::Keys { command } => match command {
            KeysCommand::Add {
                file,
                format,
                recipients,
            } => keys::add(keys::KeysAddArgs {
                file,
                format,
                recipients,
                identity,
            }),
            KeysCommand::Remove {
                file,
                format,
                recipients,
            } => keys::remove(keys::KeysRemoveArgs {
                file,
                format,
                recipients,
            }),
            KeysCommand::List { file, format } => keys::list(file, format),
        },
        Command::View { file, path, format } => run::view(run::ViewArgs {
            file,
            path,
            format,
            identity,
        }),
        Command::Set { file, path, format } => run::set(run::SetArgs {
            file,
            path,
            format,
            identity,
        }),
        Command::Unset { file, path, format } => run::unset(run::UnsetArgs {
            file,
            path,
            format,
            identity,
        }),
        Command::Metadata { file, format } => plumbing::metadata(file, format),
        Command::Recipients { file, format } => plumbing::recipients(file, format),
        Command::PathEncrypted { file, path, format } => {
            plumbing::path_encrypted(file, path, format)
        }
        Command::Mac {
            file,
            verify,
            format,
        } => {
            if verify {
                run::mac_verify(run::VerifyArgs {
                    file,
                    format,
                    identity,
                })
            } else {
                Err(CliError::Usage("kerf mac requires --verify".into()))
            }
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        // Predicate commands (e.g. path-encrypted) signal a clean "false" via
        // exit 1 with no diagnostic — the exit code is the contract.
        Err(CliError::Predicate) => ExitCode::from(1),
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

    /// A predicate plumbing command (e.g. `path-encrypted`) returned false.
    /// Maps to exit 1 with no message — the exit code is the signal.
    #[error("")]
    Predicate,

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
            Self::Unimplemented | Self::Other(_) | Self::Predicate => exit::GENERIC,
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
