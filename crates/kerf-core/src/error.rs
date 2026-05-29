//! Typed errors for `kerf-core`. Variants map to exit codes in `kerf-cli`.

use thiserror::Error;

/// Errors produced by `kerf-core`.
///
/// Variants are kept distinct so the CLI can map them to specific exit codes
/// (see SPEC § 7.6). Collapsing variants would lose forensic signal.
#[derive(Debug, Error)]
pub enum Error {
    /// YAML failed to parse.
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// Encrypted envelope (`ENC[...]`) failed to parse.
    #[error("envelope parse error: {0}")]
    Envelope(String),

    /// AES-GCM seal failed. Should be unreachable in practice — surfaces only
    /// on misuse (e.g. wrong key length, which our types prevent).
    #[error("encrypt failed")]
    Encrypt,

    /// AES-GCM open failed — wrong key, wrong nonce, or ciphertext tampered.
    /// Maps to exit code 11 (MAC failure) at the CLI boundary.
    #[error("decrypt failed (key, nonce, or ciphertext mismatch)")]
    Decrypt,

    /// AAD mismatch on decrypt — ciphertext was moved between paths.
    /// Maps to exit code 12 at the CLI boundary.
    #[error("aad mismatch on path {0:?}")]
    AadMismatch(String),

    /// The `kerf:` metadata block is missing, malformed, or inconsistent.
    #[error("kerf block error: {0}")]
    KerfBlock(String),

    /// Plaintext value is not a scalar we can encrypt as a string.
    #[error("value at {path:?} is not an encryptable scalar")]
    NonScalar {
        /// Dotted path of the offending value.
        path: String,
    },

    /// The `encrypted_regex` failed to compile.
    #[error("invalid encrypted_regex: {0}")]
    InvalidRegex(#[from] regex::Error),

    /// Path canonicalization rejected a key containing `.` or `[`.
    #[error("path contains reserved characters: {path:?}")]
    PathReserved {
        /// The key that contains a reserved character.
        path: String,
    },
}

/// Convenience alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;
