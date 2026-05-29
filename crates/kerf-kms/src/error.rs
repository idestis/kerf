//! Errors produced by `kerf-kms`.

use thiserror::Error;

/// Errors produced by `kerf-kms`.
#[derive(Debug, Error)]
pub enum Error {
    /// Recipient string failed to parse (bad age recipient, bad KMS ARN, etc.).
    #[error("invalid recipient spec: {0}")]
    ParseRecipient(String),

    /// Failed to read or parse an age identity file.
    #[error("identity error: {0}")]
    Identity(String),

    /// Wrapping the DEK failed.
    #[error("wrap failed: {0}")]
    Wrap(String),

    /// Unwrapping the DEK failed — wrong identity, or wrapped DEK is corrupt.
    #[error("unwrap failed: {0}")]
    Unwrap(String),

    /// Base64 decode of an on-disk wrapped DEK failed.
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),

    /// I/O error reading an identity file.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Unwrapped DEK had the wrong length (must be exactly 32 bytes).
    #[error("unwrapped DEK has wrong length: got {got}, expected 32")]
    DekLength {
        /// Actual byte count returned by the recipient.
        got: usize,
    },
}
