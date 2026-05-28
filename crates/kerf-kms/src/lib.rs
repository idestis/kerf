//! `kerf-kms` — KMS recipient implementations.
//!
//! AWS KMS, GCP KMS, Azure Key Vault, and `age` recipients live here. This is
//! where async lives; `kerf-core` stays sync.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Errors produced by `kerf-kms`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Placeholder until real recipient impls land.
    #[error("not yet implemented")]
    Unimplemented,
}
