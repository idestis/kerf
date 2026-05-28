//! `kerf-core` — format, crypto, and diff-aware encrypt algorithm.
//!
//! See `SPEC.md` for the authoritative description of behaviour. The core
//! invariant this crate exists to uphold:
//!
//! > If a value's plaintext is unchanged across an encrypt operation, its
//! > on-disk ciphertext, nonce, and authentication tag MUST be byte-identical
//! > to the previous version.
//!
//! This crate has **no I/O and no async**. Anything that touches the filesystem,
//! the clock, the env, or the network lives in `kerf-cli` or `kerf-kms`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Errors produced by `kerf-core`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Placeholder until real variants land.
    #[error("not yet implemented")]
    Unimplemented,
}

/// Convenience alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;
