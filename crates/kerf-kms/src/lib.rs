//! `kerf-kms` — recipient implementations for kerf.
//!
//! v0.1 ships only the `age` recipient, which is local-only (no network).
//! AWS, GCP, and Azure KMS recipients are stubbed pending the integration-
//! test harness (`LocalStack` + emulators) called for in CLAUDE.md.
//!
//! Why this lives in its own crate: it's the only place async appears.
//! Keeping `kerf-core` sync makes the crypto easy to fuzz and test.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod age;
#[cfg(feature = "aws-kms")]
pub mod aws;
mod error;
#[cfg(feature = "gcp-kms")]
pub mod gcp;
pub mod recipient;

pub use error::Error;
pub use recipient::{Identity, Recipient, WrappedDek};

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;
