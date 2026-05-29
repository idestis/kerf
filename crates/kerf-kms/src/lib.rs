//! `kerf-kms` — recipient implementations for kerf.
//!
//! Backends (each behind a cargo feature so unused SDKs aren't built):
//!
//! - **age** (always on) — local, no network.
//! - **`aws-kms`** (default) — AWS KMS Encrypt/Decrypt. Emulator-verified
//!   (floci / `LocalStack`).
//! - **`gcp-kms`** — GCP Cloud KMS Encrypt/Decrypt. Emulator-verified
//!   (fake-cloud-kms).
//! - **`azure-kv`** — Azure Key Vault Wrap/Unwrap Key (RSA-OAEP-256).
//!   Production path follows the documented SDK usage; emulator verification
//!   is pending (see `azure` module docs).
//!
//! Why this lives in its own crate: it's the only place async appears.
//! Keeping `kerf-core` sync makes the crypto easy to fuzz and test. Each
//! KMS backend adapts its async SDK to the sync `Recipient`/`Identity`
//! traits via a lazily-built shared tokio runtime.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod age;
#[cfg(feature = "aws-kms")]
pub mod aws;
#[cfg(feature = "azure-kv")]
pub mod azure;
mod error;
#[cfg(feature = "gcp-kms")]
pub mod gcp;
pub mod recipient;

pub use error::Error;
pub use recipient::{Identity, Recipient, WrappedDek};

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;
