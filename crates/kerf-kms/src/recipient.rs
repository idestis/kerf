//! The `Recipient` trait that all KMS / age backends implement.
//!
//! Kept synchronous in this crate because v0.1 ships only the `age` backend
//! (no network). When AWS/GCP/Azure recipients land, they'll either:
//!
//! - Take a `&tokio::runtime::Handle` argument, or
//! - Live behind their own async trait and adapt to this sync trait via
//!   `Handle::block_on` at the wiring layer.
//!
//! Deciding between those is left for the PR that adds the first KMS
//! backend; whichever path is taken, the existing `age` impl below stays
//! sync.

use kerf_core::{Dek, RecipientEntry};

use crate::Result;

/// Opaque wrapped-DEK bytes. The shape is recipient-specific (an age
/// ciphertext, a KMS Encrypt blob, …). Stored base64-encoded inside the
/// `RecipientEntry` on disk.
pub type WrappedDek = Vec<u8>;

/// Wrap and unwrap a DEK for a single recipient.
pub trait Recipient: Send + Sync {
    /// Kind discriminator — must match the `type:` tag we'll write to the
    /// kerf block. e.g. `"age"`, `"aws-kms"`.
    fn kind(&self) -> &'static str;

    /// Wrap a DEK for this recipient, returning bytes the same recipient can
    /// later unwrap. Must use a CSPRNG; deterministic wrapping is forbidden.
    fn wrap(&self, dek: &Dek) -> Result<WrappedDek>;

    /// Build the on-disk `RecipientEntry` for a freshly-wrapped DEK.
    /// The wrapped bytes get base64-encoded here so callers don't repeat
    /// themselves.
    fn entry(&self, wrapped: &WrappedDek) -> RecipientEntry;
}

/// Unwrap a DEK from a `RecipientEntry`. Decryption-side counterpart to
/// `Recipient::wrap`.
///
/// Separate trait because unwrap typically needs a credential (an age
/// identity, AWS credentials) that wrap does not.
pub trait Identity: Send + Sync {
    /// Returns `true` if this identity *might* be able to unwrap the given
    /// entry — used to filter candidate recipients before attempting a
    /// (potentially expensive) network call.
    fn can_unwrap(&self, entry: &RecipientEntry) -> bool;

    /// Attempt to unwrap. Returns the DEK on success, or an error.
    fn unwrap(&self, entry: &RecipientEntry) -> Result<Dek>;
}
