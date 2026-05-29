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

pub mod crypto;
pub mod engine;
pub mod envelope;
pub mod error;
pub mod format;
pub mod kerf_block;
pub mod mac;

pub use crypto::{Dek, Nonce, Sealed};
pub use engine::{decrypt, default_encrypted_regex, encrypt, snapshot_previous};
pub use envelope::Envelope;
pub use error::{Error, Result};
pub use kerf_block::{KerfBlock, RecipientEntry, DEFAULT_ENCRYPTED_REGEX, RESERVED_KEY};
