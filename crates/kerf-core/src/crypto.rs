//! AES-256-GCM primitive with typed `Dek` and `Nonce`.
//!
//! Security properties this module upholds:
//!
//! - The `Dek` is wrapped in `secrecy::Secret` and zeroized on drop. Its
//!   `Debug` impl prints `[REDACTED]`; do not `expose_secret()` for logging.
//! - The `Nonce` type is `#[must_use]` and consumed on encrypt — the type
//!   system makes nonce reuse a compile-time error within this module.
//! - Nonce generation goes directly to the OS CSPRNG via `aws_lc_rs::rand`.
//!   Never use a seeded PRNG here. See SPEC § 5 and CLAUDE.md.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce as LcNonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Length of the AES-GCM authentication tag, in bytes.
pub const TAG_LEN: usize = 16;

/// Data-encryption key — 32 random bytes for AES-256-GCM.
///
/// Wrapped in `SecretBox` so it is zeroized on drop and prints `[REDACTED]`.
#[derive(Debug)]
pub struct Dek(SecretBox<DekBytes>);

#[derive(Zeroize, ZeroizeOnDrop)]
struct DekBytes([u8; 32]);

impl Dek {
    /// Generate a fresh DEK from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .expect("OS CSPRNG must be available");
        Self(SecretBox::new(Box::new(DekBytes(bytes))))
    }

    /// Construct a DEK from existing bytes — only callers who unwrap from a
    /// recipient (e.g. age, KMS Decrypt) should use this.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBox::new(Box::new(DekBytes(bytes))))
    }

    /// Expose the underlying bytes. Callers must not log or persist the
    /// returned slice. Keep the borrow tight.
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0.expose_secret().0
    }

    /// Borrow the 32-byte DEK for a `Recipient::wrap` implementation.
    ///
    /// This is the **only** public path to the raw bytes — recipients in
    /// `kerf-kms` need them to call the underlying wrap operation (age,
    /// KMS Encrypt). Do NOT log, print, format, or persist these bytes;
    /// keep the borrow tight and drop it as soon as the wrap is done.
    #[must_use]
    pub fn for_recipient(&self) -> &[u8; 32] {
        self.expose()
    }
}

/// AES-GCM nonce — 96 bits, generated fresh per encryption operation.
///
/// `#[must_use]` and consumed on encrypt — the type prevents accidental reuse
/// at compile time. Do not add `Clone` or `Copy`.
#[must_use]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Draw a fresh nonce from the OS CSPRNG. 96-bit random nonces are safe
    /// under AES-GCM for up to ~2^32 encryptions per key — DEK rotation
    /// gates this.
    pub fn random() -> Self {
        let mut bytes = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut bytes)
            .expect("OS CSPRNG must be available");
        Self(bytes)
    }

    /// Reconstruct a nonce from on-disk bytes (parsed out of an envelope).
    /// Only the envelope parser should call this.
    pub(crate) fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the nonce bytes for serialization into an envelope.
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl Zeroize for Nonce {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// AEAD ciphertext + 128-bit tag. Caller serializes into an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// Ciphertext bytes (same length as plaintext).
    pub ciphertext: Vec<u8>,
    /// 128-bit authentication tag.
    pub tag: [u8; TAG_LEN],
}

/// Seal plaintext under DEK with the given nonce and AAD.
///
/// AAD is the canonical dotted path of the value being encrypted (see SPEC
/// § 4.3). This binds each ciphertext to its location in the file — moving
/// it elsewhere will fail decryption.
pub fn seal(dek: &Dek, nonce: Nonce, plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let unbound = UnboundKey::new(&AES_256_GCM, dek.expose())
        .expect("AES-256-GCM accepts any 32 bytes");
    let key = LessSafeKey::new(unbound);
    let mut in_out = plaintext.to_vec();
    let lc_nonce = LcNonce::assume_unique_for_key(*nonce.as_bytes());
    let tag = key
        .seal_in_place_separate_tag(lc_nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| Error::Encrypt)?;
    let mut tag_bytes = [0u8; TAG_LEN];
    tag_bytes.copy_from_slice(tag.as_ref());
    Ok(Sealed {
        ciphertext: in_out,
        tag: tag_bytes,
    })
}

/// Open a sealed ciphertext under DEK with the given nonce and AAD.
///
/// AAD must match the value's canonical path — otherwise `Error::Decrypt`.
/// The caller distinguishes "wrong key/tampering" (exit 11) from "AAD moved"
/// (exit 12) at the file-engine layer, where the path context is known.
pub fn open(dek: &Dek, nonce: Nonce, sealed: &Sealed, aad: &[u8]) -> Result<Vec<u8>> {
    let unbound = UnboundKey::new(&AES_256_GCM, dek.expose())
        .expect("AES-256-GCM accepts any 32 bytes");
    let key = LessSafeKey::new(unbound);
    let mut in_out = Vec::with_capacity(sealed.ciphertext.len() + TAG_LEN);
    in_out.extend_from_slice(&sealed.ciphertext);
    in_out.extend_from_slice(&sealed.tag);
    let lc_nonce = LcNonce::assume_unique_for_key(*nonce.as_bytes());
    let plain = key
        .open_in_place(lc_nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| Error::Decrypt)?;
    Ok(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let dek = Dek::generate();
        let plaintext = b"hunter2";
        let aad = b"db.password";
        let nonce = Nonce::random();
        let nonce_bytes = *nonce.as_bytes();
        let sealed = seal(&dek, nonce, plaintext, aad).unwrap();
        let opened = open(&dek, Nonce::from_bytes(nonce_bytes), &sealed, aad).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn aad_mismatch_fails() {
        let dek = Dek::generate();
        let nonce = Nonce::random();
        let nonce_bytes = *nonce.as_bytes();
        let sealed = seal(&dek, nonce, b"hunter2", b"db.password").unwrap();
        let result = open(
            &dek,
            Nonce::from_bytes(nonce_bytes),
            &sealed,
            b"db.host",
        );
        assert!(result.is_err());
    }

    #[test]
    fn nonce_uniqueness_across_many_draws() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let n = Nonce::random();
            assert!(seen.insert(*n.as_bytes()), "duplicate nonce drawn");
        }
    }
}
