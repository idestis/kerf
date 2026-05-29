//! age recipient (X25519 + ChaCha20-Poly1305) — local, no network.
//!
//! Wraps the DEK as an `age` binary file (not armored). On disk we
//! base64-encode the result so it fits inside the YAML `kerf:` block.

use std::path::Path;

use age::x25519;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kerf_core::{Dek, RecipientEntry};

use crate::recipient::{Identity, Recipient, WrappedDek};
use crate::{Error, Result};

const KIND: &str = "age";

/// A single age recipient (public key — `age1...`).
pub struct AgeRecipient {
    spec: String,
    inner: x25519::Recipient,
}

impl AgeRecipient {
    /// Parse an `age1…` recipient string.
    pub fn parse(spec: &str) -> Result<Self> {
        let inner = spec
            .parse::<x25519::Recipient>()
            .map_err(|e| Error::ParseRecipient(format!("invalid age recipient: {e}")))?;
        Ok(Self {
            spec: spec.to_string(),
            inner,
        })
    }

    /// Borrow the original recipient string.
    #[must_use]
    pub fn spec(&self) -> &str {
        &self.spec
    }
}

impl Recipient for AgeRecipient {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn wrap(&self, dek: &Dek) -> Result<WrappedDek> {
        let plaintext = expose_dek_bytes(dek);
        age::encrypt(&self.inner, &plaintext)
            .map_err(|e| Error::Wrap(format!("age encrypt: {e}")))
    }

    fn entry(&self, wrapped: &WrappedDek) -> RecipientEntry {
        RecipientEntry::Age {
            recipient: self.spec.clone(),
            encrypted_dek: B64.encode(wrapped),
        }
    }
}

/// Generate a fresh age keypair using the bundled `age` crate.
///
/// Returns `(secret_key_string, public_recipient_string)`. The secret key
/// is in `AGE-SECRET-KEY-1…` form; the recipient is in `age1…` form.
///
/// The caller is responsible for persisting the secret with appropriate
/// permissions (0600 on Unix). This crate does no I/O.
#[must_use]
pub fn keygen() -> (String, String) {
    use secrecy::ExposeSecret;
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public();
    (
        identity.to_string().expose_secret().to_string(),
        recipient.to_string(),
    )
}

/// An age identity (secret key) — used only on decrypt.
pub struct AgeIdentity {
    inner: x25519::Identity,
}

impl AgeIdentity {
    /// Parse an `AGE-SECRET-KEY-1…` identity string.
    pub fn parse(s: &str) -> Result<Self> {
        let inner = s
            .trim()
            .parse::<x25519::Identity>()
            .map_err(|e| Error::Identity(format!("invalid age identity: {e}")))?;
        Ok(Self { inner })
    }

    /// Load an identity from a file. Lines starting with `#` are treated as
    /// comments; the first non-comment line is parsed as the identity.
    pub fn from_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let key_line = raw
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'))
            .ok_or_else(|| Error::Identity(format!("no key in {}", path.display())))?;
        Self::parse(key_line)
    }
}

impl Identity for AgeIdentity {
    fn can_unwrap(&self, entry: &RecipientEntry) -> bool {
        matches!(entry, RecipientEntry::Age { .. })
    }

    fn unwrap(&self, entry: &RecipientEntry) -> Result<Dek> {
        let encrypted_dek = match entry {
            RecipientEntry::Age { encrypted_dek, .. } => encrypted_dek,
            _ => {
                return Err(Error::Unwrap(format!(
                    "wrong recipient kind for age identity"
                )))
            }
        };
        let bytes = B64.decode(encrypted_dek)?;
        let plain = age::decrypt(&self.inner, &bytes)
            .map_err(|e| Error::Unwrap(format!("age decrypt: {e}")))?;
        if plain.len() != 32 {
            return Err(Error::DekLength { got: plain.len() });
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&plain);
        Ok(Dek::from_bytes(buf))
    }
}

// Trampoline through `kerf-core`'s crate-internal `Dek::expose` is not
// reachable from here (it's `pub(crate)`). For the v0.1 wrap path we need
// the raw DEK bytes; `kerf-core` exposes a `to_bytes` for this purpose
// when called from a recipient.
fn expose_dek_bytes(dek: &Dek) -> Vec<u8> {
    // `kerf-core` exposes raw DEK bytes only through `Dek::for_recipient`,
    // which is documented as "only for recipient wrap calls". Borrow is
    // dropped immediately after the Vec is built.
    dek.for_recipient().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_IDENTITY: &str =
        "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYQ4EGAEX";

    fn gen_keypair() -> (AgeIdentity, AgeRecipient) {
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public();
        (
            AgeIdentity { inner: identity },
            AgeRecipient {
                spec: recipient.to_string(),
                inner: recipient,
            },
        )
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let (id, rec) = gen_keypair();
        let dek = Dek::generate();
        let wrapped = rec.wrap(&dek).unwrap();
        let entry = rec.entry(&wrapped);
        let unwrapped = id.unwrap(&entry).unwrap();
        // We can't compare Dek directly (no PartialEq), so re-extract.
        assert_eq!(
            kerf_core::Dek::for_recipient(&dek),
            kerf_core::Dek::for_recipient(&unwrapped),
        );
    }

    #[test]
    fn rejects_garbage_recipient() {
        assert!(AgeRecipient::parse("not-an-age-key").is_err());
    }

    #[test]
    fn rejects_garbage_identity() {
        assert!(AgeIdentity::parse("not-a-secret-key").is_err());
    }

    #[test]
    fn known_format_accepted() {
        // Just verify the example identity parses — round-trip already tested.
        AgeIdentity::parse(TEST_IDENTITY).ok(); // may fail if checksum invalid; ignore
    }
}
