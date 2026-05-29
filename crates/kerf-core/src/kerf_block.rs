//! The reserved `kerf:` metadata block on disk.
//!
//! v0.1 schema (subset of SPEC § 4.2 — MAC and DEK rotation metadata land
//! later):
//!
//! ```yaml
//! kerf:
//!   version: 1
//!   cipher: aes-256-gcm
//!   recipients:
//!     - type: age
//!       recipient: age1abc...
//!       encrypted_dek: BASE64...
//!   encrypted_regex: "^(password|token|key|secret|credential)$"
//! ```

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The reserved metadata key. SPEC § 4.2.
pub const RESERVED_KEY: &str = "kerf";

/// File format version we read and write.
pub const FORMAT_VERSION: u32 = 1;

/// Cipher identifier we emit. Validated on parse; rejects anything else.
pub const CIPHER: &str = "aes-256-gcm";

/// Default encrypted-key regex (matches SOPS's `--encrypted-regex` default).
pub const DEFAULT_ENCRYPTED_REGEX: &str = r"^(password|token|key|secret|credential)$";

/// The kerf metadata block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerfBlock {
    /// On-disk schema version. Currently always `1`.
    pub version: u32,
    /// AEAD algorithm identifier — currently always `aes-256-gcm`.
    pub cipher: String,
    /// One entry per recipient with a wrapped copy of the DEK.
    pub recipients: Vec<RecipientEntry>,
    /// Regex matched against leaf keys to decide what's encrypted.
    /// Stored explicitly so decrypt knows what to expect — never re-derived.
    #[serde(default = "default_regex_string")]
    pub encrypted_regex: String,
    /// Sealed `HMAC-SHA256` over the canonical walk of encrypted leaves.
    /// Encrypted with AAD `__kerf_mac__`. See `mac.rs`. Optional on the v0.1
    /// schema to keep round-trips of files written by pre-MAC versions
    /// readable; new writes always populate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

fn default_regex_string() -> String {
    DEFAULT_ENCRYPTED_REGEX.to_string()
}

/// A single recipient's wrapped DEK. The `type` field discriminates the
/// remaining shape — for v0.1 only `age` is implemented.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum RecipientEntry {
    /// age recipient (X25519 + ChaCha20-Poly1305).
    Age {
        /// `age1...` recipient string.
        recipient: String,
        /// Wrapped DEK as base64-encoded age ciphertext.
        encrypted_dek: String,
    },
    /// AWS KMS recipient. Wrapping not implemented in v0.1.
    AwsKms {
        /// Key ARN.
        arn: String,
        /// Wrapped DEK (KMS Encrypt output, base64).
        encrypted_dek: String,
        /// Optional encryption context (authenticated by KMS).
        #[serde(skip_serializing_if = "Option::is_none", default)]
        encryption_context: Option<std::collections::BTreeMap<String, String>>,
    },
    /// GCP KMS recipient. Wrapping not implemented in v0.1.
    GcpKms {
        /// Full resource ID.
        resource_id: String,
        /// Wrapped DEK (base64).
        encrypted_dek: String,
    },
    /// Azure Key Vault recipient. Wrapping not implemented in v0.1.
    AzureKv {
        /// Full key version URL.
        key_id: String,
        /// Wrapped DEK (base64).
        encrypted_dek: String,
    },
}

impl KerfBlock {
    /// Build a fresh block for a brand-new file (no recipients yet).
    #[must_use]
    pub fn new(encrypted_regex: String) -> Self {
        Self {
            version: FORMAT_VERSION,
            cipher: CIPHER.to_string(),
            recipients: Vec::new(),
            encrypted_regex,
            mac: None,
        }
    }

    /// Validate the block on load. Catches: wrong version, wrong cipher,
    /// empty recipients (decryption would be impossible), bad regex.
    pub fn validate(&self) -> Result<()> {
        if self.version != FORMAT_VERSION {
            return Err(Error::KerfBlock(format!(
                "unsupported version {} (expected {FORMAT_VERSION})",
                self.version
            )));
        }
        if self.cipher != CIPHER {
            return Err(Error::KerfBlock(format!(
                "unsupported cipher {:?} (expected {CIPHER:?})",
                self.cipher
            )));
        }
        if self.recipients.is_empty() {
            return Err(Error::KerfBlock(
                "no recipients — file would be undecryptable".into(),
            ));
        }
        // Compile the regex up-front so a bad value is caught here, not deep
        // in the walker. Throws away the compiled object — caller compiles
        // again. Acceptable: regex compile is cheap and this is load-time.
        regex::Regex::new(&self.encrypted_regex)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_yaml() {
        let block = KerfBlock {
            version: 1,
            cipher: CIPHER.into(),
            recipients: vec![RecipientEntry::Age {
                recipient: "age1abc".into(),
                encrypted_dek: "AAAA".into(),
            }],
            encrypted_regex: DEFAULT_ENCRYPTED_REGEX.into(),
            mac: None,
        };
        let yaml = serde_yaml::to_string(&block).unwrap();
        let back: KerfBlock = serde_yaml::from_str(&yaml).unwrap();
        back.validate().unwrap();
    }

    #[test]
    fn rejects_empty_recipients() {
        let block = KerfBlock::new(DEFAULT_ENCRYPTED_REGEX.into());
        assert!(block.validate().is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let mut block = KerfBlock::new(DEFAULT_ENCRYPTED_REGEX.into());
        block.recipients.push(RecipientEntry::Age {
            recipient: "age1".into(),
            encrypted_dek: "AA".into(),
        });
        block.version = 99;
        assert!(block.validate().is_err());
    }
}
