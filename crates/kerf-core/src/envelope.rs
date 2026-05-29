//! On-disk `ENC[...]` envelope.
//!
//! Format (SPEC § 4.3, single line, no whitespace):
//!
//! ```text
//! ENC[AES-GCM,n:<b64 nonce>,c:<b64 ciphertext>,t:<b64 tag>]
//! ```

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::crypto::{Nonce, Sealed, TAG_LEN};
use crate::error::Error;

const NONCE_LEN: usize = 12;

/// Parsed `ENC[...]` envelope.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// 96-bit nonce.
    pub nonce: [u8; NONCE_LEN],
    /// AEAD output.
    pub sealed: Sealed,
}

impl Envelope {
    /// Serialize to the canonical on-disk string. Always a single line.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "ENC[AES-GCM,n:{},c:{},t:{}]",
            B64.encode(self.nonce),
            B64.encode(&self.sealed.ciphertext),
            B64.encode(self.sealed.tag),
        )
    }

    /// Parse an envelope string back into its fields. Strict — unknown fields
    /// or wrong lengths are rejected.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let inner = s
            .strip_prefix("ENC[AES-GCM,")
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(|| Error::Envelope("missing ENC[AES-GCM,...] frame".into()))?;

        let mut nonce: Option<Vec<u8>> = None;
        let mut ciphertext: Option<Vec<u8>> = None;
        let mut tag: Option<Vec<u8>> = None;

        for field in inner.split(',') {
            let (key, value) = field
                .split_once(':')
                .ok_or_else(|| Error::Envelope(format!("malformed field {field:?}")))?;
            let bytes = B64
                .decode(value)
                .map_err(|e| Error::Envelope(format!("base64 decode {key:?}: {e}")))?;
            match key {
                "n" => nonce = Some(bytes),
                "c" => ciphertext = Some(bytes),
                "t" => tag = Some(bytes),
                _ => return Err(Error::Envelope(format!("unknown field {key:?}"))),
            }
        }

        let nonce_bytes = nonce.ok_or_else(|| Error::Envelope("missing n:".into()))?;
        let ciphertext = ciphertext.ok_or_else(|| Error::Envelope("missing c:".into()))?;
        let tag_bytes = tag.ok_or_else(|| Error::Envelope("missing t:".into()))?;

        if nonce_bytes.len() != NONCE_LEN {
            return Err(Error::Envelope(format!(
                "nonce must be {NONCE_LEN} bytes, got {}",
                nonce_bytes.len()
            )));
        }
        if tag_bytes.len() != TAG_LEN {
            return Err(Error::Envelope(format!(
                "tag must be {TAG_LEN} bytes, got {}",
                tag_bytes.len()
            )));
        }

        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(&nonce_bytes);
        let mut tag_arr = [0u8; TAG_LEN];
        tag_arr.copy_from_slice(&tag_bytes);

        Ok(Self {
            nonce: nonce_arr,
            sealed: Sealed {
                ciphertext,
                tag: tag_arr,
            },
        })
    }

    /// Reconstruct a `Nonce` from the envelope for the decrypt call.
    #[must_use]
    pub fn nonce(&self) -> Nonce {
        Nonce::from_bytes(self.nonce)
    }

    /// Quick check that a string looks like an `ENC[...]` envelope. Used
    /// by the YAML walker to decide "is this an already-encrypted value or
    /// a plaintext string to encrypt".
    #[must_use]
    pub fn looks_like(s: &str) -> bool {
        s.starts_with("ENC[AES-GCM,") && s.ends_with(']')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let env = Envelope {
            nonce: [1; NONCE_LEN],
            sealed: Sealed {
                ciphertext: b"opaque".to_vec(),
                tag: [2; TAG_LEN],
            },
        };
        let s = env.encode();
        let parsed = Envelope::parse(&s).unwrap();
        assert_eq!(parsed.nonce, env.nonce);
        assert_eq!(parsed.sealed.ciphertext, env.sealed.ciphertext);
        assert_eq!(parsed.sealed.tag, env.sealed.tag);
    }

    #[test]
    fn rejects_unknown_field() {
        let s = "ENC[AES-GCM,n:AAAAAAAAAAAAAAAA,c:AA==,t:AAAAAAAAAAAAAAAAAAAAAA==,x:AA==]";
        assert!(Envelope::parse(s).is_err());
    }

    #[test]
    fn rejects_wrong_nonce_length() {
        let s = "ENC[AES-GCM,n:AA==,c:AA==,t:AAAAAAAAAAAAAAAAAAAAAA==]";
        assert!(Envelope::parse(s).is_err());
    }

    #[test]
    fn looks_like_works() {
        assert!(Envelope::looks_like("ENC[AES-GCM,n:x,c:y,t:z]"));
        assert!(!Envelope::looks_like("hunter2"));
        assert!(!Envelope::looks_like("ENC[CHACHA,n:x,c:y,t:z]"));
    }
}
