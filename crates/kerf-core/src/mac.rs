//! File-level MAC. SPEC § 4.5.
//!
//! 1. Walk the file in canonical order (depth-first, keys lexicographically
//!    sorted within each map).
//! 2. For each encrypted leaf, append `<path>:<plaintext>\n` to a running
//!    MAC input buffer.
//! 3. Compute `HMAC-SHA256(DEK, mac_input)` — 32 bytes.
//! 4. Encrypt those 32 bytes with AES-256-GCM under the same DEK, AAD =
//!    the literal bytes `__kerf_mac__`. Store as a single `ENC[...]`
//!    envelope in `kerf.mac`.
//!
//! Verification is the reverse. Mismatch is fatal — no partial decrypt is
//! returned, and the CLI surfaces exit code 11.
//!
//! Why wrap the HMAC tag in AES-GCM rather than emit the tag directly?
//! The wrap binds the MAC to the same DEK it authenticates, prevents a
//! by-design "MAC-only" forgery against the bare HMAC output, and keeps
//! the kerf block visually consistent (everything sensitive is an
//! `ENC[...]` envelope).

use aws_lc_rs::hmac;
use serde_yaml::Value;
use subtle::ConstantTimeEq;

use crate::crypto::{open, seal, Dek, Nonce, Sealed};
use crate::envelope::Envelope;
use crate::error::{Error, Result};

/// AAD used when wrapping/unwrapping the MAC envelope.
const MAC_AAD: &[u8] = b"__kerf_mac__";

/// Build the canonical MAC input for an encrypted file.
///
/// `plaintexts` maps each encrypted leaf's dotted path to its plaintext bytes.
/// We sort the paths and emit `<path>:<plaintext>\n` in order. The trailing
/// newline matters — a path ending exactly where another path's prefix ends
/// would otherwise collide.
fn build_mac_input(plaintexts: &std::collections::HashMap<String, Vec<u8>>) -> Vec<u8> {
    let mut keys: Vec<&String> = plaintexts.keys().collect();
    keys.sort();
    let mut input = Vec::new();
    for key in keys {
        input.extend_from_slice(key.as_bytes());
        input.push(b':');
        input.extend_from_slice(&plaintexts[key]);
        input.push(b'\n');
    }
    input
}

/// Compute and seal the MAC for an encrypted tree.
///
/// `plaintexts` is the same `LeafMap` the engine already builds — caller
/// passes it through so we don't decrypt the file twice.
///
/// The kerf rule applies to the MAC envelope exactly as it does to value
/// envelopes: if `previous` authenticates the *same* HMAC tag we just
/// computed, we keep it byte-for-byte (same nonce, ciphertext, tag) so a
/// no-op re-encrypt produces no diff. A fresh nonce is generated only when
/// the tag has actually changed — i.e. when some encrypted leaf changed,
/// was added, or was removed. This upholds the AES-GCM nonce-uniqueness
/// requirement: a fresh nonce is used for every distinct plaintext, and the
/// only reuse is of an envelope whose plaintext is provably identical.
///
/// `previous` is the prior `kerf.mac` envelope string, if the file had one.
/// If it fails to parse or open under `dek` (e.g. after DEK rotation), we
/// fall through to a fresh seal.
#[allow(clippy::implicit_hasher)] // internal API; LeafMap uses the default hasher
pub fn compute(
    dek: &Dek,
    plaintexts: &std::collections::HashMap<String, Vec<u8>>,
    previous: Option<&str>,
) -> Result<String> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, dek.for_recipient());
    let input = build_mac_input(plaintexts);
    let tag = hmac::sign(&key, &input);

    // The kerf rule for the MAC: reuse the previous envelope verbatim if it
    // authenticates the identical tag under this DEK. Constant-time compare.
    if let Some(prev) = previous {
        if let Ok(envelope) = Envelope::parse(prev) {
            if let Ok(old_tag) = open(dek, envelope.nonce(), &envelope.sealed, MAC_AAD) {
                if old_tag.ct_eq(tag.as_ref()).into() {
                    return Ok(prev.to_string());
                }
            }
        }
    }

    let nonce = Nonce::random();
    let nonce_bytes = *nonce.as_bytes();
    let sealed: Sealed = seal(dek, nonce, tag.as_ref(), MAC_AAD)?;
    let envelope = Envelope {
        nonce: nonce_bytes,
        sealed,
    };
    Ok(envelope.encode())
}

/// Verify a stored MAC against the current encrypted-leaf set.
///
/// Two distinct failure modes:
///
/// - Envelope decrypt fails (wrong key, wrong AAD, tampered envelope) →
///   `Error::Decrypt`. At the CLI boundary this becomes exit 11.
/// - HMAC tag doesn't match the recomputed value → also `Error::Decrypt`.
///   Same exit code; from a forensic responder's perspective both mean
///   "this file is not what it claims to be".
///
/// We use constant-time comparison even though both inputs are the same
/// length — defense in depth against timing side channels.
#[allow(clippy::implicit_hasher)] // internal API; LeafMap uses the default hasher
pub fn verify(
    dek: &Dek,
    plaintexts: &std::collections::HashMap<String, Vec<u8>>,
    stored: &str,
) -> Result<()> {
    let envelope = Envelope::parse(stored)?;
    let expected_tag = open(dek, envelope.nonce(), &envelope.sealed, MAC_AAD)?;

    let key = hmac::Key::new(hmac::HMAC_SHA256, dek.for_recipient());
    let input = build_mac_input(plaintexts);
    let actual_tag = hmac::sign(&key, &input);

    if expected_tag.ct_eq(actual_tag.as_ref()).into() {
        Ok(())
    } else {
        Err(Error::Decrypt)
    }
}

/// Convenience: extract `mac` field from a kerf block.
pub fn read_from_value(block: &Value) -> Option<String> {
    block.get("mac").and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn sample_leaves() -> HashMap<String, Vec<u8>> {
        let mut m = HashMap::new();
        m.insert("db.password".into(), b"hunter2".to_vec());
        m.insert("api.token".into(), b"ghp_xxxxxxx".to_vec());
        m
    }

    #[test]
    fn roundtrip() {
        let dek = Dek::generate();
        let leaves = sample_leaves();
        let envelope = compute(&dek, &leaves, None).unwrap();
        verify(&dek, &leaves, &envelope).unwrap();
    }

    #[test]
    fn unchanged_leaves_reuse_envelope_verbatim() {
        // The kerf rule for the MAC: a no-op re-encrypt keeps the envelope
        // byte-identical (same nonce + ciphertext + tag) so git sees no diff.
        let dek = Dek::generate();
        let leaves = sample_leaves();
        let first = compute(&dek, &leaves, None).unwrap();
        let second = compute(&dek, &leaves, Some(&first)).unwrap();
        assert_eq!(first, second, "no-op re-encrypt must not churn the MAC");
        verify(&dek, &leaves, &second).unwrap();
    }

    #[test]
    fn changed_leaves_reroll_nonce() {
        // The corollary: when an encrypted leaf changes, the HMAC tag changes,
        // so the MAC envelope MUST be resealed with a fresh nonce.
        let dek = Dek::generate();
        let leaves = sample_leaves();
        let first = compute(&dek, &leaves, None).unwrap();

        let mut changed = leaves.clone();
        changed.insert("db.password".into(), b"rotated".to_vec());
        let second = compute(&dek, &changed, Some(&first)).unwrap();
        assert_ne!(first, second, "a changed leaf must reroll the MAC");
        verify(&dek, &changed, &second).unwrap();
    }

    #[test]
    fn previous_under_different_dek_is_ignored() {
        // After DEK rotation the prior envelope won't open; we must fall
        // through to a fresh seal rather than error or reuse it.
        let old_dek = Dek::generate();
        let leaves = sample_leaves();
        let prior = compute(&old_dek, &leaves, None).unwrap();

        let new_dek = Dek::generate();
        let fresh = compute(&new_dek, &leaves, Some(&prior)).unwrap();
        verify(&new_dek, &leaves, &fresh).unwrap();
        assert!(verify(&old_dek, &leaves, &fresh).is_err());
    }

    #[test]
    fn tampered_plaintext_fails() {
        let dek = Dek::generate();
        let leaves = sample_leaves();
        let envelope = compute(&dek, &leaves, None).unwrap();

        let mut tampered = leaves.clone();
        tampered.insert("db.password".into(), b"different".to_vec());
        let err = verify(&dek, &tampered, &envelope).unwrap_err();
        assert!(matches!(err, Error::Decrypt));
    }

    #[test]
    fn added_leaf_fails() {
        let dek = Dek::generate();
        let leaves = sample_leaves();
        let envelope = compute(&dek, &leaves, None).unwrap();

        let mut extra = leaves.clone();
        extra.insert("db.extra".into(), b"sneaked".to_vec());
        let err = verify(&dek, &extra, &envelope).unwrap_err();
        assert!(matches!(err, Error::Decrypt));
    }

    #[test]
    fn flipping_envelope_bit_fails() {
        let dek = Dek::generate();
        let leaves = sample_leaves();
        let envelope = compute(&dek, &leaves, None).unwrap();
        // flip one base64 char inside the ciphertext — the envelope still
        // parses but the tag check fails.
        let mut bytes: Vec<u8> = envelope.into_bytes();
        // Find the `c:` marker and flip a byte just after it.
        let idx = bytes
            .windows(2)
            .position(|w| w == b"c:")
            .expect("envelope has c:");
        bytes[idx + 4] ^= 1;
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(verify(&dek, &leaves, &tampered).is_err());
    }

    #[test]
    fn wrong_dek_fails() {
        let dek = Dek::generate();
        let leaves = sample_leaves();
        let envelope = compute(&dek, &leaves, None).unwrap();
        let other = Dek::generate();
        assert!(verify(&other, &leaves, &envelope).is_err());
    }
}
