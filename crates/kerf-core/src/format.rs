//! YAML format support — walk, encrypt, decrypt.
//!
//! Notes:
//!
//! - Key order is preserved (via `serde_yaml::Mapping`'s `IndexMap` backing).
//! - Comments, whitespace, and quoting survive a round trip through
//!   [`crate::FileFormat::serialize_preserving`], which patches the original
//!   text rather than reserializing the value model (SPEC § 11.1). This
//!   `walk_*` layer operates on the value tree; the preserving serializer
//!   reconciles that tree back against the original bytes.

use std::collections::HashMap;

use regex::Regex;
use serde_yaml::Value;

use crate::crypto::{open, seal, Dek, Nonce};
use crate::envelope::Envelope;
use crate::error::{Error, Result};

/// Walk a YAML value and produce one entry per encryptable leaf, keyed by
/// canonical dotted path. Used by the decrypt path to reconstruct
/// `path -> plaintext` maps.
pub type LeafMap = HashMap<String, Vec<u8>>;

/// Walk-encrypt: visit every leaf, encrypt the ones matching `encrypted_regex`.
///
/// If `previous` is `Some`, this implements the kerf rule: for each leaf, if
/// the new plaintext matches the previous plaintext at the same path, the
/// previous envelope string is copied byte-for-byte. Only changed (or new)
/// leaves get a fresh nonce + encrypt.
///
/// The walker mutates `value` in place.
pub fn walk_encrypt(
    value: &mut Value,
    encrypted_regex: &Regex,
    dek: &Dek,
    previous: Option<&PreviousFile>,
) -> Result<()> {
    walk_encrypt_inner(value, "", encrypted_regex, dek, previous)
}

/// Companion to `walk_encrypt`: visit every encrypted leaf and replace it
/// with its plaintext.
pub fn walk_decrypt(value: &mut Value, dek: &Dek) -> Result<()> {
    walk_decrypt_inner(value, "", dek)
}

/// Decrypt a value tree without mutating it — used to build the
/// `path -> plaintext` map for the diff-aware encrypt path.
pub fn collect_plaintexts(value: &Value, dek: &Dek) -> Result<LeafMap> {
    let mut out = LeafMap::new();
    collect_inner(value, "", dek, &mut out)?;
    Ok(out)
}

/// Snapshot of the previous file used for diff-aware re-encryption.
#[derive(Debug, Default)]
pub struct PreviousFile {
    /// `path -> (envelope_string, decrypted_plaintext)` for every encrypted leaf.
    pub by_path: HashMap<String, (String, Vec<u8>)>,
    /// The previous `kerf.mac` envelope string, if the file had one. Lets the
    /// engine keep the MAC byte-identical when no encrypted leaf changed.
    pub mac: Option<String>,
}

impl PreviousFile {
    /// Build a snapshot from a decrypted-but-not-mutated previous file.
    /// `original` must still contain the `ENC[...]` envelopes; we read both
    /// the envelope string and decrypt it for plaintext comparison. The
    /// caller is responsible for setting [`PreviousFile::mac`] — the kerf
    /// block is stripped before this walk, so the MAC isn't visible here.
    pub fn build(original: &Value, dek: &Dek) -> Result<Self> {
        let mut by_path = HashMap::new();
        build_inner(original, "", dek, &mut by_path)?;
        Ok(Self { by_path, mac: None })
    }
}

// ──── walk_encrypt ───────────────────────────────────────────────────────

fn walk_encrypt_inner(
    value: &mut Value,
    path: &str,
    encrypted_regex: &Regex,
    dek: &Dek,
    previous: Option<&PreviousFile>,
) -> Result<()> {
    match value {
        Value::Mapping(map) => {
            for (k, v) in map.iter_mut() {
                let key_str = key_as_string(k)?;
                validate_key(&key_str)?;
                let new_path = push_path(path, &key_str);
                if is_nested(v) {
                    walk_encrypt_inner(v, &new_path, encrypted_regex, dek, previous)?;
                } else if encrypted_regex.is_match(&key_str) {
                    encrypt_leaf(v, &new_path, dek, previous)?;
                }
            }
        }
        Value::Sequence(seq) => {
            for (i, item) in seq.iter_mut().enumerate() {
                let new_path = format!("{path}[{i}]");
                walk_encrypt_inner(item, &new_path, encrypted_regex, dek, previous)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn encrypt_leaf(
    v: &mut Value,
    path: &str,
    dek: &Dek,
    previous: Option<&PreviousFile>,
) -> Result<()> {
    let plaintext = scalar_to_bytes(v).ok_or_else(|| Error::NonScalar {
        path: path.to_string(),
    })?;

    // The kerf rule: copy the previous envelope verbatim if the plaintext
    // is unchanged at this path. Fresh nonce only on real change.
    if let Some(prev) = previous {
        if let Some((envelope_str, old_plain)) = prev.by_path.get(path) {
            if *old_plain == plaintext {
                *v = Value::String(envelope_str.clone());
                return Ok(());
            }
        }
    }

    let nonce = Nonce::random();
    let nonce_bytes = *nonce.as_bytes();
    let sealed = seal(dek, nonce, &plaintext, path.as_bytes())?;
    let envelope = Envelope {
        nonce: nonce_bytes,
        sealed,
    };
    *v = Value::String(envelope.encode());
    Ok(())
}

// ──── walk_decrypt ───────────────────────────────────────────────────────

fn walk_decrypt_inner(value: &mut Value, path: &str, dek: &Dek) -> Result<()> {
    match value {
        Value::Mapping(map) => {
            for (k, v) in map.iter_mut() {
                let key_str = key_as_string(k)?;
                let new_path = push_path(path, &key_str);
                if is_nested(v) {
                    walk_decrypt_inner(v, &new_path, dek)?;
                } else if let Value::String(s) = v {
                    if Envelope::looks_like(s) {
                        let envelope = Envelope::parse(s)?;
                        let opened =
                            open(dek, envelope.nonce(), &envelope.sealed, new_path.as_bytes())
                                .map_err(|_| Error::AadMismatch(new_path.clone()))?;
                        *v = bytes_to_scalar(&opened);
                    }
                }
            }
        }
        Value::Sequence(seq) => {
            for (i, item) in seq.iter_mut().enumerate() {
                let new_path = format!("{path}[{i}]");
                walk_decrypt_inner(item, &new_path, dek)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ──── plaintext collection (helper for PreviousFile) ──────────────────────

fn collect_inner(value: &Value, path: &str, dek: &Dek, out: &mut LeafMap) -> Result<()> {
    match value {
        Value::Mapping(map) => {
            for (k, v) in map {
                let key_str = key_as_string(k)?;
                let new_path = push_path(path, &key_str);
                if is_nested(v) {
                    collect_inner(v, &new_path, dek, out)?;
                } else if let Value::String(s) = v {
                    if Envelope::looks_like(s) {
                        let envelope = Envelope::parse(s)?;
                        let opened =
                            open(dek, envelope.nonce(), &envelope.sealed, new_path.as_bytes())
                                .map_err(|_| Error::AadMismatch(new_path.clone()))?;
                        out.insert(new_path, opened);
                    }
                }
            }
        }
        Value::Sequence(seq) => {
            for (i, item) in seq.iter().enumerate() {
                let new_path = format!("{path}[{i}]");
                collect_inner(item, &new_path, dek, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn build_inner(
    value: &Value,
    path: &str,
    dek: &Dek,
    out: &mut HashMap<String, (String, Vec<u8>)>,
) -> Result<()> {
    match value {
        Value::Mapping(map) => {
            for (k, v) in map {
                let key_str = key_as_string(k)?;
                let new_path = push_path(path, &key_str);
                if is_nested(v) {
                    build_inner(v, &new_path, dek, out)?;
                } else if let Value::String(s) = v {
                    if Envelope::looks_like(s) {
                        let envelope = Envelope::parse(s)?;
                        let opened =
                            open(dek, envelope.nonce(), &envelope.sealed, new_path.as_bytes())
                                .map_err(|_| Error::AadMismatch(new_path.clone()))?;
                        out.insert(new_path, (s.clone(), opened));
                    }
                }
            }
        }
        Value::Sequence(seq) => {
            for (i, item) in seq.iter().enumerate() {
                let new_path = format!("{path}[{i}]");
                build_inner(item, &new_path, dek, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ──── helpers ────────────────────────────────────────────────────────────

fn is_nested(v: &Value) -> bool {
    matches!(v, Value::Mapping(_) | Value::Sequence(_))
}

fn key_as_string(k: &Value) -> Result<String> {
    match k {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        _ => Err(Error::KerfBlock(format!("unsupported map key type: {k:?}"))),
    }
}

fn push_path(prefix: &str, segment: &str) -> String {
    if prefix.is_empty() {
        segment.to_string()
    } else {
        format!("{prefix}.{segment}")
    }
}

/// SPEC § 4.4: paths use `.` as separator and `[N]` for array indices, so
/// keys containing those literal characters must be rejected at load time.
fn validate_key(key: &str) -> Result<()> {
    if key.contains('.') || key.contains('[') {
        Err(Error::PathReserved {
            path: key.to_string(),
        })
    } else {
        Ok(())
    }
}

fn scalar_to_bytes(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::String(s) => Some(s.as_bytes().to_vec()),
        Value::Bool(b) => Some(b.to_string().into_bytes()),
        Value::Number(n) => Some(n.to_string().into_bytes()),
        Value::Null => Some(b"".to_vec()),
        _ => None,
    }
}

/// Decrypted bytes always come back as YAML strings — the original type
/// (number, bool, etc.) is lost on encrypt. For a secret value this is
/// almost always what you want: "1234" stays a string, not a number.
fn bytes_to_scalar(bytes: &[u8]) -> Value {
    Value::String(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_regex() -> Regex {
        Regex::new(r"^(password|token|key|secret|credential)$").unwrap()
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let dek = Dek::generate();
        let yaml = "db:\n  host: db.prod\n  password: hunter2\napi:\n  token: abc123\n";
        let mut tree: Value = serde_yaml::from_str(yaml).unwrap();
        walk_encrypt(&mut tree, &default_regex(), &dek, None).unwrap();
        walk_decrypt(&mut tree, &dek).unwrap();

        let pw = tree["db"]["password"].as_str().unwrap();
        let tk = tree["api"]["token"].as_str().unwrap();
        assert_eq!(pw, "hunter2");
        assert_eq!(tk, "abc123");
    }

    #[test]
    fn kerf_rule_byte_identity_for_unchanged_values() {
        let dek = Dek::generate();
        let yaml = "db:\n  password: hunter2\napi:\n  token: abc123\n";
        let mut first: Value = serde_yaml::from_str(yaml).unwrap();
        walk_encrypt(&mut first, &default_regex(), &dek, None).unwrap();

        // Build previous snapshot from the first encrypt result.
        let prev = PreviousFile::build(&first, &dek).unwrap();

        // Change ONLY the password; re-encrypt with the previous snapshot.
        let yaml2 = "db:\n  password: NEW_pw\napi:\n  token: abc123\n";
        let mut second: Value = serde_yaml::from_str(yaml2).unwrap();
        walk_encrypt(&mut second, &default_regex(), &dek, Some(&prev)).unwrap();

        // api.token envelope MUST be byte-identical; db.password MUST differ.
        assert_eq!(
            first["api"]["token"], second["api"]["token"],
            "unchanged value's envelope must be byte-identical (the kerf rule)"
        );
        assert_ne!(
            first["db"]["password"], second["db"]["password"],
            "changed value's envelope must use a fresh nonce"
        );
    }

    #[test]
    fn rejects_keys_with_reserved_chars() {
        let dek = Dek::generate();
        let yaml = "weird.key:\n  password: hunter2\n";
        let mut tree: Value = serde_yaml::from_str(yaml).unwrap();
        let err = walk_encrypt(&mut tree, &default_regex(), &dek, None).unwrap_err();
        assert!(matches!(err, Error::PathReserved { .. }));
    }
}
