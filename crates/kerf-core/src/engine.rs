//! High-level encrypt/decrypt of a parsed YAML tree.
//!
//! The engine is the glue between `format::walk_*`, `kerf_block`, and a
//! caller-supplied `Recipient` trait. Recipient wrapping/unwrapping lives in
//! `kerf-kms`; this crate is recipient-agnostic.

use regex::Regex;
use serde_yaml::Value;

use crate::crypto::Dek;
use crate::error::{Error, Result};
use crate::format::{collect_plaintexts, walk_decrypt, walk_encrypt, PreviousFile};
use crate::kerf_block::{KerfBlock, RecipientEntry, DEFAULT_ENCRYPTED_REGEX, RESERVED_KEY};
use crate::mac;

/// What the engine produces — a fully-encrypted YAML tree with a `kerf:` block.
pub type EncryptedTree = Value;

/// What the engine consumes/produces on decrypt — a clean plaintext tree.
pub type PlainTree = Value;

/// Strip the `kerf:` reserved block from a top-level YAML mapping, returning
/// it as a typed struct. Errors if the file isn't a mapping or the block is
/// missing/malformed.
///
/// On a successful return, `tree` no longer contains the reserved key —
/// caller can hand it straight to `walk_*` without worrying about the
/// walker accidentally trying to decrypt metadata.
pub fn extract_kerf_block(tree: &mut Value) -> Result<KerfBlock> {
    let Value::Mapping(map) = tree else {
        return Err(Error::KerfBlock("file root must be a YAML mapping".into()));
    };

    let block_value = map
        .remove(Value::String(RESERVED_KEY.into()))
        .ok_or_else(|| Error::KerfBlock("missing top-level `kerf:` block".into()))?;

    let block: KerfBlock =
        serde_yaml::from_value(block_value).map_err(|e| Error::KerfBlock(e.to_string()))?;
    block.validate()?;
    Ok(block)
}

/// Insert (or replace) the `kerf:` block into a YAML mapping at the end —
/// keeps it visually separated from the user's data.
pub fn embed_kerf_block(tree: &mut Value, block: &KerfBlock) -> Result<()> {
    let Value::Mapping(map) = tree else {
        return Err(Error::KerfBlock(
            "can only embed into a YAML mapping".into(),
        ));
    };
    let block_value = serde_yaml::to_value(block)?;
    // Remove first so it always lands at the end of the map (insertion
    // order is preserved by serde_yaml's IndexMap-backed Mapping).
    map.remove(Value::String(RESERVED_KEY.into()));
    map.insert(Value::String(RESERVED_KEY.into()), block_value);
    Ok(())
}

/// Reject user files that put data under the reserved `kerf:` key.
pub fn validate_no_shadow(tree: &Value) -> Result<()> {
    if let Value::Mapping(map) = tree {
        if map.contains_key(Value::String(RESERVED_KEY.into())) {
            return Err(Error::KerfBlock(format!(
                "user data uses reserved top-level key `{RESERVED_KEY}:`"
            )));
        }
    }
    Ok(())
}

/// Encrypt a clean plaintext tree, embedding a fresh `kerf:` block.
///
/// `wrapped_deks` is `(recipient_entry, ...)` pairs already produced by the
/// caller via the `Recipient` trait — this function does not know how to
/// wrap a DEK for AWS KMS / age / etc. It just records what the caller
/// wrapped.
///
/// If `previous` is `Some`, byte-identity is preserved for unchanged values.
pub fn encrypt(
    plain: PlainTree,
    dek: &Dek,
    encrypted_regex: &Regex,
    recipients: Vec<RecipientEntry>,
    previous: Option<&PreviousFile>,
) -> Result<EncryptedTree> {
    validate_no_shadow(&plain)?;
    if recipients.is_empty() {
        return Err(Error::KerfBlock("no recipients provided".into()));
    }

    // Snapshot the plaintext leaves *before* encrypt so the MAC is computed
    // over the same paths the walker will encrypt.
    let plaintexts_for_mac = collect_leaf_plaintexts(&plain, encrypted_regex);

    let mut tree = plain;
    walk_encrypt(&mut tree, encrypted_regex, dek, previous)?;

    let mac_envelope = mac::compute(dek, &plaintexts_for_mac)?;

    let block = KerfBlock {
        version: crate::kerf_block::FORMAT_VERSION,
        cipher: crate::kerf_block::CIPHER.into(),
        recipients,
        encrypted_regex: encrypted_regex.as_str().to_string(),
        mac: Some(mac_envelope),
    };
    embed_kerf_block(&mut tree, &block)?;
    Ok(tree)
}

/// Walk plaintext tree, returning the same `path -> plaintext` map the
/// engine will MAC. Mirrors the regex match logic in `walk_encrypt`.
fn collect_leaf_plaintexts(
    tree: &Value,
    encrypted_regex: &Regex,
) -> std::collections::HashMap<String, Vec<u8>> {
    let mut out = std::collections::HashMap::new();
    walk_plaintext(tree, "", encrypted_regex, &mut out);
    out
}

fn walk_plaintext(
    value: &Value,
    path: &str,
    encrypted_regex: &Regex,
    out: &mut std::collections::HashMap<String, Vec<u8>>,
) {
    match value {
        Value::Mapping(map) => {
            for (k, v) in map {
                let Some(key_str) = key_as_string(k) else {
                    continue;
                };
                let new_path = if path.is_empty() {
                    key_str.clone()
                } else {
                    format!("{path}.{key_str}")
                };
                match v {
                    Value::Mapping(_) | Value::Sequence(_) => {
                        walk_plaintext(v, &new_path, encrypted_regex, out);
                    }
                    Value::String(_) | Value::Number(_) | Value::Bool(_)
                        if encrypted_regex.is_match(&key_str) =>
                    {
                        if let Some(bytes) = scalar_to_bytes(v) {
                            out.insert(new_path, bytes);
                        }
                    }
                    _ => {}
                }
            }
        }
        Value::Sequence(seq) => {
            for (i, item) in seq.iter().enumerate() {
                walk_plaintext(item, &format!("{path}[{i}]"), encrypted_regex, out);
            }
        }
        _ => {}
    }
}

fn key_as_string(k: &Value) -> Option<String> {
    match k {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
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

/// Decrypt a kerf-encrypted tree given the DEK. Returns a clean plaintext
/// tree (no `kerf:` block). Verifies the file MAC before returning — a
/// MAC failure surfaces as `Error::Decrypt`, which the CLI maps to exit 11.
///
/// Files written by pre-MAC versions of kerf (`kerf.mac == None`) are
/// accepted on decrypt for now; new writes always populate the MAC. This
/// will tighten to "MAC required" once the format reaches v2.
pub fn decrypt(mut encrypted: EncryptedTree, dek: &Dek) -> Result<PlainTree> {
    let block = extract_kerf_block(&mut encrypted)?;
    let plaintexts = collect_plaintexts(&encrypted, dek)?;
    if let Some(stored_mac) = &block.mac {
        mac::verify(dek, &plaintexts, stored_mac)?;
    }
    walk_decrypt(&mut encrypted, dek)?;
    Ok(encrypted)
}

/// Decrypt without mutation — returns the previous-file snapshot used to
/// drive the kerf rule on a subsequent encrypt.
pub fn snapshot_previous(encrypted: &EncryptedTree, dek: &Dek) -> Result<PreviousFile> {
    let mut clone = encrypted.clone();
    let _ = extract_kerf_block(&mut clone)?;
    PreviousFile::build(&clone, dek)
}

/// Default compiled regex — convenience for callers that don't configure.
#[must_use]
pub fn default_encrypted_regex() -> Regex {
    Regex::new(DEFAULT_ENCRYPTED_REGEX).expect("default regex is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kerf_block::RecipientEntry;

    fn fake_recipient() -> RecipientEntry {
        RecipientEntry::Age {
            recipient: "age1test".into(),
            encrypted_dek: "AAAA".into(),
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dek = Dek::generate();
        let plain: Value =
            serde_yaml::from_str("db:\n  password: hunter2\n  host: db.local\n").unwrap();
        let encrypted = encrypt(
            plain.clone(),
            &dek,
            &default_encrypted_regex(),
            vec![fake_recipient()],
            None,
        )
        .unwrap();
        // kerf block must be present
        assert!(
            matches!(encrypted, Value::Mapping(ref m) if m.contains_key(Value::String("kerf".into())))
        );
        // password must be encrypted; host must be plain
        let pw = &encrypted["db"]["password"];
        let host = &encrypted["db"]["host"];
        assert!(pw.as_str().unwrap().starts_with("ENC[AES-GCM"));
        assert_eq!(host.as_str().unwrap(), "db.local");

        let decrypted = decrypt(encrypted, &dek).unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn rejects_user_data_under_kerf_key() {
        let dek = Dek::generate();
        let plain: Value = serde_yaml::from_str("kerf:\n  malicious: yes\n").unwrap();
        let err = encrypt(
            plain,
            &dek,
            &default_encrypted_regex(),
            vec![fake_recipient()],
            None,
        )
        .unwrap_err();
        assert!(matches!(err, Error::KerfBlock(_)));
    }

    #[test]
    fn diff_aware_only_changes_what_changed() {
        let dek = Dek::generate();
        let plain: Value =
            serde_yaml::from_str("db:\n  password: hunter2\napi:\n  token: tok\n").unwrap();
        let first = encrypt(
            plain.clone(),
            &dek,
            &default_encrypted_regex(),
            vec![fake_recipient()],
            None,
        )
        .unwrap();

        let prev = snapshot_previous(&first, &dek).unwrap();

        let edited: Value =
            serde_yaml::from_str("db:\n  password: NEW\napi:\n  token: tok\n").unwrap();
        let second = encrypt(
            edited,
            &dek,
            &default_encrypted_regex(),
            vec![fake_recipient()],
            Some(&prev),
        )
        .unwrap();

        assert_ne!(first["db"]["password"], second["db"]["password"]);
        assert_eq!(first["api"]["token"], second["api"]["token"]);
    }
}
