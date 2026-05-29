//! High-level encrypt/decrypt of a parsed YAML tree.
//!
//! The engine is the glue between `format::walk_*`, `kerf_block`, and a
//! caller-supplied `Recipient` trait. Recipient wrapping/unwrapping lives in
//! `kerf-kms`; this crate is recipient-agnostic.

use regex::Regex;
use serde_yaml::Value;

use crate::crypto::Dek;
use crate::error::{Error, Result};
use crate::format::{walk_decrypt, walk_encrypt, PreviousFile};
use crate::kerf_block::{KerfBlock, RecipientEntry, DEFAULT_ENCRYPTED_REGEX, RESERVED_KEY};

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
        return Err(Error::KerfBlock(
            "file root must be a YAML mapping".into(),
        ));
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
        return Err(Error::KerfBlock("can only embed into a YAML mapping".into()));
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

    let mut tree = plain;
    walk_encrypt(&mut tree, encrypted_regex, dek, previous)?;

    let block = KerfBlock {
        version: crate::kerf_block::FORMAT_VERSION,
        cipher: crate::kerf_block::CIPHER.into(),
        recipients,
        encrypted_regex: encrypted_regex.as_str().to_string(),
    };
    embed_kerf_block(&mut tree, &block)?;
    Ok(tree)
}

/// Decrypt a kerf-encrypted tree given the DEK. Returns a clean plaintext
/// tree (no `kerf:` block).
pub fn decrypt(mut encrypted: EncryptedTree, dek: &Dek) -> Result<PlainTree> {
    let _ = extract_kerf_block(&mut encrypted)?;
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
        assert!(matches!(encrypted, Value::Mapping(ref m) if m.contains_key(Value::String("kerf".into()))));
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

