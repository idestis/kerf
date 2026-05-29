//! Plumbing commands (SPEC § 7.5) — stable, scriptable contracts.
//!
//! Unlike porcelain, the stdout format and exit behaviour here are a stability
//! promise: scripts depend on them, so don't change them without a version
//! bump. All three commands in this module are read-only and need no DEK —
//! they read the plaintext `kerf:` block only. (`mac --verify`, which *does*
//! need the DEK, lives next to `verify` in `run.rs`.)

use std::path::{Path, PathBuf};

use kerf_core::engine::extract_kerf_block;
use serde_json::Value as Json;
use serde_yaml::Value;

use crate::io::{read, write_stdout};
use crate::run::resolve_format;
use crate::CliError;

/// Read a file and lift out its `kerf:` block as JSON, with every recipient's
/// `encrypted_dek` stripped. Shared by `metadata` and `recipients` — neither
/// command should ever emit wrapped key material.
fn block_json_without_deks(file: &Path, format: Option<&str>) -> Result<Json, CliError> {
    let format = resolve_format(file, format)?;
    let raw = read(file)?;
    let mut tree: Value = format.parse(&raw).map_err(|e| {
        CliError::BadInput(format!("{} parse {}: {e}", format.name(), file.display()))
    })?;

    // extract_kerf_block validates version/cipher/recipients and gives us a
    // typed block. Round-trip it through serde_json so we can prune fields
    // without hand-writing a parallel "view" struct.
    let block = extract_kerf_block(&mut tree)?;
    let mut json = serde_json::to_value(&block)
        .map_err(|e| CliError::Other(format!("serialize kerf block: {e}")))?;

    if let Some(recipients) = json.get_mut("recipients").and_then(Json::as_array_mut) {
        for entry in recipients {
            if let Some(obj) = entry.as_object_mut() {
                obj.remove("encrypted_dek");
            }
        }
    }
    Ok(json)
}

/// `kerf metadata <file>` — print the `kerf:` block (minus DEKs) as JSON.
/// No decryption needed.
pub fn metadata(file: PathBuf, format: Option<String>) -> Result<(), CliError> {
    let json = block_json_without_deks(&file, format.as_deref())?;
    print_json(&json)
}

/// `kerf recipients <file>` — print just the recipient list (minus DEKs) as
/// JSON. No decryption needed.
pub fn recipients(file: PathBuf, format: Option<String>) -> Result<(), CliError> {
    let json = block_json_without_deks(&file, format.as_deref())?;
    let recipients = json
        .get("recipients")
        .cloned()
        .unwrap_or(Json::Array(Vec::new()));
    print_json(&recipients)
}

/// `kerf path-encrypted <file> <path>` — exit 0 if `path`'s leaf key would be
/// encrypted under the file's `encrypted_regex`, exit 1 if not. Quiet: the
/// exit code is the signal, so scripts can `if kerf path-encrypted …; then`.
///
/// Matching mirrors the engine: the regex is tested against the *leaf key
/// name*, not the full dotted path. A path whose final component is an array
/// index (`…[0]`) has no key of its own and is therefore never encrypted.
pub fn path_encrypted(file: PathBuf, path: String, format: Option<String>) -> Result<(), CliError> {
    let format = resolve_format(&file, format.as_deref())?;
    let raw = read(&file)?;
    let mut tree: Value = format.parse(&raw).map_err(|e| {
        CliError::BadInput(format!("{} parse {}: {e}", format.name(), file.display()))
    })?;
    let block = extract_kerf_block(&mut tree)?;
    let regex = regex::Regex::new(&block.encrypted_regex)
        .map_err(|e| CliError::Other(format!("stored encrypted_regex is invalid: {e}")))?;

    let leaf = path.rsplit('.').next().unwrap_or(&path);
    let encrypted = !leaf.ends_with(']') && regex.is_match(leaf);
    if encrypted {
        Ok(())
    } else {
        Err(CliError::Predicate)
    }
}

/// Pretty-print JSON to stdout with a trailing newline.
fn print_json(value: &Json) -> Result<(), CliError> {
    let mut s = serde_json::to_string_pretty(value)
        .map_err(|e| CliError::Other(format!("format json: {e}")))?;
    s.push('\n');
    write_stdout(s.as_bytes())
}
