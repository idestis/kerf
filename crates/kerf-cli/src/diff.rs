//! `kerf diff <old> <new> [--show-values]` (SPEC § 7.1) — decrypt both files
//! and show a plaintext diff at the path level.
//!
//! Values are **redacted by default**: the diff shows which paths were added,
//! removed, or changed, but not the secrets themselves — safe to paste into a
//! review or CI log. `--show-values` opts into printing the plaintext, for
//! local use. Either way the plaintext lives only in memory; nothing is
//! written to disk.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_yaml::Value;

use crate::io::{read, write_stdout};
use crate::recipients::ResolvedIdentity;
use crate::run::{resolve_format, unwrap_any};
use crate::{CliError, IdentityFlags};

pub struct DiffArgs {
    pub old: PathBuf,
    pub new: PathBuf,
    pub show_values: bool,
    pub format: Option<String>,
    pub identity: IdentityFlags,
}

/// Decrypt `old` and `new` and print their path-level difference.
pub fn diff(args: DiffArgs) -> Result<(), CliError> {
    let identity = ResolvedIdentity::resolve(&args.identity)?;
    let old = decrypt_to_leaves(&args.old, args.format.as_deref(), &identity)?;
    let new = decrypt_to_leaves(&args.new, args.format.as_deref(), &identity)?;

    // Union of paths in sorted order so output is deterministic.
    let mut paths: Vec<&String> = old.keys().chain(new.keys()).collect();
    paths.sort_unstable();
    paths.dedup();

    let mut out = String::new();
    let mut changes = 0usize;
    for path in paths {
        match (old.get(path), new.get(path)) {
            (Some(o), Some(n)) if o == n => {}
            (Some(o), Some(n)) => {
                changes += 1;
                if args.show_values {
                    out.push_str(&format!("~ {path}: {o} → {n}\n"));
                } else {
                    out.push_str(&format!("~ {path} (changed)\n"));
                }
            }
            (None, Some(n)) => {
                changes += 1;
                if args.show_values {
                    out.push_str(&format!("+ {path}: {n}\n"));
                } else {
                    out.push_str(&format!("+ {path} (added)\n"));
                }
            }
            (Some(o), None) => {
                changes += 1;
                if args.show_values {
                    out.push_str(&format!("- {path}: {o}\n"));
                } else {
                    out.push_str(&format!("- {path} (removed)\n"));
                }
            }
            (None, None) => unreachable!("path came from one of the two maps"),
        }
    }

    if changes == 0 {
        eprintln!("kerf: no differences");
        return Ok(());
    }
    write_stdout(out.as_bytes())
}

/// Decrypt one file and flatten it to a `path -> scalar` map.
fn decrypt_to_leaves(
    file: &std::path::Path,
    format: Option<&str>,
    identity: &ResolvedIdentity,
) -> Result<BTreeMap<String, String>, CliError> {
    let format = resolve_format(file, format)?;
    let raw = read(file)?;
    let tree: Value = format.parse(&raw).map_err(|e| {
        CliError::BadInput(format!("{} parse {}: {e}", format.name(), file.display()))
    })?;

    let dek = {
        let mut probe = tree.clone();
        let block = kerf_core::engine::extract_kerf_block(&mut probe)?;
        unwrap_any(&block.recipients, identity)?
    };
    let plain = kerf_core::decrypt(tree, &dek)?;

    let mut leaves = BTreeMap::new();
    flatten(&plain, "", &mut leaves);
    Ok(leaves)
}

/// Flatten a plaintext tree into dotted-path → scalar-string entries, matching
/// the path canonicalization in SPEC § 4.4 (`a.b`, `a[0].b`).
fn flatten(value: &Value, prefix: &str, out: &mut BTreeMap<String, String>) {
    match value {
        Value::Mapping(m) => {
            for (k, v) in m {
                let Some(key) = key_string(k) else { continue };
                let path = if prefix.is_empty() {
                    key
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(v, &path, out);
            }
        }
        Value::Sequence(s) => {
            for (i, v) in s.iter().enumerate() {
                flatten(v, &format!("{prefix}[{i}]"), out);
            }
        }
        scalar => {
            out.insert(prefix.to_string(), scalar_string(scalar));
        }
    }
}

fn key_string(k: &Value) -> Option<String> {
    match k {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn scalar_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        // Non-scalars never reach here (flatten recurses into them).
        _ => String::new(),
    }
}
