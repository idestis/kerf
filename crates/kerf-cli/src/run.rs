//! Command implementations — `encrypt` and `decrypt` are real in v0.1.

use std::path::{Path, PathBuf};

use kerf_core::engine::{default_encrypted_regex, snapshot_previous};
use kerf_core::{Dek, FileFormat, RecipientEntry};
use kerf_kms::recipient::{Identity, Recipient};
use regex::Regex;
use serde_yaml::Value;

use crate::io::{atomic_write, read, write_stdout};
use crate::recipients::{ResolvedIdentity, ResolvedRecipients};
use crate::{CliError, IdentityFlags, RecipientFlags};

pub struct EncryptArgs {
    pub file: PathBuf,
    pub output: Option<PathBuf>,
    pub in_place: bool,
    pub encrypted_regex: Option<String>,
    pub format: Option<String>,
    pub recipients: RecipientFlags,
}

pub struct DecryptArgs {
    pub file: PathBuf,
    pub output: Option<PathBuf>,
    pub format: Option<String>,
    pub identity: IdentityFlags,
}

/// Pick the on-disk format for a path: explicit --format override > extension
/// detection > error. We don't default to YAML silently because doing so on
/// an unrecognized extension would silently mis-parse the file.
fn resolve_format(path: &Path, override_name: Option<&str>) -> Result<FileFormat, CliError> {
    if let Some(name) = override_name {
        return match name.to_ascii_lowercase().as_str() {
            "yaml" | "yml" => Ok(FileFormat::Yaml),
            "json" => Ok(FileFormat::Json),
            other => Err(CliError::Usage(format!(
                "--format {other:?} not supported (yaml, json)"
            ))),
        };
    }
    FileFormat::detect(path).ok_or_else(|| {
        CliError::Usage(format!(
            "could not detect format from {} (use --format yaml|json)",
            path.display()
        ))
    })
}

/// Generate a fresh age keypair and write the secret to `output`.
///
/// On Unix the file is created with 0600 perms. We refuse to overwrite an
/// existing file — losing a secret key by accident is exactly the kind of
/// mistake a CLI tool should not enable.
pub fn keygen(output: PathBuf) -> Result<(), CliError> {
    if output.exists() {
        return Err(CliError::Usage(format!(
            "refusing to overwrite existing file {}",
            output.display()
        )));
    }
    let (secret, recipient) = kerf_kms::age::keygen();

    // Build the file content. The header lets `age-keygen`-format consumers
    // also read this file if they ever need to.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let content = format!(
        "# created: {now} (kerf keygen)\n# public key: {recipient}\n{secret}\n"
    );

    write_secret_file(&output, content.as_bytes())?;
    eprintln!("kerf: wrote secret key → {}", output.display());
    println!("{recipient}");
    Ok(())
}

#[cfg(unix)]
fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| CliError::Other(format!("create {}: {e}", path.display())))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| CliError::Other(format!("create {}: {e}", path.display())))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn encrypt(args: EncryptArgs) -> Result<(), CliError> {
    let dest = resolve_dest(&args.file, args.output.as_deref(), args.in_place)?;
    let resolved = ResolvedRecipients::resolve(&args.recipients)?;
    let regex = compile_regex(args.encrypted_regex.as_deref())?;
    // Format is decided once per command — input and output use the same.
    // If the user wants to convert YAML→JSON they go through decrypt + re-encrypt.
    let format = resolve_format(&args.file, args.format.as_deref())?;

    // Parse plaintext input.
    let raw = read(&args.file)?;
    let plain: Value = format.parse(&raw).map_err(|e| {
        CliError::BadInput(format!("{} parse {}: {e}", format.name(), args.file.display()))
    })?;

    // If destination exists, build a previous-file snapshot for the kerf rule.
    // We need to unwrap the DEK from the existing file's recipient block first.
    let (dek, previous, existing_entries) = if dest.exists() {
        let existing_raw = read(&dest)?;
        let existing: Value = format.parse(&existing_raw).map_err(|e| {
            CliError::BadInput(format!(
                "{} parse {}: {e}",
                format.name(),
                dest.display()
            ))
        })?;

        match try_unwrap_for_diff(&existing) {
            Ok((existing_dek, prev, entries)) => (existing_dek, Some(prev), Some(entries)),
            Err(reason) => {
                tracing::warn!(
                    %reason,
                    "could not unwrap previous DEK — using fresh DEK, byte-identity \
                     for unchanged values will not hold this round"
                );
                (Dek::generate(), None, None)
            }
        }
    } else {
        (Dek::generate(), None, None)
    };

    // SPEC § 6.4 "same recipient set: none change". If the existing
    // recipient entries match what we'd wrap now, copy them verbatim so
    // the on-disk `encrypted_dek` bytes are byte-identical too.
    let entries: Vec<RecipientEntry> = match existing_entries.as_ref() {
        Some(prev_entries) if recipients_match(prev_entries, &resolved.age) => {
            prev_entries.clone()
        }
        _ => {
            let mut fresh = Vec::with_capacity(resolved.age.len());
            for recipient in &resolved.age {
                let wrapped = recipient.wrap(&dek)?;
                fresh.push(recipient.entry(&wrapped));
            }
            fresh
        }
    };
    if !resolved.unsupported.is_empty() {
        let kinds: Vec<&str> = resolved.unsupported.iter().map(|u| u.kind).collect();
        return Err(CliError::Unimplemented).map_err(|_| {
            CliError::Other(format!(
                "recipients {kinds:?} are accepted at the CLI but not yet implemented \
                 — v0.1 supports --age only"
            ))
        });
    }

    let encrypted = kerf_core::encrypt(plain, &dek, &regex, entries, previous.as_ref())?;

    let serialized = format
        .serialize(&encrypted)
        .map_err(|e| CliError::Other(format!("serialize: {e}")))?;
    atomic_write(&dest, serialized.as_bytes())?;
    eprintln!("kerf: wrote {}", dest.display());
    Ok(())
}

pub fn decrypt(args: DecryptArgs) -> Result<(), CliError> {
    let identity = ResolvedIdentity::resolve(&args.identity)?;
    let age_identity = identity
        .age
        .ok_or_else(|| CliError::NoRecipient("no age identity resolved".into()))?;
    let format = resolve_format(&args.file, args.format.as_deref())?;

    let raw = read(&args.file)?;
    let tree: Value = format.parse(&raw).map_err(|e| {
        CliError::BadInput(format!("{} parse {}: {e}", format.name(), args.file.display()))
    })?;

    // Probe the kerf block once to find a recipient our identity can unwrap.
    // We then re-parse the original bytes so the engine sees the block intact.
    let dek = {
        let mut probe = tree.clone();
        let block = kerf_core::engine::extract_kerf_block(&mut probe)?;
        let entry = block
            .recipients
            .iter()
            .find(|e| age_identity.can_unwrap(e))
            .ok_or_else(|| {
                CliError::NoRecipient(
                    "file has no age recipient that this identity can unwrap".into(),
                )
            })?;
        age_identity.unwrap(entry)?
    };

    // engine::decrypt extracts the block, verifies the MAC against the
    // decrypted leaves, then walks-decrypt. Any tampering — value-level
    // or whole-file MAC — surfaces here.
    let plain_tree = kerf_core::decrypt(tree, &dek)?;

    let serialized = format
        .serialize(&plain_tree)
        .map_err(|e| CliError::Other(format!("serialize: {e}")))?;
    match args.output {
        Some(path) => {
            atomic_write(&path, serialized.as_bytes())?;
            eprintln!("kerf: wrote {}", path.display());
        }
        None => write_stdout(serialized.as_bytes())?,
    }
    Ok(())
}

fn resolve_dest(
    input: &std::path::Path,
    output: Option<&std::path::Path>,
    in_place: bool,
) -> Result<PathBuf, CliError> {
    match (output, in_place) {
        (Some(p), false) => Ok(p.to_path_buf()),
        (None, true) => Ok(input.to_path_buf()),
        (None, false) => Err(CliError::Usage(
            "encrypt needs --output PATH or --in-place".into(),
        )),
        (Some(_), true) => unreachable!("clap conflicts_with prevents this"),
    }
}

fn compile_regex(custom: Option<&str>) -> Result<Regex, CliError> {
    match custom {
        Some(s) => {
            Regex::new(s).map_err(|e| CliError::Usage(format!("--encrypted-regex {s:?}: {e}")))
        }
        None => Ok(default_encrypted_regex()),
    }
}

/// For the kerf rule, we need to unwrap the *existing* file's DEK so we can
/// reuse it (same DEK → byte-identity for unchanged values is even possible).
/// v0.1 only supports unwrapping via an age identity, which means re-encrypt
/// on an existing file requires the same age identity to be available.
///
/// If we can't unwrap (no identity, or no matching recipient), we fall back
/// to a fresh DEK and re-encrypt everything from scratch. That's safe but
/// defeats the kerf rule for that round.
fn try_unwrap_for_diff(
    existing: &Value,
) -> Result<(Dek, kerf_core::format::PreviousFile, Vec<RecipientEntry>), String> {
    let mut clone = existing.clone();
    let block = kerf_core::engine::extract_kerf_block(&mut clone).map_err(|e| e.to_string())?;

    let identity = ResolvedIdentity::resolve(&IdentityFlags {
        identity_file: None,
    })
    .map_err(|e| e.to_string())?;
    let age_identity = identity
        .age
        .ok_or_else(|| "no age identity in env".to_string())?;
    let entry = block
        .recipients
        .iter()
        .find(|e| age_identity.can_unwrap(e))
        .ok_or_else(|| "no matching age recipient in existing file".to_string())?;
    let dek = age_identity.unwrap(entry).map_err(|e| e.to_string())?;

    let previous = snapshot_previous(existing, &dek).map_err(|e| e.to_string())?;
    Ok((dek, previous, block.recipients))
}

/// True iff the on-disk recipient set is exactly the set we'd produce now.
/// For age, identifier is the `age1…` recipient string. For other backends
/// (none implemented yet), we'd compare on the relevant identifier (ARN,
/// resource ID, key URL).
fn recipients_match(
    existing: &[RecipientEntry],
    age: &[kerf_kms::age::AgeRecipient],
) -> bool {
    let existing_age: Vec<&str> = existing
        .iter()
        .filter_map(|e| match e {
            RecipientEntry::Age { recipient, .. } => Some(recipient.as_str()),
            _ => None,
        })
        .collect();
    let proposed_age: Vec<&str> = age.iter().map(kerf_kms::age::AgeRecipient::spec).collect();
    // Only matches if it's the same set, no extras, no missing.
    existing.len() == existing_age.len()
        && proposed_age.len() == existing_age.len()
        && existing_age.iter().all(|r| proposed_age.contains(r))
        && proposed_age.iter().all(|r| existing_age.contains(r))
}
