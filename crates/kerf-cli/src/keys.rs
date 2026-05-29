//! `kerf keys add | remove | list` — recipient management WITHOUT DEK
//! rotation (SPEC § 7.2).
//!
//! Adding or removing a recipient only re-wraps (or drops) a copy of the
//! existing DEK. Per SPEC § 6.4 the per-value ciphertexts and the file MAC do
//! **not** change — we extract the typed `kerf:` block, edit only its
//! `recipients` list, and re-embed it; every `ENC[...]` envelope in the body
//! is left as the exact string it was. To rotate the DEK itself (which *does*
//! rewrite every value), use `kerf rotate`.

use std::path::PathBuf;

use kerf_core::engine::{embed_kerf_block, extract_kerf_block};
use kerf_core::RecipientEntry;
use serde_yaml::Value;

use crate::io::{atomic_write, read, write_stdout};
use crate::recipients::{ResolvedIdentity, ResolvedRecipients};
use crate::run::{azure_key_base, resolve_format, unwrap_any};
use crate::{CliError, IdentityFlags, RecipientFlags};

pub struct KeysAddArgs {
    pub file: PathBuf,
    pub format: Option<String>,
    pub recipients: RecipientFlags,
    pub identity: IdentityFlags,
}

pub struct KeysRemoveArgs {
    pub file: PathBuf,
    pub format: Option<String>,
    pub recipients: RecipientFlags,
}

/// `kerf keys list <file>` — print the recipients (no DEKs). Read-only.
pub fn list(file: PathBuf, format: Option<String>) -> Result<(), CliError> {
    let (_, block) = load_block(&file, format.as_deref())?;
    let mut out = format!("{} recipient(s):\n", block.recipients.len());
    for entry in &block.recipients {
        let (kind, id) = entry_addr(entry);
        out.push_str(&format!("  {kind:<9} {id}\n"));
    }
    write_stdout(out.as_bytes())
}

/// `kerf keys add <file> --age/--kms/… ` — wrap the existing DEK for one or
/// more new recipients and append them. The body and MAC stay byte-identical.
pub fn add(args: KeysAddArgs) -> Result<(), CliError> {
    let (format, mut tree) = load_tree(&args.file, args.format.as_deref())?;
    let mut block = extract_kerf_block(&mut tree)?;

    // Unwrap the DEK from an existing recipient so we can wrap fresh copies.
    let identity = ResolvedIdentity::resolve(&args.identity)?;
    let dek = unwrap_any(&block.recipients, &identity)?;

    let resolved = ResolvedRecipients::resolve(&args.recipients)?;
    if !resolved.unsupported.is_empty() {
        let kinds: Vec<&str> = resolved.unsupported.iter().map(|u| u.kind).collect();
        return Err(CliError::Other(format!(
            "recipients {kinds:?} are accepted at the CLI but not yet implemented"
        )));
    }

    let new_entries = resolved.wrap_all(&dek)?;
    let mut added = 0usize;
    for entry in new_entries {
        let addr = entry_addr(&entry);
        if block.recipients.iter().any(|e| entry_addr(e) == addr) {
            eprintln!(
                "kerf: recipient {} {} already present — skipping",
                addr.0, addr.1
            );
            continue;
        }
        block.recipients.push(entry);
        added += 1;
    }

    if added == 0 {
        eprintln!("kerf: no new recipients to add");
        return Ok(());
    }

    embed_kerf_block(&mut tree, &block)?;
    write_back(&args.file, format, &tree)?;
    eprintln!(
        "kerf: added {added} recipient(s) to {}",
        args.file.display()
    );
    Ok(())
}

/// `kerf keys remove <file> --age/--kms/…` — drop matching recipients. Warns
/// that historical git versions remain decryptable by the removed key, and
/// refuses to remove the last recipient (which would orphan the file).
pub fn remove(args: KeysRemoveArgs) -> Result<(), CliError> {
    let (format, mut tree) = load_tree(&args.file, args.format.as_deref())?;
    let mut block = extract_kerf_block(&mut tree)?;

    let resolved = ResolvedRecipients::resolve(&args.recipients)?;
    let targets = resolved.addrs();

    let before = block.recipients.len();
    block.recipients.retain(|e| {
        let (kind, id) = entry_addr(e);
        !targets.iter().any(|t| t.0 == kind && t.1 == id)
    });
    let removed = before - block.recipients.len();

    if removed == 0 {
        return Err(CliError::Usage(
            "no matching recipient found in the file".into(),
        ));
    }
    if block.recipients.is_empty() {
        return Err(CliError::Usage(
            "refusing to remove the last recipient — the file would be undecryptable \
             (use `kerf rotate` to change keys, or add a replacement first)"
                .into(),
        ));
    }

    embed_kerf_block(&mut tree, &block)?;
    write_back(&args.file, format, &tree)?;
    eprintln!(
        "kerf: removed {removed} recipient(s) from {}",
        args.file.display()
    );
    eprintln!(
        "kerf: warning — anyone who held a removed key and a previous git version \
         of this file can still decrypt that version. Run `kerf rotate` to limit \
         forward exposure."
    );
    Ok(())
}

/// The addressing key for an on-disk entry: `(kind, normalized-id)`. Azure ids
/// are normalized to their unversioned base, matching `ResolvedRecipients::addrs`.
fn entry_addr(entry: &RecipientEntry) -> (&'static str, String) {
    match entry {
        RecipientEntry::Age { recipient, .. } => ("age", recipient.clone()),
        RecipientEntry::AwsKms { arn, .. } => ("aws-kms", arn.clone()),
        RecipientEntry::GcpKms { resource_id, .. } => ("gcp-kms", resource_id.clone()),
        RecipientEntry::AzureKv { key_id, .. } => ("azure-kv", azure_key_base(key_id)),
    }
}

/// Read + parse a file into its format and tree.
fn load_tree(
    file: &std::path::Path,
    format: Option<&str>,
) -> Result<(kerf_core::FileFormat, Value), CliError> {
    let format = resolve_format(file, format)?;
    let raw = read(file)?;
    let tree: Value = format.parse(&raw).map_err(|e| {
        CliError::BadInput(format!("{} parse {}: {e}", format.name(), file.display()))
    })?;
    Ok((format, tree))
}

/// Read a file and lift out its `kerf:` block without mutating the original
/// tree (for read-only `list`).
fn load_block(
    file: &std::path::Path,
    format: Option<&str>,
) -> Result<(kerf_core::FileFormat, kerf_core::KerfBlock), CliError> {
    let (format, mut tree) = load_tree(file, format)?;
    let block = extract_kerf_block(&mut tree)?;
    Ok((format, block))
}

/// Serialize a tree and atomically write it back to `file`.
fn write_back(
    file: &std::path::Path,
    format: kerf_core::FileFormat,
    tree: &Value,
) -> Result<(), CliError> {
    let serialized = format
        .serialize(tree)
        .map_err(|e| CliError::Other(format!("serialize: {e}")))?;
    atomic_write(file, serialized.as_bytes())
}
