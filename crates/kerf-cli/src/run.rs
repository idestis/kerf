//! Command implementations — `encrypt` and `decrypt` are real in v0.1.

use std::path::{Path, PathBuf};

use kerf_core::engine::{default_encrypted_regex, snapshot_previous};
use kerf_core::{Dek, FileFormat, RecipientEntry};
use kerf_kms::recipient::Identity;
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

pub struct VerifyArgs {
    pub file: PathBuf,
    pub format: Option<String>,
    pub identity: IdentityFlags,
}

/// Pick the on-disk format for a path: explicit --format override > extension
/// detection > error. We don't default to YAML silently because doing so on
/// an unrecognized extension would silently mis-parse the file.
pub(crate) fn resolve_format(
    path: &Path,
    override_name: Option<&str>,
) -> Result<FileFormat, CliError> {
    if let Some(name) = override_name {
        return match name.to_ascii_lowercase().as_str() {
            "yaml" | "yml" => Ok(FileFormat::Yaml),
            "json" => Ok(FileFormat::Json),
            "toml" => Ok(FileFormat::Toml),
            "env" | "dotenv" => Ok(FileFormat::Env),
            other => Err(CliError::Usage(format!(
                "--format {other:?} not supported (yaml, json, toml, env)"
            ))),
        };
    }
    FileFormat::detect(path).ok_or_else(|| {
        CliError::Usage(format!(
            "could not detect format from {} (use --format yaml|json|toml|env)",
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
    let content = format!("# created: {now} (kerf keygen)\n# public key: {recipient}\n{secret}\n");

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
        CliError::BadInput(format!(
            "{} parse {}: {e}",
            format.name(),
            args.file.display()
        ))
    })?;

    // If destination exists, build a previous-file snapshot for the kerf rule.
    // We need to unwrap the DEK from the existing file's recipient block first.
    let (dek, previous, existing_entries) = if dest.exists() {
        let existing_raw = read(&dest)?;
        let existing: Value = format.parse(&existing_raw).map_err(|e| {
            CliError::BadInput(format!("{} parse {}: {e}", format.name(), dest.display()))
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
        Some(prev_entries) if recipients_match(prev_entries, &resolved) => prev_entries.clone(),
        _ => resolved.wrap_all(&dek)?,
    };
    if !resolved.unsupported.is_empty() {
        let kinds: Vec<&str> = resolved.unsupported.iter().map(|u| u.kind).collect();
        return Err(CliError::Other(format!(
            "recipients {kinds:?} are accepted at the CLI but not yet implemented \
             — built-in support covers --age, --kms, and --gcp-kms"
        )));
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
    let format = resolve_format(&args.file, args.format.as_deref())?;

    let raw = read(&args.file)?;
    let tree: Value = format.parse(&raw).map_err(|e| {
        CliError::BadInput(format!(
            "{} parse {}: {e}",
            format.name(),
            args.file.display()
        ))
    })?;

    // Probe the kerf block once to find a recipient any of our identities
    // can unwrap.
    let dek = {
        let mut probe = tree.clone();
        let block = kerf_core::engine::extract_kerf_block(&mut probe)?;
        unwrap_any(&block.recipients, &identity)?
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

pub struct ViewArgs {
    pub file: PathBuf,
    pub path: Option<String>,
    pub format: Option<String>,
    pub identity: IdentityFlags,
}

/// `kerf view <file> [--path <dotted.path>]` (SPEC § 7.1) — read-only decrypt
/// to stdout. With `--path`, print just that one value: a scalar is emitted
/// raw (no quoting), a subtree is re-serialized in the file's format.
///
/// Like `decrypt`, this writes plaintext to stdout — it is *read-only* with
/// respect to the file (never writes plaintext to disk).
pub fn view(args: ViewArgs) -> Result<(), CliError> {
    let identity = ResolvedIdentity::resolve(&args.identity)?;
    let format = resolve_format(&args.file, args.format.as_deref())?;

    let raw = read(&args.file)?;
    let tree: Value = format.parse(&raw).map_err(|e| {
        CliError::BadInput(format!(
            "{} parse {}: {e}",
            format.name(),
            args.file.display()
        ))
    })?;

    let dek = {
        let mut probe = tree.clone();
        let block = kerf_core::engine::extract_kerf_block(&mut probe)?;
        unwrap_any(&block.recipients, &identity)?
    };

    let plain_tree = kerf_core::decrypt(tree, &dek)?;

    match args.path {
        None => {
            let serialized = format
                .serialize(&plain_tree)
                .map_err(|e| CliError::Other(format!("serialize: {e}")))?;
            write_stdout(serialized.as_bytes())
        }
        Some(p) => {
            let segs = crate::path::parse(&p)?;
            let value = crate::path::get(&plain_tree, &segs)
                .ok_or_else(|| CliError::Usage(format!("path {p:?} not found")))?;
            let out = render_scalar_or_subtree(value, format)?;
            write_stdout(out.as_bytes())
        }
    }
}

/// Render a single extracted value: scalars print raw (so `kerf view f --path
/// db.password` yields exactly the secret, pipe-friendly), everything else is
/// serialized as a subtree in the file's format.
fn render_scalar_or_subtree(value: &Value, format: FileFormat) -> Result<String, CliError> {
    match value {
        Value::String(s) => Ok(format!("{s}\n")),
        Value::Bool(b) => Ok(format!("{b}\n")),
        Value::Number(n) => Ok(format!("{n}\n")),
        Value::Null => Ok("\n".to_string()),
        Value::Mapping(_) | Value::Sequence(_) => format
            .serialize(value)
            .map_err(|e| CliError::Other(format!("serialize: {e}"))),
        Value::Tagged(_) => format
            .serialize(value)
            .map_err(|e| CliError::Other(format!("serialize: {e}"))),
    }
}

pub fn verify(args: VerifyArgs) -> Result<(), CliError> {
    let identity = ResolvedIdentity::resolve(&args.identity)?;
    let format = resolve_format(&args.file, args.format.as_deref())?;

    let raw = read(&args.file)?;
    let tree: Value = format.parse(&raw).map_err(|e| {
        CliError::BadInput(format!(
            "{} parse {}: {e}",
            format.name(),
            args.file.display()
        ))
    })?;

    // Find a recipient any of our identities can unwrap, exactly as decrypt
    // does — verify needs the DEK to check the per-value AAD and the MAC.
    let dek = {
        let mut probe = tree.clone();
        let block = kerf_core::engine::extract_kerf_block(&mut probe)?;
        unwrap_any(&block.recipients, &identity)?
    };

    // engine::verify runs the same crypto checks as decrypt but discards the
    // plaintext. Failures surface as distinct error types → distinct exit
    // codes (AAD mismatch = 12, MAC failure = 11).
    let count = kerf_core::engine::verify(tree, &dek)?;
    eprintln!(
        "kerf: {} OK — {count} encrypted value(s), MAC verified",
        args.file.display()
    );
    Ok(())
}

/// `kerf mac --verify <file>` (SPEC § 7.5) — verify the whole-file MAC.
///
/// Provided for scripting symmetry with SOPS. Note the MAC is computed over
/// the *plaintext* leaves (SPEC § 4.5), so verifying it necessarily opens
/// every `ENC[...]` envelope — there is no cheaper MAC-only path in this
/// construction. The recovered plaintext is dropped, never returned.
pub fn mac_verify(args: VerifyArgs) -> Result<(), CliError> {
    let identity = ResolvedIdentity::resolve(&args.identity)?;
    let format = resolve_format(&args.file, args.format.as_deref())?;

    let raw = read(&args.file)?;
    let tree: Value = format.parse(&raw).map_err(|e| {
        CliError::BadInput(format!(
            "{} parse {}: {e}",
            format.name(),
            args.file.display()
        ))
    })?;

    let dek = {
        let mut probe = tree.clone();
        let block = kerf_core::engine::extract_kerf_block(&mut probe)?;
        unwrap_any(&block.recipients, &identity)?
    };

    let count = kerf_core::engine::verify(tree, &dek)?;
    eprintln!(
        "kerf: {} MAC OK ({count} encrypted value(s))",
        args.file.display()
    );
    Ok(())
}

pub struct SetArgs {
    pub file: PathBuf,
    pub path: String,
    pub format: Option<String>,
    pub identity: IdentityFlags,
}

pub struct UnsetArgs {
    pub file: PathBuf,
    pub path: String,
    pub format: Option<String>,
    pub identity: IdentityFlags,
}

/// `kerf set <file> <path>` (SPEC § 7.4) — set one value through the
/// diff-aware encrypt path. The value is read from **stdin** (never argv, per
/// CLAUDE.md CLI rule 3) and stored as a string.
///
/// Only the touched value's envelope changes on disk; every other value keeps
/// its byte-identical ciphertext (the kerf rule), so the git diff is one line.
pub fn set(args: SetArgs) -> Result<(), CliError> {
    let segs = crate::path::parse(&args.path)?;
    let value_bytes = crate::io::read_stdin_value()?;
    let value = String::from_utf8(value_bytes)
        .map_err(|_| CliError::BadInput("value on stdin is not valid UTF-8".into()))?;

    mutate_in_place(
        &args.file,
        args.format.as_deref(),
        &args.identity,
        |plain| crate::path::set(plain, &segs, Value::String(value)),
    )
}

/// `kerf unset <file> <path>` (SPEC § 7.4) — remove one value through the
/// diff-aware encrypt path. The removed line disappears; all others are
/// byte-identical.
pub fn unset(args: UnsetArgs) -> Result<(), CliError> {
    let segs = crate::path::parse(&args.path)?;
    mutate_in_place(
        &args.file,
        args.format.as_deref(),
        &args.identity,
        |plain| crate::path::remove(plain, &segs),
    )
}

/// Load an encrypted file, decrypt it (verifying the MAC), apply `mutate` to
/// the plaintext tree, then diff-aware re-encrypt in place under the *same*
/// DEK, recipients, and `encrypted_regex`. Atomic write.
///
/// Reusing the existing DEK and recipient entries verbatim is what keeps
/// unchanged values byte-identical — this is the `set`/`unset` engine.
fn mutate_in_place(
    file: &Path,
    format_override: Option<&str>,
    identity_flags: &IdentityFlags,
    mutate: impl FnOnce(&mut Value) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let identity = ResolvedIdentity::resolve(identity_flags)?;
    let format = resolve_format(file, format_override)?;

    let raw = read(file)?;
    let tree: Value = format.parse(&raw).map_err(|e| {
        CliError::BadInput(format!("{} parse {}: {e}", format.name(), file.display()))
    })?;

    // Pull recipients + regex from the existing block, and unwrap its DEK.
    let block = {
        let mut probe = tree.clone();
        kerf_core::engine::extract_kerf_block(&mut probe)?
    };
    let dek = unwrap_any(&block.recipients, &identity)?;

    // Snapshot before decrypt drives the kerf rule; decrypt verifies the MAC.
    let previous = snapshot_previous(&tree, &dek)?;
    let mut plain = kerf_core::decrypt(tree, &dek)?;

    mutate(&mut plain)?;

    let regex = Regex::new(&block.encrypted_regex)
        .map_err(|e| CliError::Other(format!("stored encrypted_regex is invalid: {e}")))?;
    let encrypted = kerf_core::encrypt(plain, &dek, &regex, block.recipients, Some(&previous))?;

    let serialized = format
        .serialize(&encrypted)
        .map_err(|e| CliError::Other(format!("serialize: {e}")))?;
    atomic_write(file, serialized.as_bytes())?;
    eprintln!("kerf: wrote {}", file.display());
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
    let dek = unwrap_any(&block.recipients, &identity).map_err(|e| e.to_string())?;
    let previous = snapshot_previous(existing, &dek).map_err(|e| e.to_string())?;
    Ok((dek, previous, block.recipients))
}

/// True iff the on-disk recipient set is exactly the set we'd produce now.
/// Match key per backend: age recipient string, AWS KMS ARN, …
fn recipients_match(existing: &[RecipientEntry], resolved: &ResolvedRecipients) -> bool {
    let mut existing_age: Vec<&str> = Vec::new();
    let mut existing_aws: Vec<&str> = Vec::new();
    let mut existing_gcp: Vec<&str> = Vec::new();
    let mut existing_azure: Vec<&str> = Vec::new();
    for entry in existing {
        match entry {
            RecipientEntry::Age { recipient, .. } => existing_age.push(recipient),
            RecipientEntry::AwsKms { arn, .. } => existing_aws.push(arn),
            RecipientEntry::GcpKms { resource_id, .. } => existing_gcp.push(resource_id),
            RecipientEntry::AzureKv { key_id, .. } => existing_azure.push(key_id),
        }
    }
    let proposed_age: Vec<&str> = resolved
        .age
        .iter()
        .map(kerf_kms::age::AgeRecipient::spec)
        .collect();
    if !same_set(&existing_age, &proposed_age) {
        return false;
    }
    #[cfg(feature = "aws-kms")]
    let proposed_aws: Vec<&str> = resolved
        .aws_kms
        .iter()
        .map(kerf_kms::aws::AwsKmsRecipient::arn)
        .collect();
    #[cfg(not(feature = "aws-kms"))]
    let proposed_aws: Vec<&str> = Vec::new();
    if !same_set(&existing_aws, &proposed_aws) {
        return false;
    }
    #[cfg(feature = "gcp-kms")]
    let proposed_gcp: Vec<&str> = resolved
        .gcp_kms
        .iter()
        .map(kerf_kms::gcp::GcpKmsRecipient::resource_id)
        .collect();
    #[cfg(not(feature = "gcp-kms"))]
    let proposed_gcp: Vec<&str> = Vec::new();
    if !same_set(&existing_gcp, &proposed_gcp) {
        return false;
    }

    // Azure: the stored key_id is versioned (`.../keys/name/version`) but the
    // user's --azure-kv URL may be unversioned, so compare on the unversioned
    // `.../keys/name` prefix. Matching means we copy the existing entry (and
    // its wrapped DEK) verbatim, preserving byte-identity.
    #[cfg(feature = "azure-kv")]
    let proposed_azure: Vec<String> = resolved
        .azure_kv
        .iter()
        .map(|r| azure_key_base(r.key_url()))
        .collect();
    #[cfg(not(feature = "azure-kv"))]
    let proposed_azure: Vec<String> = Vec::new();
    let existing_azure_base: Vec<String> =
        existing_azure.iter().map(|k| azure_key_base(k)).collect();
    same_set_owned(&existing_azure_base, &proposed_azure)
}

fn same_set(a: &[&str], b: &[&str]) -> bool {
    a.len() == b.len() && a.iter().all(|x| b.contains(x)) && b.iter().all(|x| a.contains(x))
}

fn same_set_owned(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().all(|x| b.contains(x)) && b.iter().all(|x| a.contains(x))
}

/// Normalize an Azure key URL to its unversioned `.../keys/<name>` form so a
/// versioned stored kid and an unversioned supplied URL compare equal.
pub(crate) fn azure_key_base(url: &str) -> String {
    match url.find("/keys/") {
        Some(idx) => {
            let rest = &url[idx + "/keys/".len()..];
            let name = rest.split('/').next().unwrap_or(rest);
            format!("{}/keys/{name}", &url[..idx])
        }
        None => url.to_string(),
    }
}

/// Try every available identity against the recipient list. Returns the
/// DEK from the first successful unwrap. Errors with exit-10 NoRecipient
/// if none match.
pub(crate) fn unwrap_any(
    recipients: &[RecipientEntry],
    identity: &ResolvedIdentity,
) -> Result<Dek, CliError> {
    let mut last_error: Option<String> = None;
    for entry in recipients {
        if let Some(age) = &identity.age {
            if age.can_unwrap(entry) {
                match age.unwrap(entry) {
                    Ok(dek) => return Ok(dek),
                    Err(e) => last_error = Some(format!("age unwrap: {e}")),
                }
            }
        }
        #[cfg(feature = "aws-kms")]
        if let Some(aws) = &identity.aws_kms {
            if aws.can_unwrap(entry) {
                match aws.unwrap(entry) {
                    Ok(dek) => return Ok(dek),
                    Err(e) => last_error = Some(format!("aws unwrap: {e}")),
                }
            }
        }
        #[cfg(feature = "gcp-kms")]
        if let Some(gcp) = &identity.gcp_kms {
            if gcp.can_unwrap(entry) {
                match gcp.unwrap(entry) {
                    Ok(dek) => return Ok(dek),
                    Err(e) => last_error = Some(format!("gcp unwrap: {e}")),
                }
            }
        }
        #[cfg(feature = "azure-kv")]
        if let Some(azure) = &identity.azure_kv {
            if azure.can_unwrap(entry) {
                match azure.unwrap(entry) {
                    Ok(dek) => return Ok(dek),
                    Err(e) => last_error = Some(format!("azure unwrap: {e}")),
                }
            }
        }
    }
    Err(CliError::NoRecipient(format!(
        "no configured identity matched any recipient in the file{}",
        last_error
            .map(|e| format!(" (last error: {e})"))
            .unwrap_or_default()
    )))
}
