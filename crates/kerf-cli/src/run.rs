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

/// Serialize `tree`, preserving the comments/whitespace/order of `original`
/// where possible (SPEC § 11.1). `original` is the source whose formatting we
/// want to keep: the existing ciphertext on re-encrypt/edit, or the plaintext
/// input on a first encrypt. Falls back to normalized output if it isn't valid
/// UTF-8 (our formats always are, but be defensive).
fn serialize_preserving(
    format: FileFormat,
    original: &[u8],
    tree: &Value,
) -> Result<String, CliError> {
    let result = match std::str::from_utf8(original) {
        Ok(orig) => format.serialize_preserving(orig, tree),
        Err(_) => format.serialize(tree),
    };
    result.map_err(|e| CliError::Other(format!("serialize: {e}")))
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
    let (dek, previous, existing_entries, existing_raw) = if dest.exists() {
        let existing_raw = read(&dest)?;
        let existing: Value = format.parse(&existing_raw).map_err(|e| {
            CliError::BadInput(format!("{} parse {}: {e}", format.name(), dest.display()))
        })?;

        match try_unwrap_for_diff(&existing) {
            Ok((existing_dek, prev, entries)) => {
                (existing_dek, Some(prev), Some(entries), Some(existing_raw))
            }
            Err(reason) => {
                tracing::warn!(
                    %reason,
                    "could not unwrap previous DEK — using fresh DEK, byte-identity \
                     for unchanged values will not hold this round"
                );
                (Dek::generate(), None, None, None)
            }
        }
    } else {
        (Dek::generate(), None, None, None)
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

    // Preserve the existing ciphertext's layout on re-encrypt; otherwise
    // preserve the plaintext input's layout (carrying its comments forward).
    let original_for_preserve = existing_raw.unwrap_or(raw);
    let serialized = serialize_preserving(format, &original_for_preserve, &encrypted)?;
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

    // Preserve the ciphertext's comments/layout in the decrypted output: the
    // kerf block is removed and ENC[...] values are replaced by plaintext, but
    // everything else stays as written.
    let serialized = serialize_preserving(format, &raw, &plain_tree)?;
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
            let serialized = serialize_preserving(format, &raw, &plain_tree)?;
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

pub struct EditArgs {
    pub file: PathBuf,
    pub format: Option<String>,
    pub identity: IdentityFlags,
}

/// `kerf edit <file>` (SPEC § 7.1) — decrypt, open `$EDITOR`, then diff-aware
/// re-encrypt on save. Atomic.
///
/// The plaintext is handed to the editor through a scratch file created `0600`
/// on a RAM-backed filesystem when one is available (`/dev/shm`), and that
/// file is zeroed and unlinked on every exit path by [`ScratchFile`]'s drop
/// (SPEC § 11.2 — no plaintext left on disk). Re-encryption reuses the existing
/// DEK, recipients, and regex with a previous-file snapshot, so editing one
/// value yields a one-line diff.
pub fn edit(args: EditArgs) -> Result<(), CliError> {
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

    let block = {
        let mut probe = tree.clone();
        kerf_core::engine::extract_kerf_block(&mut probe)?
    };
    let dek = unwrap_any(&block.recipients, &identity)?;
    let previous = snapshot_previous(&tree, &dek)?;
    let plain = kerf_core::decrypt(tree, &dek)?;
    // The editor should see the file's own comments/layout, not a normalized
    // dump — preserve them while stripping the kerf block and decrypting values.
    let original_text = serialize_preserving(format, &raw, &plain)?;

    // Hand the plaintext to the editor via a scratch file that wipes itself.
    let ext = args
        .file
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("txt");
    let scratch = ScratchFile::create(ext, original_text.as_bytes())?;
    run_editor(&scratch.path)?;
    let edited = read(&scratch.path)?;

    if edited == original_text.as_bytes() {
        eprintln!("kerf: no changes — {} left untouched", args.file.display());
        return Ok(());
    }

    // Re-parse the edited text. A parse failure must NOT destroy the encrypted
    // file — bail and let the scratch guard clean up.
    let edited_tree: Value = format.parse(&edited).map_err(|e| {
        CliError::BadInput(format!(
            "edited content is not valid {}: {e}",
            format.name()
        ))
    })?;

    let regex = Regex::new(&block.encrypted_regex)
        .map_err(|e| CliError::Other(format!("stored encrypted_regex is invalid: {e}")))?;
    let encrypted =
        kerf_core::encrypt(edited_tree, &dek, &regex, block.recipients, Some(&previous))?;
    // Preserve the layout of what the user just saved (their comments win).
    let serialized = serialize_preserving(format, &edited, &encrypted)?;
    atomic_write(&args.file, serialized.as_bytes())?;
    eprintln!("kerf: wrote {}", args.file.display());
    Ok(())
}

/// Resolve the editor command from `$KERF_EDITOR` → `$VISUAL` → `$EDITOR`.
/// The value is whitespace-split so `"code --wait"` works; the scratch path is
/// appended as the final argument.
fn run_editor(path: &Path) -> Result<(), CliError> {
    let mut chosen = None;
    for var in ["KERF_EDITOR", "VISUAL", "EDITOR"] {
        if let Ok(v) = std::env::var(var) {
            if !v.trim().is_empty() {
                chosen = Some(v);
                break;
            }
        }
    }
    let editor = chosen.ok_or_else(|| {
        CliError::Usage("no editor set — export $EDITOR (or $VISUAL / $KERF_EDITOR)".into())
    })?;
    let mut parts = editor.split_whitespace();
    let program = parts.next().expect("non-empty checked above");
    let status = std::process::Command::new(program)
        .args(parts)
        .arg(path)
        .status()
        .map_err(|e| CliError::Other(format!("launch editor {program:?}: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::Usage(
            "editor exited non-zero — aborting without saving".into(),
        ))
    }
}

/// A scratch plaintext file that zeroes and unlinks itself on drop. Created
/// `0600` on a RAM-backed filesystem when available so the plaintext never
/// touches persistent storage (best-effort; see SPEC § 3 on host side channels).
struct ScratchFile {
    path: PathBuf,
}

impl ScratchFile {
    fn create(ext: &str, contents: &[u8]) -> Result<Self, CliError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let name = format!(".kerf-edit.{}.{nanos:x}.{ext}", std::process::id());
        let path = scratch_dir().join(name);
        write_secret_file(&path, contents)?;
        Ok(Self { path })
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        // Best-effort wipe: overwrite with zeros, then unlink. On CoW / SSD
        // filesystems this isn't a guaranteed erase, but it removes the
        // plaintext from the common read path.
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&self.path) {
                use std::io::Write;
                let _ = f.write_all(&vec![0u8; meta.len() as usize]);
                let _ = f.sync_all();
            }
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Pick a directory for the scratch file, preferring a RAM-backed filesystem.
fn scratch_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        let shm = Path::new("/dev/shm");
        if shm.is_dir() {
            return shm.to_path_buf();
        }
    }
    std::env::temp_dir()
}

pub struct ExecArgs {
    pub file: PathBuf,
    pub format: Option<String>,
    pub command: Vec<String>,
    pub identity: IdentityFlags,
}

/// `kerf exec <file> -- <cmd> [args...]` (SPEC § 7.1) — decrypt the file into
/// environment variables and run `cmd` with them overlaid on the current env.
///
/// Dotted paths become `UPPER_SNAKE_CASE` (`db.password` → `DB_PASSWORD`);
/// array indices are concatenated (`users[0].api_key` → `USERS_0_API_KEY`).
/// Every scalar leaf is exported, secret or not. No temp files: plaintext
/// lives only in this process's memory and the child's environment, and the
/// child's exit code is propagated verbatim.
pub fn exec(args: ExecArgs) -> Result<(), CliError> {
    let Some((program, child_args)) = args.command.split_first() else {
        return Err(CliError::Usage(
            "exec needs a command after `--`, e.g. `kerf exec f.kerf.yaml -- env`".into(),
        ));
    };

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
    let plain = kerf_core::decrypt(tree, &dek)?;

    let env = build_env(&plain)?;

    let status = std::process::Command::new(program)
        .args(child_args)
        .envs(&env)
        .status()
        .map_err(|e| CliError::Other(format!("exec {program:?}: {e}")))?;

    // Propagate the child's exact exit code. A signal-terminated child has no
    // code; map that to 1.
    match status.code() {
        Some(0) => Ok(()),
        Some(code) => Err(CliError::ChildExit(u8::try_from(code & 0xff).unwrap_or(1))),
        None => Err(CliError::ChildExit(1)),
    }
}

/// Flatten the plaintext tree into `ENV_NAME -> value`, erroring on a name
/// collision (two distinct paths mapping to the same env var) so a silent
/// overwrite can't hide a secret.
fn build_env(tree: &Value) -> Result<std::collections::BTreeMap<String, String>, CliError> {
    // Track the source path per name so a collision message can name both.
    let mut by_name: std::collections::BTreeMap<String, (String, String)> =
        std::collections::BTreeMap::new();
    walk_env(tree, "", &mut by_name)?;
    Ok(by_name.into_iter().map(|(k, (_, v))| (k, v)).collect())
}

fn walk_env(
    value: &Value,
    prefix: &str,
    out: &mut std::collections::BTreeMap<String, (String, String)>,
) -> Result<(), CliError> {
    match value {
        Value::Mapping(map) => {
            for (k, v) in map {
                let Some(key) = scalar_key(k) else { continue };
                let path = if prefix.is_empty() {
                    key
                } else {
                    format!("{prefix}.{key}")
                };
                walk_env(v, &path, out)?;
            }
        }
        Value::Sequence(seq) => {
            for (i, v) in seq.iter().enumerate() {
                walk_env(v, &format!("{prefix}[{i}]"), out)?;
            }
        }
        scalar => {
            let name = env_name(prefix);
            if name.is_empty() {
                return Ok(());
            }
            let val = scalar_to_string(scalar);
            if let Some((existing_path, _)) = out.get(&name) {
                if existing_path != prefix {
                    return Err(CliError::Usage(format!(
                        "env var {name} maps from two paths ({existing_path} and {prefix}) \
                         — rename a key to disambiguate"
                    )));
                }
            }
            out.insert(name, (prefix.to_string(), val));
        }
    }
    Ok(())
}

/// Convert a dotted path to an `UPPER_SNAKE_CASE` env var name: runs of
/// non-alphanumeric characters (`.`, `[`, `]`, `_`) collapse to one `_`.
fn env_name(path: &str) -> String {
    let mut name = String::new();
    let mut at_sep = true; // suppress a leading underscore
    for ch in path.chars() {
        if ch.is_ascii_alphanumeric() {
            name.push(ch.to_ascii_uppercase());
            at_sep = false;
        } else if !at_sep {
            name.push('_');
            at_sep = true;
        }
    }
    while name.ends_with('_') {
        name.pop();
    }
    name
}

fn scalar_key(k: &Value) -> Option<String> {
    match k {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn scalar_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        _ => String::new(),
    }
}

pub struct RotateArgs {
    pub file: PathBuf,
    pub format: Option<String>,
    pub reason: Option<String>,
    pub identity: IdentityFlags,
}

/// `kerf rotate <file> [--reason]` (SPEC § 7.3) — generate a fresh DEK,
/// re-encrypt every value with fresh nonces, and re-wrap for the *same*
/// recipients. This is the one operation that legitimately rewrites the whole
/// file: it deliberately runs encrypt with `previous = None`, so the kerf
/// byte-identity rule does not apply and every envelope changes.
///
/// Use it to limit forward exposure after a suspected DEK compromise — the old
/// DEK can no longer decrypt the new file.
pub fn rotate(args: RotateArgs) -> Result<(), CliError> {
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

    // Old block → old recipients + regex; unwrap the old DEK to read values.
    let block = {
        let mut probe = tree.clone();
        kerf_core::engine::extract_kerf_block(&mut probe)?
    };
    let old_dek = unwrap_any(&block.recipients, &identity)?;
    let plain = kerf_core::decrypt(tree, &old_dek)?;

    // Reconstruct the recipient set from the stored addressing so we re-wrap
    // for exactly the same keys. A file whose backend isn't compiled in can't
    // be rotated by this binary — surface that rather than silently dropping.
    let flags = flags_from_entries(&block.recipients);
    let resolved = ResolvedRecipients::resolve(&flags)?;
    if !resolved.unsupported.is_empty() {
        let kinds: Vec<&str> = resolved.unsupported.iter().map(|u| u.kind).collect();
        return Err(CliError::Other(format!(
            "file has recipients {kinds:?} whose backend isn't built into this binary \
             — rebuild with the matching feature to rotate"
        )));
    }

    let new_dek = Dek::generate();
    let entries = resolved.wrap_all(&new_dek)?;
    let regex = Regex::new(&block.encrypted_regex)
        .map_err(|e| CliError::Other(format!("stored encrypted_regex is invalid: {e}")))?;

    // previous = None → full re-encrypt with fresh nonces under the new DEK.
    let encrypted = kerf_core::encrypt(plain, &new_dek, &regex, entries, None)?;

    // Every value changes (that's the point of rotation), but comments and
    // layout are preserved against the existing ciphertext.
    let serialized = serialize_preserving(format, &raw, &encrypted)?;
    atomic_write(&args.file, serialized.as_bytes())?;

    // --reason is audit output. The v1 on-disk block has no field for it
    // (adding one is a format-version change, SPEC § 7.3 vs § 4.2), so we log
    // it rather than silently dropping it or mutating the format.
    if let Some(reason) = &args.reason {
        eprintln!("kerf: rotated {} — reason: {reason}", args.file.display());
    } else {
        eprintln!("kerf: rotated {} (fresh DEK)", args.file.display());
    }
    Ok(())
}

/// Reconstruct `RecipientFlags` from on-disk entries so `ResolvedRecipients`
/// can re-parse them into wrap-capable recipients (used by `rotate`).
fn flags_from_entries(entries: &[RecipientEntry]) -> RecipientFlags {
    let mut flags = RecipientFlags::default();
    for entry in entries {
        match entry {
            RecipientEntry::Age { recipient, .. } => flags.age.push(recipient.clone()),
            RecipientEntry::AwsKms { arn, .. } => flags.kms.push(arn.clone()),
            RecipientEntry::GcpKms { resource_id, .. } => flags.gcp_kms.push(resource_id.clone()),
            RecipientEntry::AzureKv { key_id, .. } => flags.azure_kv.push(key_id.clone()),
        }
    }
    flags
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

    // Only the touched value changes on disk; preserve the rest of the
    // ciphertext's layout and comments.
    let serialized = serialize_preserving(format, &raw, &encrypted)?;
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
