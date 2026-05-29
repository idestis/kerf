//! Filesystem helpers — atomic write, read, stdout.
//!
//! Per CLAUDE.md "File format" §4: atomic writes only. Encrypt to a temp file
//! in the same directory, fsync, then rename. Never write in place.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::CliError;

/// Read a file fully into memory.
pub fn read(path: &Path) -> Result<Vec<u8>, CliError> {
    std::fs::read(path).map_err(|e| CliError::Other(format!("read {}: {e}", path.display())))
}

/// Atomically replace `path`'s contents with `bytes`. Same-directory tempfile,
/// `fsync`, then `rename`. Crash recovery never leaves a half-written file.
///
/// The tempfile name uses a random suffix so concurrent writes from multiple
/// kerf processes don't collide.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let suffix = random_suffix();
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::Other(format!("invalid destination {}", path.display())))?;
    let tmp = parent.join(format!(".{}.kerf-tmp.{suffix}", file_name.to_string_lossy()));

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| CliError::Other(format!("create tmp {}: {e}", tmp.display())))?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);

    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(CliError::Other(format!(
            "write tmp {}: {e}",
            tmp.display()
        )));
    }

    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        CliError::Other(format!("rename {}: {e}", tmp.display()))
    })?;

    // Best-effort: also fsync the parent directory so the rename is durable.
    if let Ok(dir) = File::open(&parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Write to stdout, flushing at the end.
pub fn write_stdout(bytes: &[u8]) -> Result<(), CliError> {
    let mut out = std::io::stdout().lock();
    out.write_all(bytes)?;
    out.flush()?;
    Ok(())
}

fn random_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let pid = std::process::id();
    format!("{pid}-{nanos:x}")
}
