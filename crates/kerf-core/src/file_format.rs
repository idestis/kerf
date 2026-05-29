//! File format selection — YAML, JSON, and TOML.
//!
//! Internal tree representation is [`serde_yaml::Value`] because it's the
//! most general superset of the structured formats: JSON is a strict subset
//! of YAML, and `serde_yaml`'s `Value` can hold every JSON and TOML shape we
//! care about. Each format owns its own parse/serialize via the native serde
//! crate, converting to and from the shared internal tree.
//!
//! Known fidelity limitations (documented, not bugs):
//!
//! - **Comments are not preserved** in any format (the serde value model
//!   discards them on parse).
//! - **TOML datetimes** round-trip as strings — kerf has no datetime type
//!   and never needs one, since encrypted values are always strings.
//! - **TOML output groups scalars before sub-tables** at each level. This is
//!   required by the TOML grammar (a key/value pair cannot follow a table
//!   header within the same table) and matches conventional TOML style.

use std::fmt::Write as _;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_yaml::Value;

use crate::error::{Error, Result};

/// On-disk format. Detected from the file extension; `--format` flag at
/// the CLI level overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// YAML 1.2 via `serde_yaml`.
    Yaml,
    /// JSON via `serde_json`. Round-trips through the same internal tree.
    Json,
    /// TOML via the `toml` crate. Datetimes degrade to strings; output
    /// groups scalars before tables per the TOML grammar.
    Toml,
    /// dotenv (`KEY=value`). Flat namespace: there is no place to nest a
    /// `kerf:` block, so the metadata is packed into a single reserved
    /// `KERF_METADATA` key (base64 of the block as YAML). The file stays a
    /// valid, ordinary dotenv file. Only flat string values are
    /// representable — nested structure is rejected on serialize.
    Env,
}

/// Reserved dotenv key that carries the packed `kerf:` block. Chosen to be
/// extremely unlikely to collide with a real env var.
const ENV_METADATA_KEY: &str = "KERF_METADATA";

impl FileFormat {
    /// Detect from a file path. Returns `None` if the extension isn't
    /// recognized — caller decides whether to default to YAML or error.
    ///
    /// dotenv files always lead with `.env` (a dotfile), optionally followed
    /// by an environment suffix:
    /// - bare `.env`
    /// - `.env.prod`, `.env.local`, `.env.development`, `.env.example`, …
    ///
    /// They are never front-named (`config.env`); pass `--format env` for any
    /// non-standard spelling.
    #[must_use]
    pub fn detect(path: &Path) -> Option<Self> {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if is_dotenv_filename(&name.to_ascii_lowercase()) {
                return Some(Self::Env);
            }
        }
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "yaml" | "yml" => Some(Self::Yaml),
            "json" => Some(Self::Json),
            "toml" => Some(Self::Toml),
            _ => None,
        }
    }

    /// Parse bytes into the internal tree representation.
    pub fn parse(self, bytes: &[u8]) -> Result<Value> {
        match self {
            Self::Yaml => Ok(serde_yaml::from_slice(bytes)?),
            Self::Json => {
                let json: serde_json::Value = serde_json::from_slice(bytes)
                    .map_err(|e| Error::Yaml(serde_yaml_from_json_error(&e)))?;
                Ok(json_to_yaml_value(json))
            }
            Self::Toml => {
                let text = std::str::from_utf8(bytes)
                    .map_err(|e| Error::Envelope(format!("toml is not valid UTF-8: {e}")))?;
                let toml_value: toml::Value = toml::from_str(text)
                    .map_err(|e| Error::Envelope(format!("toml parse: {e}")))?;
                Ok(toml_to_yaml_value(toml_value))
            }
            Self::Env => {
                let text = std::str::from_utf8(bytes)
                    .map_err(|e| Error::Envelope(format!("env is not valid UTF-8: {e}")))?;
                parse_env(text)
            }
        }
    }

    /// Serialize the internal tree back out as bytes in this format.
    pub fn serialize(self, tree: &Value) -> Result<String> {
        match self {
            Self::Yaml => Ok(serde_yaml::to_string(tree)?),
            Self::Json => {
                let json = yaml_to_json_value(tree)?;
                serde_json::to_string_pretty(&json)
                    .map(|mut s| {
                        s.push('\n');
                        s
                    })
                    .map_err(|e| Error::Yaml(serde_yaml_from_json_error(&e)))
            }
            Self::Toml => {
                let mut toml_value = yaml_to_toml_value(tree)?;
                // TOML grammar: scalar key/values must precede table headers
                // within a table. Reorder so serialization can't fail with
                // ValueAfterTable.
                reorder_values_before_tables(&mut toml_value);
                toml::to_string(&toml_value)
                    .map_err(|e| Error::Envelope(format!("toml serialize: {e}")))
            }
            Self::Env => serialize_env(tree),
        }
    }

    /// Serialize `tree` while preserving the comments, blank lines, key order,
    /// and quoting of `original` for everything that did **not** change
    /// (SPEC § 11.1, CLAUDE.md "File format" rule 1).
    ///
    /// The crypto pipeline still produces a normal [`Value`] tree; this step
    /// rewrites only the scalar leaves whose rendered value differs from
    /// `original`, leaving unchanged leaves — and all surrounding comments and
    /// formatting — byte-for-byte intact. The `kerf:` metadata block is
    /// appended (encrypt) or removed (decrypt) as the tree dictates.
    ///
    /// It falls back to [`serialize`](Self::serialize) (normalized output) when
    /// the document structure changed too much to splice safely, and for JSON
    /// (which has no comments). Correctness first: the fallback never emits
    /// wrong data — only a noisier diff.
    pub fn serialize_preserving(self, original: &str, tree: &Value) -> Result<String> {
        match self {
            Self::Env => env_serialize_preserving(original, tree),
            // Implemented in follow-up commits; until then, identical to the
            // normalized path (no regression — that's today's behaviour).
            Self::Toml | Self::Yaml | Self::Json => self.serialize(tree),
        }
    }

    /// Human-readable name — used in error messages.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Yaml => "yaml",
            Self::Json => "json",
            Self::Toml => "toml",
            Self::Env => "env",
        }
    }
}

/// Convert a `serde_json::Value` tree to the `serde_yaml::Value`
/// representation we use internally. Lossless for our purposes — JSON has
/// no concept of YAML's tagged values or aliases, and we don't accept
/// those for encrypted inputs anyway.
fn json_to_yaml_value(j: serde_json::Value) -> Value {
    match j {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => {
            // serde_yaml::Number can be built from a string round-trip; this
            // preserves precision for very large integers.
            if let Some(i) = n.as_i64() {
                Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                Value::Number(u.into())
            } else if let Some(f) = n.as_f64() {
                Value::Number(f.into())
            } else {
                Value::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => Value::String(s),
        serde_json::Value::Array(items) => {
            Value::Sequence(items.into_iter().map(json_to_yaml_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut out = serde_yaml::Mapping::new();
            for (k, v) in map {
                out.insert(Value::String(k), json_to_yaml_value(v));
            }
            Value::Mapping(out)
        }
    }
}

/// Convert internal tree back to `serde_json::Value` for serialization.
/// Errors if the YAML tree contains non-JSON-able constructs (tagged values).
fn yaml_to_json_value(v: &Value) -> Result<serde_json::Value> {
    match v {
        Value::Null => Ok(serde_json::Value::Null),
        Value::Bool(b) => Ok(serde_json::Value::Bool(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(serde_json::json!(i))
            } else if let Some(u) = n.as_u64() {
                Ok(serde_json::json!(u))
            } else if let Some(f) = n.as_f64() {
                Ok(serde_json::json!(f))
            } else {
                Ok(serde_json::Value::String(n.to_string()))
            }
        }
        Value::String(s) => Ok(serde_json::Value::String(s.clone())),
        Value::Sequence(items) => Ok(serde_json::Value::Array(
            items
                .iter()
                .map(yaml_to_json_value)
                .collect::<Result<_>>()?,
        )),
        Value::Mapping(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => return Err(Error::KerfBlock("JSON object keys must be scalar".into())),
                };
                obj.insert(key, yaml_to_json_value(v)?);
            }
            Ok(serde_json::Value::Object(obj))
        }
        Value::Tagged(_) => Err(Error::KerfBlock(
            "YAML tagged values are not representable in JSON".into(),
        )),
    }
}

/// JSON errors don't fit into `serde_yaml::Error` cleanly. We wrap as a
/// generic YAML parse error so the CLI can map both to exit 20 uniformly.
/// Replace with a proper variant if JSON-specific diagnostics become useful.
fn serde_yaml_from_json_error(e: &serde_json::Error) -> serde_yaml::Error {
    // serde_yaml::Error has no public From<&str>; build via a serializer
    // that immediately errors.
    serde_yaml::Error::custom(e.to_string())
}

// Required for the `serde_yaml::Error::custom` call above.
use serde::ser::Error as _;

/// Convert a `toml::Value` tree to the internal `serde_yaml::Value`.
///
/// Datetimes degrade to strings (kerf has no datetime type). TOML has no
/// null, so this conversion never produces `Value::Null`.
fn toml_to_yaml_value(t: toml::Value) -> Value {
    match t {
        toml::Value::String(s) => Value::String(s),
        toml::Value::Integer(i) => Value::Number(i.into()),
        toml::Value::Float(f) => Value::Number(f.into()),
        toml::Value::Boolean(b) => Value::Bool(b),
        toml::Value::Datetime(dt) => Value::String(dt.to_string()),
        toml::Value::Array(items) => {
            Value::Sequence(items.into_iter().map(toml_to_yaml_value).collect())
        }
        toml::Value::Table(table) => {
            let mut out = serde_yaml::Mapping::new();
            for (k, v) in table {
                out.insert(Value::String(k), toml_to_yaml_value(v));
            }
            Value::Mapping(out)
        }
    }
}

/// Convert the internal tree back to `toml::Value` for serialization.
///
/// Errors if the tree contains constructs TOML can't represent: `null`
/// (no TOML null) or YAML tagged values. Numbers are mapped to TOML
/// integers when they fit `i64`, else floats.
fn yaml_to_toml_value(v: &Value) -> Result<toml::Value> {
    match v {
        Value::Null => Err(Error::KerfBlock(
            "TOML has no null; cannot serialize a null value".into(),
        )),
        Value::Bool(b) => Ok(toml::Value::Boolean(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(toml::Value::Integer(i))
            } else if let Some(u) = n.as_u64() {
                // TOML integers are i64; very large u64 degrade to float to
                // avoid silent truncation. Secrets are strings, so this only
                // affects non-encrypted numeric config at the extreme range.
                // The precision loss is the deliberate, documented tradeoff.
                #[allow(clippy::cast_precision_loss)]
                Ok(i64::try_from(u)
                    .map_or_else(|_| toml::Value::Float(u as f64), toml::Value::Integer))
            } else if let Some(f) = n.as_f64() {
                Ok(toml::Value::Float(f))
            } else {
                Ok(toml::Value::String(n.to_string()))
            }
        }
        Value::String(s) => Ok(toml::Value::String(s.clone())),
        Value::Sequence(items) => Ok(toml::Value::Array(
            items
                .iter()
                .map(yaml_to_toml_value)
                .collect::<Result<_>>()?,
        )),
        Value::Mapping(map) => {
            let mut table = toml::map::Map::new();
            for (k, v) in map {
                let key = match k {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => return Err(Error::KerfBlock("TOML table keys must be scalar".into())),
                };
                table.insert(key, yaml_to_toml_value(v)?);
            }
            Ok(toml::Value::Table(table))
        }
        Value::Tagged(_) => Err(Error::KerfBlock(
            "YAML tagged values are not representable in TOML".into(),
        )),
    }
}

/// True if a `toml::Value` serializes as a table header (`[x]`) or an
/// array-of-tables (`[[x]]`), both of which must follow plain key/values
/// within their parent table.
fn is_toml_table_like(v: &toml::Value) -> bool {
    match v {
        toml::Value::Table(_) => true,
        toml::Value::Array(items) => {
            !items.is_empty() && items.iter().all(|i| matches!(i, toml::Value::Table(_)))
        }
        _ => false,
    }
}

/// Recursively reorder each table so that scalar/inline-array entries come
/// before table-like entries, preserving relative order within each group.
/// This is required for `toml::to_string` to succeed (the `ValueAfterTable`
/// error) and is idiomatic TOML besides.
fn reorder_values_before_tables(v: &mut toml::Value) {
    match v {
        toml::Value::Table(table) => {
            // Stable partition: take the existing entries in order, emit
            // non-table-like first, then table-like. Recurse into each.
            let entries: Vec<(String, toml::Value)> = std::mem::take(table).into_iter().collect();
            let (mut values, mut tables): (Vec<_>, Vec<_>) = entries
                .into_iter()
                .partition(|(_, val)| !is_toml_table_like(val));
            for (_, val) in values.iter_mut().chain(tables.iter_mut()) {
                reorder_values_before_tables(val);
            }
            let mut rebuilt = toml::map::Map::new();
            for (k, val) in values.into_iter().chain(tables) {
                rebuilt.insert(k, val);
            }
            *table = rebuilt;
        }
        toml::Value::Array(items) => {
            for item in items.iter_mut() {
                reorder_values_before_tables(item);
            }
        }
        _ => {}
    }
}

// ──── dotenv ─────────────────────────────────────────────────────────────
//
// Minimal, well-defined dotenv subset (no external crate, full control over
// round-tripping):
//
// - `KEY=value`, optionally `export KEY=value`.
// - Blank lines and `#` comment lines are ignored (not preserved — consistent
//   with the no-comment-preservation limitation across all formats).
// - Double-quoted values support `\n`, `\t`, `\"`, `\\` escapes.
// - Single-quoted values are literal (no escapes).
// - Unquoted values are taken verbatim up to a trailing inline ` #` comment,
//   then trimmed of surrounding whitespace.
// - The reserved `KERF_METADATA` key, if present, is decoded (base64 → YAML)
//   into the `kerf` sub-mapping the engine expects.

/// True for the conventional dotenv filenames: bare `.env`, or `.env`
/// followed by an environment suffix (`.env.prod`, `.env.local`, …).
/// Input is expected already lowercased.
fn is_dotenv_filename(name: &str) -> bool {
    name == ".env" || name.starts_with(".env.")
}

/// Parse dotenv text into a flat `Mapping`, reconstructing the `kerf` block
/// from `KERF_METADATA` if present.
fn parse_env(text: &str) -> Result<Value> {
    let mut map = serde_yaml::Mapping::new();
    let mut metadata: Option<String> = None;

    for (lineno, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            Error::Envelope(format!("env line {} has no '=': {raw_line:?}", lineno + 1))
        })?;
        let key = key.trim();
        if !is_valid_env_key(key) {
            return Err(Error::Envelope(format!(
                "env line {}: invalid key {key:?}",
                lineno + 1
            )));
        }
        let value = parse_env_value(raw_value);
        if key == ENV_METADATA_KEY {
            metadata = Some(value);
        } else {
            map.insert(Value::String(key.to_string()), Value::String(value));
        }
    }

    let mut tree = Value::Mapping(map);
    if let Some(packed) = metadata {
        let yaml_bytes = B64
            .decode(packed.as_bytes())
            .map_err(|e| Error::KerfBlock(format!("KERF_METADATA base64: {e}")))?;
        let block: Value = serde_yaml::from_slice(&yaml_bytes)
            .map_err(|e| Error::KerfBlock(format!("KERF_METADATA yaml: {e}")))?;
        if let Value::Mapping(m) = &mut tree {
            m.insert(Value::String(crate::kerf_block::RESERVED_KEY.into()), block);
        }
    }
    Ok(tree)
}

/// Render a flat-tree scalar to its raw dotenv value (before quoting).
fn env_scalar(v: &Value, key: &str) -> Result<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Null => Ok(String::new()),
        Value::Sequence(_) | Value::Mapping(_) | Value::Tagged(_) => Err(Error::KerfBlock(
            format!("env format is flat: value at {key:?} is not a scalar"),
        )),
    }
}

/// Comment/whitespace-preserving dotenv serializer (SPEC § 11.1).
///
/// Walks `original` line by line: comment and blank lines are kept verbatim; a
/// `KEY=value` line whose value is unchanged is kept byte-for-byte (preserving
/// its quoting, spacing, and any inline comment); only changed values are
/// rewritten. Keys absent from the new tree are dropped (e.g. `unset`); keys
/// new to the tree are appended. The packed `KERF_METADATA` line is updated,
/// appended, or removed to match the tree's `kerf` block.
fn env_serialize_preserving(original: &str, tree: &Value) -> Result<String> {
    let Value::Mapping(map) = tree else {
        return Err(Error::KerfBlock("env root must be a mapping".into()));
    };

    // Desired end state from the tree: data key -> raw (unquoted) value, in
    // tree order, plus the packed metadata blob if a kerf block is present.
    let mut desired: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut desired_metadata: Option<String> = None;
    for (k, v) in map {
        let Value::String(key) = k else {
            return Err(Error::KerfBlock("env keys must be strings".into()));
        };
        if key == crate::kerf_block::RESERVED_KEY {
            let yaml = serde_yaml::to_string(v)?;
            desired_metadata = Some(B64.encode(yaml.as_bytes()));
            continue;
        }
        desired.insert(key.clone(), env_scalar(v, key)?);
        order.push(key.clone());
    }

    let mut out = String::new();
    let mut emitted: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut metadata_emitted = false;

    for raw_line in original.lines() {
        let trimmed = raw_line.trim();
        // Preserve comments and blank lines exactly.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push_str(raw_line);
            out.push('\n');
            continue;
        }
        let (has_export, kv) = match trimmed.strip_prefix("export ") {
            Some(rest) => (true, rest.trim_start()),
            None => (false, trimmed),
        };
        let Some((raw_key, raw_val)) = kv.split_once('=') else {
            // Not a recognizable assignment — keep it verbatim rather than guess.
            out.push_str(raw_line);
            out.push('\n');
            continue;
        };
        let key = raw_key.trim();

        if key == ENV_METADATA_KEY {
            if let Some(meta) = &desired_metadata {
                writeln!(out, "{ENV_METADATA_KEY}={}", quote_env_value(meta))
                    .expect("write to String");
                metadata_emitted = true;
            }
            // else: tree has no kerf block (decrypt) → drop the line.
            continue;
        }

        match desired.get(key) {
            // Key removed from the tree (e.g. `unset`) → drop the line.
            None => {}
            Some(scalar) => {
                if &parse_env_value(raw_val) == scalar {
                    // Unchanged: keep the original line verbatim.
                    out.push_str(raw_line);
                    out.push('\n');
                } else {
                    // Changed: rewrite the value, preserving export + key.
                    let prefix = if has_export { "export " } else { "" };
                    writeln!(out, "{prefix}{key}={}", quote_env_value(scalar))
                        .expect("write to String");
                }
                emitted.insert(key.to_string());
            }
        }
    }

    // Keys new to the tree (added, e.g. `set` of a fresh key) go at the end.
    for key in &order {
        if !emitted.contains(key) {
            writeln!(out, "{key}={}", quote_env_value(&desired[key])).expect("write to String");
        }
    }
    // First encrypt: no KERF_METADATA line existed yet, so append one.
    if let Some(meta) = &desired_metadata {
        if !metadata_emitted {
            writeln!(out, "{ENV_METADATA_KEY}={}", quote_env_value(meta)).expect("write to String");
        }
    }
    Ok(out)
}

/// Serialize a flat tree to dotenv, packing the `kerf` block into
/// `KERF_METADATA`. Errors if any non-`kerf` value is nested (dotenv is flat).
fn serialize_env(tree: &Value) -> Result<String> {
    let Value::Mapping(map) = tree else {
        return Err(Error::KerfBlock("env root must be a mapping".into()));
    };
    let mut out = String::new();
    let mut packed_metadata: Option<String> = None;

    for (k, v) in map {
        let key = match k {
            Value::String(s) => s.clone(),
            _ => return Err(Error::KerfBlock("env keys must be strings".into())),
        };
        if key == crate::kerf_block::RESERVED_KEY {
            // Pack the block as base64(YAML) under the reserved metadata key.
            let yaml = serde_yaml::to_string(v)?;
            packed_metadata = Some(B64.encode(yaml.as_bytes()));
            continue;
        }
        let scalar = match v {
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            Value::Null => String::new(),
            Value::Sequence(_) | Value::Mapping(_) | Value::Tagged(_) => {
                return Err(Error::KerfBlock(format!(
                    "env format is flat: value at {key:?} is not a scalar"
                )))
            }
        };
        writeln!(out, "{key}={}", quote_env_value(&scalar)).expect("write to String");
    }

    if let Some(meta) = packed_metadata {
        writeln!(out, "{ENV_METADATA_KEY}={}", quote_env_value(&meta)).expect("write to String");
    }
    Ok(out)
}

fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Interpret a raw dotenv value (the text right of the first `=`).
fn parse_env_value(raw: &str) -> String {
    let trimmed = raw.trim_start();
    if let Some(inner) = trimmed.strip_prefix('"') {
        // Double-quoted: read until the closing unescaped quote, applying
        // escapes. If there's no closing quote, fall through to literal.
        if let Some(end) = find_closing_double_quote(inner) {
            return unescape_double(&inner[..end]);
        }
    } else if let Some(inner) = trimmed.strip_prefix('\'') {
        if let Some(end) = inner.find('\'') {
            return inner[..end].to_string();
        }
    }
    // Unquoted: strip a trailing ` #...` inline comment, then trim.
    let without_comment = match trimmed.find(" #") {
        Some(idx) => &trimmed[..idx],
        None => trimmed,
    };
    without_comment.trim_end().to_string()
}

fn find_closing_double_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2, // skip escaped char
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn unescape_double(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some(other) => {
                    if other != '\\' {
                        out.push('\\');
                    }
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Quote a dotenv value if it contains characters that would otherwise be
/// ambiguous (whitespace, `#`, quotes, `=`, or newlines). The `ENC[...]`
/// envelope contains `=` (base64 padding), so it is always quoted — which is
/// safe and unambiguous.
fn quote_env_value(value: &str) -> String {
    let needs_quoting = value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '#' | '"' | '\'' | '='))
        || value.starts_with(' ')
        || value.ends_with(' ');
    if !needs_quoting {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_yaml() {
        assert_eq!(
            FileFormat::detect(Path::new("foo.yaml")),
            Some(FileFormat::Yaml)
        );
        assert_eq!(
            FileFormat::detect(Path::new("foo.yml")),
            Some(FileFormat::Yaml)
        );
        assert_eq!(
            FileFormat::detect(Path::new("foo.kerf.yaml")),
            Some(FileFormat::Yaml)
        );
    }

    #[test]
    fn detect_json() {
        assert_eq!(
            FileFormat::detect(Path::new("foo.json")),
            Some(FileFormat::Json)
        );
        assert_eq!(
            FileFormat::detect(Path::new("foo.kerf.json")),
            Some(FileFormat::Json)
        );
    }

    #[test]
    fn detect_unknown() {
        assert_eq!(FileFormat::detect(Path::new("foo")), None);
        assert_eq!(FileFormat::detect(Path::new("foo.txt")), None);
    }

    #[test]
    fn json_roundtrip() {
        let original = br#"{"db":{"host":"db.local","password":"hunter2"}}"#;
        let tree = FileFormat::Json.parse(original).unwrap();
        let back = FileFormat::Json.serialize(&tree).unwrap();
        // The output is pretty-printed; reparse and structurally compare.
        let reparsed = FileFormat::Json.parse(back.as_bytes()).unwrap();
        assert_eq!(reparsed, tree);
    }

    #[test]
    fn yaml_to_json_via_internal_tree() {
        let yaml = b"db:\n  host: db.local\n  password: hunter2\n";
        let tree = FileFormat::Yaml.parse(yaml).unwrap();
        let json = FileFormat::Json.serialize(&tree).unwrap();
        let reparsed = FileFormat::Json.parse(json.as_bytes()).unwrap();
        assert_eq!(reparsed, tree);
    }

    #[test]
    fn detect_toml() {
        assert_eq!(
            FileFormat::detect(Path::new("foo.toml")),
            Some(FileFormat::Toml)
        );
        assert_eq!(
            FileFormat::detect(Path::new("foo.kerf.toml")),
            Some(FileFormat::Toml)
        );
    }

    #[test]
    fn toml_roundtrip() {
        let original = b"[db]\nhost = \"db.local\"\npassword = \"hunter2\"\n";
        let tree = FileFormat::Toml.parse(original).unwrap();
        let back = FileFormat::Toml.serialize(&tree).unwrap();
        let reparsed = FileFormat::Toml.parse(back.as_bytes()).unwrap();
        assert_eq!(reparsed, tree);
    }

    #[test]
    fn toml_reorders_scalars_before_tables() {
        // A top-level scalar declared AFTER a table would break naive TOML
        // serialization. Our reorder step must fix it so output is valid.
        let mut map = serde_yaml::Mapping::new();
        let mut db = serde_yaml::Mapping::new();
        db.insert(
            Value::String("host".into()),
            Value::String("db.local".into()),
        );
        map.insert(Value::String("db".into()), Value::Mapping(db));
        // top-level scalar after the table:
        map.insert(
            Value::String("token".into()),
            Value::String("secret".into()),
        );
        let tree = Value::Mapping(map);

        let out = FileFormat::Toml.serialize(&tree).unwrap();
        // Must be parseable back, and the scalar must appear before [db].
        let reparsed = FileFormat::Toml.parse(out.as_bytes()).unwrap();
        assert_eq!(reparsed["token"].as_str().unwrap(), "secret");
        assert_eq!(reparsed["db"]["host"].as_str().unwrap(), "db.local");
        let token_pos = out.find("token").unwrap();
        let table_pos = out.find("[db]").unwrap();
        assert!(
            token_pos < table_pos,
            "scalar must be emitted before the table header:\n{out}"
        );
    }

    #[test]
    fn toml_datetime_degrades_to_string() {
        let original = b"created = 2026-05-29T10:00:00Z\n";
        let tree = FileFormat::Toml.parse(original).unwrap();
        assert_eq!(tree["created"].as_str().unwrap(), "2026-05-29T10:00:00Z");
    }

    #[test]
    fn toml_array_roundtrip() {
        let original = b"ports = [8080, 8081, 8082]\n";
        let tree = FileFormat::Toml.parse(original).unwrap();
        let back = FileFormat::Toml.serialize(&tree).unwrap();
        let reparsed = FileFormat::Toml.parse(back.as_bytes()).unwrap();
        assert_eq!(reparsed, tree);
    }

    #[test]
    fn detect_env_conventional_names() {
        for name in [
            ".env",
            ".env.prod",
            ".env.local",
            ".env.development",
            ".env.example",
            "/path/to/.env.staging",
        ] {
            assert_eq!(
                FileFormat::detect(Path::new(name)),
                Some(FileFormat::Env),
                "{name} should be detected as env"
            );
        }
    }

    #[test]
    fn detect_env_rejects_front_named_and_lookalikes() {
        // Front-named files are not a real dotenv convention.
        assert_eq!(FileFormat::detect(Path::new("config.env")), None);
        assert_eq!(FileFormat::detect(Path::new("prod.env")), None);
        // .environment is not a dotenv file.
        assert_eq!(FileFormat::detect(Path::new(".environment")), None);
    }

    #[test]
    fn env_basic_parse() {
        let text = "DB_HOST=db.local\nDB_PASSWORD=hunter2\n# a comment\n\nexport API_TOKEN=abc\n";
        let tree = FileFormat::Env.parse(text.as_bytes()).unwrap();
        assert_eq!(tree["DB_HOST"].as_str().unwrap(), "db.local");
        assert_eq!(tree["DB_PASSWORD"].as_str().unwrap(), "hunter2");
        assert_eq!(tree["API_TOKEN"].as_str().unwrap(), "abc");
    }

    #[test]
    fn env_quoting_roundtrip() {
        // Values with spaces, '#', and '=' must survive a round trip.
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            Value::String("MSG".into()),
            Value::String("hello world # not a comment".into()),
        );
        map.insert(Value::String("EQ".into()), Value::String("a=b=c".into()));
        let tree = Value::Mapping(map);
        let out = FileFormat::Env.serialize(&tree).unwrap();
        let reparsed = FileFormat::Env.parse(out.as_bytes()).unwrap();
        assert_eq!(
            reparsed["MSG"].as_str().unwrap(),
            "hello world # not a comment"
        );
        assert_eq!(reparsed["EQ"].as_str().unwrap(), "a=b=c");
    }

    #[test]
    fn env_double_quote_escapes() {
        let text = "MULTILINE=\"line1\\nline2\"\n";
        let tree = FileFormat::Env.parse(text.as_bytes()).unwrap();
        assert_eq!(tree["MULTILINE"].as_str().unwrap(), "line1\nline2");
    }

    #[test]
    fn env_single_quote_literal() {
        let text = "RAW='no \\n escape here'\n";
        let tree = FileFormat::Env.parse(text.as_bytes()).unwrap();
        assert_eq!(tree["RAW"].as_str().unwrap(), "no \\n escape here");
    }

    #[test]
    fn env_metadata_packing_roundtrip() {
        // Simulate a tree with a kerf block (as the engine would produce).
        let mut block = serde_yaml::Mapping::new();
        block.insert(Value::String("version".into()), Value::Number(1.into()));
        block.insert(
            Value::String("cipher".into()),
            Value::String("aes-256-gcm".into()),
        );
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            Value::String("DB_PASSWORD".into()),
            Value::String("ENC[AES-GCM,n:x,c:y,t:z]".into()),
        );
        map.insert(Value::String("kerf".into()), Value::Mapping(block.clone()));
        let tree = Value::Mapping(map);

        let out = FileFormat::Env.serialize(&tree).unwrap();
        // No bare `kerf` key; instead a packed KERF_METADATA line.
        assert!(out.contains("KERF_METADATA="));
        assert!(!out.contains("\nkerf="));

        let reparsed = FileFormat::Env.parse(out.as_bytes()).unwrap();
        assert_eq!(
            reparsed["DB_PASSWORD"].as_str().unwrap(),
            "ENC[AES-GCM,n:x,c:y,t:z]"
        );
        assert_eq!(reparsed["kerf"], Value::Mapping(block));
    }

    #[test]
    fn env_preserving_keeps_comments_and_changes_only_touched_value() {
        let original = "# header\nDB_HOST=db.local   # inline\nDB_PASSWORD=old\n";
        let mut block = serde_yaml::Mapping::new();
        block.insert(Value::String("version".into()), Value::Number(1.into()));
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            Value::String("DB_HOST".into()),
            Value::String("db.local".into()),
        );
        map.insert(
            Value::String("DB_PASSWORD".into()),
            Value::String("ENC[AES-GCM,n:x,c:y,t:z]".into()),
        );
        map.insert(Value::String("kerf".into()), Value::Mapping(block));

        let out = FileFormat::Env
            .serialize_preserving(original, &Value::Mapping(map))
            .unwrap();
        // Comment and unchanged line (with inline comment) kept verbatim.
        assert!(out.contains("# header\n"), "{out}");
        assert!(out.contains("DB_HOST=db.local   # inline\n"), "{out}");
        // Changed secret rewritten to the envelope; old plaintext gone.
        assert!(out.contains("ENC[AES-GCM,n:x,c:y,t:z]"), "{out}");
        assert!(!out.contains("DB_PASSWORD=old"), "{out}");
        assert!(out.contains("KERF_METADATA="), "{out}");
    }

    #[test]
    fn env_preserving_decrypt_removes_metadata_and_restores_value() {
        let original =
            "# keep me\nDB_PASSWORD=\"ENC[AES-GCM,n:x,c:y,t:z]\"\nKERF_METADATA=abc123\n";
        // No `kerf` key in the tree → decrypt direction.
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            Value::String("DB_PASSWORD".into()),
            Value::String("plaintext-secret".into()),
        );
        let out = FileFormat::Env
            .serialize_preserving(original, &Value::Mapping(map))
            .unwrap();
        assert!(out.contains("# keep me\n"), "{out}");
        assert!(out.contains("DB_PASSWORD=plaintext-secret\n"), "{out}");
        assert!(
            !out.contains("KERF_METADATA"),
            "metadata must be dropped:\n{out}"
        );
    }

    #[test]
    fn env_preserving_unset_drops_line_and_set_appends() {
        // Original has A and B; tree drops B (unset) and adds C (set new key).
        let original = "# top\nA=1\nB=2\n";
        let mut map = serde_yaml::Mapping::new();
        map.insert(Value::String("A".into()), Value::String("1".into()));
        map.insert(Value::String("C".into()), Value::String("3".into()));
        let out = FileFormat::Env
            .serialize_preserving(original, &Value::Mapping(map))
            .unwrap();
        assert!(out.contains("# top\n"), "{out}");
        assert!(out.contains("A=1\n"), "{out}");
        assert!(!out.contains("B="), "removed key must be dropped:\n{out}");
        assert!(out.contains("C=3\n"), "added key must be appended:\n{out}");
    }

    #[test]
    fn env_rejects_nested_non_kerf_value() {
        let mut nested = serde_yaml::Mapping::new();
        nested.insert(Value::String("a".into()), Value::String("b".into()));
        let mut map = serde_yaml::Mapping::new();
        map.insert(Value::String("DB".into()), Value::Mapping(nested));
        let tree = Value::Mapping(map);
        assert!(FileFormat::Env.serialize(&tree).is_err());
    }
}
