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

use std::path::Path;

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
}

impl FileFormat {
    /// Detect from a file path. Returns `None` if the extension isn't
    /// recognized — caller decides whether to default to YAML or error.
    #[must_use]
    pub fn detect(path: &Path) -> Option<Self> {
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
        }
    }

    /// Human-readable name — used in error messages.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Yaml => "yaml",
            Self::Json => "json",
            Self::Toml => "toml",
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
            items.iter().map(yaml_to_json_value).collect::<Result<_>>()?,
        )),
        Value::Mapping(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => {
                        return Err(Error::KerfBlock(
                            "JSON object keys must be scalar".into(),
                        ))
                    }
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
                Ok(i64::try_from(u).map_or_else(
                    |_| toml::Value::Float(u as f64),
                    toml::Value::Integer,
                ))
            } else if let Some(f) = n.as_f64() {
                Ok(toml::Value::Float(f))
            } else {
                Ok(toml::Value::String(n.to_string()))
            }
        }
        Value::String(s) => Ok(toml::Value::String(s.clone())),
        Value::Sequence(items) => Ok(toml::Value::Array(
            items.iter().map(yaml_to_toml_value).collect::<Result<_>>()?,
        )),
        Value::Mapping(map) => {
            let mut table = toml::map::Map::new();
            for (k, v) in map {
                let key = match k {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => {
                        return Err(Error::KerfBlock(
                            "TOML table keys must be scalar".into(),
                        ))
                    }
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
            let (mut values, mut tables): (Vec<_>, Vec<_>) =
                entries.into_iter().partition(|(_, val)| !is_toml_table_like(val));
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
        db.insert(Value::String("host".into()), Value::String("db.local".into()));
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
        assert_eq!(
            tree["created"].as_str().unwrap(),
            "2026-05-29T10:00:00Z"
        );
    }

    #[test]
    fn toml_array_roundtrip() {
        let original = b"ports = [8080, 8081, 8082]\n";
        let tree = FileFormat::Toml.parse(original).unwrap();
        let back = FileFormat::Toml.serialize(&tree).unwrap();
        let reparsed = FileFormat::Toml.parse(back.as_bytes()).unwrap();
        assert_eq!(reparsed, tree);
    }
}
