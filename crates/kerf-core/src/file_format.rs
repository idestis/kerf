//! File format selection — YAML and JSON in v1; TOML/ENV land next.
//!
//! Internal tree representation is [`serde_yaml::Value`] because it's the
//! most general superset of YAML and JSON: JSON is a strict subset of YAML,
//! and `serde_yaml`'s `Value` can hold every JSON shape losslessly.
//! Each format owns its own parse/serialize via the native serde crate.

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
        }
    }

    /// Human-readable name — used in error messages.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Yaml => "yaml",
            Self::Json => "json",
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
}
