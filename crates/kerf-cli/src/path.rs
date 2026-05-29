//! Dotted-path navigation over a parsed tree (SPEC § 4.4).
//!
//! Paths are dot-separated with `[N]` array indices: `db.password`,
//! `users[0].api_key`, `matrix[0][1]`. This module parses such a path into
//! segments and resolves / mutates a `serde_yaml::Value` against them. It is
//! shared by `view` (read), `set`, and `unset` (write).

use serde_yaml::Value;

use crate::CliError;

/// One step of a path: a map key or a sequence index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg {
    /// A mapping key.
    Key(String),
    /// A sequence index.
    Index(usize),
}

/// Parse a dotted path into segments. Rejects empty components and malformed
/// `[…]` brackets so a typo is a usage error, not a silent miss.
pub fn parse(path: &str) -> Result<Vec<Seg>, CliError> {
    if path.is_empty() {
        return Err(CliError::Usage("empty path".into()));
    }
    let mut segs = Vec::new();
    for part in path.split('.') {
        if part.is_empty() {
            return Err(CliError::Usage(format!(
                "path {path:?} has an empty component"
            )));
        }
        let key_end = part.find('[').unwrap_or(part.len());
        let key = &part[..key_end];
        if !key.is_empty() {
            segs.push(Seg::Key(key.to_string()));
        }
        let mut rest = &part[key_end..];
        while let Some(stripped) = rest.strip_prefix('[') {
            let close = stripped
                .find(']')
                .ok_or_else(|| CliError::Usage(format!("path {path:?} has an unclosed `[`")))?;
            let idx: usize = stripped[..close].parse().map_err(|_| {
                CliError::Usage(format!(
                    "path {path:?} has a non-numeric array index {:?}",
                    &stripped[..close]
                ))
            })?;
            segs.push(Seg::Index(idx));
            rest = &stripped[close + 1..];
        }
        if !rest.is_empty() {
            return Err(CliError::Usage(format!(
                "path {path:?} has trailing junk {rest:?}"
            )));
        }
    }
    if segs.is_empty() {
        return Err(CliError::Usage(format!(
            "path {path:?} resolved to nothing"
        )));
    }
    Ok(segs)
}

/// Resolve a path to a reference, or `None` if any segment is missing or the
/// shape doesn't match (key on a sequence, index on a map, out of range).
#[must_use]
pub fn get<'a>(tree: &'a Value, segs: &[Seg]) -> Option<&'a Value> {
    let mut cur = tree;
    for seg in segs {
        cur = match (seg, cur) {
            (Seg::Key(k), Value::Mapping(m)) => m.get(Value::String(k.clone()))?,
            (Seg::Index(i), Value::Sequence(s)) => s.get(*i)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Set the value at `path`, creating intermediate mappings as needed.
///
/// Sequence indices must already exist — we never auto-grow arrays, since the
/// intended index is ambiguous and silently appending is a footgun. A missing
/// map key along the way is created as an empty mapping.
pub fn set(tree: &mut Value, segs: &[Seg], value: Value) -> Result<(), CliError> {
    let (last, parents) = segs
        .split_last()
        .ok_or_else(|| CliError::Usage("empty path".into()))?;

    let mut cur = tree;
    for seg in parents {
        cur = descend_or_create(cur, seg)?;
    }
    match (last, cur) {
        (Seg::Key(k), Value::Mapping(m)) => {
            m.insert(Value::String(k.clone()), value);
            Ok(())
        }
        (Seg::Index(i), Value::Sequence(s)) => {
            let slot = s
                .get_mut(*i)
                .ok_or_else(|| CliError::Usage(format!("array index [{i}] is out of range")))?;
            *slot = value;
            Ok(())
        }
        (Seg::Key(_), _) => Err(CliError::Usage(
            "cannot set a key on a non-mapping value".into(),
        )),
        (Seg::Index(_), _) => Err(CliError::Usage("cannot index a non-sequence value".into())),
    }
}

/// Remove the value at `path`. Returns an error if the path doesn't exist —
/// `unset` of an absent key is a mistake worth surfacing.
pub fn remove(tree: &mut Value, segs: &[Seg]) -> Result<(), CliError> {
    let (last, parents) = segs
        .split_last()
        .ok_or_else(|| CliError::Usage("empty path".into()))?;

    let mut cur = tree;
    for seg in parents {
        cur = match (seg, cur) {
            (Seg::Key(k), Value::Mapping(m)) => m
                .get_mut(Value::String(k.clone()))
                .ok_or_else(|| not_found(segs))?,
            (Seg::Index(i), Value::Sequence(s)) => s.get_mut(*i).ok_or_else(|| not_found(segs))?,
            _ => return Err(not_found(segs)),
        };
    }
    match (last, cur) {
        (Seg::Key(k), Value::Mapping(m)) => {
            m.remove(Value::String(k.clone()))
                .ok_or_else(|| not_found(segs))?;
            Ok(())
        }
        (Seg::Index(i), Value::Sequence(s)) => {
            if *i < s.len() {
                s.remove(*i);
                Ok(())
            } else {
                Err(not_found(segs))
            }
        }
        _ => Err(not_found(segs)),
    }
}

/// Descend into a child for a parent segment, creating an empty mapping for a
/// missing map key. Sequence indices must already exist.
fn descend_or_create<'a>(cur: &'a mut Value, seg: &Seg) -> Result<&'a mut Value, CliError> {
    match seg {
        Seg::Key(k) => {
            let Value::Mapping(m) = cur else {
                return Err(CliError::Usage(
                    "cannot descend into a non-mapping value".into(),
                ));
            };
            let key = Value::String(k.clone());
            if !m.contains_key(&key) {
                m.insert(key.clone(), Value::Mapping(serde_yaml::Mapping::new()));
            }
            Ok(m.get_mut(&key).expect("just inserted"))
        }
        Seg::Index(i) => {
            let Value::Sequence(s) = cur else {
                return Err(CliError::Usage("cannot index a non-sequence value".into()));
            };
            s.get_mut(*i)
                .ok_or_else(|| CliError::Usage(format!("array index [{i}] is out of range")))
        }
    }
}

fn not_found(segs: &[Seg]) -> CliError {
    CliError::Usage(format!("path {} not found", render(segs)))
}

/// Render segments back to dotted-path form for error messages.
fn render(segs: &[Seg]) -> String {
    let mut out = String::new();
    for seg in segs {
        match seg {
            Seg::Key(k) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(k);
            }
            Seg::Index(i) => out.push_str(&format!("[{i}]")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> Value {
        serde_yaml::from_str("db:\n  password: hunter2\nusers:\n  - api_key: k0\n  - api_key: k1\n")
            .unwrap()
    }

    #[test]
    fn parses_keys_and_indices() {
        assert_eq!(
            parse("users[0].api_key").unwrap(),
            vec![
                Seg::Key("users".into()),
                Seg::Index(0),
                Seg::Key("api_key".into())
            ]
        );
    }

    #[test]
    fn rejects_bad_paths() {
        assert!(parse("").is_err());
        assert!(parse("a..b").is_err());
        assert!(parse("a[x]").is_err());
        assert!(parse("a[0").is_err());
    }

    #[test]
    fn gets_nested_value() {
        let t = tree();
        let segs = parse("users[1].api_key").unwrap();
        assert_eq!(get(&t, &segs).unwrap().as_str(), Some("k1"));
    }

    #[test]
    fn get_missing_is_none() {
        let t = tree();
        assert!(get(&t, &parse("db.nope").unwrap()).is_none());
        assert!(get(&t, &parse("users[9].api_key").unwrap()).is_none());
    }

    #[test]
    fn set_replaces_and_creates() {
        let mut t = tree();
        set(
            &mut t,
            &parse("db.password").unwrap(),
            Value::String("new".into()),
        )
        .unwrap();
        assert_eq!(
            get(&t, &parse("db.password").unwrap()).unwrap().as_str(),
            Some("new")
        );
        // creates an intermediate mapping
        set(
            &mut t,
            &parse("db.extra.token").unwrap(),
            Value::String("t".into()),
        )
        .unwrap();
        assert_eq!(
            get(&t, &parse("db.extra.token").unwrap()).unwrap().as_str(),
            Some("t")
        );
    }

    #[test]
    fn set_array_in_range_ok_out_of_range_err() {
        let mut t = tree();
        set(
            &mut t,
            &parse("users[0].api_key").unwrap(),
            Value::String("z".into()),
        )
        .unwrap();
        assert_eq!(
            get(&t, &parse("users[0].api_key").unwrap())
                .unwrap()
                .as_str(),
            Some("z")
        );
        assert!(set(
            &mut t,
            &parse("users[5].api_key").unwrap(),
            Value::String("z".into())
        )
        .is_err());
    }

    #[test]
    fn remove_existing_ok_absent_err() {
        let mut t = tree();
        remove(&mut t, &parse("db.password").unwrap()).unwrap();
        assert!(get(&t, &parse("db.password").unwrap()).is_none());
        assert!(remove(&mut t, &parse("db.password").unwrap()).is_err());
    }
}
