//! `.kerf.yaml` configuration schema and `kerf init`.
//!
//! The config records *creation rules* (SPEC § 8): for files whose path
//! matches `path_regex`, which recipients to wrap the DEK for and which keys
//! to encrypt. Rules are evaluated top-to-bottom, first match wins.
//!
//! v0.1 *writes* this file via `kerf init`; the encrypt path does not yet
//! consult it — recipients still come from flags / env (see `recipients.rs`).
//! The schema is defined here so that reader and writer share one source of
//! truth when config-driven encryption lands.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::io::atomic_write;
use crate::CliError;

/// Default `path_regex` written by `init`: match any `<name>.kerf.<ext>` file
/// under the current tree. Scoped to the kerf suffix convention (SPEC § 4.1)
/// so plaintext files are never matched by accident.
const DEFAULT_PATH_REGEX: &str = r".*\.kerf\.[^.]+$";

/// Top-level `.kerf.yaml` document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Config schema version. v1 is the shape in SPEC § 8.
    pub version: u32,
    /// Ordered creation rules; first `path_regex` match wins.
    pub creation_rules: Vec<CreationRule>,
}

/// One creation rule: a path matcher plus the recipients and encryption
/// policy to apply to files it matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationRule {
    /// Regex matched against the destination file path.
    pub path_regex: String,
    /// Recipients the DEK is wrapped for when this rule applies.
    pub recipients: Vec<ConfigRecipient>,
    /// Which leaf keys to encrypt. Omitted → the built-in default
    /// (`^(password|token|key|secret|credential)$`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub encrypted_regex: Option<String>,
    /// Whether the file MAC covers only encrypted leaves (`true`, the
    /// default) or all leaves (`false`). See SPEC § 4.5.
    pub mac_only_encrypted: bool,
}

/// A recipient as recorded in config — the *addressing* of a key, without any
/// wrapped DEK (that is per-file, in the `kerf:` block). Mirrors the on-disk
/// [`kerf_core::RecipientEntry`] shape minus `encrypted_dek`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ConfigRecipient {
    /// age recipient (X25519 + ChaCha20-Poly1305).
    Age {
        /// `age1…` recipient string.
        recipient: String,
    },
    /// AWS KMS key.
    AwsKms {
        /// Key ARN.
        arn: String,
        /// Optional AWS encryption context (authenticated by KMS).
        #[serde(skip_serializing_if = "Option::is_none", default)]
        encryption_context: Option<BTreeMap<String, String>>,
    },
    /// GCP Cloud KMS crypto key.
    GcpKms {
        /// Full crypto-key resource id.
        resource_id: String,
    },
    /// Azure Key Vault key.
    AzureKv {
        /// Full key (version) URL.
        key_id: String,
    },
}

/// Parse a `--recipient` spec into a typed recipient.
///
/// Accepted forms:
/// - `age:age1…` or a bare `age1…` (convenience)
/// - `aws-kms:<arn>` (alias `kms:`)
/// - `gcp-kms:<resource-id>` (alias `gcp:`)
/// - `azure-kv:<key-url>` (alias `azure:`)
///
/// The split is on the *first* `:` only, so ARNs and `https://` URLs (which
/// contain their own colons) survive intact. age recipients are validated by
/// parsing; KMS specs are checked for a non-empty value, with deeper
/// validation deferred to the KMS backend at encrypt time.
pub fn parse_recipient_spec(spec: &str) -> Result<ConfigRecipient, CliError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(CliError::Usage("empty --recipient".into()));
    }

    // Bare age recipient, no prefix needed.
    if spec.starts_with("age1") {
        return parse_age(spec);
    }

    let (kind, value) = spec.split_once(':').ok_or_else(|| {
        CliError::Usage(format!(
            "recipient {spec:?} has no type prefix \
             (expected age:/aws-kms:/gcp-kms:/azure-kv: or a bare age1… string)"
        ))
    })?;
    let value = value.trim();
    if value.is_empty() {
        return Err(CliError::Usage(format!(
            "recipient {spec:?} has an empty value after {kind:?}:"
        )));
    }

    match kind.to_ascii_lowercase().as_str() {
        "age" => parse_age(value),
        "aws-kms" | "kms" | "aws" => Ok(ConfigRecipient::AwsKms {
            arn: value.to_string(),
            encryption_context: None,
        }),
        "gcp-kms" | "gcp" => Ok(ConfigRecipient::GcpKms {
            resource_id: value.to_string(),
        }),
        "azure-kv" | "azure" => Ok(ConfigRecipient::AzureKv {
            key_id: value.to_string(),
        }),
        other => Err(CliError::Usage(format!(
            "unknown recipient type {other:?} in {spec:?} \
             (expected age, aws-kms, gcp-kms, or azure-kv)"
        ))),
    }
}

/// Validate and wrap an age recipient string.
fn parse_age(value: &str) -> Result<ConfigRecipient, CliError> {
    // Validate at init time so a typo is caught now rather than at first
    // encrypt. age parsing is always available (not feature-gated).
    kerf_kms::age::AgeRecipient::parse(value)
        .map_err(|e| CliError::Usage(format!("invalid age recipient {value:?}: {e}")))?;
    Ok(ConfigRecipient::Age {
        recipient: value.to_string(),
    })
}

/// Arguments for `kerf init`.
pub struct InitArgs {
    /// Recipient specs (`--recipient`). At least one required.
    pub recipients: Vec<String>,
    /// Destination path. Defaults to `./.kerf.yaml`.
    pub output: Option<PathBuf>,
    /// Override the rule's `path_regex`.
    pub path_regex: Option<String>,
    /// Override the rule's `encrypted_regex`.
    pub encrypted_regex: Option<String>,
    /// MAC over *all* leaves rather than only encrypted ones.
    pub mac_all: bool,
}

/// `kerf init` — write a `.kerf.yaml` with a single creation rule.
///
/// Refuses to overwrite an existing config: clobbering recipient policy by
/// accident is the kind of mistake the tool should not enable (cf. `keygen`).
pub fn init(args: InitArgs) -> Result<(), CliError> {
    let dest = args.output.unwrap_or_else(|| PathBuf::from(".kerf.yaml"));

    if dest.exists() {
        return Err(CliError::Usage(format!(
            "refusing to overwrite existing config {} (edit it by hand or pass --output)",
            dest.display()
        )));
    }
    if args.recipients.is_empty() {
        return Err(CliError::Usage(
            "kerf init needs at least one --recipient".into(),
        ));
    }

    let recipients = args
        .recipients
        .iter()
        .map(|s| parse_recipient_spec(s))
        .collect::<Result<Vec<_>, _>>()?;

    let config = Config {
        version: 1,
        creation_rules: vec![CreationRule {
            path_regex: args
                .path_regex
                .unwrap_or_else(|| DEFAULT_PATH_REGEX.to_string()),
            recipients,
            encrypted_regex: Some(
                args.encrypted_regex
                    .unwrap_or_else(|| kerf_core::DEFAULT_ENCRYPTED_REGEX.to_string()),
            ),
            mac_only_encrypted: !args.mac_all,
        }],
    };

    let body = serde_yaml::to_string(&config)
        .map_err(|e| CliError::Other(format!("serialize config: {e}")))?;
    let document = format!("{HEADER}{body}");

    atomic_write(&dest, document.as_bytes())?;
    eprintln!("kerf: wrote {}", dest.display());
    Ok(())
}

/// Comment header prepended to a generated `.kerf.yaml`.
const HEADER: &str = "\
# .kerf.yaml — kerf creation rules. See SPEC § 8.
# Files whose path matches a rule's path_regex are encrypted for that rule's
# recipients. Rules are evaluated top-to-bottom; the first match wins.
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_age_recipient_parses() {
        // Generate a genuinely valid recipient so the parse-time validation
        // exercises the real Bech32 path.
        let (_secret, recipient) = kerf_kms::age::keygen();
        let parsed = parse_recipient_spec(&recipient).unwrap();
        assert_eq!(parsed, ConfigRecipient::Age { recipient });
    }

    #[test]
    fn prefixed_age_recipient_parses() {
        let (_secret, recipient) = kerf_kms::age::keygen();
        assert!(matches!(
            parse_recipient_spec(&format!("age:{recipient}")).unwrap(),
            ConfigRecipient::Age { .. }
        ));
    }

    #[test]
    fn aws_arn_keeps_internal_colons() {
        let spec = "aws-kms:arn:aws:kms:us-east-1:111:key/prod-secrets";
        assert_eq!(
            parse_recipient_spec(spec).unwrap(),
            ConfigRecipient::AwsKms {
                arn: "arn:aws:kms:us-east-1:111:key/prod-secrets".to_string(),
                encryption_context: None,
            }
        );
    }

    #[test]
    fn azure_url_keeps_internal_colons() {
        let spec = "azure-kv:https://vault.vault.azure.net/keys/dek/abc123";
        assert_eq!(
            parse_recipient_spec(spec).unwrap(),
            ConfigRecipient::AzureKv {
                key_id: "https://vault.vault.azure.net/keys/dek/abc123".to_string(),
            }
        );
    }

    #[test]
    fn gcp_alias_parses() {
        assert_eq!(
            parse_recipient_spec("gcp:projects/p/locations/l/keyRings/r/cryptoKeys/k").unwrap(),
            ConfigRecipient::GcpKms {
                resource_id: "projects/p/locations/l/keyRings/r/cryptoKeys/k".to_string(),
            }
        );
    }

    #[test]
    fn no_prefix_non_age_is_rejected() {
        assert!(parse_recipient_spec("just-some-arn").is_err());
    }

    #[test]
    fn unknown_type_is_rejected() {
        assert!(parse_recipient_spec("pgp:0xDEADBEEF").is_err());
    }

    #[test]
    fn empty_value_is_rejected() {
        assert!(parse_recipient_spec("aws-kms:").is_err());
    }

    #[test]
    fn invalid_age_recipient_is_rejected() {
        assert!(parse_recipient_spec("age1-not-a-real-recipient").is_err());
    }

    #[test]
    fn config_round_trips_through_yaml() {
        let config = Config {
            version: 1,
            creation_rules: vec![CreationRule {
                path_regex: DEFAULT_PATH_REGEX.to_string(),
                recipients: vec![
                    ConfigRecipient::AwsKms {
                        arn: "arn:aws:kms:us-east-1:111:key/prod".to_string(),
                        encryption_context: None,
                    },
                    ConfigRecipient::Age {
                        recipient: "age1abc".to_string(),
                    },
                ],
                encrypted_regex: Some(kerf_core::DEFAULT_ENCRYPTED_REGEX.to_string()),
                mac_only_encrypted: true,
            }],
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        // Tag discriminator and kebab-case type names land as SPEC § 8 shows.
        assert!(yaml.contains("type: aws-kms"));
        assert!(yaml.contains("type: age"));
        let back: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            back.creation_rules[0].recipients,
            config.creation_rules[0].recipients
        );
        assert!(back.creation_rules[0].mac_only_encrypted);
    }
}
