//! Recipient + identity resolution from CLI flags and env vars.
//!
//! Precedence (matches what reference/cli.mdx documents):
//!
//!     CLI flag > KERF_* env > SOPS_* env > .kerf.yaml config
//!
//! v0.1 reads only CLI + env (no config file walking yet).
//!
//! SOPS-prefixed env vars are honoured as fallback so existing SOPS users
//! can keep their shell setup unchanged.

use std::path::PathBuf;

use kerf_kms::age::{AgeIdentity, AgeRecipient};

use crate::{CliError, IdentityFlags, RecipientFlags};

/// Resolved set of recipients ready to be handed to the engine.
pub struct ResolvedRecipients {
    /// Real age recipients we'll actually use to wrap the DEK.
    pub age: Vec<AgeRecipient>,
    /// Other backends, recorded but errored on use until impls land.
    pub unsupported: Vec<UnsupportedRecipient>,
}

pub struct UnsupportedRecipient {
    pub kind: &'static str,
    #[allow(dead_code)] // read once impls land
    pub spec: String,
}

impl ResolvedRecipients {
    /// Build from CLI flags, falling back to env vars when a flag class is empty.
    /// Hard-errors if no recipient of any usable kind ends up configured.
    pub fn resolve(flags: &RecipientFlags) -> Result<Self, CliError> {
        let age_specs = pick_specs(&flags.age, &["KERF_AGE_RECIPIENTS", "SOPS_AGE_RECIPIENTS"]);
        let kms_specs = pick_specs(&flags.kms, &["KERF_KMS_ARN", "SOPS_KMS_ARN"]);
        let gcp_specs = pick_specs(&flags.gcp_kms, &["KERF_GCP_KMS_IDS", "SOPS_GCP_KMS_IDS"]);
        let azure_specs = pick_specs(
            &flags.azure_kv,
            &["KERF_AZURE_KEYVAULT_URLS", "SOPS_AZURE_KEYVAULT_URLS"],
        );

        let mut age = Vec::with_capacity(age_specs.len());
        for spec in &age_specs {
            age.push(AgeRecipient::parse(spec).map_err(|e| {
                CliError::Usage(format!("invalid age recipient {spec:?}: {e}"))
            })?);
        }

        let mut unsupported = Vec::new();
        for spec in kms_specs {
            unsupported.push(UnsupportedRecipient {
                kind: "aws-kms",
                spec,
            });
        }
        for spec in gcp_specs {
            unsupported.push(UnsupportedRecipient {
                kind: "gcp-kms",
                spec,
            });
        }
        for spec in azure_specs {
            unsupported.push(UnsupportedRecipient {
                kind: "azure-kv",
                spec,
            });
        }

        if age.is_empty() && unsupported.is_empty() {
            return Err(CliError::NoRecipient(
                "pass --age (or --kms/--gcp-kms/--azure-kv, when supported), \
                 or set KERF_AGE_RECIPIENTS / SOPS_AGE_RECIPIENTS"
                    .into(),
            ));
        }
        if age.is_empty() {
            return Err(CliError::Unimplemented);
        }
        Ok(Self { age, unsupported })
    }
}

/// Resolved decryption identity. v0.1 supports only an age identity loaded
/// from a file or pasted into an env var.
pub struct ResolvedIdentity {
    pub age: Option<AgeIdentity>,
}

impl ResolvedIdentity {
    pub fn resolve(flags: &IdentityFlags) -> Result<Self, CliError> {
        // 1. --identity-file flag
        if let Some(path) = &flags.identity_file {
            return Ok(Self {
                age: Some(AgeIdentity::from_file(path)?),
            });
        }
        // 2. KERF_AGE_KEY_FILE → SOPS_AGE_KEY_FILE
        for env in ["KERF_AGE_KEY_FILE", "SOPS_AGE_KEY_FILE"] {
            if let Ok(path) = std::env::var(env) {
                if !path.is_empty() {
                    return Ok(Self {
                        age: Some(AgeIdentity::from_file(&PathBuf::from(path))?),
                    });
                }
            }
        }
        // 3. KERF_AGE_KEY → SOPS_AGE_KEY (inline)
        for env in ["KERF_AGE_KEY", "SOPS_AGE_KEY"] {
            if let Ok(key) = std::env::var(env) {
                if !key.is_empty() {
                    return Ok(Self {
                        age: Some(AgeIdentity::parse(&key)?),
                    });
                }
            }
        }
        Err(CliError::NoRecipient(
            "no decryption identity — pass --identity-file or set \
             KERF_AGE_KEY_FILE / SOPS_AGE_KEY_FILE / KERF_AGE_KEY / SOPS_AGE_KEY"
                .into(),
        ))
    }
}

/// Pick a list of comma-separated specs from CLI flags first, falling back
/// to the first non-empty env var in `envs`.
fn pick_specs(flag_values: &[String], envs: &[&str]) -> Vec<String> {
    if !flag_values.is_empty() {
        return flag_values.to_vec();
    }
    for env in envs {
        if let Ok(raw) = std::env::var(env) {
            let parts: Vec<String> = raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            if !parts.is_empty() {
                return parts;
            }
        }
    }
    Vec::new()
}
