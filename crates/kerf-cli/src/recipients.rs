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

#[cfg(feature = "aws-kms")]
use std::collections::BTreeMap;
use std::path::PathBuf;

use kerf_core::{Dek, RecipientEntry};
use kerf_kms::age::{AgeIdentity, AgeRecipient};
#[cfg(feature = "aws-kms")]
use kerf_kms::aws::{AwsKmsIdentity, AwsKmsRecipient};
#[cfg(feature = "azure-kv")]
use kerf_kms::azure::{AzureKvIdentity, AzureKvRecipient};
#[cfg(feature = "gcp-kms")]
use kerf_kms::gcp::{GcpKmsIdentity, GcpKmsRecipient};
use kerf_kms::recipient::Recipient;

use crate::{CliError, IdentityFlags, RecipientFlags};

/// Resolved set of recipients ready to be handed to the engine.
pub struct ResolvedRecipients {
    /// Real age recipients we'll actually use to wrap the DEK.
    pub age: Vec<AgeRecipient>,
    /// AWS KMS recipients (one per --kms ARN). Empty when the `aws-kms`
    /// feature is disabled at compile time.
    #[cfg(feature = "aws-kms")]
    pub aws_kms: Vec<AwsKmsRecipient>,
    /// GCP Cloud KMS recipients (one per --gcp-kms resource id).
    #[cfg(feature = "gcp-kms")]
    pub gcp_kms: Vec<GcpKmsRecipient>,
    /// Azure Key Vault recipients (one per --azure-kv key URL).
    #[cfg(feature = "azure-kv")]
    pub azure_kv: Vec<AzureKvRecipient>,
    /// Other backends still pending implementation. Surfaced so the CLI
    /// can hard-error on use rather than silently dropping the flag.
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
            age.push(
                AgeRecipient::parse(spec)
                    .map_err(|e| CliError::Usage(format!("invalid age recipient {spec:?}: {e}")))?,
            );
        }

        #[cfg(feature = "aws-kms")]
        let aws_kms = {
            // Per-recipient encryption context isn't surfaced as a CLI flag
            // in v0.1; deferred until --kms-context lands. Empty map for now.
            let context = BTreeMap::new();
            let mut out = Vec::with_capacity(kms_specs.len());
            for spec in &kms_specs {
                out.push(AwsKmsRecipient::parse(spec, context.clone()).map_err(|e| {
                    CliError::Usage(format!("invalid AWS KMS recipient {spec:?}: {e}"))
                })?);
            }
            out
        };
        #[cfg(not(feature = "aws-kms"))]
        let aws_kms_specs = kms_specs.clone();

        #[cfg(feature = "gcp-kms")]
        let gcp_kms = {
            let mut out = Vec::with_capacity(gcp_specs.len());
            for spec in &gcp_specs {
                out.push(GcpKmsRecipient::parse(spec).map_err(|e| {
                    CliError::Usage(format!("invalid GCP KMS recipient {spec:?}: {e}"))
                })?);
            }
            out
        };
        #[cfg(not(feature = "gcp-kms"))]
        let gcp_kms_specs = gcp_specs.clone();

        #[cfg(feature = "azure-kv")]
        let azure_kv = {
            let mut out = Vec::with_capacity(azure_specs.len());
            for spec in &azure_specs {
                out.push(AzureKvRecipient::parse(spec).map_err(|e| {
                    CliError::Usage(format!("invalid Azure Key Vault recipient {spec:?}: {e}"))
                })?);
            }
            out
        };
        #[cfg(not(feature = "azure-kv"))]
        let azure_kv_specs = azure_specs.clone();

        // `mut` is used only when a KMS feature is disabled (the cfg'd loops
        // below push unsupported specs); the allow keeps the all-features
        // build warning-free.
        #[allow(unused_mut)]
        let mut unsupported = Vec::new();
        #[cfg(not(feature = "aws-kms"))]
        for spec in aws_kms_specs {
            unsupported.push(UnsupportedRecipient {
                kind: "aws-kms",
                spec,
            });
        }
        #[cfg(not(feature = "gcp-kms"))]
        for spec in gcp_kms_specs {
            unsupported.push(UnsupportedRecipient {
                kind: "gcp-kms",
                spec,
            });
        }
        #[cfg(not(feature = "azure-kv"))]
        for spec in azure_kv_specs {
            unsupported.push(UnsupportedRecipient {
                kind: "azure-kv",
                spec,
            });
        }

        // `mut` is used only when a KMS feature is enabled; the allow keeps
        // the age-only build warning-free.
        #[allow(unused_mut)]
        let mut any_real = !age.is_empty();
        #[cfg(feature = "aws-kms")]
        {
            any_real = any_real || !aws_kms.is_empty();
        }
        #[cfg(feature = "gcp-kms")]
        {
            any_real = any_real || !gcp_kms.is_empty();
        }
        #[cfg(feature = "azure-kv")]
        {
            any_real = any_real || !azure_kv.is_empty();
        }

        if !any_real && unsupported.is_empty() {
            return Err(CliError::NoRecipient(
                "pass --age / --kms / --gcp-kms (or set the matching KERF_* / SOPS_* env var)"
                    .into(),
            ));
        }
        if !any_real {
            return Err(CliError::Unimplemented);
        }
        Ok(Self {
            age,
            #[cfg(feature = "aws-kms")]
            aws_kms,
            #[cfg(feature = "gcp-kms")]
            gcp_kms,
            #[cfg(feature = "azure-kv")]
            azure_kv,
            unsupported,
        })
    }

    /// Wrap `dek` once per resolved recipient, producing the on-disk
    /// `RecipientEntry` list. Each `wrap` uses a fresh CSPRNG nonce (the
    /// `Recipient` contract), so this is safe to call for fresh wraps and
    /// for re-wraps under an existing DEK (`keys add`).
    pub fn wrap_all(&self, dek: &Dek) -> Result<Vec<RecipientEntry>, CliError> {
        let mut out = Vec::new();
        for recipient in &self.age {
            out.push(recipient.entry(&recipient.wrap(dek)?));
        }
        #[cfg(feature = "aws-kms")]
        for recipient in &self.aws_kms {
            out.push(recipient.entry(&recipient.wrap(dek)?));
        }
        #[cfg(feature = "gcp-kms")]
        for recipient in &self.gcp_kms {
            out.push(recipient.entry(&recipient.wrap(dek)?));
        }
        #[cfg(feature = "azure-kv")]
        for recipient in &self.azure_kv {
            out.push(recipient.entry(&recipient.wrap(dek)?));
        }
        Ok(out)
    }

    /// Addressing key per resolved recipient: `(kind, normalized-id)`. Used by
    /// `keys add`/`remove` to match against entries already in the file. Azure
    /// ids are normalized to their unversioned base so a versioned stored kid
    /// and an unversioned supplied URL compare equal.
    #[must_use]
    pub fn addrs(&self) -> Vec<(&'static str, String)> {
        #[allow(unused_mut)]
        let mut out: Vec<(&'static str, String)> = self
            .age
            .iter()
            .map(|r| ("age", r.spec().to_string()))
            .collect();
        #[cfg(feature = "aws-kms")]
        out.extend(
            self.aws_kms
                .iter()
                .map(|r| ("aws-kms", r.arn().to_string())),
        );
        #[cfg(feature = "gcp-kms")]
        out.extend(
            self.gcp_kms
                .iter()
                .map(|r| ("gcp-kms", r.resource_id().to_string())),
        );
        #[cfg(feature = "azure-kv")]
        out.extend(
            self.azure_kv
                .iter()
                .map(|r| ("azure-kv", crate::run::azure_key_base(r.key_url()))),
        );
        out
    }
}

/// Resolved decryption identity — one or both of an age identity and an
/// AWS KMS identity may be set. Decrypt walks the file's recipient list
/// and tries the first one that matches an available identity.
pub struct ResolvedIdentity {
    pub age: Option<AgeIdentity>,
    #[cfg(feature = "aws-kms")]
    pub aws_kms: Option<AwsKmsIdentity>,
    #[cfg(feature = "gcp-kms")]
    pub gcp_kms: Option<GcpKmsIdentity>,
    #[cfg(feature = "azure-kv")]
    pub azure_kv: Option<AzureKvIdentity>,
}

impl ResolvedIdentity {
    /// Build whatever identities we can from the environment.
    ///
    /// We're permissive here: build an identity for each provider whose
    /// credentials/keys are reachable. The caller (decrypt path) picks
    /// whichever matches a recipient in the file. Missing all of them is
    /// only an error if the file requires one.
    pub fn resolve(flags: &IdentityFlags) -> Result<Self, CliError> {
        let age = resolve_age_identity(flags)?;
        #[cfg(feature = "aws-kms")]
        let aws_kms = resolve_aws_identity();
        #[cfg(feature = "gcp-kms")]
        let gcp_kms = resolve_gcp_identity();
        #[cfg(feature = "azure-kv")]
        let azure_kv = Some(AzureKvIdentity::new());
        Ok(Self {
            age,
            #[cfg(feature = "aws-kms")]
            aws_kms,
            #[cfg(feature = "gcp-kms")]
            gcp_kms,
            #[cfg(feature = "azure-kv")]
            azure_kv,
        })
    }
}

fn resolve_age_identity(flags: &IdentityFlags) -> Result<Option<AgeIdentity>, CliError> {
    if let Some(path) = &flags.identity_file {
        return Ok(Some(AgeIdentity::from_file(path)?));
    }
    for env in ["KERF_AGE_KEY_FILE", "SOPS_AGE_KEY_FILE"] {
        if let Ok(path) = std::env::var(env) {
            if !path.is_empty() {
                return Ok(Some(AgeIdentity::from_file(&PathBuf::from(path))?));
            }
        }
    }
    for env in ["KERF_AGE_KEY", "SOPS_AGE_KEY"] {
        if let Ok(key) = std::env::var(env) {
            if !key.is_empty() {
                return Ok(Some(AgeIdentity::parse(&key)?));
            }
        }
    }
    Ok(None)
}

#[cfg(feature = "aws-kms")]
fn resolve_aws_identity() -> Option<AwsKmsIdentity> {
    // The SDK's default chain handles env / profile / IAM role discovery.
    // We only need a region hint to build the initial client; the actual
    // region for each Decrypt call is taken from the entry's ARN.
    let region = std::env::var("AWS_REGION")
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .unwrap_or_else(|_| "us-east-1".to_string());
    Some(AwsKmsIdentity::new(&region))
}

#[cfg(feature = "gcp-kms")]
fn resolve_gcp_identity() -> Option<GcpKmsIdentity> {
    // Building the client performs auth discovery (ADC / GOOGLE_APPLICATION_
    // CREDENTIALS / metadata server) or, with KERF_KMS_ENDPOINT_GCP set, an
    // unauthenticated emulator client. If that fails (e.g. no creds on this
    // host), we simply have no GCP identity — the decrypt path falls back to
    // other identities and only errors if nothing can unwrap the file.
    GcpKmsIdentity::new().ok()
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
