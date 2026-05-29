//! AWS KMS recipient — uses the official `aws-sdk-kms` for `Encrypt` /
//! `Decrypt`. The SDK is async; we adapt to the sync `Recipient` trait by
//! running calls on a shared tokio runtime via `Handle::block_on`. The
//! runtime is built lazily on first use so users who don't touch AWS pay
//! no tokio startup cost.
//!
//! What's stored on disk (matches SPEC § 4.6):
//!
//! - `type: aws-kms`
//! - `arn`: the key ARN — used to route the `Decrypt` call without parsing
//!   the wrapped blob.
//! - `encrypted_dek`: base64 of the raw `kms:Encrypt` output (KMS's own
//!   ciphertext blob, opaque to us).
//! - `encryption_context`: optional `{k: v}` map. KMS authenticates this on
//!   both Encrypt and Decrypt — a mismatch on decrypt means a tamper attempt
//!   or a deployment misconfiguration; surface as `Error::Unwrap`.
//!
//! Region inference: extracted from the ARN's third field. The endpoint
//! can be overridden via `KERF_KMS_ENDPOINT_AWS` so the same code talks to
//! `LocalStack` / `floci` during local integration tests.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use aws_config::BehaviorVersion;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::Client;
use aws_types::region::Region;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kerf_core::{Dek, RecipientEntry};
use tokio::runtime::{Handle, Runtime};

use crate::recipient::{Identity, Recipient, WrappedDek};
use crate::{Error, Result};

const KIND: &str = "aws-kms";

/// Lazily-initialised tokio runtime. Created once per process the first
/// time an AWS recipient/identity is built. We deliberately use a
/// multi-threaded runtime so blocking the current thread on `block_on`
/// doesn't deadlock if SDK calls fan out internally.
fn runtime_handle() -> Handle {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("kerf-aws")
                .worker_threads(2)
                .build()
                .expect("tokio runtime")
        })
        .handle()
        .clone()
}

/// Parse an AWS KMS ARN into (`region`, `account_id`, `resource`).
///
/// Format (per AWS docs): `arn:aws:kms:<region>:<account>:key/<id>` or
/// `arn:aws:kms:<region>:<account>:alias/<name>`. We tolerate the alias
/// form but reject anything that doesn't match those shapes.
fn parse_arn(arn: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() != 6 || parts[0] != "arn" || parts[2] != "kms" {
        return Err(Error::ParseRecipient(format!(
            "not a KMS ARN: {arn:?} (expected arn:aws:kms:<region>:<account>:key/...)"
        )));
    }
    let region = parts[3].to_string();
    let account = parts[4].to_string();
    let resource = parts[5].to_string();
    if region.is_empty() || resource.is_empty() {
        return Err(Error::ParseRecipient(format!(
            "incomplete KMS ARN: {arn:?}"
        )));
    }
    Ok((region, account, resource))
}

fn build_client(region: &str) -> Client {
    runtime_handle().block_on(async move {
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.to_string()));
        if let Ok(endpoint) = std::env::var("KERF_KMS_ENDPOINT_AWS") {
            if !endpoint.is_empty() {
                loader = loader.endpoint_url(endpoint);
            }
        }
        let config = loader.load().await;
        Client::new(&config)
    })
}

/// An AWS KMS encryption recipient.
pub struct AwsKmsRecipient {
    arn: String,
    encryption_context: BTreeMap<String, String>,
    client: Client,
}

impl AwsKmsRecipient {
    /// Construct from an ARN and an optional encryption context.
    pub fn parse(arn: &str, encryption_context: BTreeMap<String, String>) -> Result<Self> {
        let (region, _account, _resource) = parse_arn(arn)?;
        Ok(Self {
            arn: arn.to_string(),
            encryption_context,
            client: build_client(&region),
        })
    }

    /// Borrow the ARN.
    #[must_use]
    pub fn arn(&self) -> &str {
        &self.arn
    }
}

impl Recipient for AwsKmsRecipient {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn wrap(&self, dek: &Dek) -> Result<WrappedDek> {
        let plaintext = Blob::new(dek.for_recipient().to_vec());
        let arn = self.arn.clone();
        let context = self.encryption_context.clone();
        let client = self.client.clone();
        let bytes = runtime_handle().block_on(async move {
            let mut req = client.encrypt().key_id(arn).plaintext(plaintext);
            for (k, v) in context {
                req = req.encryption_context(k, v);
            }
            req.send().await
        });
        let resp = bytes.map_err(|e| Error::Wrap(format!("kms:Encrypt: {e}")))?;
        let ciphertext = resp
            .ciphertext_blob
            .ok_or_else(|| Error::Wrap("kms:Encrypt returned no ciphertext".into()))?;
        Ok(ciphertext.into_inner())
    }

    fn entry(&self, wrapped: &WrappedDek) -> RecipientEntry {
        RecipientEntry::AwsKms {
            arn: self.arn.clone(),
            encrypted_dek: B64.encode(wrapped),
            encryption_context: if self.encryption_context.is_empty() {
                None
            } else {
                Some(self.encryption_context.clone())
            },
        }
    }
}

/// An AWS KMS identity — credentials are resolved by the SDK's default
/// chain (env, profile, instance role, etc.). No fields beyond a client
/// because KMS Decrypt routes by the ARN stored inside each
/// `RecipientEntry::AwsKms`.
pub struct AwsKmsIdentity {
    // We need a client per region. Built lazily; common case is one region
    // per file. Stored as a single client built from a "default" region;
    // when we see an entry with a different region we rebuild.
    default_region: String,
    client: Client,
}

impl AwsKmsIdentity {
    /// Construct an identity. `region` is a hint for the initial client;
    /// the actual region used at decrypt time comes from each entry's ARN.
    #[must_use]
    pub fn new(region: &str) -> Self {
        Self {
            default_region: region.to_string(),
            client: build_client(region),
        }
    }

    fn client_for(&self, region: &str) -> Client {
        if region == self.default_region {
            self.client.clone()
        } else {
            build_client(region)
        }
    }
}

impl Identity for AwsKmsIdentity {
    fn can_unwrap(&self, entry: &RecipientEntry) -> bool {
        matches!(entry, RecipientEntry::AwsKms { .. })
    }

    fn unwrap(&self, entry: &RecipientEntry) -> Result<Dek> {
        let RecipientEntry::AwsKms {
            arn,
            encrypted_dek,
            encryption_context,
        } = entry
        else {
            return Err(Error::Unwrap(
                "wrong recipient kind for aws-kms identity".into(),
            ));
        };
        let (region, _, _) = parse_arn(arn)?;
        let client = self.client_for(&region);
        let bytes = B64.decode(encrypted_dek)?;
        let blob = Blob::new(bytes);
        let context = encryption_context.clone().unwrap_or_default();
        let resp = runtime_handle().block_on(async move {
            let mut req = client.decrypt().ciphertext_blob(blob).key_id(arn);
            for (k, v) in context {
                req = req.encryption_context(k, v);
            }
            req.send().await
        });
        let resp = resp.map_err(|e| Error::Unwrap(format!("kms:Decrypt: {e}")))?;
        let plain = resp
            .plaintext
            .ok_or_else(|| Error::Unwrap("kms:Decrypt returned no plaintext".into()))?
            .into_inner();
        if plain.len() != 32 {
            return Err(Error::DekLength { got: plain.len() });
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&plain);
        Ok(Dek::from_bytes(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_arn() {
        let (region, account, resource) =
            parse_arn("arn:aws:kms:us-east-1:111122223333:key/abc-123").unwrap();
        assert_eq!(region, "us-east-1");
        assert_eq!(account, "111122223333");
        assert_eq!(resource, "key/abc-123");
    }

    #[test]
    fn rejects_garbage_arn() {
        assert!(parse_arn("not-an-arn").is_err());
        assert!(parse_arn("arn:aws:s3:::bucket").is_err());
        assert!(parse_arn("arn:aws:kms:::key/abc").is_err());
    }

    #[test]
    fn entry_shape() {
        // Don't actually build a client here — that hits the network. Just
        // verify the entry shape via the data we'd construct directly.
        let mut ctx = BTreeMap::new();
        ctx.insert("env".into(), "prod".into());
        let entry = RecipientEntry::AwsKms {
            arn: "arn:aws:kms:us-east-1:111:key/abc".into(),
            encrypted_dek: "AAAA".into(),
            encryption_context: Some(ctx.clone()),
        };
        match entry {
            RecipientEntry::AwsKms {
                arn,
                encryption_context,
                ..
            } => {
                assert_eq!(arn, "arn:aws:kms:us-east-1:111:key/abc");
                assert_eq!(encryption_context.unwrap(), ctx);
            }
            _ => panic!("wrong variant"),
        }
    }
}
