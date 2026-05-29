//! GCP Cloud KMS recipient — uses `gcloud-kms` for `Encrypt` / `Decrypt`.
//! Same sync-adapter pattern as the AWS backend: async SDK calls run on a
//! lazily-built shared tokio runtime via `Handle::block_on`.
//!
//! What's stored on disk (SPEC § 4.6):
//!
//! - `type: gcp-kms`
//! - `resource_id`: the full crypto-key resource name,
//!   `projects/P/locations/L/keyRings/R/cryptoKeys/K` — used to route the
//!   `Decrypt` call. Cloud KMS uses one global endpoint
//!   (`cloudkms.googleapis.com`); the location lives in the resource path,
//!   so a single client serves every location.
//! - `encrypted_dek`: base64 of the raw Cloud KMS ciphertext blob.
//!
//! Auth: the production path calls `ClientConfig::with_auth()`, which uses
//! Google's standard credential discovery (`GOOGLE_APPLICATION_CREDENTIALS`,
//! gcloud ADC, metadata server). When `KERF_KMS_ENDPOINT_GCP` is set the
//! client is pointed at that endpoint with the no-op token source instead —
//! intended for a local emulator (see the integration test notes).

use std::sync::OnceLock;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use gcloud_kms::client::{Client, ClientConfig};
use gcloud_kms::grpc::kms::v1::{DecryptRequest, EncryptRequest};
use kerf_core::{Dek, RecipientEntry};
use tokio::runtime::{Handle, Runtime};

use crate::recipient::{Identity, Recipient, WrappedDek};
use crate::{Error, Result};

const KIND: &str = "gcp-kms";

fn runtime_handle() -> Handle {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("kerf-gcp")
                .worker_threads(2)
                .build()
                .expect("tokio runtime")
        })
        .handle()
        .clone()
}

/// Validate a Cloud KMS crypto-key resource name. Format:
/// `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`, optionally with a
/// trailing `/cryptoKeyVersions/<v>`.
fn validate_resource_id(id: &str) -> Result<()> {
    let parts: Vec<&str> = id.split('/').collect();
    let ok = parts.len() >= 8
        && parts[0] == "projects"
        && parts[2] == "locations"
        && parts[4] == "keyRings"
        && parts[6] == "cryptoKeys"
        && parts.iter().all(|p| !p.is_empty());
    if ok {
        Ok(())
    } else {
        Err(Error::ParseRecipient(format!(
            "not a Cloud KMS resource id: {id:?} \
             (expected projects/P/locations/L/keyRings/R/cryptoKeys/K)"
        )))
    }
}

fn build_client() -> Result<Client> {
    runtime_handle().block_on(async {
        let config = if let Ok(endpoint) = std::env::var("KERF_KMS_ENDPOINT_GCP") {
            if endpoint.is_empty() {
                with_auth().await?
            } else {
                // Emulator path: keep the default no-op token source, just
                // override the endpoint. No real credentials required.
                ClientConfig {
                    endpoint,
                    ..Default::default()
                }
            }
        } else {
            with_auth().await?
        };
        Client::new(config)
            .await
            .map_err(|e| Error::Wrap(format!("gcp kms client: {e}")))
    })
}

async fn with_auth() -> Result<ClientConfig> {
    ClientConfig::default()
        .with_auth()
        .await
        .map_err(|e| Error::Identity(format!("gcp auth: {e}")))
}

/// A GCP Cloud KMS encryption recipient.
pub struct GcpKmsRecipient {
    resource_id: String,
    client: Client,
}

impl GcpKmsRecipient {
    /// Construct from a crypto-key resource name.
    pub fn parse(resource_id: &str) -> Result<Self> {
        validate_resource_id(resource_id)?;
        Ok(Self {
            resource_id: resource_id.to_string(),
            client: build_client()?,
        })
    }

    /// Borrow the resource id.
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
}

impl Recipient for GcpKmsRecipient {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn wrap(&self, dek: &Dek) -> Result<WrappedDek> {
        let req = EncryptRequest {
            name: self.resource_id.clone(),
            plaintext: dek.for_recipient().to_vec(),
            ..Default::default()
        };
        let client = self.client.clone();
        let resp = runtime_handle()
            .block_on(async move { client.encrypt(req, None).await })
            .map_err(|e| Error::Wrap(format!("gcp kms encrypt: {e}")))?;
        if resp.ciphertext.is_empty() {
            return Err(Error::Wrap("gcp kms encrypt returned no ciphertext".into()));
        }
        Ok(resp.ciphertext)
    }

    fn entry(&self, wrapped: &WrappedDek) -> RecipientEntry {
        RecipientEntry::GcpKms {
            resource_id: self.resource_id.clone(),
            encrypted_dek: B64.encode(wrapped),
        }
    }
}

/// A GCP Cloud KMS identity. Credentials come from the SDK's auth flow; the
/// `Decrypt` call routes by the `resource_id` stored in each entry.
pub struct GcpKmsIdentity {
    client: Client,
}

impl GcpKmsIdentity {
    /// Build an identity using the ambient GCP credentials / emulator endpoint.
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: build_client()?,
        })
    }
}

impl Identity for GcpKmsIdentity {
    fn can_unwrap(&self, entry: &RecipientEntry) -> bool {
        matches!(entry, RecipientEntry::GcpKms { .. })
    }

    fn unwrap(&self, entry: &RecipientEntry) -> Result<Dek> {
        let RecipientEntry::GcpKms {
            resource_id,
            encrypted_dek,
        } = entry
        else {
            return Err(Error::Unwrap(
                "wrong recipient kind for gcp-kms identity".into(),
            ));
        };
        validate_resource_id(resource_id)?;
        let req = DecryptRequest {
            name: resource_id.clone(),
            ciphertext: B64.decode(encrypted_dek)?,
            ..Default::default()
        };
        let client = self.client.clone();
        let resp = runtime_handle()
            .block_on(async move { client.decrypt(req, None).await })
            .map_err(|e| Error::Unwrap(format!("gcp kms decrypt: {e}")))?;
        let plain = resp.plaintext;
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
    fn parses_valid_resource_id() {
        validate_resource_id(
            "projects/my-proj/locations/global/keyRings/my-ring/cryptoKeys/my-key",
        )
        .unwrap();
    }

    #[test]
    fn rejects_garbage_resource_id() {
        assert!(validate_resource_id("not-a-resource").is_err());
        assert!(validate_resource_id("projects/p/locations/l").is_err());
        assert!(validate_resource_id(
            "projects//locations/l/keyRings/r/cryptoKeys/k"
        )
        .is_err());
    }

    #[test]
    fn entry_shape() {
        let entry = RecipientEntry::GcpKms {
            resource_id: "projects/p/locations/global/keyRings/r/cryptoKeys/k".into(),
            encrypted_dek: "AAAA".into(),
        };
        match entry {
            RecipientEntry::GcpKms {
                resource_id,
                encrypted_dek,
            } => {
                assert!(resource_id.contains("cryptoKeys"));
                assert_eq!(encrypted_dek, "AAAA");
            }
            _ => panic!("wrong variant"),
        }
    }
}
