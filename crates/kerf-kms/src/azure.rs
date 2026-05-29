//! Azure Key Vault recipient — wraps the DEK with a vault key via the
//! **Wrap Key / Unwrap Key** operations (RSA-OAEP-256), the Key Vault
//! equivalent of AWS/GCP `Encrypt`/`Decrypt`. Same sync-adapter pattern:
//! async SDK calls run on a lazily-built shared tokio runtime.
//!
//! What's stored on disk (SPEC § 4.6):
//!
//! - `type: azure-kv`
//! - `key_id`: the **versioned** key identifier returned by Wrap Key,
//!   `https://<vault>/keys/<name>/<version>`. Storing the version is required
//!   because Unwrap Key targets a specific key version (Wrap uses the latest).
//! - `encrypted_dek`: base64 of the wrapped-key bytes.
//!
//! Auth: production uses `DeveloperToolsCredential` (Azure CLI / developer
//! credential chain). When `KERF_KMS_ENDPOINT_AZURE` is set we use a dummy
//! credential — local emulators (floci-az, lowkey-vault) accept any token.
//!
//! Emulator status: NOT yet verified end-to-end. floci-az currently confirms
//! only Key Vault *Secrets* (not the Keys/wrapKey API); lowkey-vault supports
//! Keys but serves self-signed HTTPS, which needs TLS-trust configuration.
//! The production path follows the documented Azure SDK usage. See
//! `tests/azure_kv_local.rs`.

use std::sync::{Arc, Mutex, OnceLock};

use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_security_keyvault_keys::clients::KeyClient;
use azure_security_keyvault_keys::models::{EncryptionAlgorithm, KeyOperationParameters};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kerf_core::{Dek, RecipientEntry};
use tokio::runtime::{Handle, Runtime};

use crate::recipient::{Identity, Recipient, WrappedDek};
use crate::{Error, Result};

const KIND: &str = "azure-kv";

fn runtime_handle() -> Handle {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("kerf-azure")
                .worker_threads(2)
                .build()
                .expect("tokio runtime")
        })
        .handle()
        .clone()
}

/// Split a Key Vault key URL into `(vault_endpoint, key_name, key_version)`.
///
/// Handles both real Azure (`https://v.vault.azure.net/keys/name/ver`) and
/// emulators that put the vault under a path prefix
/// (`http://localhost:4577/acct-keyvault/keys/name`): the endpoint is
/// everything before `/keys/`, so the prefix is preserved.
fn parse_key_url(url: &str) -> Result<(String, String, Option<String>)> {
    let marker = "/keys/";
    let idx = url.find(marker).ok_or_else(|| {
        Error::ParseRecipient(format!(
            "not a Key Vault key URL: {url:?} (expected .../keys/<name>[/<version>])"
        ))
    })?;
    let endpoint = url[..idx].to_string();
    let rest = &url[idx + marker.len()..];
    let mut segs = rest.splitn(2, '/');
    let name = segs.next().unwrap_or_default().to_string();
    let version = segs.next().map(|s| s.trim_end_matches('/').to_string());
    if endpoint.is_empty() || name.is_empty() {
        return Err(Error::ParseRecipient(format!(
            "incomplete Key Vault key URL: {url:?}"
        )));
    }
    Ok((endpoint, name, version))
}

fn emulator_mode() -> bool {
    std::env::var("KERF_KMS_ENDPOINT_AZURE").is_ok_and(|s| !s.is_empty())
}

fn build_client(endpoint: &str) -> Result<KeyClient> {
    let credential: Arc<dyn TokenCredential> = if emulator_mode() {
        Arc::new(EmulatorCredential)
    } else {
        azure_identity::DeveloperToolsCredential::new(None)
            .map_err(|e| Error::Identity(format!("azure auth: {e}")))?
    };
    KeyClient::new(endpoint, credential, None)
        .map_err(|e| Error::Wrap(format!("azure key client: {e}")))
}

/// Dummy credential for the local-emulator path. Emulators accept any token;
/// the production `DeveloperToolsCredential` is used otherwise.
#[derive(Debug)]
struct EmulatorCredential;

#[async_trait::async_trait]
impl TokenCredential for EmulatorCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        // Far-future expiry so the SDK never tries to refresh.
        let expires_on = time::OffsetDateTime::now_utc() + time::Duration::days(3650);
        Ok(AccessToken::new("emulator".to_string(), expires_on))
    }
}

/// An Azure Key Vault encryption recipient.
pub struct AzureKvRecipient {
    /// Original key URL the caller supplied (used as the recipient match key).
    key_url: String,
    key_name: String,
    client: KeyClient,
    /// Versioned `kid` resolved by the most recent `wrap`, read by `entry`.
    resolved_kid: Mutex<Option<String>>,
}

impl AzureKvRecipient {
    /// Construct from a Key Vault key URL.
    pub fn parse(key_url: &str) -> Result<Self> {
        let (endpoint, key_name, _version) = parse_key_url(key_url)?;
        let client = build_client(&endpoint)?;
        Ok(Self {
            key_url: key_url.to_string(),
            key_name,
            client,
            resolved_kid: Mutex::new(None),
        })
    }

    /// Borrow the original key URL — used as the recipient match key.
    #[must_use]
    pub fn key_url(&self) -> &str {
        &self.key_url
    }
}

impl Recipient for AzureKvRecipient {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn wrap(&self, dek: &Dek) -> Result<WrappedDek> {
        let params = KeyOperationParameters {
            algorithm: Some(EncryptionAlgorithm::RsaOaep256),
            value: Some(dek.for_recipient().to_vec()),
            ..Default::default()
        };
        // block_on is synchronous, so capturing &self (a Copy reference) and
        // moving `params` into the future is sound — self outlives the call.
        let result = runtime_handle().block_on(async move {
            let body = params
                .try_into()
                .map_err(|e| Error::Wrap(format!("azure wrap request: {e}")))?;
            let resp = self
                .client
                .wrap_key(&self.key_name, body, None)
                .await
                .map_err(|e| Error::Wrap(format!("azure wrapKey: {e}")))?;
            resp.into_model()
                .map_err(|e| Error::Wrap(format!("azure wrapKey body: {e}")))
        })?;

        // Capture the versioned kid so `entry` can record the exact version
        // that Unwrap Key will need.
        if let Some(kid) = &result.kid {
            *self.resolved_kid.lock().expect("resolved_kid mutex") = Some(kid.clone());
        }
        result
            .result
            .ok_or_else(|| Error::Wrap("azure wrapKey returned no result".into()))
    }

    fn entry(&self, wrapped: &WrappedDek) -> RecipientEntry {
        // Prefer the versioned kid from wrap; fall back to the supplied URL.
        let key_id = self
            .resolved_kid
            .lock()
            .expect("resolved_kid mutex")
            .clone()
            .unwrap_or_else(|| self.key_url.clone());
        RecipientEntry::AzureKv {
            key_id,
            encrypted_dek: B64.encode(wrapped),
        }
    }
}

/// An Azure Key Vault identity. The `Unwrap Key` call routes by the versioned
/// `key_id` stored in each entry.
pub struct AzureKvIdentity {
    _private: (),
}

impl AzureKvIdentity {
    /// Build an identity. Credentials/endpoint are resolved per entry at
    /// unwrap time from the entry's `key_id`.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for AzureKvIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl Identity for AzureKvIdentity {
    fn can_unwrap(&self, entry: &RecipientEntry) -> bool {
        matches!(entry, RecipientEntry::AzureKv { .. })
    }

    fn unwrap(&self, entry: &RecipientEntry) -> Result<Dek> {
        let RecipientEntry::AzureKv {
            key_id,
            encrypted_dek,
        } = entry
        else {
            return Err(Error::Unwrap(
                "wrong recipient kind for azure-kv identity".into(),
            ));
        };
        let (endpoint, key_name, version) = parse_key_url(key_id)?;
        let version = version.ok_or_else(|| {
            Error::Unwrap(format!(
                "azure key_id has no version, cannot unwrap: {key_id:?}"
            ))
        })?;
        let wrapped = B64.decode(encrypted_dek)?;
        let client = build_client(&endpoint)?;

        let result = runtime_handle().block_on(async move {
            let params = KeyOperationParameters {
                algorithm: Some(EncryptionAlgorithm::RsaOaep256),
                value: Some(wrapped),
                ..Default::default()
            };
            let body = params
                .try_into()
                .map_err(|e| Error::Unwrap(format!("azure unwrap request: {e}")))?;
            let resp = client
                .unwrap_key(&key_name, &version, body, None)
                .await
                .map_err(|e| Error::Unwrap(format!("azure unwrapKey: {e}")))?;
            resp.into_model()
                .map_err(|e| Error::Unwrap(format!("azure unwrapKey body: {e}")))
        })?;

        let plain = result
            .result
            .ok_or_else(|| Error::Unwrap("azure unwrapKey returned no result".into()))?;
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
    fn parses_real_azure_url() {
        let (ep, name, ver) =
            parse_key_url("https://myvault.vault.azure.net/keys/mykey/abc123").unwrap();
        assert_eq!(ep, "https://myvault.vault.azure.net");
        assert_eq!(name, "mykey");
        assert_eq!(ver.as_deref(), Some("abc123"));
    }

    #[test]
    fn parses_emulator_url_with_path_prefix() {
        let (ep, name, ver) =
            parse_key_url("http://localhost:4577/acct-keyvault/keys/test").unwrap();
        assert_eq!(ep, "http://localhost:4577/acct-keyvault");
        assert_eq!(name, "test");
        assert_eq!(ver, None);
    }

    #[test]
    fn rejects_non_key_url() {
        assert!(parse_key_url("https://myvault.vault.azure.net/secrets/foo").is_err());
        assert!(parse_key_url("not-a-url").is_err());
    }

    #[test]
    fn entry_shape() {
        let entry = RecipientEntry::AzureKv {
            key_id: "https://v.vault.azure.net/keys/k/ver".into(),
            encrypted_dek: "AAAA".into(),
        };
        match entry {
            RecipientEntry::AzureKv { key_id, .. } => assert!(key_id.contains("/keys/")),
            _ => panic!("wrong variant"),
        }
    }
}
