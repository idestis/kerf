//! End-to-end test against a local Azure Key Vault emulator.
//!
//! Gated on `KERF_KMS_ENDPOINT_AZURE` + `KERF_AZURE_TEST_KEY` and `#[ignore]`d,
//! so plain `cargo test` never attempts it.
//!
//! ## Status: not yet verified end-to-end
//!
//! Unlike AWS (floci) and GCP (fake-cloud-kms), the Azure Key Vault *Keys*
//! API is not cleanly emulator-testable yet:
//!
//! - **floci-az** serves plaintext HTTP (no TLS friction) but currently
//!   confirms only Key Vault *Secrets*, not the Keys/wrapKey API kerf needs.
//! - **lowkey-vault** implements the Keys API but serves self-signed HTTPS,
//!   which needs TLS-trust configuration in the SDK transport.
//!
//! The production backend follows the documented Azure SDK usage (RSA-OAEP-256
//! wrap/unwrap). To try this test, point it at an emulator that implements the
//! Keys API and pre-create an RSA key:
//!
//! ```bash
//! export KERF_KMS_ENDPOINT_AZURE=http://localhost:4577   # signals emulator mode
//! export KERF_AZURE_TEST_KEY=http://localhost:4577/acct-keyvault/keys/test
//! cargo test -p kerf-kms --features azure-kv azure_kv_local -- --ignored
//! ```

#![cfg(feature = "azure-kv")]

use kerf_core::Dek;
use kerf_kms::azure::{AzureKvIdentity, AzureKvRecipient};
use kerf_kms::recipient::{Identity, Recipient};

fn test_key() -> Option<String> {
    let endpoint = std::env::var("KERF_KMS_ENDPOINT_AZURE")
        .ok()
        .filter(|s| !s.is_empty());
    let key = std::env::var("KERF_AZURE_TEST_KEY")
        .ok()
        .filter(|s| !s.is_empty());
    if let (Some(_), Some(k)) = (endpoint, key) {
        Some(k)
    } else {
        eprintln!(
            "kerf-kms azure integration test: set KERF_KMS_ENDPOINT_AZURE and \
             KERF_AZURE_TEST_KEY to run. Skipping. See tests/azure_kv_local.rs."
        );
        None
    }
}

#[test]
#[ignore = "requires a Key Vault emulator with the Keys API; see module docs"]
fn wrap_unwrap_roundtrip_against_emulator() {
    let Some(key_url) = test_key() else { return };

    let recipient = AzureKvRecipient::parse(&key_url).expect("parse recipient");
    let identity = AzureKvIdentity::new();

    let dek = Dek::generate();
    let wrapped = recipient.wrap(&dek).expect("wrap");
    let entry = recipient.entry(&wrapped);

    let unwrapped = identity.unwrap(&entry).expect("unwrap");
    assert_eq!(
        kerf_core::Dek::for_recipient(&dek),
        kerf_core::Dek::for_recipient(&unwrapped),
        "DEK roundtrip"
    );
}
