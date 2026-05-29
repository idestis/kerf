//! End-to-end tests against a local GCP Cloud KMS emulator.
//!
//! Gated on `KERF_KMS_ENDPOINT_GCP` so CI (no emulator) skips cleanly.
//!
//! GCP emulator note: unlike AWS (`LocalStack`/`floci` serve plaintext on
//! 4566 and the AWS SDK happily uses an `http://` endpoint), `floci-gcp` does
//! **not** implement Cloud KMS. Use a dedicated emulator such as
//! `fake-cloud-kms`. Because `gcloud-kms`'s client connects over gRPC, the
//! emulator must be reachable at the host:port given in
//! `KERF_KMS_ENDPOINT_GCP` and speak the Cloud KMS gRPC API. Local setup:
//!
//! ```bash
//! # start fake-cloud-kms (see its README), then:
//! export KERF_KMS_ENDPOINT_GCP=localhost:8085
//! export KERF_GCP_TEST_KEY=projects/test/locations/global/keyRings/r/cryptoKeys/k
//! cargo test -p kerf-kms --features gcp-kms gcp_kms_local
//! ```
//!
//! We do not mock the SDK — per CLAUDE.md, mock/prod divergence is the bug
//! class we're avoiding.

#![cfg(feature = "gcp-kms")]

use kerf_core::Dek;
use kerf_kms::gcp::{GcpKmsIdentity, GcpKmsRecipient};
use kerf_kms::recipient::{Identity, Recipient};

/// Returns the configured crypto-key resource id, or `None` if the emulator
/// isn't configured (caller skips). The key is expected to already exist in
/// the emulator — creation semantics vary between emulators, so we leave key
/// provisioning to the test setup rather than guessing an API.
fn test_key() -> Option<String> {
    let endpoint = std::env::var("KERF_KMS_ENDPOINT_GCP")
        .ok()
        .filter(|s| !s.is_empty());
    let key = std::env::var("KERF_GCP_TEST_KEY")
        .ok()
        .filter(|s| !s.is_empty());
    if let (Some(_), Some(k)) = (endpoint, key) {
        Some(k)
    } else {
        eprintln!(
            "kerf-kms gcp integration tests: set KERF_KMS_ENDPOINT_GCP and \
             KERF_GCP_TEST_KEY to run. Skipping. See tests/gcp_kms_local.rs."
        );
        None
    }
}

#[test]
#[ignore = "requires a local GCP KMS emulator; run via `task test:integration`"]
fn wrap_unwrap_roundtrip_against_emulator() {
    let Some(key) = test_key() else { return };
    let recipient = GcpKmsRecipient::parse(&key).expect("parse recipient");
    let identity = GcpKmsIdentity::new().expect("build identity");

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
