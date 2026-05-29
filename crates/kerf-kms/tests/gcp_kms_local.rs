//! End-to-end tests against a local GCP Cloud KMS emulator.
//!
//! Gated on `KERF_KMS_ENDPOINT_GCP` so CI (no emulator) skips cleanly, and
//! marked `#[ignore]` so plain `cargo test` never attempts them — run via
//! `task test:integration`, which brings the emulator up first.
//!
//! GCP emulator note: floci-gcp does **not** implement Cloud KMS, so we use
//! `fake-cloud-kms` (gRPC, listens on :9010). The test self-provisions its own
//! key ring + crypto key via the SDK — mirroring how the AWS test calls
//! `kms:CreateKey` — so no external `grpcurl` step or pre-seeded key is needed.
//!
//! We do not mock the SDK — per CLAUDE.md, mock/prod divergence is the bug
//! class we're avoiding.

#![cfg(feature = "gcp-kms")]

use gcloud_kms::client::{Client, ClientConfig};
use gcloud_kms::grpc::kms::v1::{
    crypto_key::CryptoKeyPurpose, CreateCryptoKeyRequest, CreateKeyRingRequest, CryptoKey,
};
use kerf_core::Dek;
use kerf_kms::gcp::{GcpKmsIdentity, GcpKmsRecipient};
use kerf_kms::recipient::{Identity, Recipient};

const KEY_RING: &str = "projects/test/locations/global/keyRings/kerf";
const CRYPTO_KEY: &str = "projects/test/locations/global/keyRings/kerf/cryptoKeys/test";

/// Returns the emulator endpoint, or `None` if unset (caller skips).
fn endpoint() -> Option<String> {
    match std::env::var("KERF_KMS_ENDPOINT_GCP") {
        Ok(s) if !s.is_empty() => Some(s),
        _ => {
            eprintln!(
                "kerf-kms gcp integration test: KERF_KMS_ENDPOINT_GCP unset, skipping. \
                 Run `task test:integration`."
            );
            None
        }
    }
}

/// Create the key ring + crypto key in the emulator (idempotent — ignores
/// `AlreadyExists`). `CreateCryptoKey` auto-creates version 1, so the key is
/// immediately usable for Encrypt/Decrypt.
fn provision(endpoint: &str) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let config = ClientConfig {
            endpoint: endpoint.to_string(),
            ..Default::default()
        };
        let client = Client::new(config).await.expect("emulator client");

        // Ignore errors: the most common is "already exists" on a re-run.
        let _ = client
            .create_key_ring(
                CreateKeyRingRequest {
                    parent: "projects/test/locations/global".into(),
                    key_ring_id: "kerf".into(),
                    ..Default::default()
                },
                None,
            )
            .await;
        let _ = client
            .create_crypto_key(
                CreateCryptoKeyRequest {
                    parent: KEY_RING.into(),
                    crypto_key_id: "test".into(),
                    crypto_key: Some(CryptoKey {
                        purpose: CryptoKeyPurpose::EncryptDecrypt as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                None,
            )
            .await;
    });
}

#[test]
#[ignore = "requires a local GCP KMS emulator; run via `task test:integration`"]
fn wrap_unwrap_roundtrip_against_emulator() {
    let Some(ep) = endpoint() else { return };
    provision(&ep);

    let recipient = GcpKmsRecipient::parse(CRYPTO_KEY).expect("parse recipient");
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
