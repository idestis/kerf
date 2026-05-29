//! End-to-end tests against a local AWS KMS emulator (`floci` or `LocalStack`).
//!
//! Gated on `KERF_KMS_ENDPOINT_AWS` being set so CI runs (which don't have
//! an emulator handy) silently skip rather than fail. Locally:
//!
//! ```bash
//! # start floci or LocalStack on the default port, then:
//! export KERF_KMS_ENDPOINT_AWS=http://localhost:4566
//! export AWS_ACCESS_KEY_ID=test
//! export AWS_SECRET_ACCESS_KEY=test
//! export AWS_REGION=us-east-1
//! cargo test -p kerf-kms --features aws-kms aws_kms_local
//! ```
//!
//! These tests create a real KMS key in the emulator via `kms:CreateKey`,
//! exercise wrap/unwrap, then delete the key. We deliberately do not mock
//! the SDK — per CLAUDE.md, mock/prod divergence is exactly the bug class
//! we're trying not to introduce.

#![cfg(feature = "aws-kms")]

use std::collections::BTreeMap;

use kerf_core::Dek;
use kerf_kms::aws::{AwsKmsIdentity, AwsKmsRecipient};
use kerf_kms::recipient::{Identity, Recipient};

/// Returns `true` if the emulator endpoint isn't configured — caller should
/// skip the test. Printed once so it's obvious in test output that we
/// didn't actually exercise the wire format.
fn emulator_configured() -> bool {
    match std::env::var("KERF_KMS_ENDPOINT_AWS") {
        Ok(s) if !s.is_empty() => true,
        _ => {
            eprintln!(
                "kerf-kms aws integration tests: KERF_KMS_ENDPOINT_AWS unset, skipping. \
                 See tests/aws_kms_local.rs for setup."
            );
            false
        }
    }
}

/// Create a fresh KMS key in the emulator and return its ARN. The key is
/// not cleaned up — emulators are typically ephemeral; if you're running
/// against a real account this test would have already failed earlier.
fn create_kms_key() -> Option<String> {
    use aws_config::BehaviorVersion;
    use aws_sdk_kms::Client;
    use aws_types::region::Region;
    use tokio::runtime::Runtime;

    let rt = Runtime::new().ok()?;
    rt.block_on(async {
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let endpoint = std::env::var("KERF_KMS_ENDPOINT_AWS").ok()?;
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region))
            .endpoint_url(endpoint)
            .load()
            .await;
        let client = Client::new(&config);
        let resp = client
            .create_key()
            .description("kerf integration test key")
            .send()
            .await
            .ok()?;
        let arn = resp.key_metadata?.arn?;
        Some(arn)
    })
}

#[test]
#[ignore = "requires a local AWS KMS emulator; run via `task test:integration`"]
fn wrap_unwrap_roundtrip_against_emulator() {
    if !emulator_configured() {
        return;
    }
    let arn = create_kms_key().expect("create test key");
    let recipient = AwsKmsRecipient::parse(&arn, BTreeMap::new()).expect("parse recipient");
    let identity = AwsKmsIdentity::new("us-east-1");

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

#[test]
#[ignore = "requires a local AWS KMS emulator; run via `task test:integration`"]
fn encryption_context_is_authenticated() {
    if !emulator_configured() {
        return;
    }
    let arn = create_kms_key().expect("create test key");

    let mut ctx = BTreeMap::new();
    ctx.insert("env".to_string(), "test".to_string());

    let recipient = AwsKmsRecipient::parse(&arn, ctx.clone()).expect("parse recipient");
    let identity = AwsKmsIdentity::new("us-east-1");

    let dek = Dek::generate();
    let wrapped = recipient.wrap(&dek).expect("wrap with context");

    // Tampering with the encryption_context on disk must cause unwrap to
    // fail — that's what makes the context "authenticated" rather than
    // just decorative metadata.
    let mut bad_ctx = BTreeMap::new();
    bad_ctx.insert("env".to_string(), "prod".to_string()); // wrong value

    let tampered_entry = kerf_core::RecipientEntry::AwsKms {
        arn: arn.clone(),
        encrypted_dek: base64::engine::general_purpose::STANDARD.encode(&wrapped),
        encryption_context: Some(bad_ctx),
    };

    assert!(
        identity.unwrap(&tampered_entry).is_err(),
        "tampered encryption_context must fail to unwrap"
    );

    // And the original context still unwraps.
    let good_entry = kerf_core::RecipientEntry::AwsKms {
        arn,
        encrypted_dek: base64::engine::general_purpose::STANDARD.encode(&wrapped),
        encryption_context: Some(ctx),
    };
    identity.unwrap(&good_entry).expect("good context unwraps");
}

// Required for the base64::Engine call above.
use base64::Engine as _;
