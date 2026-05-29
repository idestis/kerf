#![no_main]
//! Fuzz the `kerf:` / recipient-block parser (SPEC § 4.2, § 11.4). The block
//! is deserialized from untrusted file contents into `KerfBlock` (a tagged
//! `RecipientEntry` enum) and then validated. Neither deserialization nor
//! `validate()` may panic — including on the regex compile inside validate.

use kerf_core::KerfBlock;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = serde_yaml::from_slice::<KerfBlock>(data) {
        // validate() compiles the stored encrypted_regex; a pathological
        // pattern must error, not panic.
        let _ = block.validate();
    }
});
