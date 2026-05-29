#![no_main]
//! Fuzz the `ENC[...]` envelope parser (SPEC § 4.3, § 11.4). The parser walks
//! attacker-controlled strings (every encrypted value in a repo file), so it
//! must reject malformed input with an error rather than panicking — e.g. on
//! bad base64, wrong field lengths, or unknown fields.

use kerf_core::Envelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Envelope::parse takes &str; non-UTF-8 can't appear in a parsed string
    // value anyway, so skip it rather than lossily transcoding.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Envelope::looks_like(s);
        let _ = Envelope::parse(s);
    }
});
