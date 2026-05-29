#![no_main]
//! Fuzz the structured-file parsers (SPEC § 11.4). Arbitrary bytes are thrown
//! at every format; none may panic, hang, or over-allocate on any input.
//! Parse *errors* are expected and fine — only a crash is a finding.

use kerf_core::FileFormat;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Each format independently. We don't assert success — malformed input
    // should yield `Err`, not a panic.
    let _ = FileFormat::Yaml.parse(data);
    let _ = FileFormat::Json.parse(data);
    let _ = FileFormat::Toml.parse(data);
    let _ = FileFormat::Env.parse(data);
});
