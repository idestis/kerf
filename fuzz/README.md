# kerf fuzz targets

`cargo-fuzz` (libFuzzer) targets for kerf's untrusted-input parsers, per
SPEC § 11.4 and the CLAUDE.md testing rules. Every parser that reads
attacker-controlled bytes has a target here; **adding a new parser means
adding a new target.**

| Target | Parser under test | Entry point |
|---|---|---|
| `file_parser` | structured-file parsers (YAML/JSON/TOML/ENV) | `FileFormat::parse` |
| `envelope_parser` | the `ENC[...]` value envelope | `Envelope::parse` |
| `recipient_block` | the `kerf:` / recipient block | `serde_yaml::from_slice::<KerfBlock>` + `validate()` |

A finding is a **crash, panic, hang, OOM, or sanitizer error**. Parse *errors*
are expected and correct — these parsers face hostile input by design.

## Requirements

cargo-fuzz needs a nightly toolchain and the libFuzzer/ASan runtime:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

This crate is its own workspace (the empty `[workspace]` in `Cargo.toml`), so
`cargo test --workspace` at the repo root never tries to build it.

## Running

```sh
# From the repo root. Seed the corpus first so magic-prefix parsers
# (envelope, recipient block) reach their interesting code quickly.
cp -n fuzz/seeds/envelope_parser/* fuzz/corpus/envelope_parser/ 2>/dev/null || true

cargo +nightly fuzz run envelope_parser -- -max_total_time=300
cargo +nightly fuzz run file_parser    -- -max_total_time=300
cargo +nightly fuzz run recipient_block -- -max_total_time=300
```

Or via Taskfile: `task fuzz:build` (compile all targets — a cheap smoke test)
and `task fuzz:run -- envelope_parser` (run one for 60s).

`corpus/`, `artifacts/`, and `coverage/` are git-ignored; libFuzzer manages
them. The committed `seeds/` give each target a valid starting input — without
the envelope seed, blind fuzzing rarely produces the `ENC[AES-GCM,` prefix and
coverage stalls (~30 edges vs. ~370 seeded).

## Reproducing a crash

If a run finds one, it writes `fuzz/artifacts/<target>/crash-<hash>`. Replay it:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```
