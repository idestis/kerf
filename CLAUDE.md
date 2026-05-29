# CLAUDE.md

Guidance for AI coding assistants (Claude Code, Cursor, etc.) working in this repository.

## What this project is

`kerf` is a CLI tool that encrypts secrets in structured files (YAML/JSON/TOML/ENV) such that **changing one value produces a one-line git diff**. The name is the metaphor: a kerf is the narrow cut a saw makes through wood — only the material along the blade's path is removed, the rest is untouched. The tool encrypts the same way.

Read `SPEC.md` before doing substantive work — the on-disk format and the diff-aware encrypt algorithm are not negotiable, and "improvements" to them are usually security bugs.

This is a security-sensitive tool. Crypto correctness > performance > convenience > brevity.

## Core invariant — the kerf rule

> If a value's plaintext is unchanged across an encrypt operation, its on-disk ciphertext, nonce, and authentication tag MUST be byte-identical to the previous version. The cut goes only where the change is.

If you find code that violates this, it is a bug. If a proposed change would violate this, push back even if the user asks for it.

The corollary is just as important: if a value's plaintext **has** changed, the nonce MUST be fresh from the OS CSPRNG. Never reuse a nonce under the same DEK. AES-GCM nonce reuse is catastrophic — it leaks plaintext relationships and enables tag forgery.

## Stack

- Rust 2021, MSRV 1.96
- `aws-lc-rs` for AEAD, HMAC, RNG. Never `ring` directly, never `openssl`.
- `age` crate for age recipients
- `aws-sdk-kms`, `google-cloud-kms`, `azure_security_keyvault_keys` for KMS
- `zeroize` + `secrecy` for secret lifecycle
- `clap` v4 for CLI
- `tokio` only where KMS clients require it; prefer sync elsewhere

## Layout

```
crates/
  kerf-core/       # format, crypto, encrypt/decrypt algorithm. No I/O.
  kerf-kms/        # KMS recipient implementations. Async.
  kerf-cli/        # the binary. CLI parsing, file I/O, exit codes.
tests/
  integration/     # end-to-end tests across formats and recipients
  fixtures/        # canonical encrypted files for regression tests
fuzz/              # cargo-fuzz targets
SPEC.md            # the source of truth for format and behavior
CLAUDE.md          # this file
```

`kerf-core` is pure logic with no async, no I/O, no clock, no env access. This is what makes it testable. Don't add `tokio` or `std::fs` to it.

## Rules for code changes

### Crypto
1. Never invent. If the construction isn't in `SPEC.md` § 5, it isn't allowed.
2. Never use `rand::thread_rng()` or any seeded PRNG for key material or nonces. Use `aws_lc_rs::rand::SystemRandom` or `getrandom::getrandom` directly.
3. Never log, print, or format DEKs, plaintexts, or unwrapped key material. The `secrecy::Secret<T>` type's `Debug` impl prints `[REDACTED]` — use it. Don't `.expose_secret()` to log.
4. Constant-time comparison for any authenticator check. Use `subtle::ConstantTimeEq`, never `==` on bytes.
5. AAD is the dotted path. Always. If a function encrypts without an explicit AAD argument, that's a bug.
6. The `Nonce` type from the crypto module is `#[must_use]` and consumed on encrypt. Don't add `Clone` or `Copy` to it.

### File format
1. Round-tripping must preserve formatting: comments, key order, whitespace, quoting. Use format-aware AST manipulation (e.g., `serde_yaml` with `Mapping` ordering preserved), never reserialize from a `HashMap`.
2. The `kerf:` block is reserved. Do not put encrypted values under `kerf:`, and do not let the user's data shadow it. Validate at load time.
3. The `ENC[...]` envelope is a single line, no whitespace, no line breaks. If you're tempted to "pretty-print" it, don't.
4. Atomic writes only: write to `<dest>.tmp.<random>` in the same directory, `fsync`, then rename. Never write in place.

### CLI
1. Porcelain commands can change. Plumbing commands (§ 7.5 of SPEC) are stable contracts — don't change their stdout format without a version bump.
2. Exit codes are part of the contract. See § 7.6.
3. Never put secrets in argv. `kerf set` reads values from `--stdin` by default. `kerf exec` reads its child command's env from the decrypted file but does not echo it.
4. No interactive prompts in scripts. If a command needs input and stdin is not a TTY, fail with a clear message.

### Errors
1. Use `thiserror` for library errors in `kerf-core`, `anyhow` only at the CLI boundary in `kerf-cli`.
2. Error messages MUST NOT contain plaintext values or unwrapped key material. They MAY contain paths, recipient ARNs, and ciphertext lengths.
3. MAC failures and AAD failures are distinct error types and distinct exit codes. Don't collapse them — they mean different things to a forensic responder.

### Testing
1. Every PR that touches `kerf-core` adds or extends a property test for the minimal-diff invariant.
2. Every new cryptographic code path gets a known-answer test (KAT) checked in as a fixture.
3. KMS code paths are tested against LocalStack / emulators in CI. Don't mock the KMS client — test against the wire format.
4. Fuzz targets exist for: file parser, envelope parser, recipient block parser. Adding a new parser means adding a new fuzz target.

## Things that look like improvements but aren't

You will be tempted to do these. Don't.

- **"Add a fast path that skips the decrypt step if the file's mtime hasn't changed."** mtime is attacker-controlled in repo contexts. The decrypt-and-diff is the security boundary.
- **"Use a faster hash for the MAC, like Blake3."** HMAC-SHA256 is the standard, has FIPS validation paths, and the MAC isn't on the hot path. Don't change it.
- **"Cache the unwrapped DEK in `~/.cache/kerf/` for the session."** No. The whole point of KMS is that the DEK is short-lived in memory. A disk cache is a DEK exfiltration vector.
- **"Auto-rotate the DEK every N encrypts."** Rotation is a user decision with operational consequences (every dependent system must re-decrypt). The user runs `kerf rotate` when they mean it.
- **"Encrypt the keys too, with a deterministic mode so diffs still work."** Deterministic encryption leaks equality. SOPS doesn't do this; neither do we.
- **"Add a `--force` flag that re-encrypts everything."** That's already what `kerf rotate` does; don't add a second path that bypasses rotation accounting.
- **"Speed up `encrypt` by skipping MAC verification on the existing file."** The MAC check is what protects you from re-encrypting a tampered file and signing your name to it.

## Style

- `rustfmt` default settings. No custom config.
- `clippy::pedantic` is on for `kerf-core`. Allow lints with justification in comments, never blanket-allow.
- Doc comments (`///`) on every public item. Crypto-relevant items must document the security property they uphold, not just what they do.
- No `unsafe` outside of explicitly-marked FFI shims in `kerf-kms`. Any `unsafe` block requires a SAFETY comment that a reviewer can verify.
- `#[must_use]` on types that wrap secret material or that must be consumed (nonces, tags, MAC inputs).

## Commit hygiene

- Conventional Commits: `feat:`, `fix:`, `sec:`, `docs:`, `test:`, `refactor:`, `chore:`. Use `sec:` for any security-relevant change, even tiny ones — it makes the audit trail searchable.
- Security-relevant changes get a `Security-impact:` trailer describing what changed and why. Reviewers grep for this.
- Don't squash security-relevant commits into "chore" or "refactor" commits. The git history is part of the audit story.

## When to ask the user

- Anything that changes `SPEC.md`. The spec is the contract; don't edit it as a side effect of a code change.
- Anything that changes file format version, recipient block shape, or the envelope format.
- Adding a new crypto dependency or replacing an existing one.
- Adding a new KMS provider (the threat model assumes the existing set).
- Anything labeled "open question" in SPEC.md § 13.

For everything else — code style, refactors, test additions, doc improvements — proceed without asking.

## Useful commands

```bash
cargo test --workspace                       # full test suite
cargo test -p kerf-core --release            # core tests, optimized (fast)
cargo fuzz run envelope_parser -- -max_total_time=300
cargo deny check                             # supply chain audit (advisories, licenses)
cargo dist build                             # build release artifacts locally
```

Don't run `cargo update` without reading the resulting diff — pinning matters for a security tool.
