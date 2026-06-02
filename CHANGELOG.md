# Changelog

All notable changes to kerf.
Format roughly follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.1] — 2026-06-02

### Documentation

- **examples:** Encrypt initial secrets (yaml/json/env)
- **examples:** Rotate database.password -- one secret, one line
- **examples:** Add cache.password without touching the old secrets
- Link the examples/ diff demo from the README
- Point example links at the post-rebase commit hashes
- CLI reference split, key-provider guides, GFM fix; Homebrew tap publish (#3)
- **readme:** Add documentation site badge and link (#4)

### Security

- **core:** Make file MAC diff-aware so no-op re-encrypt is byte-identical

## [0.2.0] — 2026-06-02

### Bug Fixes

- **release:** Bump internal dep requirements in workspace version bump

### Build

- **msrv:** Raise MSRV to 1.96 to match the cloud KMS SDKs

### Documentation

- **readme:** Mark view/set/unset/rotate/keys/plumbing as implemented
- **readme:** Mark edit/exec/diff implemented — full porcelain surface done

### Features

- **cli:** Add `kerf init` to write .kerf.yaml creation rules
- **cli:** Add plumbing commands (metadata, recipients, path-encrypted, mac --verify)
- **cli:** Add view, set, and unset for single-value access
- **cli:** Add keys add/remove/list for recipient management
- **cli:** Add kerf rotate (fresh DEK, full re-encrypt, re-wrap)
- **cli:** Add kerf diff (path-level plaintext diff, redacted by default)
- **cli:** Add kerf exec (decrypt into child env, no temp files)
- **cli:** Add kerf edit ($EDITOR round-trip, minimal-diff re-encrypt)
- **core:** Preserve comments/whitespace on round trip for ENV
- **core:** Preserve comments/whitespace on round trip for TOML
- **core:** Preserve comments/whitespace on round trip for YAML
- **core:** Add INI format with comment/whitespace preservation

### Refactor

- **cli:** Make --identity-file a global flag

### Security

- **cli:** Add `kerf verify` integrity check (MAC + AAD, no plaintext)

### Tests

- **fuzz:** Add cargo-fuzz targets for file, envelope, and recipient-block parsers
- **core:** Make MAC-tamper test deterministic (was flaky ~20%)

## [0.1.0] — 2026-05-29

### Bug Fixes

- **test:** Correct fake-cloud-kms port (9010) + arm64 platform; GCP test self-provisions
- **test:** Make KMS integration tests pass against free emulators

### CI

- **release:** Build-and-deliver all-features binary, drop Homebrew

### Chore

- **lint:** Clippy::pedantic clean across the workspace

### Documentation

- Add Astro Starlight site with logo bundle and GH Pages deploy
- **kms:** Correct gcp module doc to describe the plaintext-emulator path
- **readme:** Add roadmap checklist of remaining work

### Features

- Scaffold workspace, release pipeline, and CLI stub
- Age-only MVP with diff-aware encrypt/decrypt
- **core:** File-level MAC closes the integrity boundary
- **core:** JSON support alongside YAML via FileFormat abstraction
- **kms:** AWS KMS recipient backend with floci/LocalStack scaffolding
- **core:** TOML format support
- **core:** Dotenv (.env) format support
- **kms:** GCP Cloud KMS recipient backend
- **kms:** Azure Key Vault recipient backend (RSA-OAEP-256 wrap/unwrap)

### Security

- **kms:** Use aws-lc-rs TLS for AWS KMS, drop legacy rustls/ring

### Tests

- Split unit vs integration test tiers + document in README/Taskfile
- One-command `task test:integration` spins up/tears down KMS emulators


