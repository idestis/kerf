# Changelog

All notable changes to kerf.
Format roughly follows [Keep a Changelog](https://keepachangelog.com/).

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


