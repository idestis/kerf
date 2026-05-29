# kerf

> Diff-aware, KMS-first encryption for structured secret files.

A kerf is the narrow cut a saw makes through wood — only the material along the blade's path is removed, the rest is untouched. `kerf` encrypts the same way: edit one value in a YAML/JSON/TOML/ENV/INI file, and only that value's ciphertext changes in git.

Tools like SOPS reroll every nonce on every encrypt, so changing one secret produces a diff that touches every encrypted line. That makes code review of secret changes effectively impossible. `kerf` fixes this with a single invariant: **if a value's plaintext is unchanged, its on-disk ciphertext, nonce, and authentication tag are byte-identical to the previous version.**

See [`SPEC.md`](SPEC.md) for the format and algorithm. See [`CLAUDE.md`](CLAUDE.md) for contributor rules.

## Status

**v0.1.0 — pre-alpha.** Working end-to-end: diff-aware encrypt/decrypt with the byte-identity rule, file MAC, five formats (YAML / JSON / TOML / ENV / INI), and recipients for **age**, **AWS KMS**, **GCP Cloud KMS**, and **Azure Key Vault**. AWS and GCP are verified against local emulators; Azure's production path follows the documented SDK usage but isn't emulator-verified yet (see [Testing](#testing)). Not yet audited — don't protect real secrets with it until it stabilises.

Recipient backends are cargo features (`aws-kms` on by default; `gcp-kms`, `azure-kv` opt-in) so you only build the cloud SDKs you use.

## Roadmap

What's done and what's next. The full porcelain surface is implemented: `init`, `encrypt`, `decrypt`, `verify`, `keygen`, `edit`, `view`, `diff`, `set`, `unset`, `exec`, `rotate`, `keys`, plus the plumbing set (`metadata`, `recipients`, `mac --verify`, `path-encrypted`).

### Core / crypto
- [x] Diff-aware encrypt with the byte-identity rule
- [x] File MAC (HMAC-SHA256, AES-GCM-wrapped, AAD `__kerf_mac__`)
- [x] AES-256-GCM per value, AAD = dotted path
- [x] Fuzz targets for the file, envelope, and recipient-block parsers (`cargo-fuzz`)

### Formats
- [x] YAML, JSON, TOML, ENV (dotenv)
- [x] Comment / whitespace preservation on round-trip (YAML, TOML, ENV, INI; JSON has no comments)
- [x] INI

### Recipients
- [x] age (local, no network)
- [x] AWS KMS — emulator-verified (floci)
- [x] GCP Cloud KMS — emulator-verified (fake-cloud-kms)
- [x] Azure Key Vault (RSA-OAEP-256 wrap/unwrap)
- [ ] Verify Azure end-to-end against an emulator with the Keys API

### CLI commands
- [x] `kerf init` — write `.kerf.yaml` creation rules
- [x] `kerf verify` — MAC + AAD check, no plaintext output (exit codes per SPEC § 7.6)
- [x] `kerf rotate` — fresh DEK, re-encrypt every value, re-wrap
- [x] `kerf edit` — decrypt → `$EDITOR` → minimal-diff re-encrypt, scratch wiped on exit
- [x] `kerf exec -- <cmd>` — decrypt into child env, no plaintext on disk
- [x] `kerf set` / `kerf unset` — scripted single-value mutations (`set` reads from `--stdin`)
- [x] `kerf view` — read-only inspection (whole file or one `--path`)
- [x] `kerf diff` — plaintext diff of two encrypted files (redacted unless `--show-values`)
- [x] `kerf keys add` / `remove` / `list` — recipient management without DEK rotation
- [x] Plumbing commands (`recipients`, `metadata`, `mac --verify`, `path-encrypted`)

### Migration & distribution
- [ ] `kerf import-sops` — read SOPS-format files and re-encrypt into kerf format
- [ ] Security audit before any 1.0 / "safe for real secrets" claim

## Install

### GitHub Releases

Download the binary for your platform from the [Releases](https://github.com/idestis/kerf/releases) page. Verify the checksum against `SHA256SUMS` published alongside the archives.

```
tar -xzf kerf-v0.1.0-aarch64-apple-darwin.tar.gz
sudo mv kerf-v0.1.0-aarch64-apple-darwin/kerf /usr/local/bin/
kerf --version
```

Supported platforms:

| OS | Architecture |
|---|---|
| Linux | x86_64, aarch64 |
| macOS | arm64, x86_64 |
| Windows | x86_64 |

### From source

```
cargo install --git https://github.com/idestis/kerf kerf-cli
```

Requires Rust 1.96 or newer.

## Quick example

```bash
# Initialise config in the repo root
kerf init --recipient 'aws-kms:arn:aws:kms:us-east-1:111:key/prod-secrets'

# Encrypt a plaintext file
kerf encrypt secrets/prod.yaml

# Decrypt to stdout
kerf decrypt secrets/prod.kerf.yaml

# Edit in $EDITOR — minimal-diff re-encrypt on save
kerf edit secrets/prod.kerf.yaml

# Verify integrity (MAC + AAD) without producing plaintext
kerf verify secrets/prod.kerf.yaml
```

The single line of diff after editing one value is the entire point.

## Development

Common tasks are exposed via [Taskfile](https://taskfile.dev):

```bash
task            # list everything
task test       # unit + offline tests (no network, safe anywhere — CI runs this)
task lint       # fmt --check + clippy + cargo-deny
task build      # release binary at target/release/kerf
task release    # bump version, write CHANGELOG, push tag (CI builds binaries)
```

### Testing

There are two tiers, split so the default suite never needs the network:

| Command | What it runs | Needs |
|---|---|---|
| `task test` | All crypto, format, envelope, MAC, and KMS request-shape tests. KMS end-to-end tests are `#[ignore]`d and skipped here. | nothing |
| `task test:integration` | Spins up local KMS emulators in Docker, runs the `#[ignore]`d KMS end-to-end tests against the real wire (no mocks — per [`CLAUDE.md`](CLAUDE.md)), then tears the emulators back down. | Docker |

`task test` is what CI runs on every PR — fully offline, runs anywhere.

`task test:integration` is **batteries-included**: it brings the emulators up
(`docker compose -f docker-compose.test.yml`), waits for them, runs the tests,
and tears everything down afterwards — even if the tests fail. Each test
self-provisions its own KMS key (AWS via `kms:CreateKey`, GCP via
`CreateKeyRing`/`CreateCryptoKey`), so there's nothing to seed. One command:

```bash
task test:integration
```

Emulators used: [floci](https://github.com/floci-io/floci) for AWS on `:4566`
(free, MIT, no auth token — unlike recent LocalStack, which gates KMS behind a
paid license), and `fake-cloud-kms` for GCP on `:9010` (floci-gcp has no KMS;
the image is amd64-only and runs under emulation on Apple Silicon). Azure's
backend is implemented but not in the auto-managed stack yet — its Keys API
isn't cleanly emulator-testable (floci-az confirms only Secrets; lowkey-vault
needs TLS-trust config), so `tests/azure_kv_local.rs` is gated and documents
manual setup.

For a persistent / already-running setup, drive the pieces yourself:

```bash
task infra:up                 # start emulators
eval "$(task infra:env)"      # export endpoint + credential env vars
task test:integration:manual  # run against the running infra (no up/down)
task infra:down               # stop + remove
```

Conventional Commits drive both the changelog and the version bump:

```
feat(cli): add `kerf rotate --reason` flag
fix(core): preserve YAML quoting style across encrypt round-trip
sec(kms): pin aws-sdk-kms to a version with the latest CVE fixes
```

Use `sec:` for any security-relevant change — it makes the audit trail searchable.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
