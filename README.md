# kerf

> Diff-aware, KMS-first encryption for structured secret files.

A kerf is the narrow cut a saw makes through wood — only the material along the blade's path is removed, the rest is untouched. `kerf` encrypts the same way: edit one value in a YAML/JSON/TOML/ENV file, and only that value's ciphertext changes in git.

Tools like SOPS reroll every nonce on every encrypt, so changing one secret produces a diff that touches every encrypted line. That makes code review of secret changes effectively impossible. `kerf` fixes this with a single invariant: **if a value's plaintext is unchanged, its on-disk ciphertext, nonce, and authentication tag are byte-identical to the previous version.**

See [`SPEC.md`](SPEC.md) for the format and algorithm. See [`CLAUDE.md`](CLAUDE.md) for contributor rules.

## Status

**v0.1.0 — pre-alpha.** The CLI surface is stubbed; the diff-aware encrypt algorithm, KMS recipients, and file format are still being implemented. Do not use to protect real secrets yet.

## Install

### GitHub Releases

Download the signed binary for your platform from the [Releases](https://github.com/idestis/kerf/releases) page. Verify the checksum against `SHA256SUMS` published alongside the archives.

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

### Homebrew (planned)

```
brew tap idestis/kerf
brew install kerf
```

Not yet published — the tap repository will be `idestis/homebrew-kerf`.

### From source

```
cargo install --git https://github.com/idestis/kerf kerf-cli
```

Requires Rust 1.75 or newer.

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
| `task test:integration` | The `#[ignore]`d KMS end-to-end tests, against **local emulators** over the real wire (no mocks — per [`CLAUDE.md`](CLAUDE.md)). | running emulator(s) + env vars |

`task test` is what CI runs on every PR. Integration tests are for maintainers
with emulators up locally; each provider's tests skip cleanly unless its
endpoint env var is set, so you only need the emulators you actually want to
exercise:

```bash
# AWS — floci or LocalStack on :4566
export KERF_KMS_ENDPOINT_AWS=http://localhost:4566
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1

# GCP — fake-cloud-kms (floci-gcp has no KMS) on :8085
export KERF_KMS_ENDPOINT_GCP=localhost:8085
export KERF_GCP_TEST_KEY=projects/test/locations/global/keyRings/r/cryptoKeys/k

# Azure — floci-az or lowkey-vault on :4577
export KERF_KMS_ENDPOINT_AZURE=http://localhost:4577
export KERF_AZURE_TEST_KEY=https://<vault>/keys/<name>/<version>

task test:integration
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
