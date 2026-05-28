# kerf — Technical Specification

> Diff-aware, KMS-first encryption for structured secret files.

**Status:** Draft v0.1
**Audience:** Implementers, security reviewers, contributors

> *A kerf is the narrow slit a saw cuts through wood — material removed only along the path of the blade, the rest of the board untouched. This tool encrypts the same way: edit one value, and only that value's ciphertext changes. One cut. One diff.*

---

## 1. Problem statement

Tools like SOPS encrypt structured secret files (YAML/JSON/TOML/ENV) per-value so the file structure stays diff-able. But every encryption operation rerolls the data encryption key (DEK) and generates fresh nonces for every value, so editing one secret produces a git diff that touches every encrypted value in the file. This makes code review of secret changes effectively impossible: reviewers cannot see *which* secrets changed, only that *some* did.

`kerf` solves this with a single invariant:

> **If a value's plaintext is unchanged, its on-disk ciphertext, nonce, and authentication tag are byte-identical to the previous version.**

This produces minimal git diffs — one changed secret yields one changed line of ciphertext (plus the file-level MAC).

## 2. Scope

### In scope
- Per-value encryption of structured files: YAML, JSON, TOML, ENV (dotenv), INI.
- KMS-backed key wrapping: AWS KMS, GCP KMS, Azure Key Vault.
- Software recipients: `age` (X25519 + ChaCha20-Poly1305, via the `age` crate).
- Minimal-diff re-encryption when an existing ciphertext file is present.
- Recipient management without DEK rotation (add/remove KMS keys cheaply).
- Explicit DEK rotation as a separate, named operation.
- Cross-platform single-binary distribution: Linux (x86_64, aarch64), macOS (arm64, x86_64), Windows (x86_64).

### Out of scope (v1)
- PGP / GnuPG recipients. Modern KMS + age cover the realistic threat models without gpg-agent pain.
- HashiCorp Vault integration. Possible later as an external recipient type; not in core.
- Encrypting arbitrary unstructured files. Use `age` directly for that.
- Built-in Kubernetes Operator. The file format will be stable enough that third-party integrations (Flux, ArgoCD plugins) can be written against it.
- Secret rotation policies, expiry, audit logging. Those belong in a higher layer.

## 3. Threat model

### Assumptions
- The attacker has read access to the git repository (clones, pushes, mirrors).
- The attacker does **not** have access to any configured KMS key or age private key.
- The host running `kerf` for encryption/decryption is trusted for the duration of the operation. Plaintext exists in memory during use.
- KMS providers are trusted to enforce their own access controls.

### What `kerf` protects
- **Confidentiality of values.** Without a valid recipient credential, ciphertext is computationally indistinguishable from random.
- **Integrity of the file.** Tampering with any ciphertext, key, or path is detected at decrypt time.
- **Integrity of structure.** Reordering entries, swapping ciphertexts between keys, or adding/removing entries is detected.
- **Key-blob unforgeability.** AAD binds each ciphertext to its dotted path; ciphertext cannot be moved between fields.

### What `kerf` does NOT protect
- **The set of keys/paths in the file.** Keys are stored in plaintext to preserve diff-ability. Do not put secrets in key names.
- **Approximate value lengths.** Ciphertext length leaks plaintext length (within AES-GCM block granularity).
- **Edit metadata.** Which values changed in a given commit is visible in git history.
- **Compromised endpoints.** A user with a valid KMS credential can decrypt; that is by design.
- **Side channels on the encrypting host.** Memory dumps, swap, hibernation files may contain plaintext.

### Non-goals
- Resistance to nation-state attackers with KMS-provider collusion.
- Forward secrecy across DEK rotations. If a key is exfiltrated, all prior ciphertexts encrypted under that DEK are exposed; rotate the DEK to limit blast radius going forward.

## 4. File format

### 4.1 Identity
- File suffix convention: `<name>.kerf.<ext>` (e.g., `prod.kerf.yaml`). No magic bytes; the suffix is the canonical signal.
- Files are valid YAML/JSON/TOML on their own — they parse cleanly with standard parsers; `kerf` metadata lives under a reserved top-level key `kerf:`.
- Inside the reserved block, all binary blobs are base64 (standard, no URL-safe variant) for cross-format consistency.

### 4.2 Layout (YAML example)

```yaml
db:
  password: ENC[AES-GCM,n:9wK3y...,c:Hf82L...,t:9aB1c...]
  host: db.prod.internal
api:
  token: ENC[AES-GCM,n:p0Qm1...,c:Ks83x...,t:7vN2m...]

kerf:
  version: 1
  cipher: aes-256-gcm
  file_uuid: 7f3b4a2c-1d8e-4a5b-9c2f-3e1d4a5b9c2f
  created_at: 2026-05-28T14:23:00Z
  recipients:
    - type: aws-kms
      arn: arn:aws:kms:us-east-1:111:key/prod-secrets
      encrypted_dek: BASE64...
      encryption_context: {env: prod}
      created_at: 2026-05-28T14:23:00Z
    - type: age
      recipient: age1abc...
      encrypted_dek: BASE64...
      created_at: 2026-05-28T14:23:00Z
  encrypted_regex: "^(password|token|key|secret|credential)$"
  mac: ENC[AES-GCM,n:...,c:...,t:...]
  mac_only_encrypted: true
```

### 4.3 The `ENC[...]` envelope

Each encrypted value is serialized as a single string with this exact format:

```
ENC[AES-GCM,n:<base64 nonce>,c:<base64 ciphertext>,t:<base64 tag>]
```

- `n` — 96-bit (12 byte) random nonce, fresh per encryption operation on that value.
- `c` — AES-256-GCM ciphertext.
- `t` — 128-bit (16 byte) GCM authentication tag.
- AAD (additional authenticated data) is the **dotted path** of the value within the file, encoded as UTF-8 bytes. For `db.password` the AAD is the literal bytes `db.password`. Not stored in the envelope — derived at encrypt/decrypt time.

### 4.4 Path canonicalization

Paths are dot-separated. Array indices use `[N]`. Examples:
- `db.password`
- `users[0].api_key`
- `services.gateway.tls.private_key`

Keys containing literal `.` or `[` must not occur in paths to be encrypted. The encryptor MUST reject such files at load time. (This is consistent with SOPS behavior and downstream tooling expectations.)

### 4.5 The MAC

`kerf.mac` is the AES-GCM encryption of an HMAC-SHA256 computed as follows:

1. Walk the file in canonical order (depth-first, keys sorted lexicographically within each map).
2. For each *encrypted* leaf, append `<path>:<plaintext>\n` to the MAC input.
3. Compute `HMAC-SHA256(DEK, mac_input)`.
4. Encrypt the resulting 32 bytes with AES-GCM under the DEK, AAD = the literal bytes `__kerf_mac__`.

If `mac_only_encrypted: false`, the walk includes plaintext leaves too; this is a deployment choice — including plaintext catches changes to non-secret config but causes more diff churn. Default is `true`.

The MAC is verified on every decrypt. Failure is fatal — no partial decrypt is returned.

### 4.6 KMS-wrapped DEK format

The DEK is 32 random bytes (AES-256). Each recipient stores a wrapped copy:

- **AWS KMS:** `encrypted_dek` is the raw output of `kms:Encrypt` (base64). `encryption_context` is a key-value map passed as AWS encryption context (also authenticated by KMS). The ARN is stored separately so `kms:Decrypt` can be routed without parsing the blob.
- **GCP KMS:** `encrypted_dek` is the output of `projects.locations.keyRings.cryptoKeys.encrypt`. `resource_id` stored separately.
- **Azure Key Vault:** `encrypted_dek` is the output of the Wrap Key operation. `key_id` stored as the full key version URL.
- **age:** `encrypted_dek` is a complete age ciphertext (an age file containing the 32 DEK bytes). This lets us use the `age` crate without modification and inherits age's recipient-stanza format.

Each recipient block is independent. To decrypt, `kerf` tries recipients in order and uses the first one it has a credential for.

## 5. Cryptographic primitives

| Primitive | Choice | Rationale |
|---|---|---|
| Symmetric AEAD (per-value) | AES-256-GCM | Hardware-accelerated everywhere, FIPS-friendly, well-understood, matches what KMS providers use internally. |
| Symmetric AEAD (age recipients) | ChaCha20-Poly1305 | Inherited from age. Faster than AES-GCM in software, hardware-agnostic. |
| Nonce generation | OS CSPRNG (96 bits) | `getrandom(2)` / `BCryptGenRandom`. 96-bit random nonces are safe under AES-GCM up to ~2^32 encryptions per key — DEK rotation gates this. |
| MAC | HMAC-SHA256 | Standard, simple, distinct from the AEAD construction. |
| Asymmetric (age path) | X25519 + ChaCha20-Poly1305 | Inherited from age. |
| RNG | `getrandom` crate (which delegates to OS) | No userland PRNG. Never `rand::thread_rng()` for key material. |

**Banned constructions:**
- AES-CBC, AES-CTR without an AEAD. No unauthenticated ciphers anywhere.
- Custom or "tweaked" AES-GCM. Use the well-known constructions only.
- ECB. Ever.

## 6. The encrypt algorithm (the differentiator)

### 6.1 Inputs
- `plain_path` — path to the plaintext input.
- `out_path` — destination path. May or may not exist.
- Config (`.kerf.yaml`) — recipients and encrypted-key regex.

### 6.2 Decision tree

```
read plain_path
parse into AST preserving format

if out_path exists:
    parse out_path into AST
    validate kerf block integrity
    fetch DEK by unwrapping the first usable recipient
    verify MAC (abort on failure)
    decrypt each value in out_path → old_plain map keyed by path

    for each encrypted leaf path in plain_path:
        new_value = plain_value at that path
        old_value = old_plain.get(path)
        if old_value is None or old_value != new_value:
            generate fresh 96-bit nonce
            encrypt new_value under DEK with AAD = path
            write fresh ENC[] envelope to AST
        else:
            copy the original ENC[] envelope byte-for-byte from out_path

    for each path in old_plain but not in plain_path:
        omit (deletion)

    recompute MAC over canonical (path, plaintext) pairs
    encrypt MAC under DEK with AAD = "__kerf_mac__"
    write the new kerf block (recipients unchanged)
    serialize AST → out_path

else:
    generate fresh 32-byte DEK
    wrap DEK once per recipient
    for each encrypted leaf:
        fresh nonce, encrypt under DEK with AAD = path
    compute and encrypt MAC
    serialize → out_path
```

### 6.3 Invariants the implementation MUST maintain

1. **Nonce-uniqueness.** A nonce is generated fresh for every distinct `(DEK, plaintext-write)` pair. Never reuse a nonce under the same DEK. Implementations MUST use `getrandom` directly, not a seeded PRNG, for nonces.
2. **Byte-identity for unchanged values.** When `old_value == new_value`, the implementation MUST copy the original `ENC[...]` string verbatim. It MUST NOT re-encrypt with a fresh nonce "to be safe" — doing so is the SOPS bug `kerf` exists to fix.
3. **AAD binding.** Every encrypted value's AAD is its canonical dotted path. Decryption MUST fail if the path changes (e.g., an attacker moves a ciphertext to a different key).
4. **MAC covers what it claims to.** If `mac_only_encrypted: true`, the MAC input includes exactly the encrypted leaves. If `false`, all leaves. No other modes.
5. **No partial output on failure.** Writes are atomic: encrypt to a temp file in the same directory, `fsync`, then rename. Crash recovery never leaves a half-encrypted file.

### 6.4 What changes per edit

| Edit | DEK | Recipients | Per-value ciphertexts | MAC |
|---|---|---|---|---|
| Change one secret value | same | same | one changes | changes |
| Add a new secret | same | same | one added | changes |
| Delete a secret | same | same | one removed | changes |
| Add a recipient (`keys add`) | same | one added | none | none |
| Remove a recipient (`keys remove`) | same | one removed | none | none |
| `rotate` | new | re-wrapped | all change | changes |

The `keys remove` case deserves a warning in CLI output: any party who held the removed key and a previous version of the file can still decrypt that historical version. Use `rotate` to limit forward exposure.

## 7. Command surface

Commands follow git's porcelain/plumbing split. Porcelain commands are the human-facing UX and may evolve. Plumbing commands are scriptable and treated as stable contracts.

### 7.1 Porcelain

```
kerf init [--recipient KEY]...
    Create .kerf.yaml at the repo root.

kerf encrypt <file>
kerf encrypt --in-place <file>
kerf encrypt <plain> --output <enc>
    Encrypt. If output exists, performs minimal-diff re-encryption.

kerf decrypt <file> [--output <plain>]
    Decrypt to stdout or to file.

kerf edit <file>
    Decrypt → $EDITOR → minimal-diff re-encrypt. Atomic.

kerf view <file> [--path <dotted.path>]
    Read-only decrypt to stdout, optionally extracting one value.

kerf diff <old> <new> [--show-values]
    Decrypt both and show plaintext diff. Values are redacted unless --show-values.

kerf exec <file> -- <command> [args...]
    Decrypt values into env vars (UPPER_SNAKE_CASE from dotted paths) and exec.
    No temp files. Memory only.
```

### 7.2 Recipient management

```
kerf keys add    <file> --recipient <key>
kerf keys remove <file> --recipient <key>
kerf keys list   <file>
    Modify recipient block. Body unchanged. Warns on remove that historical
    git versions remain decryptable by the removed key.

kerf updatekeys <file>
    Reconcile recipients against .kerf.yaml. Adds missing, removes stale.
    Does NOT rotate the DEK unless --rotate is passed.
```

### 7.3 Rotation

```
kerf rotate <file> [--reason "<msg>"]
    Generate a new DEK, re-encrypt every value with fresh nonces, re-wrap.
    The only operation that legitimately produces a full-file diff.
    --reason is appended to the kerf block as audit metadata.
```

### 7.4 Operational

```
kerf verify <file>
    MAC check + AAD check on every value. Exits 0 on integrity, non-zero otherwise.

kerf set   <file> <path> <value>
kerf unset <file> <path>
    Scripted single-value mutations. Uses the diff-aware encrypt path.
    --stdin for set to avoid value-in-argv leaks.
```

### 7.5 Plumbing (stable contracts)

```
kerf recipients <file>      Print recipient list as JSON.
kerf metadata <file>        Print kerf block (without DEKs). No decryption needed.
kerf mac --verify <file>    MAC check only. Faster than full verify.
kerf path-encrypted <file> <path>   Exit 0 if path is encrypted per regex.
```

### 7.6 Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic error (file I/O, parse) |
| 2 | Usage error |
| 10 | No usable recipient credential |
| 11 | MAC verification failed (tampering or corruption) |
| 12 | AAD verification failed (ciphertext moved between paths) |
| 13 | Recipient unwrap failed (KMS denied / key revoked) |
| 20 | Plaintext input is not valid YAML/JSON/TOML/ENV |

## 8. Configuration: `.kerf.yaml`

```yaml
version: 1
creation_rules:
  - path_regex: "secrets/prod/.*\\.kerf\\.yaml$"
    recipients:
      - type: aws-kms
        arn: arn:aws:kms:us-east-1:111:key/prod-secrets
        encryption_context: {env: prod}
      - type: age
        recipient: age1...
    encrypted_regex: "^(password|token|key|secret|credential)$"
    mac_only_encrypted: true

  - path_regex: "secrets/dev/.*"
    recipients:
      - type: age
        recipient: age1dev...
    encrypted_regex: ".*"
```

Rules are evaluated top-to-bottom; first match wins. `init` writes a sensible default scoped to the current directory.

## 9. Language and dependencies

**Language:** Rust 2021, MSRV `1.75`.

**Why Rust:**
- Single statically-linked binary across all targets.
- `aws-lc-rs` provides FIPS-validated AES-GCM with the same API as `ring`.
- `zeroize` for guaranteed-wipe of DEKs and plaintext on drop.
- `age` crate is the reference Rust implementation of age.
- Compile-time prevention of nonce-reuse (typed `Nonce` consumed on use).

**Core crates:**
- `aws-lc-rs` — AES-256-GCM, HMAC-SHA256, RNG.
- `age` — age recipient handling.
- `aws-sdk-kms`, `google-cloud-kms`, `azure_security_keyvault_keys` — KMS clients.
- `serde`, `serde_yaml`, `serde_json`, `toml` — format parsing.
- `zeroize`, `secrecy` — secret material lifecycle.
- `clap` v4 — CLI parsing.
- `tokio` — async runtime (KMS clients require it; everything else stays sync).
- `tracing` — structured logging behind `--verbose`.

**Crates explicitly NOT used:**
- `rand::thread_rng` for any key or nonce material. Use `getrandom` (re-exported by `aws-lc-rs`).
- `openssl-sys` — pulls in C dependencies, breaks single-binary distribution on Windows.

## 10. Distribution

- **GitHub Releases:** prebuilt binaries for `linux-x86_64`, `linux-aarch64`, `macos-arm64`, `macos-x86_64`, `windows-x86_64`. Built via `cargo-dist` in CI.
- **Homebrew tap:** `kerf-cli/tap/kerf`.
- **Cargo:** `cargo install kerf-cli`.
- **Docker:** distroless image at `ghcr.io/<org>/kerf:<version>` for CI use.
- **Signing:** all release artifacts signed with `cosign` (sigstore). Checksums published.
- **No `curl | sh` install script.** Users either use a package manager or download the signed binary.

## 11. Testing requirements

### 11.1 Correctness
- **Round-trip tests** on every format (YAML, JSON, TOML, ENV, INI): encrypt → decrypt → byte-equal plaintext, structure preserved.
- **Minimal-diff property test:** generate two plaintexts differing in exactly N values; assert exactly N envelopes change in the output (plus the MAC line).
- **Format preservation:** comments, key ordering, whitespace, and quoting style must survive a round trip in YAML.

### 11.2 Security
- **AAD binding test:** swap two `ENC[]` envelopes between keys; decrypt must fail with exit code 12.
- **MAC test:** flip one bit in any envelope or in the recipient block; verify must fail with exit code 11.
- **Nonce uniqueness:** encrypt the same value to the same DEK 10,000 times in unit tests; assert all nonces are distinct.
- **No plaintext on disk:** instrument `edit` and `exec` paths to verify no plaintext is written to disk except in `--output` mode.

### 11.3 Interop
- **age compatibility:** age-wrapped DEKs must be readable by the reference `age` binary and `rage`.
- **KMS integration tests** run against LocalStack (AWS), the GCP KMS emulator, and Azure's test vault. Real-cloud tests gated behind credentials in CI.

### 11.4 Fuzzing
- **`cargo-fuzz` targets** for: file parser, ENC envelope parser, recipient block parser.
- Run continuously on OSS-Fuzz once stable.

## 12. Versioning and stability

- **File format version:** integer in `kerf.version`. v1 is the format above. Bumps require a migration path: `kerf migrate <file>` reads old version, writes new.
- **CLI porcelain commands:** semver, but breaking changes are allowed in minor versions before 1.0.
- **CLI plumbing commands:** strict semver from 0.5 onward. Output formats stable.
- **Library API (`kerf-core` crate):** not stable until 1.0.

## 13. Open questions

These are flagged for discussion before implementation begins:

1. **Default encrypted-key regex.** Should `init` default to `^(password|token|key|secret|credential|cert|.*_key|.*_token)$` (broad, opt-out) or `^.*$` (encrypt all values, opt-out via `unencrypted_regex`)? SOPS chose the latter. Argument for broad-but-not-all: most YAML has plenty of non-secret config that benefits from being readable in diffs.

2. **Should `kerf` support a "comment" mode** where an `ENC[]` envelope sits next to a plaintext comment showing the key, like:
   ```yaml
   db:
     password: ENC[...]  # last changed 2026-05-28 by alice@example.com
   ```
   Adds audit value; complicates parse/serialize round trips.

3. **Should we adopt a magic header line** (`# kerf v1 file — do not edit by hand`) in addition to the suffix? Useful for `file(1)`-style detection but adds parser fragility.

4. **Per-recipient encryption context (AWS KMS).** Currently shared across all AWS recipients. Should each AWS recipient carry its own context, allowing different IAM policies on the same file?

5. **`kerf exec` env var naming.** `db.password` → `DB_PASSWORD` is obvious, but `users[0].api_key` is not. Reject? Concatenate? Require explicit mapping?

---

## Appendix A: Anti-features

Things `kerf` will not do, and why:

- **Re-encrypt unchanged values to "freshen" them.** This is the SOPS bug. Doing it under the same DEK adds nothing cryptographically (same key, same algorithm) and destroys the diff property. Doing it under a new DEK is what `rotate` is for.
- **Encrypt keys as well as values.** Breaks the diff property entirely. If your key names are secret, `kerf` is not the right tool — use whole-file encryption (`age`, `git-crypt`).
- **Provide a daemon mode by default.** Long-lived processes with DEKs in memory are an attack surface. The `exec` path is the only acceptable long-lived form.
- **Auto-detect file format.** Explicit `--format` or the file suffix decides. Heuristic detection is a footgun.
- **Build an editor.** `$EDITOR` is the contract. We do not ship a UI.
