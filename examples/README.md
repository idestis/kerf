# kerf examples

These files exist to **validate and demonstrate the kerf invariant** in real
git history: when you change one secret, only that secret's ciphertext line
moves; when you add a new secret, the existing ciphertext stays byte-identical.

The marquee file is [`config.kerf.yaml`](config.kerf.yaml). It starts life as
six lines of plaintext config and secrets:

```yaml
environment: production
database:
  host: db.internal
  password: pg-prod-7Hq2Wx91
api:
  token: api-prod-Lm91Qd
```

`environment` and `database.host` stay readable — only the leaf keys that match
the rule's `encrypted_regex` (`password`, `token`, `key`, `secret`,
`credential`) become ciphertext. Config review still works in a PR.

## The three commits to look at

This directory was built up across three commits so you can click each diff:

1. **Encrypt.** The plaintext above becomes `config.kerf.yaml`: two `ENC[...]`
   envelopes, a wrapped DEK, and a file MAC.
2. **Change one secret** (`database.password`, via `kerf set`). The diff is
   exactly two lines: the rotated value, and the file MAC. `api.token` is
   untouched, byte for byte.
3. **Extend with a new secret** (`cache.password`). The diff adds the two new
   lines and updates the MAC — and *every existing ciphertext line is
   byte-identical*. Adding a secret does not reroll the others.

The links to those commits are in the [root README](../README.md#see-it-in-git).

## Other formats

`app.kerf.json` (JSON) and `service.kerf.env` (dotenv) show the same encryption
across other formats. The dotenv file uses uppercase keys, so its rule matches
secret-shaped names case-insensitively — see [`.kerf.yaml`](.kerf.yaml).

## Reproduce it yourself

The committed files are encrypted to a **throwaway demo age key whose secret
half is not in this repo** (see `.gitignore`) — they're here for the diffs, not
for decryption. To run the whole flow locally with a fresh key:

```bash
cargo build --release        # if you don't have a kerf binary yet
./examples/reproduce.sh
```

`reproduce.sh` works in a scratch directory and cleans up after itself. It
prints the diff after each step so you can see the byte-identity rule hold.

## A note on comments and non-ASCII

kerf preserves comments and whitespace when it can splice a changed value back
into the original layout. Two cases fall back to a normalized re-serialization
(which drops comments): a **structural change** (adding or removing a key), and
any file containing **non-ASCII bytes**. The encrypted *values* are still
byte-identical in both cases — only comment/whitespace layout is affected. The
narrative file here is kept ASCII and comment-free so every diff is crisp.
