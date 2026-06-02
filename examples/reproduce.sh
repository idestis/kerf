#!/usr/bin/env bash
# Reproduce the kerf diff-aware demo end to end, in a throwaway scratch dir,
# with a freshly generated age key. Nothing here touches your real secrets or
# the committed example files.
#
#   ./examples/reproduce.sh
#
# It walks the same three steps the example commits show:
#   1. encrypt a small config file
#   2. change one secret        -> one ciphertext line moves (+ the file MAC)
#   3. add a new secret         -> existing ciphertext is byte-identical
#
# Requires: a `kerf` binary on PATH (or run `cargo build --release` first and
# this script will pick up ./target/release/kerf).
set -euo pipefail

KERF="${KERF:-kerf}"
if ! command -v "$KERF" >/dev/null 2>&1; then
  if [ -x "$(git rev-parse --show-toplevel 2>/dev/null)/target/release/kerf" ]; then
    KERF="$(git rev-parse --show-toplevel)/target/release/kerf"
  else
    echo "error: no 'kerf' on PATH. Run 'cargo build --release' first." >&2
    exit 1
  fi
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "==> scratch dir: $WORK"
echo "==> generating a throwaway age key"
REC="$("$KERF" keygen --output demo.age)"
export KERF_AGE_KEY_FILE="$WORK/demo.age"

cat > config.yaml <<'YAML'
environment: production
database:
  host: db.internal
  password: pg-prod-7Hq2Wx91
api:
  token: api-prod-Lm91Qd
YAML

echo
echo "==> step 1: encrypt"
"$KERF" encrypt config.yaml --output config.kerf.yaml --age "$REC"
cp config.kerf.yaml v1.yaml
cat config.kerf.yaml

echo
echo "==> step 2: change one secret (database.password)"
printf 'pg-prod-ROTATED-9988' | "$KERF" set config.kerf.yaml database.password
echo "--- diff vs step 1 (expect: database.password + mac, nothing else) ---"
diff v1.yaml config.kerf.yaml || true
cp config.kerf.yaml v2.yaml

echo
echo "==> step 3: extend with a NEW secret (cache.password), no edit to the old ones"
printf 'redis-NEW-Zz99Mn' | "$KERF" set config.kerf.yaml cache.password
echo "--- diff vs step 2 (expect: new cache lines + mac; api.token untouched) ---"
diff v2.yaml config.kerf.yaml || true

echo
echo "==> api.token ciphertext, step 1 vs step 3 (must be byte-identical):"
grep 'token:' v1.yaml
grep 'token:' config.kerf.yaml

echo
echo "==> verify + decrypt"
"$KERF" verify config.kerf.yaml
"$KERF" view config.kerf.yaml
