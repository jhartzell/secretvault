#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="$ROOT_DIR/.secrets-vault-smoke-bin"
TMP_PROJ=""
TMP_HOME=""

cleanup() {
  rm -f "$BIN_PATH"
  if [[ -n "$TMP_PROJ" && -d "$TMP_PROJ" ]]; then
    rm -rf "$TMP_PROJ"
  fi
  if [[ -n "$TMP_HOME" && -d "$TMP_HOME" ]]; then
    rm -rf "$TMP_HOME"
  fi
}
trap cleanup EXIT

assert_file_exists() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "assertion failed: expected file to exist: $path" >&2
    exit 1
  fi
}

assert_file_missing() {
  local path="$1"
  if [[ -f "$path" ]]; then
    echo "assertion failed: expected file to be missing: $path" >&2
    exit 1
  fi
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "assertion failed: expected content to include: $needle" >&2
    exit 1
  fi
}

echo "[1/7] Building CLI"
cd "$ROOT_DIR"
go build -o "$BIN_PATH" ./cmd/secretvault

echo "[2/7] Creating temporary project"
TMP_PROJ="$(mktemp -d)"

cat > "$TMP_PROJ/.env" <<'EOF'
API_KEY=abc123
EOF

cat > "$TMP_PROJ/terraform.tfvars" <<'EOF'
db_password = "supersecret"
EOF

mkdir -p "$TMP_PROJ/secrets"
cat > "$TMP_PROJ/secrets/token.txt" <<'EOF'
token=xyz
EOF

cat > "$TMP_PROJ/notes.txt" <<'EOF'
hello world
EOF

sha256sum \
  "$TMP_PROJ/.env" \
  "$TMP_PROJ/terraform.tfvars" \
  "$TMP_PROJ/secrets/token.txt" > "$TMP_PROJ/before.sha"

echo "[3/7] Setting project key and scanning"
cd "$TMP_PROJ"
"$BIN_PATH" key set --generate
SCAN_OUTPUT="$("$BIN_PATH" scan)"
echo "$SCAN_OUTPUT"

if [[ "$SCAN_OUTPUT" != *".env"* ]]; then
  echo "assertion failed: scan output missing .env" >&2
  exit 1
fi
if [[ "$SCAN_OUTPUT" != *"terraform.tfvars"* ]]; then
  echo "assertion failed: scan output missing terraform.tfvars" >&2
  exit 1
fi

echo "[4/7] Locking files"
"$BIN_PATH" lock --dry-run
"$BIN_PATH" lock

echo "[5/7] Verifying locked state"
assert_file_missing "$TMP_PROJ/.env"
assert_file_exists "$TMP_PROJ/.env.svault"
assert_file_missing "$TMP_PROJ/terraform.tfvars"
assert_file_exists "$TMP_PROJ/terraform.tfvars.svault"
assert_file_missing "$TMP_PROJ/secrets/token.txt"
assert_file_exists "$TMP_PROJ/secrets/token.txt.svault"
assert_file_exists "$TMP_PROJ/notes.txt"

echo "[5.3/7] Validating run wrapper unshields then reshields"
"$BIN_PATH" run -- sh -c 'test -f .env && test -f terraform.tfvars && test -f secrets/token.txt'
assert_file_missing "$TMP_PROJ/.env"
assert_file_exists "$TMP_PROJ/.env.svault"
assert_file_missing "$TMP_PROJ/terraform.tfvars"
assert_file_exists "$TMP_PROJ/terraform.tfvars.svault"
assert_file_missing "$TMP_PROJ/secrets/token.txt"
assert_file_exists "$TMP_PROJ/secrets/token.txt.svault"

echo "[5.5/7] Simulating lost encrypted file and restoring from vault backup"
rm -f "$TMP_PROJ/.env.svault"
"$BIN_PATH" restore .env
assert_file_exists "$TMP_PROJ/.env"

echo "[5.7/7] Validating hook installer commands"
TMP_HOME="$(mktemp -d)"
HOME="$TMP_HOME" "$BIN_PATH" install opencode
HOME="$TMP_HOME" "$BIN_PATH" install claude --mode strict
assert_file_exists "$TMP_HOME/.config/opencode/hooks/pre-message.d/secretvault-lock.sh"
assert_file_exists "$TMP_HOME/.config/opencode/hooks/post-response.d/secretvault-unlock.sh"
assert_file_exists "$TMP_HOME/.config/opencode/plugins/secretvault-hooks.js"
assert_file_exists "$TMP_HOME/.claude/hooks/pre-message.d/secretvault-lock.sh"
assert_file_exists "$TMP_HOME/.claude/hooks/post-response.d/secretvault-unlock.sh"

OPENCODE_POST_CONTENT="$(<"$TMP_HOME/.config/opencode/hooks/post-response.d/secretvault-unlock.sh")"
OPENCODE_PLUGIN_CONTENT="$(<"$TMP_HOME/.config/opencode/plugins/secretvault-hooks.js")"
CLAUDE_POST_CONTENT="$(<"$TMP_HOME/.claude/hooks/post-response.d/secretvault-unlock.sh")"
assert_contains "$OPENCODE_POST_CONTENT" "secretvault unlock"
assert_contains "$OPENCODE_PLUGIN_CONTENT" "event.type === \"session.status\""
assert_contains "$OPENCODE_PLUGIN_CONTENT" "run(\"lock\")"
assert_contains "$OPENCODE_PLUGIN_CONTENT" "run(\"unlock\")"
assert_contains "$CLAUDE_POST_CONTENT" "secretvault unlock"

echo "[6/7] Unlocking files"
"$BIN_PATH" unlock

echo "[7/7] Verifying round-trip integrity"
sha256sum \
  "$TMP_PROJ/.env" \
  "$TMP_PROJ/terraform.tfvars" \
  "$TMP_PROJ/secrets/token.txt" > "$TMP_PROJ/after.sha"
diff -u "$TMP_PROJ/before.sha" "$TMP_PROJ/after.sha"

"$BIN_PATH" key clear

echo "SMOKE TEST PASSED"
