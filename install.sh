#!/usr/bin/env bash
set -euo pipefail

REPO_ARCHIVE_URL="${SECRETVAULT_ARCHIVE_URL:-https://github.com/jhartzell/secrets-vault/archive/refs/heads/main.tar.gz}"

if ! command -v go >/dev/null 2>&1; then
  printf 'error: Go is required to install secretvault (Go 1.22+)\n' >&2
  exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
  printf 'error: tar is required to install secretvault\n' >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

printf 'Downloading secretvault source...\n'
curl -fsSL "$REPO_ARCHIVE_URL" -o "$tmpdir/source.tar.gz"
tar -xzf "$tmpdir/source.tar.gz" -C "$tmpdir"

src_dir=""
for entry in "$tmpdir"/*; do
  if [ -d "$entry" ]; then
    src_dir="$entry"
    break
  fi
done

if [ -z "$src_dir" ]; then
  printf 'error: failed to unpack source archive\n' >&2
  exit 1
fi

gobin="$(go env GOBIN)"
if [ -z "$gobin" ]; then
  gopath="$(go env GOPATH)"
  gobin="$gopath/bin"
fi
mkdir -p "$gobin"

printf 'Building secretvault...\n'
(
  cd "$src_dir"
  go build -o "$gobin/secretvault" ./cmd/secretvault
)

printf 'Installed secretvault to %s\n' "$gobin/secretvault"
case ":$PATH:" in
  *":$gobin:"*) ;;
  *) printf 'warning: %s is not in PATH; add it to run secretvault directly\n' "$gobin" ;;
esac
