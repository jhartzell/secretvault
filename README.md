# secretvault CLI

`secretvault` is a project-local CLI for finding, encrypting, tracking, and restoring sensitive files.

Core features:

- Detects common secret files, including `.env*`, `terraform.tfvars`, and `*.tfvars`.
- Detects sensitive files by secret-like content patterns.
- Encrypts/decrypts files with AES-256-GCM.
- Stores the project key in the OS keychain/keyring (not in project files).
- Tracks locked files per project in a vault manifest (project, directory, file metadata).
- Stores encrypted backup copies in `~/.secretvault/projects/<project-id>/files/...`.
- Absorbs sensitive plaintext files into 1Password Documents.
- Restores missing files from vault backups when needed.
- Installs auto lock/unlock hooks for OpenCode and Claude.

## Platform support

- Supported OS targets: macOS, Linux, Windows (Go CLI + keyring + `op` CLI).
- `secretvault setup` can suggest/install `op` using:
  - macOS: `brew`
  - Linux: `apt-get`, `dnf`, `pacman`, `zypper`
  - Windows: `winget`
- CI coverage currently runs on Ubuntu, so Linux is the most continuously validated path.

## Compatibility notes

- 1Password features (`absorb`, 1Password-based `restore`) require `op` installed and authenticated.
- Hook installers currently generate Bash scripts (`.sh`), so hooks are first-class on macOS/Linux.
- On Windows, hooks typically require Git Bash/WSL for shell-script execution.

## 1Password support

Use interactive setup first:

```bash
secretvault setup
```

This checks for `op` CLI, detects your OS/package manager, and can install dependencies for you.

## Install

Quick install (via gist):

```bash
curl -fsSL https://gist.githubusercontent.com/jhartzell/324260eb4a80f486fcff0179cde00998/raw/install.sh | bash
```

This installer downloads source from GitHub and builds `secretvault` into `$(go env GOBIN)` (or `$(go env GOPATH)/bin`).
Requirements: Go 1.22+, `curl`, and `tar`.

Gist: https://gist.github.com/jhartzell/324260eb4a80f486fcff0179cde00998

```bash
go install ./cmd/secretvault
```

Or build locally:

```bash
go build -o secretvault ./cmd/secretvault
```

## Quick start

From inside your project folder:

```bash
secretvault key set --generate
secretvault scan
secretvault absorb --vault "Private"
secretvault run -- terraform plan
```

You can set your own passphrase-derived key:

```bash
secretvault key set --value "my-strong-passphrase"
```

## Commands

```bash
secretvault key set [--value <string> | --generate]
secretvault key show
secretvault key clear
secretvault scan [path ...]
secretvault lock [--dry-run] [path ...]
secretvault unlock [--dry-run] [path ...]
secretvault restore [--all] [--force] [path ...]
secretvault absorb --vault <name> [--dry-run] [--yes] [path ...]
secretvault vault status
secretvault install [--mode stable-dev|strict] opencode
secretvault install [--mode stable-dev|strict] claude
secretvault run -- <command> [args ...]
secretvault setup [--yes]
```

## Absorb workflow

- `secretvault absorb --vault <name>` uploads discovered secrets to 1Password Document items.
- After successful upload, each absorbed file is locked locally (`.svault`) and tracked in the manifest.
- Manifest entries retain exact source paths, so `restore` recreates files in the same locations.
- Restore order: local encrypted copy -> local vault backup -> 1Password document.

## How locking works

- Lock writes encrypted files as `<original>.svault`.
- After successful encryption, plaintext files are removed.
- Lock also stores encrypted backups + metadata in the user vault store.
- Unlock restores plaintext filenames and removes `.svault` files.
- Restore can recover files from project `.svault` files or vault backups.
- File permissions are preserved and restored.

## Vault metadata and recovery

- Per-project metadata is stored in `~/.secretvault/projects/<project-id>/manifest.json`.
- Each entry tracks project path, absolute/relative file path, directory, file name, encrypted file path, and lock timestamps.
- `secretvault restore` restores missing tracked files by default.
- `secretvault restore --all` attempts to restore all tracked entries.
- `secretvault restore --force` overwrites existing plaintext files.

## Hook installers

- `secretvault install opencode --mode stable-dev` creates:
  - `~/.config/opencode/hooks/pre-message.d/secretvault-lock.sh`
  - `~/.config/opencode/hooks/post-response.d/secretvault-unlock.sh`
- `secretvault install claude --mode stable-dev` creates:
  - `~/.claude/hooks/pre-message.d/secretvault-lock.sh`
  - `~/.claude/hooks/post-response.d/secretvault-unlock.sh`

Modes:

- `stable-dev` (recommended): pre hook runs `lock`, post hook runs `lock` again (vault stays shielded for LLM turns).
- `strict`: pre hook runs `lock`, post hook runs `unlock`.

These hook scripts are best-effort and non-fatal.

## Wrapped runtime commands

- `secretvault run -- <cmd ...>` temporarily restores tracked secrets, runs your command, then re-shields by locking again.
- Example: `secretvault run -- terraform plan`
- Example: `secretvault run -- npm run dev`

## Sensitive file discovery

The scanner prioritizes:

1. Known secret names and extensions (`.env`, `.tfvars`, `.pem`, `.key`, etc.)
2. Files under secret-like directories (`secrets/`, `.aws/`, `.ssh/`, etc.)
3. Small files with secret-like content patterns

Ignored folders include `.git/`, `node_modules/`, `dist/`, `build/`, `vendor/`.

## Notes

- Key storage is per project path, allowing different keys per project.
- This repository currently focuses on CLI core functionality.
- NeoVim integration can be added later on top of this CLI.

## Smoke test

Run the end-to-end smoke test script:

```bash
./smoke-test.sh
```
