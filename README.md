# secretvault CLI

`secretvault` keeps secrets out of your repo while making them easy to restore for local workflows.

## What it does

- Detects likely secret files (`.env*`, `*.tfvars`, keys/certs, secret-like paths, config-like content patterns).
- Encrypts with AES-256-GCM and replaces plaintext with `<file>.svault`.
- Stores project key in OS keyring (never in repo files).
- Tracks encrypted file metadata in `~/.secretvault/projects/<project-id>/manifest.json`.
- Stores encrypted backup payloads in `~/.secretvault/projects/<project-id>/files/...`.
- Optionally absorbs files into 1Password Documents for cloud-backed restore.
- Installs OpenCode / Claude integrations for automatic lock/unlock around assistant turns.

## Install

```bash
curl -fsSL https://gist.githubusercontent.com/jhartzell/324260eb4a80f486fcff0179cde00998/raw/install.sh | bash
```

Or from source:

```bash
go install ./cmd/secretvault
```

## Recommended setup

Inside your project directory:

```bash
secretvault setup
secretvault install
```

`secretvault install` (no args) runs a guided flow:

1. Ensures/generates a project key
2. Scans for secrets
3. Lets you review detections with arrow keys + space (include/exclude)
4. Lets you add extra files manually
5. Absorbs to 1Password (default) or lock-only
6. Installs editor hooks/plugins

## Command reference

```bash
secretvault key [set|show|clear] [--value <string> | --generate]
secretvault scan [path ...]
secretvault lock [--dry-run] [path ...]
secretvault unlock [--dry-run] [path ...]
secretvault restore [--all] [--force] [path ...]
secretvault absorb [--vault <name>] [--dry-run] [--yes] [path ...]
secretvault cleanup [--dry-run] [--yes]
secretvault vault status
secretvault install [--mode stable-dev|strict] [opencode|claude]
secretvault run -- <command> [args ...]
secretvault setup [--yes] [--signin-address <address>]
```

Tip: running `secretvault` with no args opens an interactive command picker.

## Hook/plugin behavior

- `opencode` default mode: `strict` (lock before prompt, unlock after response).
- `claude` default mode: `stable-dev` (lock before prompt, lock again after response).
- `opencode` install writes:
  - `~/.config/opencode/hooks/pre-message.d/secretvault-lock.sh`
  - `~/.config/opencode/hooks/post-response.d/secretvault-unlock.sh`
  - `~/.config/opencode/plugins/secretvault-hooks.js` (event-driven reliability)
- `claude` install writes shell hooks under `~/.claude/hooks/...`.

## 1Password integration

- `secretvault setup` can install/configure `op` CLI and guide desktop-app integration.
- Default sign-in address is `my.1password.com` (override with `--signin-address` or `SECRETVAULT_OP_SIGNIN_ADDRESS`).
- `absorb` stores source metadata on each 1Password item (project, path, host, user, timestamp) plus searchable tags.
- `cleanup` removes project-tracked 1Password documents and clears 1Password fields from the local manifest.

## Discovery notes

- Scanner intentionally ignores noisy/generated artifacts like `.terraform/`, `node_modules/`, `*.pre-absorb`, `*.bak`, `*.orig`.
- Locking includes both newly detected files and previously tracked manifest entries.

## Verification

```bash
task test
task smoke
```
