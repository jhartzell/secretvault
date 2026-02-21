# Agent Instructions

This file is the canonical guidance for agents working in `secretvault`.
Primary goals: open-source readiness, readability, safe evolution, and no regressions.

## Package Manager

- Language/toolchain: Go 1.22+
- Task runner: `task` via `Taskfile.yml`
- External runtime dependency for absorb flow: 1Password CLI `op`

## Build & Test

- Preferred commands:
  - `task build`
  - `task test`
  - `task smoke`
- Release automation:
  - `task release VERSION=vX.Y.Z` (pushes tag, triggers `.github/workflows/release.yml`)
- Before completing non-trivial work, run at minimum:
  - `task test`
  - `task smoke` (when behavior touches lock/unlock/restore/hooks)

## Repo Layout

- `cmd/secretvault/main.go`: CLI entrypoint and command routing
- `cmd/secretvault/main_test.go`: regression suite
- `internal/domain/`: discovery, crypto, vault manifest/store logic
- `internal/integrations/`: keyring, 1Password CLI, hook installer, system shell adapters
- `smoke-test.sh`: end-to-end CLI verification
- `.github/workflows/release.yml`: release creation from tags

## Key Conventions

### Routing

- Use architecture/design mode when changes involve command surface, vault model, storage format, or integration behavior.
- Skip heavy planning for tiny mechanical edits.

### Architecture Boundaries (DDD/Clean-ish)

Keep these concepts explicit even if code is currently in one file:

- `Discovery`: finding sensitive files and encrypted targets
- `Crypto`: payload/file encryption and decryption
- `VaultStore`: manifest + backup copy lifecycle
- `Integrations`: 1Password CLI + hook installers
- `Application`: CLI command orchestration (`lock`, `unlock`, `restore`, `absorb`, `run`, `setup`)

When adding significant behavior, prefer extracting cohesive areas into domain-named files/packages (not `utils`/`helpers`).

### Code Quality Rules

- Prefer early returns over nested conditionals.
- Keep functions focused; split functions above ~50 lines when practical.
- Split files that exceed ~200 lines when adding substantial new behavior.
- Avoid duplication by extracting reusable, domain-named functions.
- Use explicit error messages with context.
- Keep side effects localized and testable.

### Library-First Policy

- Check for maintained libraries/services before writing custom plumbing.
- Use custom code only for domain-specific behavior, security-sensitive paths, or where dependencies are overkill.
- For this repo, cryptography and secret handling should remain explicit and reviewable.

### Naming

- Avoid generic names like `utils`, `helpers`, `common`, `shared`.
- Use domain names like `VaultManifest`, `RestoreSource`, `SensitiveScanPolicy`.
- Prefer clear nouns for data, verbs for actions.

## Good / Bad Patterns

Inspired by `anomalyco/opencode` style and adapted for this Go CLI.

### Early return

```go
// good
if len(targets) == 0 {
    return nil
}
return processTargets(targets)

// bad
if len(targets) > 0 {
    return processTargets(targets)
} else {
    return nil
}
```

### Domain naming

```go
// good
func loadVaultManifest(ctx projectContext) (vaultManifest, string, error)

// bad
func loadUtils(ctx projectContext) (any, error)
```

### Keep business logic out of shell glue

```go
// good: CLI command parses args, delegates to domain function(s)
func runRestoreCommand(args []string) error { ... }

// bad: command body inlines all encryption, manifest, and I/O details
```

### Prefer explicit checks over hidden behavior

```go
// good
if !hasCommand("op") {
    return errors.New("1Password CLI (op) is not installed")
}

// bad
// silently skipping absorb integration failures
```

## Testing Expectations

- Add/adjust tests for any behavior change.
- Prefer real file-system tests over heavy mocking for vault/crypto paths.
- Keep tests deterministic and isolated (`t.TempDir`, env cleanup, cwd cleanup).
- Never merge behavior changes without `task test` passing.

Minimum coverage to preserve:

- Parse logic (`install`/`run` args)
- Crypto round-trips (payload + file)
- Sensitive file discovery rules
- Manifest read/write and restore source selection
- Hook generation (`stable-dev` vs `strict`)

## Safety & Scope

- Do exactly what is requested; avoid speculative feature work.
- Never commit secrets, `.env`, raw credentials, or private keys.
- Preserve backward compatibility for manifest/encrypted formats unless migration is explicitly included.
- For destructive operations (deletes/overwrites), provide clear flags and safe defaults.

## Local Skills

- Use `agents-md` when updating this file and keep it the single source of truth for agent behavior.
  - Reference: `/home/josh/.claude/skills/agents-md/SKILL.md`
