package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	HookModeStable = "stable-dev"
)

func InstallHookPair(target, preDir, postDir, mode string) error {
	if err := os.MkdirAll(preDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(postDir, 0o755); err != nil {
		return err
	}

	preHook := filepath.Join(preDir, "secretvault-lock.sh")
	postHook := filepath.Join(postDir, "secretvault-unlock.sh")
	postAction := "unlock"
	if mode == HookModeStable {
		postAction = "lock"
	}
	binaryPath := resolveSecretvaultBinary()
	installCWD := resolveInstallCWD()

	if err := writeExecutableFile(preHook, HookScriptWithBinary("lock", mode, binaryPath, installCWD)); err != nil {
		return err
	}
	if err := writeExecutableFile(postHook, HookScriptWithBinary(postAction, mode, binaryPath, installCWD)); err != nil {
		return err
	}

	fmt.Printf("Installed %s hooks (mode: %s):\n", target, mode)
	fmt.Printf("- %s\n", preHook)
	fmt.Printf("- %s\n", postHook)
	return nil
}

func InstallOpencodePlugin(configDir, mode string) error {
	pluginDir := filepath.Join(configDir, "plugins")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		return err
	}

	pluginPath := filepath.Join(pluginDir, "secretvault-hooks.js")
	binaryPath := resolveSecretvaultBinary()
	installCWD := resolveInstallCWD()
	if err := writeExecutableFile(pluginPath, OpencodePluginScript(mode, binaryPath, installCWD)); err != nil {
		return err
	}

	fmt.Printf("Installed opencode plugin hook (mode: %s):\n", mode)
	fmt.Printf("- %s\n", pluginPath)
	return nil
}

func HookScript(action, mode string) string {
	return HookScriptWithBinary(action, mode, "", "")
}

func OpencodePluginScript(mode, binaryPath, installCWD string) string {
	postAction := "unlock"
	if mode == HookModeStable {
		postAction = "lock"
	}

	return fmt.Sprintf(`export const SecretvaultHooksPlugin = async ({ directory, worktree }) => {
  const mode = %q
  const binPath = %q
  const installCwd = %q

  const resolveCwd = () => {
    if (process.env.SECRETVAULT_HOOK_CWD) return process.env.SECRETVAULT_HOOK_CWD
    if (process.env.OPENCODE_PROJECT_PATH) return process.env.OPENCODE_PROJECT_PATH
    if (process.env.OPENCODE_WORKDIR) return process.env.OPENCODE_WORKDIR
    if (worktree) return worktree
    if (directory) return directory
    if (installCwd) return installCwd
    return process.cwd()
  }

  const run = (action) => {
	const cwd = resolveCwd()
	const env = { ...process.env, SECRETVAULT_HOOK_CWD: cwd }
	if (process.env.SECRETVAULT_HOOK_DEBUG === "1") {
	  try {
	    Bun.write(Bun.file("/tmp/secretvault-hook.log"), new Date().toISOString() + " plugin action=" + action + " cwd=" + cwd + "\n", { append: true })
	  } catch {}
	}
	const tryRun = (cmd, args) => {
      try {
        const result = Bun.spawnSync([cmd, ...args], { cwd, env, stdout: "ignore", stderr: "ignore" })
        return result.exitCode === 0
      } catch {
        return false
      }
    }

    if (binPath && tryRun(binPath, [action])) return
    if (tryRun("secretvault", [action])) return
    tryRun("secrets-vault", [action])
  }

  return {
    event: async ({ event }) => {
      if (event.type === "session.status") {
        if (event.properties?.status?.type === "busy") {
          run("lock")
        }
        if (event.properties?.status?.type === "idle") {
          run(%q)
        }
      }
      if (event.type === "session.idle") {
        run(%q)
      }
    },
  }
}
`, mode, binaryPath, installCWD, postAction, postAction)
}

func HookScriptWithBinary(action, mode, binaryPath, installCWD string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

# secretvault hook mode: %s

SECRETVAULT_BIN=%q
SECRETVAULT_INSTALL_CWD=%q

if [[ -z "${SECRETVAULT_HOOK_CWD:-}" ]]; then
  if [[ -n "${OPENCODE_PROJECT_PATH:-}" && -d "${OPENCODE_PROJECT_PATH}" ]]; then
    export SECRETVAULT_HOOK_CWD="${OPENCODE_PROJECT_PATH}"
  elif [[ -n "${OPENCODE_WORKDIR:-}" && -d "${OPENCODE_WORKDIR}" ]]; then
    export SECRETVAULT_HOOK_CWD="${OPENCODE_WORKDIR}"
  elif [[ -n "$SECRETVAULT_INSTALL_CWD" && -d "$SECRETVAULT_INSTALL_CWD" ]]; then
    export SECRETVAULT_HOOK_CWD="$SECRETVAULT_INSTALL_CWD"
  elif command -v git >/dev/null 2>&1; then
    export SECRETVAULT_HOOK_CWD="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
  else
    export SECRETVAULT_HOOK_CWD="$PWD"
  fi
fi

if [[ -n "${SECRETVAULT_HOOK_CWD:-}" && -d "${SECRETVAULT_HOOK_CWD}" ]]; then
  cd "${SECRETVAULT_HOOK_CWD}" || true
fi

if [[ -n "$SECRETVAULT_BIN" && -x "$SECRETVAULT_BIN" ]]; then
  "$SECRETVAULT_BIN" %s >/dev/null 2>&1 || true
elif command -v secretvault >/dev/null 2>&1; then
  secretvault %s >/dev/null 2>&1 || true
elif command -v secrets-vault >/dev/null 2>&1; then
  secrets-vault %s >/dev/null 2>&1 || true
fi

if [[ "${SECRETVAULT_HOOK_DEBUG:-0}" == "1" ]]; then
  {
    echo "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ) action=%s cwd=$PWD hook_cwd=${SECRETVAULT_HOOK_CWD:-} install_cwd=$SECRETVAULT_INSTALL_CWD"
  } >> /tmp/secretvault-hook.log
fi

`, mode, binaryPath, installCWD, action, action, action, action)
}

func writeExecutableFile(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		return err
	}
	return os.Chmod(path, 0o755)
}

func resolveSecretvaultBinary() string {
	if path, err := exec.LookPath("secretvault"); err == nil {
		return path
	}
	if path, err := exec.LookPath("secrets-vault"); err == nil {
		return path
	}
	return ""
}

func resolveInstallCWD() string {
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	return ""
}
