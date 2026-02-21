package hooks

import (
	"fmt"
	"os"
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

	if err := writeExecutableFile(preHook, HookScript("lock", mode)); err != nil {
		return err
	}
	if err := writeExecutableFile(postHook, HookScript(postAction, mode)); err != nil {
		return err
	}

	fmt.Printf("Installed %s hooks (mode: %s):\n", target, mode)
	fmt.Printf("- %s\n", preHook)
	fmt.Printf("- %s\n", postHook)
	return nil
}

func HookScript(action, mode string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

# secretvault hook mode: %s

if command -v secretvault >/dev/null 2>&1; then
  secretvault %s >/dev/null 2>&1 || true
elif command -v secrets-vault >/dev/null 2>&1; then
  secrets-vault %s >/dev/null 2>&1 || true
fi
`, mode, action, action)
}

func writeExecutableFile(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		return err
	}
	return os.Chmod(path, 0o755)
}
