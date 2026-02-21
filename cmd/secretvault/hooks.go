package main

import (
	"os"

	hooksint "secrets-vault/internal/integrations/hooks"
)

func installHookPair(target, preDir, postDir, mode string) error {
	return hooksint.InstallHookPair(target, preDir, postDir, mode)
}

func writeExecutableFile(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		return err
	}
	return os.Chmod(path, 0o755)
}

func hookScript(action, mode string) string {
	return hooksint.HookScript(action, mode)
}
