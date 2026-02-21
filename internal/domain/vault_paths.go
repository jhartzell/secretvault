package domain

import (
	"os"
	"path/filepath"
	"strings"
)

func AbsoluteVaultFilePath(ctx ProjectContext, rel string) (string, error) {
	projectDir, err := VaultProjectPath(ctx)
	if err != nil {
		return "", err
	}
	return filepath.Join(projectDir, rel), nil
}

func VaultManifestPath(ctx ProjectContext) (string, error) {
	projectDir, err := VaultProjectPath(ctx)
	if err != nil {
		return "", err
	}
	return filepath.Join(projectDir, "manifest.json"), nil
}

func VaultProjectPath(ctx ProjectContext) (string, error) {
	home, err := VaultHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "projects", ctx.ProjectID), nil
}

func VaultHomeDir() (string, error) {
	envHome := strings.TrimSpace(os.Getenv("SECRETVAULT_HOME"))
	if envHome != "" {
		return filepath.Abs(envHome)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".secretvault"), nil
}
