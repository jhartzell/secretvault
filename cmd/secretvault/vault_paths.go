package main

import "secrets-vault/internal/domain"

func absoluteVaultFilePath(ctx projectContext, rel string) (string, error) {
	return domain.AbsoluteVaultFilePath(ctx, rel)
}

func vaultManifestPath(ctx projectContext) (string, error) {
	return domain.VaultManifestPath(ctx)
}

func vaultProjectPath(ctx projectContext) (string, error) {
	return domain.VaultProjectPath(ctx)
}

func vaultHomeDir() (string, error) {
	return domain.VaultHomeDir()
}

func projectRelativePath(projectRoot, absolutePath string) (string, bool) {
	return domain.ProjectRelativePath(projectRoot, absolutePath)
}

func hashPathID(path string) string {
	return domain.HashPathID(path)
}
