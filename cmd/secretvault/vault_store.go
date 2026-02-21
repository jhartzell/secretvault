package main

import (
	"io/fs"

	"secrets-vault/internal/domain"
)

func upsertVaultEntry(ctx projectContext, originalPath, encryptedPath string, originalMode fs.FileMode) error {
	return domain.UpsertVaultEntry(ctx, originalPath, encryptedPath, originalMode)
}

func loadVaultManifest(ctx projectContext) (vaultManifest, string, error) {
	return domain.LoadVaultManifest(ctx)
}

func saveVaultManifest(path string, manifest vaultManifest) error {
	return domain.SaveVaultManifest(path, manifest)
}

func newVaultManifest(ctx projectContext) vaultManifest {
	return domain.NewVaultManifest(ctx)
}

func selectRestoreEntries(ctx projectContext, manifest vaultManifest, args []string, restoreAll bool) []vaultEntry {
	return domain.SelectRestoreEntries(ctx, manifest, args, restoreAll)
}

func resolveEntryTargetPath(ctx projectContext, entry vaultEntry) string {
	return domain.ResolveEntryTargetPath(ctx, entry)
}

func resolveLocalRestoreSource(ctx projectContext, entry vaultEntry, targetPath string) (string, bool, error) {
	return domain.ResolveLocalRestoreSource(ctx, entry, targetPath)
}

func entryVaultBackupPath(ctx projectContext, entry vaultEntry) (string, error) {
	return domain.EntryVaultBackupPath(ctx, entry)
}

func sortedVaultEntryKeys(manifest vaultManifest) []string {
	return domain.SortedVaultEntryKeys(manifest)
}
