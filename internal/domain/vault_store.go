package domain

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func UpsertVaultEntry(ctx ProjectContext, originalPath, encryptedPath string, originalMode fs.FileMode) error {
	absOriginal, err := filepath.Abs(originalPath)
	if err != nil {
		return err
	}
	absEncrypted, err := filepath.Abs(encryptedPath)
	if err != nil {
		return err
	}

	manifest, manifestPath, err := LoadVaultManifest(ctx)
	if err != nil {
		return err
	}

	fileID := HashPathID(absOriginal)
	vaultRel := filepath.Join("files", fileID[:2], fileID+EncryptedExt)
	vaultAbs, err := AbsoluteVaultFilePath(ctx, vaultRel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(vaultAbs), 0o700); err != nil {
		return err
	}

	payload, err := os.ReadFile(absEncrypted)
	if err != nil {
		return err
	}
	if err := WriteAtomic(vaultAbs, payload, 0o600); err != nil {
		return err
	}

	relPath := ""
	if rel, ok := ProjectRelativePath(ctx.ProjectPath, absOriginal); ok {
		relPath = rel
	}

	now := time.Now().UTC().Format(time.RFC3339)
	manifest.Entries[absOriginal] = VaultEntry{
		FileID:               fileID,
		AbsolutePath:         absOriginal,
		RelativePath:         relPath,
		Directory:            filepath.Dir(absOriginal),
		Filename:             filepath.Base(absOriginal),
		VaultFile:            vaultRel,
		ProjectEncryptedFile: absEncrypted,
		LockedAt:             now,
		OriginalMode:         uint32(originalMode.Perm()),
	}
	manifest.UpdatedAt = now

	return SaveVaultManifest(manifestPath, manifest)
}

func LoadVaultManifest(ctx ProjectContext) (VaultManifest, string, error) {
	manifestPath, err := VaultManifestPath(ctx)
	if err != nil {
		return VaultManifest{}, "", err
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return NewVaultManifest(ctx), manifestPath, nil
		}
		return VaultManifest{}, "", err
	}

	var manifest VaultManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return VaultManifest{}, "", err
	}
	if manifest.Entries == nil {
		manifest.Entries = map[string]VaultEntry{}
	}
	if manifest.Version == 0 {
		manifest.Version = 1
	}
	if strings.TrimSpace(manifest.ProjectID) == "" {
		manifest.ProjectID = ctx.ProjectID
	}
	if strings.TrimSpace(manifest.ProjectPath) == "" {
		manifest.ProjectPath = ctx.ProjectPath
	}

	return manifest, manifestPath, nil
}

func SaveVaultManifest(path string, manifest VaultManifest) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(path, data, 0o600)
}

func NewVaultManifest(ctx ProjectContext) VaultManifest {
	return VaultManifest{
		Version:     1,
		ProjectID:   ctx.ProjectID,
		ProjectPath: ctx.ProjectPath,
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
		Entries:     map[string]VaultEntry{},
	}
}

func SelectRestoreEntries(ctx ProjectContext, manifest VaultManifest, args []string, restoreAll bool) []VaultEntry {
	if len(manifest.Entries) == 0 {
		return nil
	}

	if len(args) == 0 {
		keys := SortedVaultEntryKeys(manifest)
		out := make([]VaultEntry, 0, len(keys))
		for _, k := range keys {
			entry := manifest.Entries[k]
			target := ResolveEntryTargetPath(ctx, entry)
			if restoreAll || !FileExists(target) {
				out = append(out, entry)
			}
		}
		return out
	}

	seen := make(map[string]struct{})
	out := make([]VaultEntry, 0, len(args))
	for _, arg := range args {
		candidate := strings.TrimSpace(arg)
		if candidate == "" {
			continue
		}

		absCandidate, err := filepath.Abs(candidate)
		if err == nil {
			if entry, ok := manifest.Entries[absCandidate]; ok {
				if _, exists := seen[entry.AbsolutePath]; !exists {
					out = append(out, entry)
					seen[entry.AbsolutePath] = struct{}{}
				}
				continue
			}
		}

		cleanCandidate := filepath.Clean(candidate)
		for _, key := range SortedVaultEntryKeys(manifest) {
			entry := manifest.Entries[key]
			rel := filepath.Clean(entry.RelativePath)
			if rel == cleanCandidate || filepath.Base(entry.AbsolutePath) == cleanCandidate {
				if _, exists := seen[entry.AbsolutePath]; exists {
					continue
				}
				out = append(out, entry)
				seen[entry.AbsolutePath] = struct{}{}
			}
		}
	}

	return out
}

func ResolveEntryTargetPath(ctx ProjectContext, entry VaultEntry) string {
	if strings.TrimSpace(entry.RelativePath) != "" {
		return filepath.Join(ctx.ProjectPath, entry.RelativePath)
	}
	if strings.TrimSpace(entry.AbsolutePath) != "" {
		return entry.AbsolutePath
	}
	return filepath.Join(ctx.ProjectPath, entry.Filename)
}

func ResolveLocalRestoreSource(ctx ProjectContext, entry VaultEntry, targetPath string) (string, bool, error) {
	vaultBackup, err := EntryVaultBackupPath(ctx, entry)
	if err != nil {
		return "", false, err
	}

	candidates := []string{targetPath + EncryptedExt, entry.ProjectEncryptedFile, vaultBackup}
	for _, candidate := range candidates {
		if FileExists(candidate) {
			return candidate, true, nil
		}
	}

	return "", false, nil
}

func EntryVaultBackupPath(ctx ProjectContext, entry VaultEntry) (string, error) {
	if strings.TrimSpace(entry.VaultFile) != "" {
		return AbsoluteVaultFilePath(ctx, entry.VaultFile)
	}
	if strings.TrimSpace(entry.FileID) == "" {
		return "", errors.New("vault entry missing file id")
	}
	vaultRel := filepath.Join("files", entry.FileID[:2], entry.FileID+EncryptedExt)
	return AbsoluteVaultFilePath(ctx, vaultRel)
}

func SortedVaultEntryKeys(manifest VaultManifest) []string {
	keys := make([]string, 0, len(manifest.Entries))
	for k := range manifest.Entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
