package opcli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"secrets-vault/internal/domain"
)

func IsAuthenticated() (bool, error) {
	cmd := exec.Command("op", "account", "list", "--format", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	var accounts []map[string]any
	if err := json.Unmarshal(out, &accounts); err != nil {
		return false, err
	}
	return len(accounts) > 0, nil
}

func UploadFile(path, vaultName, title string) (string, error) {
	args := []string{"document", "create", path, "--vault", vaultName, "--title", title, "--format", "json"}
	cmd := exec.Command("op", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("op document create failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	id := ExtractDocumentID(out)
	if id == "" {
		return "", fmt.Errorf("could not parse document id from op output: %s", strings.TrimSpace(string(out)))
	}
	return id, nil
}

func ExtractDocumentID(out []byte) string {
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err == nil {
		for _, key := range []string{"id", "uuid", "documentId"} {
			if v, ok := obj[key].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	var arr []map[string]any
	if err := json.Unmarshal(out, &arr); err == nil {
		for _, item := range arr {
			for _, key := range []string{"id", "uuid", "documentId"} {
				if v, ok := item[key].(string); ok && strings.TrimSpace(v) != "" {
					return strings.TrimSpace(v)
				}
			}
		}
	}
	return strings.TrimSpace(string(out))
}

func RestoreDocument(entry domain.VaultEntry, targetPath string, mode fs.FileMode, force bool) error {
	if !HasCommand("op") {
		return fmt.Errorf("1Password CLI (op) is not installed")
	}
	authed, err := IsAuthenticated()
	if err != nil {
		return err
	}
	if !authed {
		return fmt.Errorf("1Password CLI is not authenticated")
	}

	if domain.FileExists(targetPath) {
		if !force {
			return fmt.Errorf("target already exists: %s", targetPath)
		}
		if err := os.Remove(targetPath); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return err
	}

	args := []string{"document", "get", entry.OnePasswordDocument, "--out-file", targetPath}
	if strings.TrimSpace(entry.OnePasswordVault) != "" {
		args = append(args, "--vault", entry.OnePasswordVault)
	}
	cmd := exec.Command("op", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("op document get failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	if mode == 0 {
		mode = 0o600
	}
	return os.Chmod(targetPath, mode)
}

func AnnotateVaultEntry(ctx domain.ProjectContext, originalPath, vaultName, documentID, title, checksum string) error {
	absOriginal, err := filepath.Abs(originalPath)
	if err != nil {
		return err
	}

	manifest, manifestPath, err := domain.LoadVaultManifest(ctx)
	if err != nil {
		return err
	}

	entry, ok := manifest.Entries[absOriginal]
	if !ok {
		return fmt.Errorf("vault entry not found for %s", absOriginal)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	entry.OnePasswordVault = vaultName
	entry.OnePasswordDocument = documentID
	entry.OnePasswordTitle = title
	entry.ChecksumSHA256 = checksum
	entry.AbsorbedAt = now
	manifest.Entries[absOriginal] = entry
	manifest.UpdatedAt = now

	return domain.SaveVaultManifest(manifestPath, manifest)
}

func FileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func TitleForPath(ctx domain.ProjectContext, absolutePath string) string {
	if rel, ok := domain.ProjectRelativePath(ctx.ProjectPath, absolutePath); ok {
		return fmt.Sprintf("secretvault %s %s", ctx.ProjectID, rel)
	}
	return fmt.Sprintf("secretvault %s %s", ctx.ProjectID, filepath.Base(absolutePath))
}

func HasCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
