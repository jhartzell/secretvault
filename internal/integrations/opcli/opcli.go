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
	"regexp"
	"runtime"
	"strings"
	"time"

	"secrets-vault/internal/domain"
)

var nonTagChars = regexp.MustCompile(`[^a-z0-9._-]+`)

type DocumentMetadata struct {
	ProjectID    string
	ProjectPath  string
	RelativePath string
	AbsolutePath string
	Directory    string
	Filename     string
	Machine      string
	User         string
	AbsorbedAt   string
}

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

func HasConfiguredAccount() (bool, error) {
	cmd := exec.Command("op", "account", "list", "--format", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.ToLower(string(out))
		if strings.Contains(msg, "no accounts configured") {
			return false, nil
		}
		return false, fmt.Errorf("could not list 1password accounts: %s", strings.TrimSpace(string(out)))
	}

	var accounts []map[string]any
	if err := json.Unmarshal(out, &accounts); err != nil {
		return false, err
	}
	return len(accounts) > 0, nil
}

func UploadFile(path, vaultName, title string) (string, error) {
	return UploadFileWithMetadata(path, vaultName, title, DocumentMetadata{})
}

func UploadFileWithMetadata(path, vaultName, title string, metadata DocumentMetadata) (string, error) {
	args := []string{"document", "create", path, "--vault", vaultName, "--title", title, "--format", "json"}
	tags := metadataTagList(metadata)
	if tags != "" {
		args = append(args, "--tags", tags)
	}
	cmd := exec.Command("op", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("op document create failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	id := ExtractDocumentID(out)
	if id == "" {
		return "", fmt.Errorf("could not parse document id from op output: %s", strings.TrimSpace(string(out)))
	}
	if !metadata.IsZero() {
		if err := applyDocumentMetadata(id, vaultName, metadata); err != nil {
			return "", err
		}
	}
	return id, nil
}

func DeleteDocument(documentID, vaultName string) error {
	if strings.TrimSpace(documentID) == "" {
		return fmt.Errorf("missing 1password document id")
	}

	args := []string{"item", "delete", documentID}
	if strings.TrimSpace(vaultName) != "" {
		args = append(args, "--vault", vaultName)
	}
	cmd := exec.Command("op", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("op item delete failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
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

func BuildDocumentMetadata(ctx domain.ProjectContext, originalPath string) (DocumentMetadata, error) {
	absPath, err := filepath.Abs(originalPath)
	if err != nil {
		return DocumentMetadata{}, err
	}

	rel := ""
	if projectRel, ok := domain.ProjectRelativePath(ctx.ProjectPath, absPath); ok {
		rel = projectRel
	}

	machine, _ := os.Hostname()
	user := strings.TrimSpace(os.Getenv("USER"))
	if user == "" {
		user = strings.TrimSpace(os.Getenv("USERNAME"))
	}

	return DocumentMetadata{
		ProjectID:    ctx.ProjectID,
		ProjectPath:  ctx.ProjectPath,
		RelativePath: rel,
		AbsolutePath: absPath,
		Directory:    filepath.Dir(absPath),
		Filename:     filepath.Base(absPath),
		Machine:      machine,
		User:         user,
		AbsorbedAt:   time.Now().UTC().Format(time.RFC3339),
	}, nil
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

func (m DocumentMetadata) IsZero() bool {
	return strings.TrimSpace(m.ProjectID) == "" &&
		strings.TrimSpace(m.ProjectPath) == "" &&
		strings.TrimSpace(m.RelativePath) == "" &&
		strings.TrimSpace(m.AbsolutePath) == "" &&
		strings.TrimSpace(m.Directory) == "" &&
		strings.TrimSpace(m.Filename) == "" &&
		strings.TrimSpace(m.Machine) == "" &&
		strings.TrimSpace(m.User) == "" &&
		strings.TrimSpace(m.AbsorbedAt) == ""
}

func applyDocumentMetadata(documentID, vaultName string, metadata DocumentMetadata) error {
	assignments := make([]string, 0, 9)
	appendField := func(key, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		assignments = append(assignments, fmt.Sprintf("secretvault.%s[text]=%s", key, value))
	}

	appendField("project_id", metadata.ProjectID)
	appendField("project_path", metadata.ProjectPath)
	appendField("relative_path", metadata.RelativePath)
	appendField("absolute_path", metadata.AbsolutePath)
	appendField("directory", metadata.Directory)
	appendField("filename", metadata.Filename)
	appendField("machine", metadata.Machine)
	appendField("user", metadata.User)
	appendField("absorbed_at", metadata.AbsorbedAt)

	if len(assignments) == 0 {
		return nil
	}

	args := []string{"item", "edit", documentID}
	if strings.TrimSpace(vaultName) != "" {
		args = append(args, "--vault", vaultName)
	}
	args = append(args, assignments...)

	cmd := exec.Command("op", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("op item edit failed while writing secret metadata: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func metadataTagList(metadata DocumentMetadata) string {
	tags := []string{"secretvault", "source:secretvault", "os:" + sanitizeTag(runtime.GOOS)}
	appendTag := func(key, value string) {
		value = sanitizeTag(value)
		if value == "" {
			return
		}
		tags = append(tags, key+":"+value)
	}
	appendTag("project", metadata.ProjectID)
	appendTag("host", metadata.Machine)
	appendTag("user", metadata.User)

	joined := strings.Join(tags, ",")
	if len(joined) > 1000 {
		return strings.Join(tags[:3], ",")
	}
	return joined
}

func sanitizeTag(input string) string {
	trimmed := strings.ToLower(strings.TrimSpace(input))
	if trimmed == "" {
		return ""
	}
	clean := nonTagChars.ReplaceAllString(trimmed, "-")
	clean = strings.Trim(clean, "-._")
	if len(clean) > 64 {
		clean = clean[:64]
	}
	return clean
}
