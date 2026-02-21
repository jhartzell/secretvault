package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	EncryptedExt = ".svault"
)

var (
	MagicHeader = []byte("SVAULT01")

	SensitiveExactNames = map[string]struct{}{
		".env":                  {},
		".envrc":                {},
		"terraform.tfvars":      {},
		"terraform.tfvars.json": {},
		"id_rsa":                {},
		"id_ed25519":            {},
		"id_dsa":                {},
		"credentials":           {},
		"credentials.json":      {},
		"secrets.yml":           {},
		"secrets.yaml":          {},
		"secrets.json":          {},
		".npmrc":                {},
		".pypirc":               {},
	}

	SensitiveSuffixes = []string{
		".tfvars",
		".tfvars.json",
		".pem",
		".key",
		".p12",
		".pfx",
		".jks",
		".keystore",
		".ovpn",
		".asc",
		".gpg",
		".kubeconfig",
	}

	SensitiveDirNames = map[string]struct{}{
		"secrets":     {},
		"private":     {},
		"credentials": {},
		".aws":        {},
		".ssh":        {},
		".gnupg":      {},
	}

	IgnoredDirNames = map[string]struct{}{
		".git":         {},
		".terraform":   {},
		".svn":         {},
		".hg":          {},
		"node_modules": {},
		"dist":         {},
		"build":        {},
		"vendor":       {},
		".next":        {},
		".nuxt":        {},
		".idea":        {},
		".vscode":      {},
		".ai-sessions": {},
	}

	SecretContentPattern = regexp.MustCompile(`(?i)(api[_-]?key|token|password|private[_-]?key|secret[_-]?(key|token|value))\s*[:=]|aws_secret_access_key|-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----`)
)

type ProjectContext struct {
	ProjectPath string
	ProjectID   string
	KeyID       string
}

type VaultManifest struct {
	Version     int                   `json:"version"`
	ProjectID   string                `json:"project_id"`
	ProjectPath string                `json:"project_path"`
	UpdatedAt   string                `json:"updated_at"`
	Entries     map[string]VaultEntry `json:"entries"`
}

type VaultEntry struct {
	FileID               string `json:"file_id"`
	AbsolutePath         string `json:"absolute_path"`
	RelativePath         string `json:"relative_path,omitempty"`
	Directory            string `json:"directory"`
	Filename             string `json:"filename"`
	VaultFile            string `json:"vault_file"`
	ProjectEncryptedFile string `json:"project_encrypted_file"`
	LockedAt             string `json:"locked_at"`
	LastRestoredAt       string `json:"last_restored_at,omitempty"`
	OriginalMode         uint32 `json:"original_mode"`
	OnePasswordVault     string `json:"onepassword_vault,omitempty"`
	OnePasswordDocument  string `json:"onepassword_document,omitempty"`
	OnePasswordTitle     string `json:"onepassword_title,omitempty"`
	ChecksumSHA256       string `json:"checksum_sha256,omitempty"`
	AbsorbedAt           string `json:"absorbed_at,omitempty"`
}

func LoadProjectContext() (ProjectContext, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return ProjectContext{}, err
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return ProjectContext{}, err
	}
	h := sha256.Sum256([]byte(abs))
	projectID := hex.EncodeToString(h[:8])
	return ProjectContext{ProjectPath: abs, ProjectID: projectID, KeyID: "project-" + projectID}, nil
}

func NormalizeRoots(args []string) []string {
	if len(args) == 0 {
		return []string{"."}
	}
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.TrimSpace(arg) == "" {
			continue
		}
		out = append(out, arg)
	}
	if len(out) == 0 {
		return []string{"."}
	}
	return out
}

func FileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func YesNo(ok bool) string {
	if ok {
		return "yes"
	}
	return "no"
}

func ProjectRelativePath(projectRoot, absolutePath string) (string, bool) {
	rel, err := filepath.Rel(projectRoot, absolutePath)
	if err != nil {
		return "", false
	}
	rel = filepath.Clean(rel)
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return rel, true
}

func HashPathID(path string) string {
	h := sha256.Sum256([]byte(path))
	return hex.EncodeToString(h[:])
}

func SortedKeys(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
