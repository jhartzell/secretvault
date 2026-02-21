package keyringstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"

	"secrets-vault/internal/domain"
)

const ServiceName = "secrets-vault-cli"
const metadataKeySuffix = "-metadata"

type KeyMetadata struct {
	ProjectID   string `json:"project_id"`
	ProjectPath string `json:"project_path"`
	Machine     string `json:"machine,omitempty"`
	User        string `json:"user,omitempty"`
	RecordedAt  string `json:"recorded_at"`
}

func KeyFromInput(value string, generate bool) ([]byte, error) {
	if generate {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		return k, nil
	}

	if strings.TrimSpace(value) == "" {
		v, err := PromptForKey()
		if err != nil {
			return nil, err
		}
		value = v
	}

	if strings.TrimSpace(value) == "" {
		return nil, errors.New("key value cannot be empty")
	}

	h := sha256.Sum256([]byte(value))
	out := make([]byte, 32)
	copy(out, h[:])
	return out, nil
}

func PromptForKey() (string, error) {
	fmt.Print("Enter encryption key/passphrase: ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return string(b), err
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func SaveProjectKey(ctx domain.ProjectContext, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("invalid key length: got %d, want 32", len(key))
	}
	if shouldUseFileFallback() {
		if err := saveProjectKeyToFile(ctx, key); err != nil {
			return err
		}
		return saveProjectKeyMetadataToFile(ctx)
	}
	if err := keyring.Set(ServiceName, ctx.KeyID, base64.StdEncoding.EncodeToString(key)); err != nil {
		return err
	}
	return saveProjectKeyMetadata(ctx)
}

func LoadProjectKey(ctx domain.ProjectContext) ([]byte, error) {
	if shouldUseFileFallback() {
		return loadProjectKeyFromFile(ctx)
	}
	raw, err := keyring.Get(ServiceName, ctx.KeyID)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("stored key has invalid format")
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("stored key has invalid length: %d", len(b))
	}
	return b, nil
}

func ClearProjectKey(ctx domain.ProjectContext) error {
	if shouldUseFileFallback() {
		return clearProjectKeyFileFallback(ctx)
	}
	if err := keyring.Delete(ServiceName, ctx.KeyID); err != nil {
		return err
	}
	if err := keyring.Delete(ServiceName, ctx.KeyID+metadataKeySuffix); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}

func Fingerprint(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:6])
}

func saveProjectKeyMetadata(ctx domain.ProjectContext) error {
	payload, err := projectKeyMetadataPayload(ctx)
	if err != nil {
		return err
	}
	return keyring.Set(ServiceName, ctx.KeyID+metadataKeySuffix, string(payload))
}

func saveProjectKeyToFile(ctx domain.ProjectContext, key []byte) error {
	keyPath, err := fallbackKeyPath(ctx)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(key))
	return domain.WriteAtomic(keyPath, encoded, 0o600)
}

func loadProjectKeyFromFile(ctx domain.ProjectContext) ([]byte, error) {
	keyPath, err := fallbackKeyPath(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, keyring.ErrNotFound
		}
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, errors.New("stored key has invalid format")
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("stored key has invalid length: %d", len(b))
	}
	return b, nil
}

func saveProjectKeyMetadataToFile(ctx domain.ProjectContext) error {
	metadataPath, err := fallbackMetadataPath(ctx)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(metadataPath), 0o700); err != nil {
		return err
	}
	payload, err := projectKeyMetadataPayload(ctx)
	if err != nil {
		return err
	}
	return domain.WriteAtomic(metadataPath, payload, 0o600)
}

func projectKeyMetadataPayload(ctx domain.ProjectContext) ([]byte, error) {
	hostname, _ := os.Hostname()
	user := strings.TrimSpace(os.Getenv("USER"))
	if user == "" {
		user = strings.TrimSpace(os.Getenv("USERNAME"))
	}

	payload := KeyMetadata{
		ProjectID:   ctx.ProjectID,
		ProjectPath: ctx.ProjectPath,
		Machine:     hostname,
		User:        user,
		RecordedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	return json.Marshal(payload)
}

func clearProjectKeyFileFallback(ctx domain.ProjectContext) error {
	keyPath, err := fallbackKeyPath(ctx)
	if err != nil {
		return err
	}
	if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	metadataPath, err := fallbackMetadataPath(ctx)
	if err != nil {
		return err
	}
	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func fallbackKeyPath(ctx domain.ProjectContext) (string, error) {
	return domain.AbsoluteVaultFilePath(ctx, "keyring-fallback.key")
}

func fallbackMetadataPath(ctx domain.ProjectContext) (string, error) {
	return domain.AbsoluteVaultFilePath(ctx, "keyring-fallback-metadata.json")
}

func shouldUseFileFallback() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("SECRETVAULT_KEYRING_FALLBACK")), "file")
}
