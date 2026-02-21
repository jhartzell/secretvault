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
	if err := keyring.Set(ServiceName, ctx.KeyID, base64.StdEncoding.EncodeToString(key)); err != nil {
		return err
	}
	return saveProjectKeyMetadata(ctx)
}

func LoadProjectKey(ctx domain.ProjectContext) ([]byte, error) {
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
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return keyring.Set(ServiceName, ctx.KeyID+metadataKeySuffix, string(raw))
}
