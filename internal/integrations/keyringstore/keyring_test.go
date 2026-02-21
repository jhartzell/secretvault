package keyringstore

import (
	"bytes"
	"os"
	"testing"

	"github.com/zalando/go-keyring"

	"secrets-vault/internal/domain"
)

func TestFileFallbackSaveLoadClearProjectKey(t *testing.T) {
	t.Setenv("SECRETVAULT_KEYRING_FALLBACK", "file")
	t.Setenv("SECRETVAULT_HOME", t.TempDir())

	ctx := domain.ProjectContext{
		ProjectID:   "test-project",
		ProjectPath: "/tmp/test-project",
		KeyID:       "test-key-id",
	}

	key := bytes.Repeat([]byte{0x7f}, 32)
	if err := SaveProjectKey(ctx, key); err != nil {
		t.Fatalf("save key: %v", err)
	}

	keyPath, err := fallbackKeyPath(ctx)
	if err != nil {
		t.Fatalf("fallback key path: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected fallback key file to exist: %v", err)
	}

	metadataPath, err := fallbackMetadataPath(ctx)
	if err != nil {
		t.Fatalf("fallback metadata path: %v", err)
	}
	if _, err := os.Stat(metadataPath); err != nil {
		t.Fatalf("expected fallback metadata file to exist: %v", err)
	}

	loaded, err := LoadProjectKey(ctx)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	if !bytes.Equal(loaded, key) {
		t.Fatalf("loaded key mismatch")
	}

	if err := ClearProjectKey(ctx); err != nil {
		t.Fatalf("clear key: %v", err)
	}

	_, err = LoadProjectKey(ctx)
	if err == nil {
		t.Fatalf("expected not found after clear")
	}
	if err != keyring.ErrNotFound {
		t.Fatalf("expected keyring.ErrNotFound, got %v", err)
	}
}
