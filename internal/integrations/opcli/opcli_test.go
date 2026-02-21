package opcli

import (
	"path/filepath"
	"testing"

	"secrets-vault/internal/domain"
)

func TestSanitizeTag(t *testing.T) {
	if got := sanitizeTag(" My Host.Name "); got != "my-host.name" {
		t.Fatalf("unexpected sanitized tag: %q", got)
	}
	if got := sanitizeTag("***"); got != "" {
		t.Fatalf("expected empty sanitized tag, got %q", got)
	}
}

func TestMetadataTagListIncludesProjectAndHost(t *testing.T) {
	metadata := DocumentMetadata{ProjectID: "abcd1234", Machine: "devbox", User: "josh"}
	tags := metadataTagList(metadata)

	for _, want := range []string{"secretvault", "source:secretvault", "project:abcd1234", "host:devbox", "user:josh"} {
		if !containsCSVTag(tags, want) {
			t.Fatalf("expected tag %q in %q", want, tags)
		}
	}
}

func TestBuildDocumentMetadata(t *testing.T) {
	project := t.TempDir()
	path := filepath.Join(project, "secrets", "api.txt")

	ctx := domain.ProjectContext{ProjectID: "p123", ProjectPath: project}
	metadata, err := BuildDocumentMetadata(ctx, path)
	if err != nil {
		t.Fatalf("build metadata: %v", err)
	}
	if metadata.ProjectID != "p123" {
		t.Fatalf("project id mismatch: %q", metadata.ProjectID)
	}
	if metadata.RelativePath != filepath.Join("secrets", "api.txt") {
		t.Fatalf("relative path mismatch: %q", metadata.RelativePath)
	}
	if metadata.Filename != "api.txt" {
		t.Fatalf("filename mismatch: %q", metadata.Filename)
	}
}

func containsCSVTag(csv, want string) bool {
	parts := splitCSV(csv)
	for _, part := range parts {
		if part == want {
			return true
		}
	}
	return false
}

func splitCSV(csv string) []string {
	if csv == "" {
		return nil
	}
	out := make([]string, 0)
	cur := ""
	for i := 0; i < len(csv); i++ {
		if csv[i] == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(csv[i])
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
