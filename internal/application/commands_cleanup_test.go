package application

import (
	"testing"

	"secrets-vault/internal/domain"
)

func TestCollectCleanupTargets(t *testing.T) {
	manifest := domain.VaultManifest{Entries: map[string]domain.VaultEntry{
		"/tmp/a.env": {
			AbsolutePath:        "/tmp/a.env",
			OnePasswordDocument: "doc-a",
		},
		"/tmp/b.env": {
			AbsolutePath: "/tmp/b.env",
		},
		"/tmp/c.env": {
			AbsolutePath:        "/tmp/c.env",
			OnePasswordDocument: "doc-c",
		},
	}}

	targets := collectCleanupTargets(manifest)
	if len(targets) != 2 {
		t.Fatalf("expected 2 cleanup targets, got %d", len(targets))
	}
	if targets[0].Entry.OnePasswordDocument != "doc-a" {
		t.Fatalf("unexpected first doc: %q", targets[0].Entry.OnePasswordDocument)
	}
	if targets[1].Entry.OnePasswordDocument != "doc-c" {
		t.Fatalf("unexpected second doc: %q", targets[1].Entry.OnePasswordDocument)
	}
}

func TestClearOnePasswordMetadata(t *testing.T) {
	entry := domain.VaultEntry{
		OnePasswordVault:    "Private",
		OnePasswordDocument: "doc-123",
		OnePasswordTitle:    "title",
		ChecksumSHA256:      "abc",
		AbsorbedAt:          "2026-01-01T00:00:00Z",
		Filename:            "a.env",
	}

	cleared := clearOnePasswordMetadata(entry)
	if cleared.OnePasswordVault != "" {
		t.Fatalf("expected empty vault metadata")
	}
	if cleared.OnePasswordDocument != "" {
		t.Fatalf("expected empty document metadata")
	}
	if cleared.OnePasswordTitle != "" {
		t.Fatalf("expected empty title metadata")
	}
	if cleared.ChecksumSHA256 != "" {
		t.Fatalf("expected empty checksum metadata")
	}
	if cleared.AbsorbedAt != "" {
		t.Fatalf("expected empty absorbed timestamp")
	}
	if cleared.Filename != "a.env" {
		t.Fatalf("non-1password metadata should remain unchanged")
	}
}
