package application

import "testing"

func TestMergeFileTargets(t *testing.T) {
	got := mergeFileTargets(
		[]string{"/tmp/b", "/tmp/a", ""},
		[]string{"/tmp/c", "/tmp/a", "  ", "/tmp/b"},
	)

	if len(got) != 3 {
		t.Fatalf("expected 3 merged targets, got %d", len(got))
	}
	if got[0] != "/tmp/a" || got[1] != "/tmp/b" || got[2] != "/tmp/c" {
		t.Fatalf("unexpected merged targets: %+v", got)
	}
}

func TestDefaultValue(t *testing.T) {
	if got := defaultValue("", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback, got %q", got)
	}
	if got := defaultValue("custom", "fallback"); got != "custom" {
		t.Fatalf("expected custom, got %q", got)
	}
}
