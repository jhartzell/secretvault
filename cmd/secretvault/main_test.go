package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseInstallArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		target   string
		mode     string
		wantErr  bool
		errMatch string
	}{
		{name: "default mode", args: []string{"opencode"}, target: "opencode", mode: hookModeStrict},
		{name: "default claude mode", args: []string{"claude"}, target: "claude", mode: hookModeStable},
		{name: "explicit strict mode", args: []string{"--mode", "strict", "claude"}, target: "claude", mode: hookModeStrict},
		{name: "equals style mode", args: []string{"--mode=stable-dev", "opencode"}, target: "opencode", mode: hookModeStable},
		{name: "missing target", args: []string{"--mode", "strict"}, wantErr: true, errMatch: "missing install target"},
		{name: "invalid mode", args: []string{"--mode", "bad", "opencode"}, wantErr: true, errMatch: "invalid mode"},
		{name: "unknown flag", args: []string{"--unknown", "opencode"}, wantErr: true, errMatch: "unknown flag"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, mode, err := parseInstallArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				if tc.errMatch != "" && !strings.Contains(err.Error(), tc.errMatch) {
					t.Fatalf("expected error containing %q, got %q", tc.errMatch, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if target != tc.target {
				t.Fatalf("target mismatch: got %q want %q", target, tc.target)
			}
			if mode != tc.mode {
				t.Fatalf("mode mismatch: got %q want %q", mode, tc.mode)
			}
		})
	}
}

func TestParseRunCommandArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{name: "empty", args: nil, want: nil},
		{name: "plain args", args: []string{"terraform", "plan"}, want: []string{"terraform", "plan"}},
		{name: "double dash", args: []string{"--", "npm", "run", "dev"}, want: []string{"npm", "run", "dev"}},
		{name: "trailing double dash", args: []string{"--"}, want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRunCommandArgs(tc.args)
			if len(got) != len(tc.want) {
				t.Fatalf("length mismatch: got %v want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("value mismatch at %d: got %q want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestNormalizeRoots(t *testing.T) {
	if got := normalizeRoots(nil); len(got) != 1 || got[0] != "." {
		t.Fatalf("unexpected default roots: %v", got)
	}
	if got := normalizeRoots([]string{"", "   "}); len(got) != 1 || got[0] != "." {
		t.Fatalf("unexpected roots for empty args: %v", got)
	}
	got := normalizeRoots([]string{"./a", "b"})
	if len(got) != 2 || got[0] != "./a" || got[1] != "b" {
		t.Fatalf("unexpected normalized roots: %v", got)
	}
}

func TestHookScriptAndInstallHookPair(t *testing.T) {
	t.Run("hook script includes mode and command", func(t *testing.T) {
		s := hookScript("lock", hookModeStable)
		if !strings.Contains(s, "secretvault lock") {
			t.Fatalf("hook script missing lock command: %s", s)
		}
		if !strings.Contains(s, "secretvault hook mode: stable-dev") {
			t.Fatalf("hook script missing mode comment: %s", s)
		}
	})

	t.Run("install hook stable and strict", func(t *testing.T) {
		dir := t.TempDir()
		pre := filepath.Join(dir, "pre")
		post := filepath.Join(dir, "post")

		if err := installHookPair("opencode", pre, post, hookModeStable); err != nil {
			t.Fatalf("install stable hook pair: %v", err)
		}

		postScriptPath := filepath.Join(post, "secretvault-unlock.sh")
		stablePostBytes, err := os.ReadFile(postScriptPath)
		if err != nil {
			t.Fatalf("read stable post hook: %v", err)
		}
		if !strings.Contains(string(stablePostBytes), "secretvault lock") {
			t.Fatalf("stable mode post hook should lock")
		}

		if err := installHookPair("opencode", pre, post, hookModeStrict); err != nil {
			t.Fatalf("install strict hook pair: %v", err)
		}
		strictPostBytes, err := os.ReadFile(postScriptPath)
		if err != nil {
			t.Fatalf("read strict post hook: %v", err)
		}
		if !strings.Contains(string(strictPostBytes), "secretvault unlock") {
			t.Fatalf("strict mode post hook should unlock")
		}
	})
}

func TestEncryptDecryptPayloadRoundTrip(t *testing.T) {
	keyHash := sha256.Sum256([]byte("payload-test-key"))
	key := keyHash[:]
	plaintext := []byte("super secret payload")

	payload, err := encryptPayload(plaintext, key, 0o640)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}

	gotPlaintext, mode, err := decryptPayload(payload, key)
	if err != nil {
		t.Fatalf("decrypt payload: %v", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
	if mode.Perm() != 0o640 {
		t.Fatalf("mode mismatch: got %o want %o", mode.Perm(), 0o640)
	}

	bad := append([]byte(nil), payload...)
	copy(bad[:len(magicHeader)], []byte("NOTMAGIC"))
	if _, _, err := decryptPayload(bad, key); err == nil {
		t.Fatalf("expected error for bad payload header")
	}
}

func TestEncryptDecryptFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "terraform.tfvars")
	content := []byte("db_password = \"abc\"\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod input: %v", err)
	}

	keyHash := sha256.Sum256([]byte("file-test-key"))
	key := keyHash[:]

	encryptedPath, mode, err := encryptFile(path, key)
	if err != nil {
		t.Fatalf("encrypt file: %v", err)
	}
	if mode.Perm() != 0o640 {
		t.Fatalf("original mode mismatch: got %o want %o", mode.Perm(), 0o640)
	}
	if fileExists(path) {
		t.Fatalf("plaintext should be removed after encryption")
	}
	if !fileExists(encryptedPath) {
		t.Fatalf("encrypted file should exist")
	}

	decryptedPath, err := decryptFile(encryptedPath, key)
	if err != nil {
		t.Fatalf("decrypt file: %v", err)
	}
	if decryptedPath != path {
		t.Fatalf("decrypted path mismatch: got %q want %q", decryptedPath, path)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, content) {
		t.Fatalf("restored content mismatch")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat restored: %v", err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("restored mode mismatch: got %o want %o", st.Mode().Perm(), 0o640)
	}
}

func TestRestorePlaintextFromEncrypted(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "a.env.svault")
	target := filepath.Join(dir, "a.env")

	keyHash := sha256.Sum256([]byte("restore-key"))
	key := keyHash[:]
	plain := []byte("API_KEY=xyz\n")
	payload, err := encryptPayload(plain, key, 0o600)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	if err := os.WriteFile(source, payload, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := restorePlaintextFromEncrypted(source, target, key, 0o644, false); err != nil {
		t.Fatalf("restore plaintext: %v", err)
	}
	if !fileExists(target) {
		t.Fatalf("target file should exist")
	}

	if err := restorePlaintextFromEncrypted(source, target, key, 0o644, false); err == nil {
		t.Fatalf("expected overwrite protection error")
	}

	if err := restorePlaintextFromEncrypted(source, target, key, 0o644, true); err != nil {
		t.Fatalf("restore with force: %v", err)
	}
}

func TestSensitiveFileScanAndEncryptedScan(t *testing.T) {
	dir := t.TempDir()
	paths := map[string]string{
		".env":                             "A=1\n",
		"backend.tfvars":                   "db_password=\"x\"\n",
		"secrets/token.txt":                "token=abc\n",
		"config.txt":                       "password = hunter2\n",
		"CLAUDE.md.pre-absorb":             "token=old-backup\n",
		"scripts/add-secret":               "token=example\n",
		"main.tf":                          "secret = var.some_value\n",
		"notes.txt":                        "hello\n",
		".terraform/providers/x/README.md": "secret = not-a-secret-example\n",
		"node_modules/.env":                "SHOULD_NOT_BE_FOUND=1\n",
		"node_modules/secret.tfvars":       "db=1\n",
	}

	for rel, data := range paths {
		abs := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(abs, []byte(data), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	targets, err := findSensitiveFiles([]string{dir})
	if err != nil {
		t.Fatalf("find sensitive files: %v", err)
	}
	got := toSet(targets)

	mustContain := []string{
		filepath.Join(dir, ".env"),
		filepath.Join(dir, "backend.tfvars"),
		filepath.Join(dir, "secrets", "token.txt"),
		filepath.Join(dir, "config.txt"),
	}
	for _, p := range mustContain {
		if _, ok := got[p]; !ok {
			t.Fatalf("expected sensitive file missing: %s", p)
		}
	}

	mustNotContain := []string{
		filepath.Join(dir, "CLAUDE.md.pre-absorb"),
		filepath.Join(dir, "scripts", "add-secret"),
		filepath.Join(dir, "main.tf"),
		filepath.Join(dir, ".terraform", "providers", "x", "README.md"),
		filepath.Join(dir, "notes.txt"),
		filepath.Join(dir, "node_modules", ".env"),
		filepath.Join(dir, "node_modules", "secret.tfvars"),
	}
	for _, p := range mustNotContain {
		if _, ok := got[p]; ok {
			t.Fatalf("unexpected sensitive file detected: %s", p)
		}
	}

	if err := os.WriteFile(filepath.Join(dir, "keep.svault"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write keep.svault: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node_modules", "skip.svault"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write skip.svault: %v", err)
	}

	encTargets, err := findEncryptedFiles([]string{dir})
	if err != nil {
		t.Fatalf("find encrypted files: %v", err)
	}
	encSet := toSet(encTargets)
	if _, ok := encSet[filepath.Join(dir, "keep.svault")]; !ok {
		t.Fatalf("expected encrypted file not found")
	}
	if _, ok := encSet[filepath.Join(dir, "node_modules", "skip.svault")]; ok {
		t.Fatalf("encrypted file inside ignored directory should be skipped")
	}
}

func TestManifestUpsertAnnotateAndRestoreSource(t *testing.T) {
	projectDir := t.TempDir()
	vaultHome := t.TempDir()

	withEnv(t, "SECRETVAULT_HOME", vaultHome)
	withChdir(t, projectDir)

	ctx, err := loadProjectContext()
	if err != nil {
		t.Fatalf("load project context: %v", err)
	}

	plainPath := filepath.Join(projectDir, "backend.tfvars")
	plainData := []byte("region = \"us-east-1\"\n")
	if err := os.WriteFile(plainPath, plainData, 0o600); err != nil {
		t.Fatalf("write plain file: %v", err)
	}

	keyHash := sha256.Sum256([]byte("manifest-key"))
	key := keyHash[:]
	encryptedPath, originalMode, err := encryptFile(plainPath, key)
	if err != nil {
		t.Fatalf("encrypt file: %v", err)
	}

	if err := upsertVaultEntry(ctx, plainPath, encryptedPath, originalMode); err != nil {
		t.Fatalf("upsert vault entry: %v", err)
	}

	absPlain, _ := filepath.Abs(plainPath)
	manifest, _, err := loadVaultManifest(ctx)
	if err != nil {
		t.Fatalf("load vault manifest: %v", err)
	}
	entry, ok := manifest.Entries[absPlain]
	if !ok {
		t.Fatalf("expected manifest entry for %s", absPlain)
	}
	if entry.RelativePath != "backend.tfvars" {
		t.Fatalf("relative path mismatch: got %q", entry.RelativePath)
	}
	backupPath, err := entryVaultBackupPath(ctx, entry)
	if err != nil {
		t.Fatalf("entry backup path: %v", err)
	}
	if !fileExists(backupPath) {
		t.Fatalf("vault backup file missing: %s", backupPath)
	}

	if err := annotateVaultEntryWithOnePassword(ctx, plainPath, "Private", "doc-123", "title-1", "abc"); err != nil {
		t.Fatalf("annotate vault entry: %v", err)
	}
	manifest, _, err = loadVaultManifest(ctx)
	if err != nil {
		t.Fatalf("reload vault manifest: %v", err)
	}
	entry = manifest.Entries[absPlain]
	if entry.OnePasswordDocument != "doc-123" || entry.OnePasswordVault != "Private" {
		t.Fatalf("1Password metadata not persisted: %+v", entry)
	}

	if err := os.Remove(encryptedPath); err != nil {
		t.Fatalf("remove project encrypted copy: %v", err)
	}
	targetPath := resolveEntryTargetPath(ctx, entry)
	source, found, err := resolveLocalRestoreSource(ctx, entry, targetPath)
	if err != nil {
		t.Fatalf("resolve local restore source: %v", err)
	}
	if !found {
		t.Fatalf("expected fallback source from vault backup")
	}
	if source != backupPath {
		t.Fatalf("expected backup path source, got %q want %q", source, backupPath)
	}
}

func TestSelectRestoreEntries(t *testing.T) {
	projectDir := t.TempDir()
	ctx := projectContext{ProjectPath: projectDir}

	absA := filepath.Join(projectDir, "a.env")
	absB := filepath.Join(projectDir, "b.tfvars")
	if err := os.WriteFile(absA, []byte("A=1\n"), 0o600); err != nil {
		t.Fatalf("write existing plaintext: %v", err)
	}

	manifest := vaultManifest{Entries: map[string]vaultEntry{
		absA: {AbsolutePath: absA, RelativePath: "a.env", Filename: "a.env"},
		absB: {AbsolutePath: absB, RelativePath: "b.tfvars", Filename: "b.tfvars"},
	}}

	missingOnly := selectRestoreEntries(ctx, manifest, nil, false)
	if len(missingOnly) != 1 || missingOnly[0].AbsolutePath != absB {
		t.Fatalf("expected only missing file entry, got %+v", missingOnly)
	}

	all := selectRestoreEntries(ctx, manifest, nil, true)
	if len(all) != 2 {
		t.Fatalf("expected all entries, got %+v", all)
	}

	byName := selectRestoreEntries(ctx, manifest, []string{"a.env", "b.tfvars", "a.env"}, false)
	if len(byName) != 2 {
		t.Fatalf("expected deduped explicit entries, got %+v", byName)
	}
}

func TestProjectRelativePathAndHash(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "a", "b", "file.env")
	outside := filepath.Join(filepath.Dir(root), "outside.env")

	rel, ok := projectRelativePath(root, inside)
	if !ok || rel != filepath.Join("a", "b", "file.env") {
		t.Fatalf("unexpected relative path: rel=%q ok=%v", rel, ok)
	}

	if _, ok := projectRelativePath(root, outside); ok {
		t.Fatalf("outside path should not be project-relative")
	}

	h := hashPathID("abc")
	if len(h) != 64 {
		t.Fatalf("expected sha256 hex length 64, got %d", len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		t.Fatalf("hash should be valid hex: %v", err)
	}
}

func TestExtractOnePasswordDocumentID(t *testing.T) {
	if got := extractOnePasswordDocumentID([]byte(`{"id":"doc1"}`)); got != "doc1" {
		t.Fatalf("object parse failed: got %q", got)
	}
	if got := extractOnePasswordDocumentID([]byte(`[{"uuid":"doc2"}]`)); got != "doc2" {
		t.Fatalf("array parse failed: got %q", got)
	}
	if got := extractOnePasswordDocumentID([]byte("doc3")); got != "doc3" {
		t.Fatalf("fallback parse failed: got %q", got)
	}
}

func TestOnePasswordTitleForPath(t *testing.T) {
	ctx := projectContext{ProjectID: "abcd1234", ProjectPath: "/tmp/project"}
	title := onePasswordTitleForPath(ctx, "/tmp/project/secrets/backend.tfvars")
	titleNorm := filepath.ToSlash(title)
	if !strings.Contains(titleNorm, "abcd1234") || !strings.Contains(titleNorm, "secrets/backend.tfvars") {
		t.Fatalf("unexpected title: %q", title)
	}
}

func toSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		out[v] = struct{}{}
	}
	return out
}

func withEnv(t *testing.T, key, value string) {
	t.Helper()
	old, had := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("setenv %s: %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

func withChdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(old)
	})
}
