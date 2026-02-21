package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"secrets-vault/internal/domain"
)

func normalizeRoots(args []string) []string {
	return domain.NormalizeRoots(args)
}

func findSensitiveFiles(roots []string) ([]string, error) {
	return domain.FindSensitiveFiles(roots)
}

func findEncryptedFiles(roots []string) ([]string, error) {
	return domain.FindEncryptedFiles(roots)
}

func isSensitiveFile(path string) (bool, error) {
	return domain.IsSensitiveFile(path)
}

func hasSensitiveDir(path string) bool {
	parts := strings.Split(strings.ToLower(filepath.Clean(path)), string(os.PathSeparator))
	for _, part := range parts {
		if _, ok := sensitiveDirNames[part]; ok {
			return true
		}
	}
	return false
}

func looksSensitiveByContent(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if info.Size() == 0 || info.Size() > 1<<20 {
		return false, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, 4096)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if n == 0 {
		return false, nil
	}

	return secretContentPattern.Match(buf[:n]), nil
}

func sortedKeys(in map[string]struct{}) []string {
	return domain.SortedKeys(in)
}
