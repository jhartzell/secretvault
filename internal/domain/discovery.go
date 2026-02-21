package domain

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func FindSensitiveFiles(roots []string) ([]string, error) {
	result := make(map[string]struct{})

	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}

		if !info.IsDir() {
			abs, err := filepath.Abs(root)
			if err != nil {
				return nil, err
			}
			ok, err := IsSensitiveFile(abs)
			if err != nil {
				return nil, err
			}
			if ok {
				result[abs] = struct{}{}
			}
			continue
		}

		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			name := strings.ToLower(d.Name())
			if d.IsDir() {
				if _, skip := IgnoredDirNames[name]; skip {
					return filepath.SkipDir
				}
				return nil
			}

			if !d.Type().IsRegular() {
				return nil
			}
			if strings.HasSuffix(strings.ToLower(path), EncryptedExt) {
				return nil
			}

			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			ok, err := IsSensitiveFile(abs)
			if err != nil {
				return err
			}
			if ok {
				result[abs] = struct{}{}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return SortedKeys(result), nil
}

func FindEncryptedFiles(roots []string) ([]string, error) {
	result := make(map[string]struct{})

	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}

		if !info.IsDir() {
			if strings.HasSuffix(strings.ToLower(root), EncryptedExt) {
				abs, err := filepath.Abs(root)
				if err != nil {
					return nil, err
				}
				result[abs] = struct{}{}
			}
			continue
		}

		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			name := strings.ToLower(d.Name())
			if d.IsDir() {
				if _, skip := IgnoredDirNames[name]; skip {
					return filepath.SkipDir
				}
				return nil
			}

			if !d.Type().IsRegular() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(path), EncryptedExt) {
				return nil
			}

			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			result[abs] = struct{}{}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return SortedKeys(result), nil
}

func IsSensitiveFile(path string) (bool, error) {
	base := strings.ToLower(filepath.Base(path))
	if _, ok := SensitiveExactNames[base]; ok {
		return true, nil
	}
	if strings.HasPrefix(base, ".env.") {
		return true, nil
	}
	for _, suffix := range SensitiveSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true, nil
		}
	}

	if hasSensitiveDir(path) {
		return true, nil
	}

	return looksSensitiveByContent(path)
}

func hasSensitiveDir(path string) bool {
	parts := strings.Split(strings.ToLower(filepath.Clean(path)), string(os.PathSeparator))
	for _, part := range parts {
		if _, ok := SensitiveDirNames[part]; ok {
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

	return SecretContentPattern.Match(buf[:n]), nil
}
