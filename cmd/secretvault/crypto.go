package main

import (
	"io/fs"

	"secrets-vault/internal/domain"
)

func encryptPayload(plaintext []byte, key []byte, mode fs.FileMode) ([]byte, error) {
	return domain.EncryptPayload(plaintext, key, mode)
}

func decryptPayload(payload []byte, key []byte) ([]byte, fs.FileMode, error) {
	return domain.DecryptPayload(payload, key)
}

func encryptFile(path string, key []byte) (string, fs.FileMode, error) {
	return domain.EncryptFile(path, key)
}

func decryptFile(path string, key []byte) (string, error) {
	return domain.DecryptFile(path, key)
}

func restorePlaintextFromEncrypted(sourcePath, targetPath string, key []byte, fallbackMode fs.FileMode, force bool) error {
	return domain.RestorePlaintextFromEncrypted(sourcePath, targetPath, key, fallbackMode, force)
}

func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	return domain.WriteAtomic(path, data, mode)
}
