package domain

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func EncryptPayload(plaintext []byte, key []byte, mode fs.FileMode) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	payload := make([]byte, 0, len(MagicHeader)+len(nonce)+4+len(ciphertext))
	payload = append(payload, MagicHeader...)
	payload = append(payload, nonce...)

	modeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(modeBytes, uint32(mode.Perm()))
	payload = append(payload, modeBytes...)
	payload = append(payload, ciphertext...)
	return payload, nil
}

func DecryptPayload(payload []byte, key []byte) ([]byte, fs.FileMode, error) {
	if len(payload) < len(MagicHeader)+12+4 {
		return nil, 0, errors.New("invalid encrypted payload")
	}
	if string(payload[:len(MagicHeader)]) != string(MagicHeader) {
		return nil, 0, errors.New("invalid magic header")
	}

	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, 0, err
	}

	start := len(MagicHeader)
	nonceEnd := start + aead.NonceSize()
	if len(payload) < nonceEnd+4 {
		return nil, 0, errors.New("invalid encrypted payload size")
	}
	nonce := payload[start:nonceEnd]

	modeStart := nonceEnd
	modeEnd := modeStart + 4
	modePerm := fs.FileMode(binary.BigEndian.Uint32(payload[modeStart:modeEnd]))
	plaintext, err := aead.Open(nil, nonce, payload[modeEnd:], nil)
	if err != nil {
		return nil, 0, err
	}

	return plaintext, modePerm, nil
}

func EncryptFile(path string, key []byte) (string, fs.FileMode, error) {
	if strings.HasSuffix(path, EncryptedExt) {
		return "", 0, nil
	}

	plaintext, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}

	originalMode := info.Mode().Perm()
	payload, err := EncryptPayload(plaintext, key, originalMode)
	if err != nil {
		return "", 0, err
	}

	dst := path + EncryptedExt
	if err := WriteAtomic(dst, payload, 0o600); err != nil {
		return "", 0, err
	}
	if err := os.Remove(path); err != nil {
		return "", 0, err
	}

	return dst, originalMode, nil
}

func DecryptFile(path string, key []byte) (string, error) {
	if !strings.HasSuffix(path, EncryptedExt) {
		return "", fmt.Errorf("not an encrypted file: %s", path)
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	plaintext, modePerm, err := DecryptPayload(payload, key)
	if err != nil {
		return "", err
	}

	dst := strings.TrimSuffix(path, EncryptedExt)
	if err := WriteAtomic(dst, plaintext, modePerm); err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}

	return dst, nil
}

func RestorePlaintextFromEncrypted(sourcePath, targetPath string, key []byte, fallbackMode fs.FileMode, force bool) error {
	if FileExists(targetPath) && !force {
		return fmt.Errorf("target already exists: %s", targetPath)
	}

	payload, err := os.ReadFile(sourcePath)
	if err != nil {
		return err
	}
	plaintext, modePerm, err := DecryptPayload(payload, key)
	if err != nil {
		return err
	}
	if modePerm == 0 {
		modePerm = fallbackMode
	}
	if modePerm == 0 {
		modePerm = 0o600
	}
	return WriteAtomic(targetPath, plaintext, modePerm)
}

func WriteAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".svault-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
