package main

import (
	"io/fs"

	"secrets-vault/internal/integrations/opcli"
)

func isOnePasswordAuthenticated() (bool, error) {
	return opcli.IsAuthenticated()
}

func uploadFileToOnePassword(path, vaultName, title string) (string, error) {
	return opcli.UploadFile(path, vaultName, title)
}

func extractOnePasswordDocumentID(out []byte) string {
	return opcli.ExtractDocumentID(out)
}

func restoreFromOnePasswordDocument(entry vaultEntry, targetPath string, mode fs.FileMode, force bool) error {
	return opcli.RestoreDocument(entry, targetPath, mode, force)
}

func annotateVaultEntryWithOnePassword(ctx projectContext, originalPath, vaultName, documentID, title, checksum string) error {
	return opcli.AnnotateVaultEntry(ctx, originalPath, vaultName, documentID, title, checksum)
}

func fileSHA256(path string) (string, error) {
	return opcli.FileSHA256(path)
}

func onePasswordTitleForPath(ctx projectContext, absolutePath string) string {
	return opcli.TitleForPath(ctx, absolutePath)
}
