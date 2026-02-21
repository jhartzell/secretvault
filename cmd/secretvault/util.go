package main

import "secrets-vault/internal/domain"

func fileExists(path string) bool {
	return domain.FileExists(path)
}

func yesNo(ok bool) string {
	return domain.YesNo(ok)
}
