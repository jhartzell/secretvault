package main

import "secrets-vault/internal/integrations/keyringstore"

func keyFromInput(value string, generate bool) ([]byte, error) {
	return keyringstore.KeyFromInput(value, generate)
}

func promptForKey() (string, error) {
	return keyringstore.PromptForKey()
}

func saveProjectKey(ctx projectContext, key []byte) error {
	return keyringstore.SaveProjectKey(ctx, key)
}

func loadProjectKey(ctx projectContext) ([]byte, error) {
	return keyringstore.LoadProjectKey(ctx)
}

func clearProjectKey(ctx projectContext) error {
	return keyringstore.ClearProjectKey(ctx)
}

func fingerprint(key []byte) string {
	return keyringstore.Fingerprint(key)
}
