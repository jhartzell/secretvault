package main

import "secrets-vault/internal/application"

func runKeyCommand(args []string) error {
	return application.RunKeyCommand(args, cliName())
}

func runScanCommand(args []string) error {
	return application.RunScanCommand(args)
}

func runLockCommand(args []string) error {
	return application.RunLockCommand(args, cliName())
}

func runUnlockCommand(args []string) error {
	return application.RunUnlockCommand(args, cliName())
}
