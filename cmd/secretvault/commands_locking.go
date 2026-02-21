package main

import (
	"errors"
	"fmt"

	"secrets-vault/internal/application"
)

func runKeyCommand(args []string) error {
	if len(args) == 0 {
		printKeyUsage()
		return errors.New("missing key subcommand")
	}
	if args[0] != "set" && args[0] != "show" && args[0] != "clear" {
		printKeyUsage()
		return fmt.Errorf("unknown key subcommand: %s", args[0])
	}
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
