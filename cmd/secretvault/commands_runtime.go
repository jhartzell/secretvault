package main

import (
	"fmt"

	"secrets-vault/internal/application"
)

func runRestoreCommand(args []string) error {
	return application.RunRestoreCommand(args, cliName())
}

func runVaultCommand(args []string) error {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	if sub != "status" {
		return fmt.Errorf("unknown vault subcommand: %s", sub)
	}
	return application.RunVaultStatusCommand()
}

func runInstallCommand(args []string) error {
	return application.RunInstallCommand(args)
}

func runRunCommand(args []string) error {
	return application.RunRunCommand(args, cliName())
}

func parseRunCommandArgs(args []string) []string {
	return application.ParseRunCommandArgs(args)
}

func parseInstallArgs(args []string) (string, string, error) {
	return application.ParseInstallArgs(args)
}
