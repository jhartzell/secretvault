package main

import "secrets-vault/internal/application"

func runAbsorbCommand(args []string) error {
	return application.RunAbsorbCommand(args, cliName())
}

func runSetupCommand(args []string) error {
	return application.RunSetupCommand(args)
}

func runCleanupCommand(args []string) error {
	return application.RunCleanupCommand(args)
}
