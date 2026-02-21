package main

import sys "secrets-vault/internal/integrations/system"

func runShellCommand(command string) error {
	return sys.RunShellCommand(command)
}

func runInteractiveCommand(name string, args []string) error {
	return sys.RunInteractiveCommand(name, args)
}

func hasCommand(name string) bool {
	return sys.HasCommand(name)
}

func suggestedOnePasswordInstallCommand() (string, bool) {
	return sys.SuggestedOnePasswordInstallCommand()
}
