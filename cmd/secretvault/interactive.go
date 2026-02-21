package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

type rootCommandOption struct {
	label       string
	description string
	run         func() error
}

func runInteractiveCommandPicker() error {
	options := []rootCommandOption{
		{label: "key", description: "manage project encryption key", run: func() error { return runKeyCommand(nil) }},
		{label: "scan", description: "detect sensitive files", run: func() error { return runScanCommand(nil) }},
		{label: "lock", description: "encrypt discovered sensitive files", run: func() error { return runLockCommand(nil) }},
		{label: "unlock", description: "decrypt .svault files", run: func() error { return runUnlockCommand(nil) }},
		{label: "restore", description: "restore tracked files", run: func() error { return runRestoreCommand(nil) }},
		{label: "absorb", description: "upload to 1Password then lock locally", run: func() error { return runAbsorbCommand(nil) }},
		{label: "cleanup", description: "remove project-created docs from 1Password", run: func() error { return runCleanupCommand(nil) }},
		{label: "install", description: "install auto lock/unlock hooks", run: func() error { return runInstallCommand(nil) }},
		{label: "run", description: "run command with temporary unshield", run: func() error { return runRunCommand(nil) }},
		{label: "setup", description: "install dependencies and sign in", run: func() error { return runSetupCommand(nil) }},
		{label: "vault status", description: "show tracked vault files", run: func() error { return runVaultCommand([]string{"status"}) }},
	}

	fmt.Println("Choose a command:")
	for i, option := range options {
		fmt.Printf("%d) %s - %s\n", i+1, option.label, option.description)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Select option [1-%d] (default 1): ", len(options))
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return options[0].run()
		}
		idx, err := strconv.Atoi(line)
		if err != nil || idx < 1 || idx > len(options) {
			fmt.Println("Invalid selection.")
			continue
		}
		return options[idx-1].run()
	}
}

func hasInteractiveStdio() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}
