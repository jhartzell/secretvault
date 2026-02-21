package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"secrets-vault/internal/domain"
)

const (
	serviceName    = "secrets-vault-cli"
	encryptedExt   = ".svault"
	defaultCLIName = "secretvault"
	hookModeStrict = "strict"
	hookModeStable = "stable-dev"
)

var (
	magicHeader          = domain.MagicHeader
	sensitiveExactNames  = domain.SensitiveExactNames
	sensitiveSuffixes    = domain.SensitiveSuffixes
	sensitiveDirNames    = domain.SensitiveDirNames
	ignoredDirNames      = domain.IgnoredDirNames
	secretContentPattern = domain.SecretContentPattern
)

type projectContext = domain.ProjectContext
type vaultManifest = domain.VaultManifest
type vaultEntry = domain.VaultEntry

func printUsage() {
	name := cliName()
	fmt.Printf("%s - lock/unlock sensitive project files\n", name)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Printf("  %s key [set|show|clear] [--value <string> | --generate]\n", name)
	fmt.Printf("  %s scan [path ...]\n", name)
	fmt.Printf("  %s lock [--dry-run] [path ...]\n", name)
	fmt.Printf("  %s unlock [--dry-run] [path ...]\n", name)
	fmt.Printf("  %s restore [--all] [--force] [path ...]\n", name)
	fmt.Printf("  %s absorb [--vault <name>] [--dry-run] [--yes] [path ...]\n", name)
	fmt.Printf("  %s cleanup [--dry-run] [--yes]\n", name)
	fmt.Printf("  %s vault status\n", name)
	fmt.Printf("  %s install [--mode stable-dev|strict] [opencode|claude]\n", name)
	fmt.Printf("  %s run -- <command> [args ...]\n", name)
	fmt.Printf("  %s setup [--yes] [--signin-address <address>]\n", name)
}

func printKeyUsage() {
	name := cliName()
	fmt.Println("Usage:")
	fmt.Printf("  %s key [set|show|clear] [--value <string> | --generate]\n", name)
}

func cliName() string {
	if len(os.Args) == 0 {
		return defaultCLIName
	}
	name := strings.TrimSpace(filepath.Base(os.Args[0]))
	if name == "" {
		return defaultCLIName
	}
	return name
}

func exitWithError(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func loadProjectContext() (projectContext, error) {
	return domain.LoadProjectContext()
}
