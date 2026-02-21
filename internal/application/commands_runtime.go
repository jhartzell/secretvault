package application

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"

	"secrets-vault/internal/domain"
	"secrets-vault/internal/integrations/hooks"
	"secrets-vault/internal/integrations/keyringstore"
	"secrets-vault/internal/integrations/opcli"
)

func RunRestoreCommand(args []string, cliName string) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	var restoreAll bool
	var force bool
	flags.BoolVar(&restoreAll, "all", false, "restore all tracked files (default restores missing files only)")
	flags.BoolVar(&force, "force", false, "overwrite plaintext files when restoring")
	if err := flags.Parse(args); err != nil {
		return err
	}

	ctx, err := domain.LoadProjectContext()
	if err != nil {
		return err
	}

	manifest, manifestPath, err := domain.LoadVaultManifest(ctx)
	if err != nil {
		return err
	}
	entries := domain.SelectRestoreEntries(ctx, manifest, flags.Args(), restoreAll)
	if len(entries) == 0 {
		fmt.Println("No tracked files to restore.")
		return nil
	}

	count := 0
	now := time.Now().UTC().Format(time.RFC3339)
	var key []byte
	keyLoaded := false
	for _, entry := range entries {
		target := domain.ResolveEntryTargetPath(ctx, entry)
		if domain.FileExists(target) && !force {
			fmt.Printf("skip %s (already exists, use --force to overwrite)\n", target)
			continue
		}

		source, sourceFound, err := domain.ResolveLocalRestoreSource(ctx, entry, target)
		if err != nil {
			return err
		}

		if sourceFound {
			if !keyLoaded {
				key, err = keyringstore.LoadProjectKey(ctx)
				if err != nil {
					if errors.Is(err, keyring.ErrNotFound) {
						return fmt.Errorf("missing key for this project. run: %s key set", cliName)
					}
					return err
				}
				keyLoaded = true
			}

			if err := domain.RestorePlaintextFromEncrypted(source, target, key, fs.FileMode(entry.OriginalMode), force); err != nil {
				return fmt.Errorf("restore %s: %w", target, err)
			}
		} else if strings.TrimSpace(entry.OnePasswordDocument) != "" {
			if err := opcli.RestoreDocument(entry, target, fs.FileMode(entry.OriginalMode), force); err != nil {
				return fmt.Errorf("restore %s from 1password: %w", target, err)
			}
		} else {
			return fmt.Errorf("no encrypted source available for %s", target)
		}

		entry.LastRestoredAt = now
		manifest.Entries[entry.AbsolutePath] = entry
		fmt.Printf("restored %s\n", target)
		count++
	}

	if count == 0 {
		fmt.Println("Nothing restored.")
		return nil
	}

	manifest.UpdatedAt = now
	if err := domain.SaveVaultManifest(manifestPath, manifest); err != nil {
		return err
	}

	fmt.Printf("Restored %d file(s).\n", count)
	return nil
}

func RunVaultStatusCommand() error {
	ctx, err := domain.LoadProjectContext()
	if err != nil {
		return err
	}
	manifest, _, err := domain.LoadVaultManifest(ctx)
	if err != nil {
		return err
	}
	if len(manifest.Entries) == 0 {
		fmt.Println("No tracked files in vault for this project.")
		return nil
	}

	keys := domain.SortedVaultEntryKeys(manifest)
	fmt.Printf("Tracked files for project %s\n", ctx.ProjectPath)
	for _, key := range keys {
		entry := manifest.Entries[key]
		target := domain.ResolveEntryTargetPath(ctx, entry)
		projectEncrypted := target + domain.EncryptedExt
		vaultBackup, err := domain.EntryVaultBackupPath(ctx, entry)
		if err != nil {
			return err
		}
		display := entry.RelativePath
		if strings.TrimSpace(display) == "" {
			display = entry.AbsolutePath
		}
		hasOnePassword := strings.TrimSpace(entry.OnePasswordDocument) != ""
		fmt.Printf("- %s | plain:%s project:%s backup:%s op:%s\n", display, domain.YesNo(domain.FileExists(target)), domain.YesNo(domain.FileExists(projectEncrypted)), domain.YesNo(domain.FileExists(vaultBackup)), domain.YesNo(hasOnePassword))
	}
	return nil
}

func RunInstallCommand(args []string) error {
	target, mode, err := ParseInstallArgs(args)
	if err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	switch target {
	case "opencode":
		preDir := filepath.Join(home, ".config", "opencode", "hooks", "pre-message.d")
		postDir := filepath.Join(home, ".config", "opencode", "hooks", "post-response.d")
		return hooks.InstallHookPair("opencode", preDir, postDir, mode)
	case "claude":
		preDir := filepath.Join(home, ".claude", "hooks", "pre-message.d")
		postDir := filepath.Join(home, ".claude", "hooks", "post-response.d")
		return hooks.InstallHookPair("claude", preDir, postDir, mode)
	default:
		return fmt.Errorf("unknown install target: %s", target)
	}
}

func RunRunCommand(args []string, cliName string) error {
	commandArgs := ParseRunCommandArgs(args)
	if len(commandArgs) == 0 {
		return errors.New("missing command. usage: secretvault run -- <command>")
	}

	if err := RunRestoreCommand(nil, cliName); err != nil {
		return fmt.Errorf("prepare runtime secrets: %w", err)
	}

	cmd := exec.Command(commandArgs[0], commandArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "SECRETVAULT_RUNTIME=1")

	runErr := cmd.Run()
	lockErr := RunLockCommand(nil, cliName)

	if runErr != nil && lockErr != nil {
		return fmt.Errorf("wrapped command failed: %v; re-shield failed: %v", runErr, lockErr)
	}
	if runErr != nil {
		return runErr
	}
	if lockErr != nil {
		return fmt.Errorf("re-shield failed: %w", lockErr)
	}

	return nil
}

func ParseRunCommandArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	for i, arg := range args {
		if arg == "--" {
			if i+1 >= len(args) {
				return nil
			}
			return args[i+1:]
		}
	}
	return args
}

func ParseInstallArgs(args []string) (string, string, error) {
	if len(args) == 0 {
		return "", "", errors.New("missing install target. expected: opencode or claude")
	}

	target := ""
	mode := hooks.HookModeStable

	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			continue
		}

		switch {
		case strings.HasPrefix(arg, "--mode="):
			mode = strings.TrimSpace(strings.TrimPrefix(arg, "--mode="))
		case arg == "--mode":
			if i+1 >= len(args) {
				return "", "", errors.New("missing value for --mode")
			}
			i++
			mode = strings.TrimSpace(args[i])
		case strings.HasPrefix(arg, "-"):
			return "", "", fmt.Errorf("unknown flag: %s", arg)
		default:
			if target == "" {
				target = strings.ToLower(arg)
			} else {
				return "", "", fmt.Errorf("unexpected argument: %s", arg)
			}
		}
	}

	if target == "" {
		return "", "", errors.New("missing install target. expected: opencode or claude")
	}
	if mode != hooks.HookModeStable && mode != "strict" {
		return "", "", fmt.Errorf("invalid mode %q (expected %q or %q)", mode, hooks.HookModeStable, "strict")
	}

	return target, mode, nil
}
