package application

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zalando/go-keyring"

	"secrets-vault/internal/domain"
	"secrets-vault/internal/integrations/keyringstore"
)

func RunKeyCommand(args []string, cliName string) error {
	if len(args) == 0 {
		if !isInteractiveTerminal() {
			return errors.New("missing key subcommand")
		}
		choice, err := promptSelect("Choose key command:", []promptOption{
			{Value: "set", Label: "Set", Description: "create/update encryption key"},
			{Value: "show", Label: "Show", Description: "show key status and fingerprint"},
			{Value: "clear", Label: "Clear", Description: "remove stored key for this project"},
		})
		if err != nil {
			return err
		}
		args = []string{choice}
	}

	if len(args) == 1 && args[0] == "set" && isInteractiveTerminal() {
		setMode, err := promptSelect("Set key mode:", []promptOption{
			{Value: "generate", Label: "Generate random key", Description: "recommended and strongest default"},
			{Value: "passphrase", Label: "Enter passphrase", Description: "derive key from your input"},
		})
		if err != nil {
			return err
		}
		if setMode == "generate" {
			args = []string{"set", "--generate"}
		}
	}

	ctx, err := domain.LoadProjectContext()
	if err != nil {
		return err
	}

	switch args[0] {
	case "set":
		flags := flag.NewFlagSet("key set", flag.ContinueOnError)
		var value string
		var generate bool
		flags.StringVar(&value, "value", "", "passphrase or raw key material")
		flags.BoolVar(&generate, "generate", false, "generate a random key")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}

		key, err := keyringstore.KeyFromInput(value, generate)
		if err != nil {
			return err
		}
		if err := keyringstore.SaveProjectKey(ctx, key); err != nil {
			return err
		}

		fmt.Printf("Stored encryption key for project %s\n", ctx.ProjectPath)
		fmt.Printf("Key fingerprint: %s\n", keyringstore.Fingerprint(key))
		return nil
	case "show":
		key, err := keyringstore.LoadProjectKey(ctx)
		if err != nil {
			if errors.Is(err, keyring.ErrNotFound) {
				fmt.Println("No key configured for this project.")
				fmt.Printf("Run: %s key set\n", cliName)
				return nil
			}
			return err
		}
		fmt.Printf("Key is configured for project %s\n", ctx.ProjectPath)
		fmt.Printf("Key fingerprint: %s\n", keyringstore.Fingerprint(key))
		return nil
	case "clear":
		if err := keyringstore.ClearProjectKey(ctx); err != nil {
			if errors.Is(err, keyring.ErrNotFound) {
				fmt.Println("No key configured for this project.")
				return nil
			}
			return err
		}
		fmt.Printf("Cleared key for project %s\n", ctx.ProjectPath)
		return nil
	default:
		return fmt.Errorf("unknown key subcommand: %s", args[0])
	}
}

func RunScanCommand(args []string) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	if err := flags.Parse(args); err != nil {
		return err
	}

	roots := domain.NormalizeRoots(flags.Args())
	targets, err := domain.FindSensitiveFiles(roots)
	if err != nil {
		return err
	}

	if len(targets) == 0 {
		fmt.Println("No sensitive files detected.")
		return nil
	}

	for _, t := range targets {
		fmt.Println(t)
	}
	fmt.Printf("Detected %d sensitive file(s).\n", len(targets))
	return nil
}

func RunLockCommand(args []string, cliName string) error {
	flags := flag.NewFlagSet("lock", flag.ContinueOnError)
	var dryRun bool
	flags.BoolVar(&dryRun, "dry-run", false, "show files that would be encrypted")
	if err := flags.Parse(args); err != nil {
		return err
	}

	ctx, err := domain.LoadProjectContext()
	if err != nil {
		return err
	}

	key, err := keyringstore.LoadProjectKey(ctx)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("missing key for this project. run: %s key set", cliName)
		}
		return err
	}

	roots := domain.NormalizeRoots(flags.Args())
	targets, err := domain.FindSensitiveFiles(roots)
	if err != nil {
		return err
	}
	targets, err = mergeTrackedLockTargets(ctx, targets)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("No sensitive files detected to lock.")
		return nil
	}

	count, err := lockTargets(ctx, key, targets, dryRun)
	if err != nil {
		return err
	}

	if dryRun {
		fmt.Printf("Would lock %d file(s).\n", count)
		return nil
	}
	fmt.Printf("Locked %d file(s).\n", count)
	return nil
}

func RunUnlockCommand(args []string, cliName string) error {
	flags := flag.NewFlagSet("unlock", flag.ContinueOnError)
	var dryRun bool
	flags.BoolVar(&dryRun, "dry-run", false, "show files that would be decrypted")
	if err := flags.Parse(args); err != nil {
		return err
	}

	ctx, err := domain.LoadProjectContext()
	if err != nil {
		return err
	}

	key, err := keyringstore.LoadProjectKey(ctx)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("missing key for this project. run: %s key set", cliName)
		}
		return err
	}

	roots := domain.NormalizeRoots(flags.Args())
	targets, err := domain.FindEncryptedFiles(roots)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("No encrypted files detected to unlock.")
		return nil
	}

	count := 0
	for _, path := range targets {
		dst := strings.TrimSuffix(path, domain.EncryptedExt)
		if dryRun {
			fmt.Printf("[dry-run] %s -> %s\n", path, dst)
			count++
			continue
		}

		if _, err := domain.DecryptFile(path, key); err != nil {
			return fmt.Errorf("decrypt %s: %w", path, err)
		}
		fmt.Printf("unlocked %s\n", dst)
		count++
	}

	if dryRun {
		fmt.Printf("Would unlock %d file(s).\n", count)
		return nil
	}
	fmt.Printf("Unlocked %d file(s).\n", count)
	return nil
}

func lockTargets(ctx domain.ProjectContext, key []byte, targets []string, dryRun bool) (int, error) {
	count := 0
	for _, path := range targets {
		dst := path + domain.EncryptedExt
		if dryRun {
			fmt.Printf("[dry-run] %s -> %s\n", path, dst)
			count++
			continue
		}

		encryptedPath, originalMode, err := domain.EncryptFile(path, key)
		if err != nil {
			return count, fmt.Errorf("encrypt %s: %w", path, err)
		}
		if err := domain.UpsertVaultEntry(ctx, path, encryptedPath, originalMode); err != nil {
			return count, fmt.Errorf("track vault entry %s: %w", path, err)
		}
		fmt.Printf("locked %s\n", path)
		count++
	}
	return count, nil
}

func mergeTrackedLockTargets(ctx domain.ProjectContext, scanTargets []string) ([]string, error) {
	set := make(map[string]struct{}, len(scanTargets))
	for _, target := range scanTargets {
		if strings.TrimSpace(target) == "" {
			continue
		}
		abs, err := filepath.Abs(target)
		if err != nil {
			return nil, err
		}
		if domain.FileExists(abs) {
			set[abs] = struct{}{}
		}
	}

	manifest, _, err := domain.LoadVaultManifest(ctx)
	if err != nil {
		return nil, err
	}
	for _, key := range domain.SortedVaultEntryKeys(manifest) {
		entry := manifest.Entries[key]
		target := domain.ResolveEntryTargetPath(ctx, entry)
		if domain.FileExists(target) {
			set[target] = struct{}{}
		}
	}

	out := make([]string, 0, len(set))
	for target := range set {
		out = append(out, target)
	}
	sort.Strings(out)
	return out, nil
}
