package application

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
	target, mode, err := parseInstallArgsInternal(args, false)
	if err != nil {
		return err
	}

	if strings.TrimSpace(target) == "" && isInteractiveTerminal() {
		flow, err := promptSelect("Choose install flow:", []promptOption{
			{Value: "full", Label: "Full setup", Description: "detect, confirm, absorb, lock, and install hooks (recommended)"},
			{Value: "hooks", Label: "Hooks only", Description: "install pre/post message hooks only"},
		})
		if err != nil {
			return err
		}
		if flow == "full" {
			return runGuidedInstallWorkflow()
		}
	}

	interactiveTargetPrompt := strings.TrimSpace(target) == "" && isInteractiveTerminal()
	if interactiveTargetPrompt {
		selectedTarget, err := promptSelect("Choose hook install target:", []promptOption{
			{Value: "opencode", Label: "OpenCode", Description: "install pre/post hooks in ~/.config/opencode/hooks"},
			{Value: "claude", Label: "Claude", Description: "install pre/post hooks in ~/.claude/hooks"},
		})
		if err != nil {
			return err
		}
		target = selectedTarget

		selectedMode, err := promptSelect("Choose hook mode:", installModeOptions(target))
		if err != nil {
			return err
		}
		mode = selectedMode
	}

	if strings.TrimSpace(target) == "" {
		return errors.New("missing install target. expected: opencode or claude")
	}
	return installHooksForTarget(target, mode)
}

func runGuidedInstallWorkflow() error {
	ctx, err := domain.LoadProjectContext()
	if err != nil {
		return err
	}

	key, err := ensureProjectKeyForInstall(ctx)
	if err != nil {
		return err
	}

	discovered, err := domain.FindSensitiveFiles([]string{"."})
	if err != nil {
		return err
	}
	fmt.Printf("Detected %d sensitive file(s).\n", len(discovered))
	selected, err := promptMultiSelect("Review auto-detected files (all selected by default):", discovered)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		fmt.Println("No auto-detected files selected.")
	}

	manual, err := promptAdditionalFileTargets()
	if err != nil {
		return err
	}
	selected = mergeFileTargets(selected, manual)

	if len(selected) == 0 {
		return errors.New("no files selected for onboarding")
	}

	fmt.Println("Final files for onboarding:")
	for _, path := range selected {
		fmt.Printf("- %s\n", path)
	}
	proceed, err := promptYesNo("Proceed with these files", true)
	if err != nil {
		return err
	}
	if !proceed {
		fmt.Println("Cancelled.")
		return nil
	}

	absorbFirst, err := promptYesNo("Upload files to 1Password (absorb)", true)
	if err != nil {
		return err
	}

	if absorbFirst {
		vaultName := strings.TrimSpace(os.Getenv("SECRETVAULT_OP_VAULT"))
		vaultName, err = promptInput("1Password vault", defaultValue(vaultName, "Private"))
		if err != nil {
			return err
		}
		vaultName = strings.TrimSpace(vaultName)
		if vaultName == "" {
			vaultName = "Private"
		}

		authed, err := opcli.IsAuthenticated()
		if err != nil {
			return err
		}
		if !authed {
			runSetup, err := promptYesNo("1Password is not authenticated. Run setup now", true)
			if err != nil {
				return err
			}
			if runSetup {
				if err := RunSetupCommand(nil); err != nil {
					return err
				}
			}
			authed, err = opcli.IsAuthenticated()
			if err != nil {
				return err
			}
			if !authed {
				return errors.New("1Password CLI is not authenticated")
			}
		}

		if _, err := absorbAndLockTargets(ctx, key, vaultName, selected, false); err != nil {
			return err
		}
	} else {
		if _, err := lockTargets(ctx, key, selected, false); err != nil {
			return err
		}
	}

	target, mode, err := promptHookInstallSelection()
	if err != nil {
		return err
	}
	if err := installHooksForTarget(target, mode); err != nil {
		return err
	}

	fmt.Println("Install workflow complete.")
	return nil
}

func ensureProjectKeyForInstall(ctx domain.ProjectContext) ([]byte, error) {
	key, err := keyringstore.LoadProjectKey(ctx)
	if err == nil {
		fmt.Printf("Using existing key (fingerprint: %s)\n", keyringstore.Fingerprint(key))
		return key, nil
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return nil, err
	}

	createKey, err := promptYesNo("No project key found. Generate one now", true)
	if err != nil {
		return nil, err
	}
	if !createKey {
		return nil, errors.New("missing project key")
	}

	generatedKey, err := keyringstore.KeyFromInput("", true)
	if err != nil {
		return nil, err
	}
	if err := keyringstore.SaveProjectKey(ctx, generatedKey); err != nil {
		return nil, err
	}
	fmt.Printf("Generated key (fingerprint: %s)\n", keyringstore.Fingerprint(generatedKey))
	return generatedKey, nil
}

func promptAdditionalFileTargets() ([]string, error) {
	if !isInteractiveTerminal() {
		return nil, nil
	}
	addMore, err := promptYesNo("Add more files manually", true)
	if err != nil {
		return nil, err
	}
	if !addMore {
		return nil, nil
	}

	collected := make([]string, 0)
	for {
		input, err := promptInput("Add file path (blank to finish)", "")
		if err != nil {
			return nil, err
		}
		input = strings.TrimSpace(input)
		if input == "" {
			break
		}
		abs, err := filepath.Abs(input)
		if err != nil {
			fmt.Printf("invalid path: %v\n", err)
			continue
		}
		info, err := os.Stat(abs)
		if err != nil {
			fmt.Printf("cannot read path: %v\n", err)
			continue
		}
		if info.IsDir() {
			fmt.Println("please provide a file path, not a directory")
			continue
		}
		collected = append(collected, abs)
	}
	return collected, nil
}

func mergeFileTargets(primary, extra []string) []string {
	set := make(map[string]struct{}, len(primary)+len(extra))
	for _, item := range append(primary, extra...) {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func promptHookInstallSelection() (string, string, error) {
	target, err := promptSelect("Choose hook install target:", []promptOption{
		{Value: "claude", Label: "Claude", Description: "install pre/post hooks in ~/.claude/hooks"},
		{Value: "opencode", Label: "OpenCode", Description: "install pre/post hooks in ~/.config/opencode/hooks"},
	})
	if err != nil {
		return "", "", err
	}

	mode, err := promptSelect("Choose hook mode:", installModeOptions(target))
	if err != nil {
		return "", "", err
	}

	return target, mode, nil
}

func installHooksForTarget(target, mode string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	switch target {
	case "opencode":
		configDir := filepath.Join(home, ".config", "opencode")
		preDir := filepath.Join(home, ".config", "opencode", "hooks", "pre-message.d")
		postDir := filepath.Join(home, ".config", "opencode", "hooks", "post-response.d")
		if err := hooks.InstallHookPair("opencode", preDir, postDir, mode); err != nil {
			return err
		}
		return hooks.InstallOpencodePlugin(configDir, mode)
	case "claude":
		preDir := filepath.Join(home, ".claude", "hooks", "pre-message.d")
		postDir := filepath.Join(home, ".claude", "hooks", "post-response.d")
		return hooks.InstallHookPair("claude", preDir, postDir, mode)
	default:
		return fmt.Errorf("unknown install target: %s", target)
	}
}

func defaultValue(value, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func RunRunCommand(args []string, cliName string) error {
	commandArgs := ParseRunCommandArgs(args)
	if len(commandArgs) == 0 {
		if !isInteractiveTerminal() {
			return errors.New("missing command. usage: secretvault run -- <command>")
		}
		input, err := promptInput("Enter command to run (example: terraform plan)", "")
		if err != nil {
			return err
		}
		commandArgs = strings.Fields(input)
		if len(commandArgs) == 0 {
			return errors.New("missing command. usage: secretvault run -- <command>")
		}
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
	return parseInstallArgsInternal(args, true)
}

func parseInstallArgsInternal(args []string, requireTarget bool) (string, string, error) {
	target := ""
	mode := ""
	modeSet := false

	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			continue
		}

		switch {
		case strings.HasPrefix(arg, "--mode="):
			mode = strings.TrimSpace(strings.TrimPrefix(arg, "--mode="))
			modeSet = true
		case arg == "--mode":
			if i+1 >= len(args) {
				return "", "", errors.New("missing value for --mode")
			}
			i++
			mode = strings.TrimSpace(args[i])
			modeSet = true
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

	if requireTarget && target == "" {
		return "", "", errors.New("missing install target. expected: opencode or claude")
	}
	if !modeSet {
		mode = defaultInstallMode(target)
	}
	if mode != hooks.HookModeStable && mode != "strict" {
		return "", "", fmt.Errorf("invalid mode %q (expected %q or %q)", mode, hooks.HookModeStable, "strict")
	}

	return target, mode, nil
}

func defaultInstallMode(target string) string {
	if strings.EqualFold(strings.TrimSpace(target), "opencode") {
		return "strict"
	}
	if strings.TrimSpace(target) == "" {
		return "strict"
	}
	return hooks.HookModeStable
}

func installModeOptions(target string) []promptOption {
	if defaultInstallMode(target) == "strict" {
		return []promptOption{
			{Value: "strict", Label: "strict", Description: "lock before prompt, unlock after response (default)"},
			{Value: hooks.HookModeStable, Label: hooks.HookModeStable, Description: "lock before and after assistant turns"},
		}
	}
	return []promptOption{
		{Value: hooks.HookModeStable, Label: hooks.HookModeStable, Description: "lock before and after assistant turns (default)"},
		{Value: "strict", Label: "strict", Description: "lock before prompt, unlock after response"},
	}
}
