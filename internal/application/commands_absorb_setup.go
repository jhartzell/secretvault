package application

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"

	"secrets-vault/internal/domain"
	"secrets-vault/internal/integrations/keyringstore"
	"secrets-vault/internal/integrations/opcli"
	"secrets-vault/internal/integrations/system"
)

func RunAbsorbCommand(args []string, cliName string) error {
	flags := flag.NewFlagSet("absorb", flag.ContinueOnError)
	vaultName := strings.TrimSpace(os.Getenv("SECRETVAULT_OP_VAULT"))
	var dryRun bool
	var assumeYes bool
	flags.StringVar(&vaultName, "vault", vaultName, "1Password vault name")
	flags.BoolVar(&dryRun, "dry-run", false, "show what would be absorbed")
	flags.BoolVar(&assumeYes, "yes", false, "skip confirmation prompt")
	if err := flags.Parse(args); err != nil {
		return err
	}

	vaultName = strings.TrimSpace(vaultName)
	if vaultName == "" {
		return errors.New("missing --vault value (or set SECRETVAULT_OP_VAULT)")
	}
	if !system.HasCommand("op") {
		return errors.New("1Password CLI (op) is not installed. run: secretvault setup")
	}

	authed, err := opcli.IsAuthenticated()
	if err != nil {
		return err
	}
	if !authed {
		return errors.New("1Password CLI is not authenticated. run: secretvault setup")
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
	if len(targets) == 0 {
		fmt.Println("No sensitive files found to absorb.")
		return nil
	}

	fmt.Printf("Absorb target vault: %s\n", vaultName)
	for _, path := range targets {
		fmt.Printf("- %s\n", path)
	}

	if !assumeYes {
		ok, err := promptYesNo("Proceed with absorb and local lock", true)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	count := 0
	for _, path := range targets {
		title := opcli.TitleForPath(ctx, path)
		checksum, err := opcli.FileSHA256(path)
		if err != nil {
			return err
		}

		if dryRun {
			fmt.Printf("[dry-run] absorb %s -> op vault %s\n", path, vaultName)
			count++
			continue
		}

		docID, err := opcli.UploadFile(path, vaultName, title)
		if err != nil {
			return fmt.Errorf("upload to 1password for %s: %w", path, err)
		}

		encryptedPath, originalMode, err := domain.EncryptFile(path, key)
		if err != nil {
			return fmt.Errorf("lock after absorb %s: %w", path, err)
		}
		if err := domain.UpsertVaultEntry(ctx, path, encryptedPath, originalMode); err != nil {
			return fmt.Errorf("track vault entry %s: %w", path, err)
		}
		if err := opcli.AnnotateVaultEntry(ctx, path, vaultName, docID, title, checksum); err != nil {
			return fmt.Errorf("update absorb metadata %s: %w", path, err)
		}

		fmt.Printf("absorbed %s -> %s\n", path, docID)
		count++
	}

	if dryRun {
		fmt.Printf("Would absorb %d file(s).\n", count)
		return nil
	}

	fmt.Printf("Absorbed %d file(s).\n", count)
	return nil
}

func RunSetupCommand(args []string) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	var assumeYes bool
	flags.BoolVar(&assumeYes, "yes", false, "auto-confirm installation prompts")
	if err := flags.Parse(args); err != nil {
		return err
	}

	printSetupBanner()

	opInstalled := system.HasCommand("op")
	printSetupStatus("Dependency", "1Password CLI (op)", opInstalled)

	if !opInstalled {
		installCmd, ok := system.SuggestedOnePasswordInstallCommand()
		if ok {
			fmt.Printf("Suggested install command: %s\n", installCmd)
			shouldInstall := assumeYes
			if !assumeYes {
				answer, err := promptYesNo("Install 1Password CLI now", true)
				if err != nil {
					return err
				}
				shouldInstall = answer
			}
			if shouldInstall {
				if err := system.RunShellCommand(installCmd); err != nil {
					fmt.Printf("Install command failed: %v\n", err)
				}
			}
		} else {
			fmt.Println("No supported package manager detected for auto-install.")
		}

		opInstalled = system.HasCommand("op")
		printSetupStatus("Dependency", "1Password CLI (op)", opInstalled)
	}

	opAuthed := false
	if opInstalled {
		var err error
		opAuthed, err = opcli.IsAuthenticated()
		if err != nil {
			fmt.Printf("Could not verify auth status: %v\n", err)
		}
	}
	printSetupStatus("Account", "1Password session", opAuthed)

	if opInstalled && !opAuthed {
		fmt.Println("Sign in with: op signin")
		shouldSignin := assumeYes
		if !assumeYes {
			answer, err := promptYesNo("Run op signin now", true)
			if err != nil {
				return err
			}
			shouldSignin = answer
		}
		if shouldSignin {
			if err := system.RunInteractiveCommand("op", []string{"signin"}); err != nil {
				fmt.Printf("op signin failed: %v\n", err)
			}
			opAuthed, _ = opcli.IsAuthenticated()
			printSetupStatus("Account", "1Password session", opAuthed)
		}
	}

	fmt.Println()
	if opInstalled && opAuthed {
		fmt.Println(setupOK("Setup complete. You can now run `secretvault absorb --vault <name>`."))
		return nil
	}

	fmt.Println(setupWarn("Setup incomplete. Resolve missing checks and rerun `secretvault setup`."))
	return errors.New("setup incomplete")
}

func promptYesNo(prompt string, defaultYes bool) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return defaultYes, nil
	}

	defaultLabel := "y/N"
	if defaultYes {
		defaultLabel = "Y/n"
	}
	fmt.Printf("%s [%s]: ", prompt, defaultLabel)

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return defaultYes, nil
	}
	if line == "y" || line == "yes" {
		return true, nil
	}
	if line == "n" || line == "no" {
		return false, nil
	}
	return defaultYes, nil
}

func printSetupBanner() {
	fmt.Println(setupAccent("+--------------------------------------------------+"))
	fmt.Println(setupAccent("|                secretvault setup                |"))
	fmt.Println(setupAccent("+--------------------------------------------------+"))
	fmt.Printf("Detected OS: %s\n", runtime.GOOS)
	fmt.Println()
}

func printSetupStatus(group, name string, ok bool) {
	status := setupWarn("[MISSING]")
	if ok {
		status = setupOK("[OK]")
	}
	fmt.Printf("%s %s %-24s %s\n", status, group, name, domain.YesNo(ok))
}

func setupOK(s string) string {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return s
	}
	return "\033[32m" + s + "\033[0m"
}

func setupWarn(s string) string {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return s
	}
	return "\033[33m" + s + "\033[0m"
}

func setupAccent(s string) string {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return s
	}
	return "\033[36m" + s + "\033[0m"
}
