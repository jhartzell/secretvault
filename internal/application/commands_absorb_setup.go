package application

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"

	"secrets-vault/internal/domain"
	"secrets-vault/internal/integrations/keyringstore"
	"secrets-vault/internal/integrations/opcli"
	"secrets-vault/internal/integrations/system"
)

const defaultOnePasswordSigninAddress = "my.1password.com"

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
		if !isInteractiveTerminal() {
			return errors.New("missing --vault value (or set SECRETVAULT_OP_VAULT)")
		}
		input, err := promptInput("Enter 1Password vault name", "Private")
		if err != nil {
			return err
		}
		vaultName = strings.TrimSpace(input)
		if vaultName == "" {
			return errors.New("missing --vault value (or set SECRETVAULT_OP_VAULT)")
		}
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
	count, err = absorbAndLockTargets(ctx, key, vaultName, targets, dryRun)
	if err != nil {
		return err
	}

	if dryRun {
		fmt.Printf("Would absorb %d file(s).\n", count)
		return nil
	}

	fmt.Printf("Absorbed %d file(s).\n", count)
	return nil
}

func absorbAndLockTargets(ctx domain.ProjectContext, key []byte, vaultName string, targets []string, dryRun bool) (int, error) {
	count := 0
	for _, path := range targets {
		title := opcli.TitleForPath(ctx, path)
		checksum, err := opcli.FileSHA256(path)
		if err != nil {
			return count, err
		}
		metadata, err := opcli.BuildDocumentMetadata(ctx, path)
		if err != nil {
			return count, err
		}

		if dryRun {
			fmt.Printf("[dry-run] absorb %s -> op vault %s\n", path, vaultName)
			count++
			continue
		}

		docID, err := opcli.UploadFileWithMetadata(path, vaultName, title, metadata)
		if err != nil {
			return count, fmt.Errorf("upload to 1password for %s: %w", path, err)
		}

		encryptedPath, originalMode, err := domain.EncryptFile(path, key)
		if err != nil {
			return count, fmt.Errorf("lock after absorb %s: %w", path, err)
		}
		if err := domain.UpsertVaultEntry(ctx, path, encryptedPath, originalMode); err != nil {
			return count, fmt.Errorf("track vault entry %s: %w", path, err)
		}
		if err := opcli.AnnotateVaultEntry(ctx, path, vaultName, docID, title, checksum); err != nil {
			return count, fmt.Errorf("update absorb metadata %s: %w", path, err)
		}

		fmt.Printf("absorbed %s -> %s\n", path, docID)
		count++
	}
	return count, nil
}

func RunSetupCommand(args []string) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	var assumeYes bool
	signinAddress := strings.TrimSpace(os.Getenv("SECRETVAULT_OP_SIGNIN_ADDRESS"))
	flags.BoolVar(&assumeYes, "yes", false, "auto-confirm installation prompts")
	flags.StringVar(&signinAddress, "signin-address", signinAddress, "1Password sign-in address (default: my.1password.com)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	signinAddress = normalizeSigninAddress(signinAddress)

	printSetupBanner()

	opInstalled := system.HasCommand("op")
	printSetupStatus("Dependency", "1Password CLI (op)", opInstalled)

	if !opInstalled {
		installPlan, ok := system.SuggestedOnePasswordInstallPlan()
		if ok {
			fmt.Printf("Package: %s\n", installPlan.Package)
			fmt.Printf("Source: %s\n", installPlan.Source)
			shouldInstall := assumeYes
			if !assumeYes {
				answer, err := promptYesNo("Install 1Password CLI now", true)
				if err != nil {
					return err
				}
				shouldInstall = answer
			}
			if shouldInstall {
				out, err := runSetupLoader("Installing 1Password CLI", func() (string, error) {
					return system.RunShellCommandQuiet(installPlan.Command)
				})
				if err != nil {
					fmt.Printf("Install failed: %v\n", err)
					if hint := summarizeCommandOutput(out); hint != "" {
						fmt.Printf("Installer output: %s\n", hint)
					}
				}
			}
		} else {
			fmt.Println("No supported package manager detected for auto-install.")
			if hint := system.OnePasswordInstallHint(); hint != "" {
				fmt.Println(hint)
			}
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
		desktopInstalled := system.IsOnePasswordDesktopInstalled()
		printSetupStatus("Desktop", "1Password app", desktopInstalled)
		if !desktopInstalled {
			desktopPlan, ok := system.SuggestedOnePasswordDesktopInstallPlan()
			if ok {
				fmt.Printf("Package: %s\n", desktopPlan.Package)
				fmt.Printf("Source: %s\n", desktopPlan.Source)
				shouldInstallDesktop := assumeYes
				if !assumeYes {
					answer, err := promptYesNo("Install 1Password desktop app now", true)
					if err != nil {
						return err
					}
					shouldInstallDesktop = answer
				}
				if shouldInstallDesktop {
					out, err := runSetupLoader("Installing 1Password desktop app", func() (string, error) {
						return system.RunShellCommandQuiet(desktopPlan.Command)
					})
					if err != nil {
						fmt.Printf("Desktop app install failed: %v\n", err)
						if hint := summarizeCommandOutput(out); hint != "" {
							fmt.Printf("Installer output: %s\n", hint)
						}
					}
					desktopInstalled = system.IsOnePasswordDesktopInstalled()
					printSetupStatus("Desktop", "1Password app", desktopInstalled)
				}
			} else {
				fmt.Println("No supported package manager detected for desktop app auto-install.")
				if hint := system.OnePasswordDesktopInstallHint(); hint != "" {
					fmt.Println(hint)
				}
			}
		}

		if desktopInstalled {
			printDesktopIntegrationSteps()
		}

		signinArgs, signinCommand, accountConfigured := buildSigninInvocation(signinAddress)
		fmt.Printf("Sign in with: %s\n", signinCommand)
		shouldSignin := assumeYes
		if !assumeYes {
			answer, err := promptYesNo("Run op signin now", true)
			if err != nil {
				return err
			}
			shouldSignin = answer
		}
		if shouldSignin {
			if err := system.RunInteractiveCommand("op", signinArgs); err != nil {
				fmt.Printf("op signin failed: %v\n", err)
				if !accountConfigured {
					fmt.Printf("If no account is configured yet, run: op account add --address %s\n", signinAddress)
				}
			}
			opAuthed, _ = opcli.IsAuthenticated()
			printSetupStatus("Account", "1Password session", opAuthed)
			if !opAuthed {
				fmt.Printf("If signin prints an export command, run it in your shell: %s\n", signinCommand)
			}
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

func runSetupLoader(label string, action func() (string, error)) (string, error) {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return action()
	}

	done := make(chan struct{})
	var output string
	var err error
	go func() {
		output, err = action()
		close(done)
	}()

	frames := []string{"[   ]", "[=  ]", "[== ]", "[===]", "[ ==]", "[  =]"}
	i := 0
	for {
		select {
		case <-done:
			fmt.Print("\r\033[2K")
			return output, err
		default:
			fmt.Printf("\r%s %s %s", setupAccent("[....]"), label, frames[i%len(frames)])
			time.Sleep(110 * time.Millisecond)
			i++
		}
	}
}

func summarizeCommandOutput(out string) string {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return ""
	}
	lines := strings.Split(trimmed, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return line
		}
	}
	return ""
}

func normalizeSigninAddress(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return defaultOnePasswordSigninAddress
	}
	return trimmed
}

func printDesktopIntegrationSteps() {
	fmt.Println("Desktop app integration checklist:")
	fmt.Println("1) Open 1Password desktop app and sign in")
	fmt.Println("2) Enable Security unlock (Touch ID / Windows Hello / system auth)")
	fmt.Println("3) Enable Developer -> Integrate with 1Password CLI")
}

func buildSigninInvocation(signinAddress string) ([]string, string, bool) {
	hasConfiguredAccount, err := opcli.HasConfiguredAccount()
	if err != nil {
		return []string{"signin", "-f"}, "eval $(op signin)", false
	}
	if !hasConfiguredAccount {
		return []string{"signin", "-f"}, "eval $(op signin)", false
	}
	return []string{"--account", signinAddress, "signin", "-f"}, fmt.Sprintf("eval $(op --account %s signin)", signinAddress), true
}
