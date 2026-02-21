package application

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"secrets-vault/internal/domain"
	"secrets-vault/internal/integrations/opcli"
	"secrets-vault/internal/integrations/system"
)

func RunCleanupCommand(args []string) error {
	flags := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	var dryRun bool
	var assumeYes bool
	flags.BoolVar(&dryRun, "dry-run", false, "show what would be removed from 1Password")
	flags.BoolVar(&assumeYes, "yes", false, "skip confirmation prompt")
	if err := flags.Parse(args); err != nil {
		return err
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

	manifest, manifestPath, err := domain.LoadVaultManifest(ctx)
	if err != nil {
		return err
	}

	targets := collectCleanupTargets(manifest)
	if len(targets) == 0 {
		fmt.Println("No absorbed 1Password documents found for this project.")
		return nil
	}

	fmt.Println("1Password documents queued for cleanup:")
	for _, target := range targets {
		display := strings.TrimSpace(target.Entry.RelativePath)
		if display == "" {
			display = filepath.Base(target.Entry.AbsolutePath)
		}
		if strings.TrimSpace(target.Entry.OnePasswordVault) != "" {
			fmt.Printf("- %s -> %s (vault: %s)\n", display, target.Entry.OnePasswordDocument, target.Entry.OnePasswordVault)
			continue
		}
		fmt.Printf("- %s -> %s\n", display, target.Entry.OnePasswordDocument)
	}

	if dryRun {
		fmt.Printf("Would remove %d document(s) from 1Password.\n", len(targets))
		return nil
	}

	if !assumeYes {
		ok, err := promptYesNo("Proceed with 1Password cleanup", false)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	deletedCount := 0
	failures := 0
	for _, target := range targets {
		if err := opcli.DeleteDocument(target.Entry.OnePasswordDocument, target.Entry.OnePasswordVault); err != nil {
			fmt.Printf("failed %s: %v\n", target.Entry.OnePasswordDocument, err)
			failures++
			continue
		}

		manifest.Entries[target.Key] = clearOnePasswordMetadata(target.Entry)
		fmt.Printf("deleted %s\n", target.Entry.OnePasswordDocument)
		deletedCount++
	}

	if deletedCount > 0 {
		manifest.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := domain.SaveVaultManifest(manifestPath, manifest); err != nil {
			return err
		}
	}

	if failures > 0 {
		return fmt.Errorf("cleanup removed %d document(s), %d failed", deletedCount, failures)
	}

	fmt.Printf("Cleaned up %d document(s) from 1Password.\n", deletedCount)
	return nil
}

type cleanupTarget struct {
	Key   string
	Entry domain.VaultEntry
}

func collectCleanupTargets(manifest domain.VaultManifest) []cleanupTarget {
	if len(manifest.Entries) == 0 {
		return nil
	}

	keys := domain.SortedVaultEntryKeys(manifest)
	out := make([]cleanupTarget, 0, len(keys))
	for _, key := range keys {
		entry := manifest.Entries[key]
		if strings.TrimSpace(entry.OnePasswordDocument) == "" {
			continue
		}
		out = append(out, cleanupTarget{Key: key, Entry: entry})
	}
	return out
}

func clearOnePasswordMetadata(entry domain.VaultEntry) domain.VaultEntry {
	entry.OnePasswordVault = ""
	entry.OnePasswordDocument = ""
	entry.OnePasswordTitle = ""
	entry.ChecksumSHA256 = ""
	entry.AbsorbedAt = ""
	return entry
}
