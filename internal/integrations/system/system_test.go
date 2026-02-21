package system

import "testing"

func TestSuggestedOnePasswordInstallPlanArchYay(t *testing.T) {
	has := func(name string) bool {
		switch name {
		case "pacman", "yay":
			return true
		default:
			return false
		}
	}

	plan, ok := suggestedOnePasswordInstallPlan(has, "linux")
	if !ok {
		t.Fatalf("expected install plan for arch + yay")
	}
	if plan.Source != "AUR (via yay)" {
		t.Fatalf("unexpected source: %q", plan.Source)
	}
	if plan.Command == "" {
		t.Fatalf("expected non-empty install command")
	}
}

func TestSuggestedOnePasswordInstallPlanArchWithoutAurHelper(t *testing.T) {
	has := func(name string) bool {
		return name == "pacman"
	}

	if _, ok := suggestedOnePasswordInstallPlan(has, "linux"); ok {
		t.Fatalf("expected no plan when only pacman is available")
	}
}

func TestSuggestedOnePasswordInstallPlanWindowsWinget(t *testing.T) {
	has := func(name string) bool {
		return name == "winget"
	}

	plan, ok := suggestedOnePasswordInstallPlan(has, "windows")
	if !ok {
		t.Fatalf("expected plan for windows + winget")
	}
	if plan.Package != "AgileBits.1Password.CLI" {
		t.Fatalf("unexpected package: %q", plan.Package)
	}
}

func TestSuggestedOnePasswordDesktopInstallPlanArchParu(t *testing.T) {
	has := func(name string) bool {
		switch name {
		case "pacman", "paru":
			return true
		default:
			return false
		}
	}

	plan, ok := suggestedOnePasswordDesktopInstallPlan(has, "linux")
	if !ok {
		t.Fatalf("expected desktop install plan for arch + paru")
	}
	if plan.Source != "AUR (via paru)" {
		t.Fatalf("unexpected source: %q", plan.Source)
	}
}

func TestSuggestedOnePasswordDesktopInstallPlanMacOSBrew(t *testing.T) {
	has := func(name string) bool {
		return name == "brew"
	}

	plan, ok := suggestedOnePasswordDesktopInstallPlan(has, "darwin")
	if !ok {
		t.Fatalf("expected desktop install plan for macos + brew")
	}
	if plan.Package != "1password" {
		t.Fatalf("unexpected package: %q", plan.Package)
	}
}
