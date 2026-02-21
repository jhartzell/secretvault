package system

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func RunShellCommand(command string) error {
	cmd := shellCommand(command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func RunShellCommandQuiet(command string) (string, error) {
	cmd := shellCommand(command)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func RunInteractiveCommand(name string, args []string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func HasCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

type OnePasswordInstallPlan struct {
	Package string
	Source  string
	Command string
}

func SuggestedOnePasswordInstallPlan() (OnePasswordInstallPlan, bool) {
	return suggestedOnePasswordInstallPlan(HasCommand, runtime.GOOS)
}

func SuggestedOnePasswordInstallCommand() (string, bool) {
	plan, ok := SuggestedOnePasswordInstallPlan()
	if !ok {
		return "", false
	}
	return plan.Command, true
}

func OnePasswordInstallHint() string {
	if HasCommand("pacman") {
		return "Arch Linux note: `1password-cli` is in AUR. Install an AUR helper and run `yay -S 1password-cli` (or `paru -S 1password-cli`)."
	}
	return ""
}

func SuggestedOnePasswordDesktopInstallPlan() (OnePasswordInstallPlan, bool) {
	return suggestedOnePasswordDesktopInstallPlan(HasCommand, runtime.GOOS)
}

func OnePasswordDesktopInstallHint() string {
	if HasCommand("pacman") {
		return "Arch Linux note: desktop `1password` is in AUR. Install an AUR helper and run `yay -S 1password` (or `paru -S 1password`)."
	}
	return ""
}

func IsOnePasswordDesktopInstalled() bool {
	if HasCommand("1password") || HasCommand("1Password") {
		return true
	}

	switch runtime.GOOS {
	case "darwin":
		return fileExists("/Applications/1Password.app")
	case "linux":
		return fileExists("/opt/1Password/1password") || fileExists("/usr/bin/1password")
	case "windows":
		localAppData := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
		if localAppData != "" && fileExists(filepath.Join(localAppData, "1Password", "app", "8", "1Password.exe")) {
			return true
		}
		programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
		if programFiles != "" && fileExists(filepath.Join(programFiles, "1Password", "app", "8", "1Password.exe")) {
			return true
		}
	}

	return false
}

func suggestedOnePasswordInstallPlan(hasCommand func(string) bool, goos string) (OnePasswordInstallPlan, bool) {
	if hasCommand("brew") {
		return OnePasswordInstallPlan{Package: "1password-cli", Source: "Homebrew", Command: "brew install 1password-cli"}, true
	}
	if goos == "windows" {
		if hasCommand("winget") {
			return OnePasswordInstallPlan{Package: "AgileBits.1Password.CLI", Source: "winget", Command: "winget install --id AgileBits.1Password.CLI -e"}, true
		}
		return OnePasswordInstallPlan{}, false
	}
	if hasCommand("apt-get") {
		return OnePasswordInstallPlan{Package: "1password-cli", Source: "apt repository", Command: "sudo apt-get install -y 1password-cli"}, true
	}
	if hasCommand("dnf") {
		return OnePasswordInstallPlan{Package: "1password-cli", Source: "dnf repository", Command: "sudo dnf install -y 1password-cli"}, true
	}
	if hasCommand("pacman") {
		if hasCommand("yay") {
			return OnePasswordInstallPlan{Package: "1password-cli", Source: "AUR (via yay)", Command: "yay -S --noconfirm --needed --answerclean None --answerdiff None --answeredit None 1password-cli"}, true
		}
		if hasCommand("paru") {
			return OnePasswordInstallPlan{Package: "1password-cli", Source: "AUR (via paru)", Command: "paru -S --noconfirm --needed --skipreview 1password-cli"}, true
		}
		return OnePasswordInstallPlan{}, false
	}
	if hasCommand("zypper") {
		return OnePasswordInstallPlan{Package: "1password-cli", Source: "zypper repository", Command: "sudo zypper install -y 1password-cli"}, true
	}
	return OnePasswordInstallPlan{}, false
}

func suggestedOnePasswordDesktopInstallPlan(hasCommand func(string) bool, goos string) (OnePasswordInstallPlan, bool) {
	if hasCommand("brew") {
		return OnePasswordInstallPlan{Package: "1password", Source: "Homebrew Cask", Command: "brew install --cask 1password"}, true
	}
	if goos == "windows" {
		if hasCommand("winget") {
			return OnePasswordInstallPlan{Package: "AgileBits.1Password", Source: "winget", Command: "winget install --id AgileBits.1Password -e"}, true
		}
		return OnePasswordInstallPlan{}, false
	}
	if hasCommand("apt-get") {
		return OnePasswordInstallPlan{Package: "1password", Source: "apt repository", Command: "sudo apt-get install -y 1password"}, true
	}
	if hasCommand("dnf") {
		return OnePasswordInstallPlan{Package: "1password", Source: "dnf repository", Command: "sudo dnf install -y 1password"}, true
	}
	if hasCommand("pacman") {
		if hasCommand("yay") {
			return OnePasswordInstallPlan{Package: "1password", Source: "AUR (via yay)", Command: "yay -S --noconfirm --needed --answerclean None --answerdiff None --answeredit None 1password"}, true
		}
		if hasCommand("paru") {
			return OnePasswordInstallPlan{Package: "1password", Source: "AUR (via paru)", Command: "paru -S --noconfirm --needed --skipreview 1password"}, true
		}
		return OnePasswordInstallPlan{}, false
	}
	if hasCommand("zypper") {
		return OnePasswordInstallPlan{Package: "1password", Source: "zypper repository", Command: "sudo zypper install -y 1password"}, true
	}
	return OnePasswordInstallPlan{}, false
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func shellCommand(command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("cmd", "/C", command)
	}
	if HasCommand("bash") {
		return exec.Command("bash", "-lc", command)
	}
	return exec.Command("sh", "-lc", command)
}
