package system

import (
	"os"
	"os/exec"
	"runtime"
)

func RunShellCommand(command string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-lc", command)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
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

func SuggestedOnePasswordInstallCommand() (string, bool) {
	if HasCommand("brew") {
		return "brew install 1password-cli", true
	}
	if runtime.GOOS == "windows" {
		if HasCommand("winget") {
			return "winget install --id AgileBits.1Password.CLI -e", true
		}
		return "", false
	}
	if HasCommand("apt-get") {
		return "sudo apt-get install -y 1password-cli", true
	}
	if HasCommand("dnf") {
		return "sudo dnf install -y 1password-cli", true
	}
	if HasCommand("pacman") {
		return "sudo pacman -S --noconfirm 1password-cli", true
	}
	if HasCommand("zypper") {
		return "sudo zypper install -y 1password-cli", true
	}
	return "", false
}
