package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		if hasInteractiveStdio() {
			if err := runInteractiveCommandPicker(); err != nil {
				exitWithError(err)
			}
			return
		}
		printUsage()
		exitWithError(errors.New("missing command"))
	}

	var err error
	switch os.Args[1] {
	case "key":
		err = runKeyCommand(os.Args[2:])
	case "scan":
		err = runScanCommand(os.Args[2:])
	case "lock":
		err = runLockCommand(os.Args[2:])
	case "unlock":
		err = runUnlockCommand(os.Args[2:])
	case "restore":
		err = runRestoreCommand(os.Args[2:])
	case "vault":
		err = runVaultCommand(os.Args[2:])
	case "install":
		err = runInstallCommand(os.Args[2:])
	case "run":
		err = runRunCommand(os.Args[2:])
	case "absorb":
		err = runAbsorbCommand(os.Args[2:])
	case "setup":
		err = runSetupCommand(os.Args[2:])
	case "cleanup":
		err = runCleanupCommand(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		printUsage()
		err = fmt.Errorf("unknown command: %s", os.Args[1])
	}

	if err != nil {
		exitWithError(err)
	}
}
