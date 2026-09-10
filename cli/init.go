package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/FormlessEvoker/passgo/store"
)

func runInit(vaultPath, passwordFile string, args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "error: init takes no arguments")
		return ExitUsage
	}

	password, err := readNewPassword(passwordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if errors.Is(err, ErrNoTTY) {
			return ExitUsage
		}
		return ExitGeneral
	}

	if err := store.Init(vaultPath, password); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitGeneral
	}

	fmt.Fprintln(os.Stderr, "vault created at", vaultPath)
	return ExitOK
}
