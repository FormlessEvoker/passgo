package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/FormlessEvoker/passgo/store"
	"github.com/FormlessEvoker/passgo/vault"
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
		if errors.Is(err, vault.ErrNotDurable) {
			// os.Link committed before the sync failed, so a vault
			// exists. Reporting a plain failure would leave someone
			// believing there is none — and a re-run would then
			// contradict that with "vault already exists".
			reportNotDurable(os.Stderr, "the vault WAS created at "+vaultPath+" — do not re-run init.")
		}
		return ExitGeneral
	}

	fmt.Fprintln(os.Stderr, "vault created at", vaultPath)
	return ExitOK
}
