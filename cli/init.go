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

	// os.Link is the commit point, so a vault can exist even when this
	// returns an error. Reporting a plain failure would leave someone
	// believing there is none — and a re-run would then contradict
	// that with "vault already exists".
	outcome, err := store.Init(vaultPath, password)
	if err != nil {
		return reportWrite(outcome, err, "the vault WAS created at "+vaultPath+" — do not re-run init.")
	}

	fmt.Fprintln(os.Stderr, "vault created at", vaultPath)
	return ExitOK
}
