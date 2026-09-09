package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/FormlessEvoker/passgo/crypto"
)

// handleOpenError prints err to stderr and returns the exit code for a
// failed store.Open. A failed authentication (wrong master password or
// a corrupted vault — the two are indistinguishable, per the threat
// model) gets its own exit code so scripts can tell that apart from
// every other kind of failure to open the vault.
func handleOpenError(err error) int {
	fmt.Fprintln(os.Stderr, "error:", err)
	if errors.Is(err, crypto.ErrAuthFailed) {
		return ExitAuthFailed
	}
	return ExitGeneral
}
