package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/FormlessEvoker/passgo/store"
)

// runPasswd implements `passgo passwd` per SPECIFICATION.md §6:
// prompts for the current master password, then the new one twice,
// and rewrites the vault under a fresh salt and nonce. Entries are
// unchanged.
func runPasswd(vaultPath, passwordFile string, args []string) int {
	var newPasswordFile string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--new-master-password-file":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --new-master-password-file requires a path argument")
				return ExitUsage
			}
			i++
			newPasswordFile = args[i]
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", args[i])
			return ExitUsage
		}
	}
	if newPasswordFile == "" {
		newPasswordFile = os.Getenv("PASSGO_NEW_MASTER_FILE")
	}

	password, err := readPassword("Current master password: ", passwordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if errors.Is(err, ErrNoTTY) {
			return ExitUsage
		}
		return ExitGeneral
	}

	// The vault is opened — and the current password thereby verified —
	// before the new one is asked for, so getting the old password
	// wrong costs one prompt rather than three.
	s, err := store.Open(vaultPath, password)
	if err != nil {
		return handleOpenError(err)
	}
	defer s.Close()

	newPassword, err := readReplacementPassword(newPasswordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if errors.Is(err, ErrNoTTY) || errors.Is(err, ErrNoNewPasswordSource) {
			return ExitUsage
		}
		return ExitGeneral
	}

	// Whatever route the two passwords arrived by — the same file
	// passed to both flags, the same string typed at both prompts, a
	// file whose contents happen to match — rotating a vault to the
	// password it already has and reporting success is never what was
	// meant. Refusing to fall back to $PASSGO_MASTER blocks only one
	// path to that outcome; this rejects the outcome itself.
	if newPassword == password {
		fmt.Fprintln(os.Stderr, "error: the new master password is the same as the current one")
		return ExitUsage
	}

	// The rename is the commit point, so the vault can already require
	// the new password even when this returns an error. Saying only
	// "error" would send the user back to a password that no longer
	// opens their vault.
	outcome, err := s.ChangePassword(newPassword)

	code := ExitOK
	if err != nil {
		code = reportWrite(outcome, err, "the master password WAS changed — use the new one from now on.")
	} else {
		fmt.Fprintln(os.Stderr, "master password changed")
	}

	// Either way, a rotation that reached disk left the previous vault
	// at path+".bak" (§3.4 step 3) — still readable under the password
	// just replaced.
	if outcome.Committed() {
		warnStaleBackup(os.Stderr, vaultPath)
	}
	return code
}
