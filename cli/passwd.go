package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/FormlessEvoker/passgo/store"
	"github.com/FormlessEvoker/passgo/vault"
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

	if err := s.ChangePassword(newPassword); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if errors.Is(err, vault.ErrNotDurable) {
			// The rename committed before the failure, so the vault
			// already requires the new password. Saying only "error"
			// here would send the user back to a password that no
			// longer opens their vault.
			fmt.Fprintln(os.Stderr, "IMPORTANT: the master password WAS changed — use the new one from now on.")
			fmt.Fprintln(os.Stderr, "Only the directory sync failed, so the change may not survive a power loss.")
			fmt.Fprintln(os.Stderr, "Verify with `passgo ls`, and re-run passwd if the vault still wants the old password.")
		}
		return ExitGeneral
	}

	fmt.Fprintln(os.Stderr, "master password changed")
	return ExitOK
}
