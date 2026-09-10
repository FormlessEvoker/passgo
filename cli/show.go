package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/FormlessEvoker/passgo/entry"
	"github.com/FormlessEvoker/passgo/store"
)

// secretMask is printed in place of the secret by `passgo show`, per
// SPECIFICATION.md §6: "Prints all fields with the password shown as
// ••••••••. Never reveals a secret, so it is safe to run in a shared
// terminal or a screen share."
const secretMask = "••••••••"

// runShow implements `passgo show <query>`.
func runShow(vaultPath, passwordFile string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: show requires a <query> argument")
		return ExitUsage
	}
	query := args[0]
	rest := args[1:]

	for _, arg := range rest {
		fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", arg)
		return ExitUsage
	}

	password, err := readPassword("Master password: ", passwordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if errors.Is(err, ErrNoTTY) {
			return ExitUsage
		}
		return ExitGeneral
	}

	s, err := store.Open(vaultPath, password)
	if err != nil {
		return handleOpenError(err)
	}
	defer s.Close()

	match, code, ok := resolveOne(s.Payload.Entries, query)
	if !ok {
		return code
	}

	printEntryDetail(os.Stdout, match)
	return ExitOK
}

// printEntryDetail writes every field of e to w, with the secret
// masked, never printed in the clear.
func printEntryDetail(w io.Writer, e entry.Entry) {
	fmt.Fprintf(w, "name:     %s\n", e.Name)
	fmt.Fprintf(w, "username: %s\n", e.Username)
	fmt.Fprintf(w, "secret:   %s\n", secretMask)
	fmt.Fprintf(w, "notes:    %s\n", e.Notes)
	fmt.Fprintf(w, "updated:  %s\n", e.Updated.Format(time.RFC3339))
}
