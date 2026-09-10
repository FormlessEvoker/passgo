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

	var username string
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "-u", "--username":
			if i+1 >= len(rest) {
				fmt.Fprintln(os.Stderr, "error: -u/--username requires a value")
				return ExitUsage
			}
			i++
			username = rest[i]
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", rest[i])
			return ExitUsage
		}
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

	matches := resolve(s.Payload.Entries, query, username)
	switch len(matches) {
	case 0:
		fmt.Fprintf(os.Stderr, "error: no entry matches %q\n", query)
		return ExitNotFound
	case 1:
		// proceed
	default:
		fmt.Fprintln(os.Stderr, "error: multiple entries match:")
		for _, e := range matches {
			fmt.Fprintf(os.Stderr, "  %s\t%s\n", e.Name, e.Username)
		}
		return ExitAmbiguous
	}

	printEntryDetail(os.Stdout, matches[0])
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
