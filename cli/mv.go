package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/FormlessEvoker/passgo/entry"
	"github.com/FormlessEvoker/passgo/store"
)

// runMv implements `passgo mv <query> <new-name>` per
// SPECIFICATION.md §6: renames the matched entry, leaves every other
// field untouched, and refreshes `updated`.
func runMv(vaultPath, passwordFile string, args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "error: mv requires a <query> and a <new-name> argument")
		return ExitUsage
	}
	query, newName := args[0], args[1]

	if err := validateName(newName); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
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

	i, code, ok := resolveOne(s.Payload.Entries, query)
	if !ok {
		return code
	}

	// The entry being renamed is excluded from the collision check so
	// that correcting a name's capitalisation stays possible: it
	// would otherwise collide with itself under a case-insensitive
	// comparison.
	for j, e := range s.Payload.Entries {
		if j != i && strings.EqualFold(e.Name, newName) {
			fmt.Fprintf(os.Stderr, "error: an entry named %q already exists\n", newName)
			return ExitGeneral
		}
	}

	s.Payload.Entries[i].Name = newName
	s.Payload.Entries[i].Updated = entry.Now()

	outcome, err := s.Save()
	if err != nil {
		return reportWrite(outcome, err, fmt.Sprintf("the entry WAS renamed to %q.", newName))
	}
	return ExitOK
}
