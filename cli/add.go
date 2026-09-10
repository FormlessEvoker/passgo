package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/FormlessEvoker/passgo/entry"
	"github.com/FormlessEvoker/passgo/store"
)

func runAdd(vaultPath, passwordFile string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: add requires a <name> argument")
		return ExitUsage
	}
	name := args[0]

	if err := validateName(name); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitUsage
	}

	flags, err := parseFieldFlags(args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitUsage
	}
	if flags.wantPassword == flags.wantGen {
		fmt.Fprintln(os.Stderr, "error: exactly one of -p or -g is required")
		return ExitUsage
	}

	secret, code, err := flags.newSecret()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return code
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

	// name is the entry's identity (SPECIFICATION.md §3.2), so a
	// collision on name alone is a duplicate — username plays no part.
	// Two accounts on one site are two entries with distinct names.
	for _, e := range s.Payload.Entries {
		if strings.EqualFold(e.Name, name) {
			fmt.Fprintf(os.Stderr, "error: an entry named %q already exists\n", name)
			return ExitGeneral
		}
	}

	s.Payload.Entries = append(s.Payload.Entries, entry.Entry{
		Name:     name,
		Username: flags.username,
		Secret:   secret,
		Notes:    flags.notes,
		Updated:  entry.Now(),
	})

	if err := s.Save(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitGeneral
	}

	if flags.wantGen {
		fmt.Println(secret)
	}
	return ExitOK
}
