package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/FormlessEvoker/passgo/store"
)

func runGet(vaultPath string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: get requires a <query> argument")
		return ExitUsage
	}
	query := args[0]
	rest := args[1:]

	var (
		username string
		clip     bool
	)
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "-u", "--username":
			if i+1 >= len(rest) {
				fmt.Fprintln(os.Stderr, "error: -u/--username requires a value")
				return ExitUsage
			}
			i++
			username = rest[i]
		case "--clip":
			clip = true
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", rest[i])
			return ExitUsage
		}
	}

	password, err := readPassword("Master password: ")
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

	secret := matches[0].Secret

	if clip {
		if err := copyToClipboard(secret); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return ExitGeneral
		}
		return ExitOK
	}

	if isTTY(os.Stdout) {
		fmt.Println(secret)
	} else {
		fmt.Print(secret)
	}
	return ExitOK
}
