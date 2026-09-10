package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/FormlessEvoker/passgo/store"
)

func runGet(vaultPath, passwordFile string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: get requires a <query> argument")
		return ExitUsage
	}
	query := args[0]
	rest := args[1:]

	var clip bool
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--clip":
			clip = true
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

	i, code, ok := resolveOne(s.Payload.Entries, query)
	if !ok {
		return code
	}

	secret := s.Payload.Entries[i].Secret

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
