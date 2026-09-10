package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/FormlessEvoker/passgo/crypto"
)

// runGen implements `passgo gen [length]` per SPECIFICATION.md §6:
// generates a password and prints it, touching neither the vault nor
// the master password. It is dispatched before the vault path is even
// resolved (cli.go), so a missing or unreadable vault cannot make a
// standalone generator fail.
func runGen(args []string) int {
	length := crypto.DefaultGenLength
	switch len(args) {
	case 0:
		// default length
	case 1:
		// Unlike `-g [length]`, which ignores a non-numeric next token
		// because it may be another flag, a positional argument here
		// can only be a length — so a bad one is an error rather than
		// something to skip past.
		n, err := strconv.Atoi(args[0])
		if err != nil || n <= 0 {
			fmt.Fprintf(os.Stderr, "error: length must be a positive integer, got %q\n", args[0])
			return ExitUsage
		}
		length = n
	default:
		fmt.Fprintln(os.Stderr, "error: gen takes at most one [length] argument")
		return ExitUsage
	}

	secret, err := crypto.GeneratePassword(length)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitGeneral
	}

	printSecret(secret)
	return ExitOK
}
