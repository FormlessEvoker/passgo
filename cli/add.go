package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/FormlessEvoker/passgo/crypto"
	"github.com/FormlessEvoker/passgo/entry"
	"github.com/FormlessEvoker/passgo/store"
)

func runAdd(vaultPath, passwordFile string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: add requires a <name> argument")
		return ExitUsage
	}
	name := args[0]
	rest := args[1:]

	var (
		username     string
		notes        string
		wantPassword bool
		wantGen      bool
		genLength    = crypto.DefaultGenLength
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
		case "-p", "--password":
			wantPassword = true
		case "-g", "--gen":
			wantGen = true
			// The length argument is optional: only consume the next
			// token if it actually parses as a positive integer.
			if i+1 < len(rest) {
				if n, err := strconv.Atoi(rest[i+1]); err == nil && n > 0 {
					genLength = n
					i++
				}
			}
		case "-n", "--notes":
			if i+1 >= len(rest) {
				fmt.Fprintln(os.Stderr, "error: -n/--notes requires a value")
				return ExitUsage
			}
			i++
			notes = rest[i]
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", rest[i])
			return ExitUsage
		}
	}

	if wantPassword == wantGen {
		fmt.Fprintln(os.Stderr, "error: exactly one of -p or -g is required")
		return ExitUsage
	}

	var secret string
	if wantPassword {
		pw, err := promptSecret("Password: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return ExitUsage
		}
		secret = pw
	} else {
		gen, err := crypto.GeneratePassword(genLength)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return ExitGeneral
		}
		secret = gen
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
		Username: username,
		Secret:   secret,
		Notes:    notes,
		Updated:  entry.Now(),
	})

	if err := s.Save(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitGeneral
	}

	if wantGen {
		fmt.Println(secret)
	}
	return ExitOK
}
