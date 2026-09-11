package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/FormlessEvoker/passgo/entry"
	"github.com/FormlessEvoker/passgo/store"
)

// runEdit implements `passgo edit <query> [flags]` per
// SPECIFICATION.md §6: the same field flags as `add`, changing only
// the fields whose flags were given, and refreshing `updated`.
// `name` is not among them — renaming goes through `mv`.
func runEdit(vaultPath, passwordFile string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: edit requires a <query> argument")
		return ExitUsage
	}
	query := args[0]

	flags, err := parseFieldFlags(args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitUsage
	}
	if !flags.any() {
		fmt.Fprintln(os.Stderr, "error: edit requires at least one of -u, -p, -g, or -n")
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

	// The new secret is resolved only after the query has, so a
	// mistyped query fails before prompting for a password that would
	// have nowhere to go.
	var secret string
	if flags.changesSecret() {
		secret, code, err = flags.newSecret()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return code
		}
	}

	e := &s.Payload.Entries[i]
	if flags.usernameSet {
		e.Username = flags.username
	}
	if flags.notesSet {
		e.Notes = flags.notes
	}
	if flags.changesSecret() {
		e.Secret = secret
	}
	e.Updated = entry.Now()

	outcome, err := s.Save()

	// Same contract as `add -g`: a generated secret is printed so it
	// can be piped somewhere on the spot, since nothing else in this
	// run reveals it. That holds for a write that committed without
	// being confirmed durable too — the new secret is already the one
	// in the vault, and re-running `edit -g` would generate a third.
	if outcome.Committed() && flags.wantGen {
		printSecret(secret)
	}

	if err != nil {
		return reportWrite(outcome, err, fmt.Sprintf("the changes to %q WERE saved.", e.Name))
	}
	return ExitOK
}
