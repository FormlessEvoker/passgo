package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/FormlessEvoker/passgo/entry"
	"github.com/FormlessEvoker/passgo/store"
)

// runRm implements `passgo rm <query>` per SPECIFICATION.md §6:
// prompts for confirmation unless -f/--force is given.
func runRm(vaultPath, passwordFile string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: rm requires a <query> argument")
		return ExitUsage
	}
	query := args[0]
	rest := args[1:]

	var (
		username string
		force    bool
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
		case "-f", "--force":
			force = true
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
	target := matches[0]

	if !force {
		confirmed, err := confirm(fmt.Sprintf("Delete %s (%s)? [y/N] ", target.Name, target.Username))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return ExitGeneral
		}
		if !confirmed {
			fmt.Fprintln(os.Stderr, "aborted")
			return ExitOK
		}
	}

	s.Payload.Entries = removeEntry(s.Payload.Entries, target)

	if err := s.Save(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitGeneral
	}
	return ExitOK
}

// removeEntry returns entries with the first element matching target
// on both name and username (case-insensitive) removed. target always
// comes from resolve() against this same slice, so it is guaranteed
// to be present.
func removeEntry(entries []entry.Entry, target entry.Entry) []entry.Entry {
	out := make([]entry.Entry, 0, len(entries)-1)
	for _, e := range entries {
		if strings.EqualFold(e.Name, target.Name) && strings.EqualFold(e.Username, target.Username) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// confirm writes prompt to stderr and reads one line from stdin,
// returning true only for an explicit "y" or "yes" (case-insensitive)
// — any other input, including empty, is treated as "no". It reads
// from the same stdin package variable promptSecret uses, so tests
// can drive it without a real terminal.
func confirm(prompt string) (bool, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
