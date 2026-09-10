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

	var force bool
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
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

	target, code, ok := resolveOne(s.Payload.Entries, query)
	if !ok {
		return code
	}

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

// removeEntry returns entries with target removed, matched on name
// alone — the entry's identity, per SPECIFICATION.md §3.2. target
// always comes from resolveOne() against this same slice, so it is
// guaranteed to be present exactly once.
//
// Only the first match is dropped, so a single rm can never delete
// more than one entry even if the uniqueness invariant is somehow
// violated.
func removeEntry(entries []entry.Entry, target entry.Entry) []entry.Entry {
	out := make([]entry.Entry, 0, len(entries)-1)
	removed := false
	for _, e := range entries {
		if !removed && strings.EqualFold(e.Name, target.Name) {
			removed = true
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
