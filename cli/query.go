package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/FormlessEvoker/passgo/entry"
)

// resolve implements query resolution per SPECIFICATION.md §5: an
// exact, case-insensitive match on name, falling back to a
// case-insensitive substring match on name, username, or notes.
//
// There is deliberately no field-specific filter parameter. Because
// name uniquely identifies an entry (§3.2), the exact-match stage can
// return at most one result, so an ambiguous query is always
// resolvable by typing the exact name — which is what makes filter
// flags like the former -u/--username unnecessary rather than merely
// unfashionable.
func resolve(entries []entry.Entry, query string) []entry.Entry {
	var exact []entry.Entry
	for _, e := range entries {
		if strings.EqualFold(e.Name, query) {
			exact = append(exact, e)
		}
	}
	if len(exact) > 0 {
		return exact
	}

	q := strings.ToLower(query)
	var substr []entry.Entry
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.Name), q) ||
			strings.Contains(strings.ToLower(e.Username), q) ||
			strings.Contains(strings.ToLower(e.Notes), q) {
			substr = append(substr, e)
		}
	}
	return substr
}

// resolveOne resolves query to exactly one entry. On success it
// returns the entry with ok true; otherwise it has already written the
// standard diagnostic to stderr and returns the exit code the caller
// should return — no match (§5) or a list of the candidates that made
// the query ambiguous.
//
// Every command that acts on a single entry funnels through here, so
// they cannot drift apart in how they report these two cases.
func resolveOne(entries []entry.Entry, query string) (match entry.Entry, code int, ok bool) {
	matches := resolve(entries, query)
	switch len(matches) {
	case 1:
		return matches[0], ExitOK, true
	case 0:
		fmt.Fprintf(os.Stderr, "error: no entry matches %q\n", query)
		return entry.Entry{}, ExitNotFound, false
	default:
		fmt.Fprintln(os.Stderr, "error: multiple entries match:")
		for _, e := range matches {
			fmt.Fprintf(os.Stderr, "  %s\t%s\n", e.Name, e.Username)
		}
		return entry.Entry{}, ExitAmbiguous, false
	}
}
