package cli

import (
	"strings"

	"github.com/FormlessEvoker/passgo/entry"
)

// resolve implements query resolution per SPECIFICATION.md §5: an
// exact, case-insensitive match on name, falling back to a
// case-insensitive substring match on name, username, or notes.
// usernameFilter, if non-empty, narrows the candidate set to entries
// with an exact case-insensitive username match before either stage
// runs — this is what -u/--username does.
func resolve(entries []entry.Entry, query, usernameFilter string) []entry.Entry {
	candidates := entries
	if usernameFilter != "" {
		var filtered []entry.Entry
		for _, e := range candidates {
			if strings.EqualFold(e.Username, usernameFilter) {
				filtered = append(filtered, e)
			}
		}
		candidates = filtered
	}

	var exact []entry.Entry
	for _, e := range candidates {
		if strings.EqualFold(e.Name, query) {
			exact = append(exact, e)
		}
	}
	if len(exact) > 0 {
		return exact
	}

	q := strings.ToLower(query)
	var substr []entry.Entry
	for _, e := range candidates {
		if strings.Contains(strings.ToLower(e.Name), q) ||
			strings.Contains(strings.ToLower(e.Username), q) ||
			strings.Contains(strings.ToLower(e.Notes), q) {
			substr = append(substr, e)
		}
	}
	return substr
}
