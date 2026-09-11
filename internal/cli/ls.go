package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/FormlessEvoker/passgo/internal/entry"
	"github.com/FormlessEvoker/passgo/internal/store"
)

// runLs implements `passgo ls [query]` per docs/SPECIFICATION.md §6: lists
// matching entries as an aligned table of name, username, and
// updated, never printing secrets. With no query, lists everything.
func runLs(vaultPath, passwordFile string, args []string) int {
	var query string
	switch len(args) {
	case 0:
		// list everything
	case 1:
		query = args[0]
	default:
		fmt.Fprintln(os.Stderr, "error: ls takes at most one <query> argument")
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

	// No sort here: store.Open returns entries in the order
	// entry.Marshal last wrote them in, which is always sorted by
	// name then username (entry.go). resolve() filters without
	// reordering, so that sort order carries through unchanged.
	matches := s.Payload.Entries
	if query != "" {
		idxs := resolve(s.Payload.Entries, query)
		matches = make([]entry.Entry, 0, len(idxs))
		for _, i := range idxs {
			matches = append(matches, s.Payload.Entries[i])
		}
	}

	printEntryTable(os.Stdout, matches)
	return ExitOK
}

// printEntryTable writes entries to w as a tab-aligned table of name,
// username, and updated (RFC 3339), one entry per line — never the
// secret. An empty entries slice prints nothing, not even a header,
// so the output stays trivially composable with grep/awk.
func printEntryTable(w io.Writer, entries []entry.Entry) {
	if len(entries) == 0 {
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Name, e.Username, e.Updated.Format(time.RFC3339))
	}
	tw.Flush()
}
