package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/FormlessEvoker/passgo/entry"
	"github.com/FormlessEvoker/passgo/store"
)

// runLs implements `passgo ls [query]` per SPECIFICATION.md §6: lists
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

	matches := s.Payload.Entries
	if query != "" {
		matches = resolve(s.Payload.Entries, query, "")
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
