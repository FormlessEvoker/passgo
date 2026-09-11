package cli

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func isTTY(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// printSecret writes a secret to stdout, terminating it with a
// newline only when stdout is a terminal, per docs/SPECIFICATION.md §6.
// Piping therefore yields the exact secret and nothing else: a
// trailing newline carried into `| pbcopy` and pasted into a password
// field can submit the form early.
//
// Every path that puts a secret on stdout goes through here — `get`,
// `gen`, and the -g paths of `add` and `edit` — so none of them can
// drift from the rule.
func printSecret(secret string) {
	if isTTY(os.Stdout) {
		fmt.Println(secret)
	} else {
		fmt.Print(secret)
	}
}
