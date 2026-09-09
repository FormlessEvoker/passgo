// Command passgo is a small, local-first password manager for the
// command line. See SPECIFICATION.md for the vault format and the
// exact behavior of each command.
package main

import (
	"os"

	"github.com/FormlessEvoker/passgo/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
