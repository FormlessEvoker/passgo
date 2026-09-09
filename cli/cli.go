// Package cli implements the passgo command-line interface: argument
// parsing and dispatch for each subcommand in SPECIFICATION.md §6, on
// top of the store package.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/FormlessEvoker/passgo/vault"
)

const version = "0.1.0-dev"

const usage = `passgo — a small, local-first password manager

Usage:
  passgo init
  passgo add <name> [-u username] (-p | -g [length]) [-n notes]
  passgo get <query> [-u username] [--clip]
  passgo --version | --help

Global flags:
  --vault <path>   Use this vault file instead of the resolved default.

See SPECIFICATION.md for the full command reference.
`

// Run parses args (os.Args[1:]) and executes the requested subcommand,
// returning the process exit code.
func Run(args []string) int {
	vaultPath, rest, err := extractGlobalFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitUsage
	}

	if len(rest) == 0 {
		printUsage(os.Stderr)
		return ExitUsage
	}

	cmd, cmdArgs := rest[0], rest[1:]

	switch cmd {
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return ExitOK
	case "version", "--version":
		fmt.Println("passgo", version)
		return ExitOK
	}

	if vaultPath == "" {
		vaultPath, err = vault.ResolvePath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return ExitGeneral
		}
	}

	switch cmd {
	case "init":
		return runInit(vaultPath, cmdArgs)
	case "add":
		return runAdd(vaultPath, cmdArgs)
	case "get":
		return runGet(vaultPath, cmdArgs)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", cmd)
		printUsage(os.Stderr)
		return ExitUsage
	}
}

// extractGlobalFlags pulls --vault <path> out of args regardless of
// position, returning the vault path (empty if not given) and the
// remaining args in their original order otherwise.
func extractGlobalFlags(args []string) (vaultPath string, rest []string, err error) {
	for i := 0; i < len(args); i++ {
		if args[i] == "--vault" {
			if i+1 >= len(args) {
				return "", nil, errors.New("--vault requires a path argument")
			}
			vaultPath = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return vaultPath, rest, nil
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, usage)
}
