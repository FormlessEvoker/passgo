// Package cli implements the passgo command-line interface: argument
// parsing and dispatch for each subcommand in SPECIFICATION.md §6, on
// top of the store package.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/FormlessEvoker/passgo/vault"
)

const usage = `passgo — a small, local-first password manager

Usage:
  passgo init
  passgo add <name> [-u username] (-p | -g [length]) [-n notes]
  passgo get <query> [-u username] [--clip]
  passgo ls [query]
  passgo --version | --help

Global flags:
  --vault <path>                  Use this vault file instead of the resolved default.
  --master-password-file <path>   Read the master password from this file instead of prompting.

See SPECIFICATION.md for the full command reference.
`

// Run parses args (os.Args[1:]) and executes the requested subcommand,
// returning the process exit code.
func Run(args []string) int {
	vaultPath, passwordFile, rest, err := extractGlobalFlags(args)
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
		fmt.Println("passgo", versionString())
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
		return runInit(vaultPath, passwordFile, cmdArgs)
	case "add":
		return runAdd(vaultPath, passwordFile, cmdArgs)
	case "get":
		return runGet(vaultPath, passwordFile, cmdArgs)
	case "ls":
		return runLs(vaultPath, passwordFile, cmdArgs)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", cmd)
		printUsage(os.Stderr)
		return ExitUsage
	}
}

// extractGlobalFlags pulls --vault <path> and --master-password-file
// <path> out of args regardless of position, returning each (empty if
// not given) and the remaining args in their original order
// otherwise. --master-password-file falls back to $PASSGO_MASTER_FILE
// when the flag is absent.
func extractGlobalFlags(args []string) (vaultPath, passwordFile string, rest []string, err error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--vault":
			if i+1 >= len(args) {
				return "", "", nil, errors.New("--vault requires a path argument")
			}
			vaultPath = args[i+1]
			i++
		case "--master-password-file":
			if i+1 >= len(args) {
				return "", "", nil, errors.New("--master-password-file requires a path argument")
			}
			passwordFile = args[i+1]
			i++
		default:
			rest = append(rest, args[i])
		}
	}
	if passwordFile == "" {
		passwordFile = os.Getenv("PASSGO_MASTER_FILE")
	}
	return vaultPath, passwordFile, rest, nil
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, usage)
}

// versionString reports the module version Go resolved this binary
// against — e.g. "v0.2.0" for `go install .../passgo@v0.2.0` — read
// from the build info Go embeds automatically. No ldflags wiring
// needed at build time. A local `go build` inside the repo instead
// gets Go's git-derived pseudo-version (commit hash, "+dirty" if the
// working tree had uncommitted changes), which is more useful for a
// dev build than a flat "dev" string would be.
func versionString() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "dev"
	}
	return info.Main.Version
}
