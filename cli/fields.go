package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/FormlessEvoker/passgo/crypto"
)

// fieldFlags is the set of entry-field flags shared by `add` and
// `edit`. SPECIFICATION.md §6 defines edit's flags as "the same field
// flags as add, with the same meanings", so both parse them through
// here rather than keeping two copies free to drift apart.
//
// Each value carries a Set bit because edit changes only the fields
// whose flags were given, and "given, but empty" is a real request:
// `edit x -n ""` clears the notes, which is not the same as omitting
// -n entirely.
type fieldFlags struct {
	username     string
	usernameSet  bool
	notes        string
	notesSet     bool
	wantPassword bool
	wantGen      bool
	genLength    int
}

// parseFieldFlags parses the shared -u/-p/-g/-n flags out of args.
// Callers apply their own rule about which combinations are required:
// `add` needs exactly one of -p/-g, `edit` accepts neither.
func parseFieldFlags(args []string) (fieldFlags, error) {
	f := fieldFlags{genLength: crypto.DefaultGenLength}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-u", "--username":
			if i+1 >= len(args) {
				return f, errors.New("-u/--username requires a value")
			}
			i++
			f.username, f.usernameSet = args[i], true
		case "-p", "--password":
			f.wantPassword = true
		case "-g", "--gen":
			f.wantGen = true
			// The length argument is optional: only consume the next
			// token if it actually parses as a positive integer.
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					f.genLength = n
					i++
				}
			}
		case "-n", "--notes":
			if i+1 >= len(args) {
				return f, errors.New("-n/--notes requires a value")
			}
			i++
			f.notes, f.notesSet = args[i], true
		default:
			return f, fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if f.wantPassword && f.wantGen {
		return f, errors.New("-p and -g are mutually exclusive")
	}
	return f, nil
}

// changesSecret reports whether -p or -g was given, meaning the
// caller should replace the entry's secret.
func (f fieldFlags) changesSecret() bool { return f.wantPassword || f.wantGen }

// any reports whether at least one field flag was given at all.
func (f fieldFlags) any() bool {
	return f.usernameSet || f.notesSet || f.changesSecret()
}

// newSecret produces the secret implied by -p (prompt for it) or -g
// (generate one). Call it only when changesSecret reports true.
//
// It returns the exit code to use on failure, because the two sources
// fail differently: a prompt that cannot reach a terminal is a usage
// error, while a generator failure is not.
func (f fieldFlags) newSecret() (string, int, error) {
	if f.wantPassword {
		pw, err := promptSecret("Password: ")
		if err != nil {
			return "", ExitUsage, err
		}
		return pw, ExitOK, nil
	}
	gen, err := crypto.GeneratePassword(f.genLength)
	if err != nil {
		return "", ExitGeneral, err
	}
	return gen, ExitOK, nil
}

// validateName rejects a name that could not identify an entry.
// `name` is required (§3.2), and a blank one would be unaddressable
// by any query as well as sorting ahead of everything else.
func validateName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("name must not be empty")
	}
	return nil
}
