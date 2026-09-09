package cli

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// ErrNoTTY means /dev/tty could not be opened and $PASSGO_MASTER is
// not set, so there is no way to read the master password. Per
// SPECIFICATION.md §4, this is a usage error, not read from stdin.
var ErrNoTTY = errors.New("no TTY available and $PASSGO_MASTER is not set")

// readPassword returns the master password: $PASSGO_MASTER if set
// (documented as discouraged — for scripting and tests only), otherwise
// a single prompt read from /dev/tty with echo disabled.
func readPassword(prompt string) (string, error) {
	if pw, ok := os.LookupEnv("PASSGO_MASTER"); ok {
		return pw, nil
	}
	return promptTTY(prompt)
}

// readNewPassword prompts twice, as `init` and `passwd` require, and
// fails if the two entries don't match. $PASSGO_MASTER short-circuits
// both prompts, same as readPassword.
func readNewPassword() (string, error) {
	if pw, ok := os.LookupEnv("PASSGO_MASTER"); ok {
		return pw, nil
	}
	p1, err := promptTTY("New master password: ")
	if err != nil {
		return "", err
	}
	p2, err := promptTTY("Confirm master password: ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", errors.New("passwords did not match")
	}
	return p1, nil
}

// promptTTY reads a line from /dev/tty with echo disabled, regardless
// of what stdin/stdout are — this is what lets `passgo get x | pbcopy`
// still prompt correctly while stdout is a pipe.
func promptTTY(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNoTTY, err)
	}
	defer tty.Close()

	fmt.Fprint(tty, prompt)
	pw, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", err
	}
	return string(pw), nil
}
