package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// stdin is where promptSecret reads an entry's secret from — distinct
// from the master password, which always comes from /dev/tty or
// $PASSGO_MASTER (see password.go). A package variable, rather than a
// parameter threaded through every command, so tests can substitute a
// plain reader without needing a real terminal.
var stdin io.Reader = os.Stdin

// promptSecret writes prompt to stderr and reads one line from stdin,
// with echo disabled if stdin is an interactive terminal.
func promptSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		pw, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(pw), nil
	}

	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
