package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ErrNoTTY means /dev/tty could not be opened and there is no other
// way to read the master password ($PASSGO_MASTER is not set and no
// password file was given). Per SPECIFICATION.md §4, this is a usage
// error, not read from stdin.
var ErrNoTTY = errors.New("no TTY available and $PASSGO_MASTER is not set")

// readPassword returns the master password. In order of precedence:
// passwordFile if non-empty (from --master-password-file or
// $PASSGO_MASTER_FILE), then $PASSGO_MASTER (documented as
// discouraged — for scripting and tests only), otherwise a single
// prompt read from /dev/tty with echo disabled.
func readPassword(prompt, passwordFile string) (string, error) {
	if passwordFile != "" {
		return readPasswordFile(passwordFile, os.Stderr)
	}
	if pw, ok := os.LookupEnv("PASSGO_MASTER"); ok {
		return pw, nil
	}
	return promptTTY(prompt)
}

// readNewPassword prompts twice, as `init` and `passwd` require, and
// fails if the two entries don't match. passwordFile and
// $PASSGO_MASTER short-circuit both prompts, same as readPassword.
func readNewPassword(passwordFile string) (string, error) {
	if passwordFile != "" {
		return readPasswordFile(passwordFile, os.Stderr)
	}
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

// readPasswordFile reads the master password from path: the file's
// contents with a single trailing newline stripped, same convention
// as ssh-keygen passphrase files and similar tools. If it is readable
// by group or other, a warning is written to warn (typically
// os.Stderr) — the same leniency vault.ReadFile already gives the
// vault file itself.
func readPasswordFile(path string, warn io.Writer) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o044 != 0 {
		fmt.Fprintf(warn, "warning: %s is readable by group or other; consider chmod 600\n", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return stripOneTrailingNewline(string(data)), nil
}

// stripOneTrailingNewline removes exactly one trailing "\n" (and its
// optional preceding "\r"), leaving any further trailing newlines
// alone. Editors write one final newline as a matter of convention,
// not as part of the content, so only that one is not part of the
// password — unlike strings.TrimRight("\r\n"), which would also eat
// deliberate trailing blank lines the file's author put there.
func stripOneTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
		if strings.HasSuffix(s, "\r") {
			s = s[:len(s)-1]
		}
	}
	return s
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
