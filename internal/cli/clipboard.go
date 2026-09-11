package cli

import (
	"bytes"
	"fmt"
	"os/exec"
)

// clipboardCommands lists the external clipboard tools `get --clip`
// tries, in order, along with the args that make each read the text to
// copy from stdin. No clipboard library dependency is taken — this
// just shells out, per docs/SPECIFICATION.md §6.
var clipboardCommands = [][]string{
	{"pbcopy"},
	{"wl-copy"},
	{"xclip", "-selection", "clipboard"},
}

func copyToClipboard(text string) error {
	var lastErr error
	for _, cmd := range clipboardCommands {
		path, err := exec.LookPath(cmd[0])
		if err != nil {
			lastErr = err
			continue
		}
		c := exec.Command(path, cmd[1:]...)
		c.Stdin = bytes.NewBufferString(text)
		if err := c.Run(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("no clipboard tool found (tried pbcopy, wl-copy, xclip): %w", lastErr)
}
