package vault

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	vaultMode = 0o600
	dirMode   = 0o700
)

// ReadFile reads the vault file at path. If it is readable by group or
// other, a warning is written to warn (typically os.Stderr) — the spec
// requires this on open, but does not treat it as fatal.
func ReadFile(path string, warn io.Writer) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o044 != 0 {
		fmt.Fprintf(warn, "warning: %s is readable by group or other; consider chmod 600\n", path)
	}
	return os.ReadFile(path)
}

// ErrNotDurable reports a write that was installed but may not
// survive a crash: the rename completed, so the new contents are
// already what any reader sees, but the containing directory could
// not be fsynced. The data is live; only its durability is in doubt.
//
// It is kept distinct from every other write error because the
// caller's recovery is the opposite. An error before the rename means
// nothing changed and the old file stands. This means everything
// changed. Reporting the two the same way would tell a user their
// `passwd` failed when the vault already requires the new password —
// the one mistake that can strand someone outside their own vault.
var ErrNotDurable = errors.New("vault: write installed but directory fsync failed")

// syncDir indirects fsyncDir so tests can exercise the one failure
// mode that cannot be provoked naturally: a directory sync failing
// after the rename has already committed. That window is why
// ErrNotDurable exists, so it needs to be reachable in a test.
var syncDir = fsyncDir

// WriteAtomic writes data to path, overwriting an existing vault only
// via an atomic rename — never truncating it in place — per
// SPECIFICATION.md §3.4:
//
//  1. write to a temp file in the same directory (same filesystem, so
//     the rename is atomic), mode 0600;
//  2. fsync the temp file;
//  3. copy the current vault to path+".bak" if one exists;
//  4. rename the temp file over path;
//  5. fsync the containing directory.
//
// Step 4 is the commit point, and failures on either side of it mean
// opposite things. If any step before the rename fails, the temp file
// is removed and the original vault (if any) is left untouched. If
// the rename succeeds and only step 5 fails, the new data is already
// installed and visible to every reader; WriteAtomic then returns an
// error wrapping ErrNotDurable, and callers MUST treat the write as
// having taken effect rather than as a failure.
func WriteAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmpPath, err := writeTemp(dir, data)
	if err != nil {
		return err
	}
	// Cleanup applies only before the rename. Past it the temp file no
	// longer exists under that name, and the write has committed.
	renamed := false
	defer func() {
		if err != nil && !renamed {
			os.Remove(tmpPath)
		}
	}()

	switch _, statErr := os.Stat(path); {
	case statErr == nil:
		if err = copyFile(path, path+".bak"); err != nil {
			return err
		}
	case os.IsNotExist(statErr):
		// No existing vault, so nothing to back up.
	default:
		// A permission error or similar: not knowing whether a vault
		// exists here means not knowing whether a backup is owed, so
		// fail loudly rather than silently skipping it.
		return statErr
	}

	if err = os.Rename(tmpPath, path); err != nil {
		return err
	}
	renamed = true

	if syncErr := syncDir(dir); syncErr != nil {
		err = fmt.Errorf("%w: %v", ErrNotDurable, syncErr)
		return err
	}
	return nil
}

// WriteAtomicNoOverwrite is WriteAtomic's counterpart for `init`: it
// fails rather than replacing an existing vault. Unlike a
// stat-then-write check, os.Link is atomic — it fails with
// os.ErrExist if path already exists, so there is no window between
// checking and creating for a concurrent writer to land in.
//
// The link is this function's commit point, and it carries the same
// ErrNotDurable distinction WriteAtomic does: a failure to fsync the
// directory afterwards leaves a created vault behind, not nothing.
func WriteAtomicNoOverwrite(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmpPath, err := writeTemp(dir, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	if err = os.Link(tmpPath, path); err != nil {
		return err
	}
	// Past the commit point here too: the link is what makes the vault
	// exist, so a failed directory fsync leaves a created vault behind
	// rather than nothing.
	if syncErr := syncDir(dir); syncErr != nil {
		err = fmt.Errorf("%w: %v", ErrNotDurable, syncErr)
		return err
	}
	return nil
}

// writeTemp creates the vault's containing directory if needed and
// writes data to a fresh, fsynced temp file inside it (mode 0600),
// returning the temp file's path.
func writeTemp(dir string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return "", err
	}

	tmp, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()

	if err := tmp.Chmod(vaultMode); err != nil {
		tmp.Close()
		return tmpPath, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return tmpPath, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return tmpPath, err
	}
	if err := tmp.Close(); err != nil {
		return tmpPath, err
	}
	return tmpPath, nil
}

// fsyncDir opens dir and fsyncs it, so a preceding rename or link
// inside it is durable across a crash — the final step of §3.4.
// Errors are returned rather than ignored: if this fails, the write
// may not survive a crash, and callers need to know that.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, vaultMode)
}

// ResolvePath returns the vault file path, per SPECIFICATION.md §3.3:
// $PASSGO_VAULT, then $XDG_DATA_HOME/passgo/vault.pgv, then
// ~/.local/share/passgo/vault.pgv.
func ResolvePath() (string, error) {
	if p := os.Getenv("PASSGO_VAULT"); p != "" {
		return p, nil
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "passgo", "vault.pgv"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "passgo", "vault.pgv"), nil
}
