package vault

import (
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
// If any step fails, the temp file is removed and the original vault
// (if any) is left untouched.
func WriteAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmpPath, err := writeTemp(dir, data)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(tmpPath)
		}
	}()

	if _, statErr := os.Stat(path); statErr == nil {
		if err = copyFile(path, path+".bak"); err != nil {
			return err
		}
	}

	if err = os.Rename(tmpPath, path); err != nil {
		return err
	}
	return fsyncDir(dir)
}

// WriteAtomicNoOverwrite is WriteAtomic's counterpart for `init`: it
// fails rather than replacing an existing vault. Unlike a
// stat-then-write check, os.Link is atomic — it fails with
// os.ErrExist if path already exists, so there is no window between
// checking and creating for a concurrent writer to land in.
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
	return fsyncDir(dir)
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
