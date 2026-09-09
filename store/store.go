// Package store ties the vault envelope (package vault) and the entry
// schema (package entry) together into the operations a command needs:
// create a new vault, open an existing one, and save changes back.
package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/FormlessEvoker/passgo/entry"
	"github.com/FormlessEvoker/passgo/vault"
)

// ErrConflict means the vault file on disk changed since this Store
// was opened — most likely a second passgo process ran an Open/Save
// of its own in between. Save refuses to overwrite it: a lost-update
// race (both processes read, both write, one silently disappears) is
// worse than making the second Save fail and ask the caller to retry
// against the current vault.
//
// This is an optimistic check, not a lock: it catches the case where
// the other write finished before this Save runs, not a write that
// lands in the middle of it. Good enough for the everyday "two
// terminals" case this is aimed at, not a substitute for real
// coordination if that's ever needed.
var ErrConflict = errors.New("store: vault was modified since it was opened; re-run to see the latest changes")

// Store is an open vault: its decrypted entries, plus enough state to
// write changes back to the same file without re-deriving the key.
type Store struct {
	Payload entry.Payload

	path     string
	opened   *vault.Opened
	rawBytes []byte // the file's on-disk contents as of Open/last Save
}

// Init creates a new, empty vault at path. It fails if a file already
// exists there — overwriting is never implicit, per SPECIFICATION.md §6.
//
// The real no-overwrite guarantee comes from
// vault.WriteAtomicNoOverwrite, which fails atomically (via os.Link)
// rather than racing a stat check against a concurrent writer. The
// stat here is just a fast path so a doomed `init` fails before
// paying for a master-password prompt and an Argon2id derivation.
func Init(path, password string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w: vault already exists at %s", os.ErrExist, path)
	} else if !os.IsNotExist(err) {
		return err
	}

	data, err := entry.Marshal(entry.New())
	if err != nil {
		return err
	}
	fileBytes, err := vault.Create(password, data)
	if err != nil {
		return err
	}
	if err := vault.WriteAtomicNoOverwrite(path, fileBytes); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%w: vault already exists at %s", os.ErrExist, path)
		}
		return err
	}
	return nil
}

// Open decrypts the vault at path with password and parses its entries.
func Open(path, password string) (*Store, error) {
	fileBytes, err := vault.ReadFile(path, os.Stderr)
	if err != nil {
		return nil, err
	}
	o, err := vault.Open(fileBytes, password)
	if err != nil {
		return nil, err
	}
	p, err := entry.Unmarshal(o.Plaintext)
	if err != nil {
		o.Close()
		return nil, err
	}
	return &Store{Payload: p, path: path, opened: o, rawBytes: fileBytes}, nil
}

// Close zeroes the key material held by s. Callers should defer it
// after a successful Open.
func (s *Store) Close() {
	s.opened.Close()
}

// Save re-encrypts s.Payload and atomically writes it back to the
// vault file, under the same key and KDF parameters it was opened
// with — no re-derivation of the key from the master password.
//
// It first checks that the file on disk still matches what this Store
// read at Open (or the last successful Save), and refuses with
// ErrConflict if not — see ErrConflict's doc comment.
func (s *Store) Save() error {
	current, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, s.rawBytes) {
		return ErrConflict
	}

	data, err := entry.Marshal(s.Payload)
	if err != nil {
		return err
	}
	fileBytes, err := s.opened.Save(data)
	if err != nil {
		return err
	}
	if err := vault.WriteAtomic(s.path, fileBytes); err != nil {
		return err
	}
	s.rawBytes = fileBytes
	return nil
}
