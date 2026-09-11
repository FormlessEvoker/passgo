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

// ErrRekeyed means Save was called on a Store whose vault has already
// been re-encrypted under a new master password by ChangePassword.
// The key this Store holds no longer matches the file on disk, so
// saving would re-encrypt the vault under the superseded password and
// lock the user out with a password they just replaced.
var ErrRekeyed = errors.New("store: vault was re-encrypted by ChangePassword; reopen it before saving")

// Store is an open vault: its decrypted entries, plus enough state to
// write changes back to the same file without re-deriving the key.
type Store struct {
	Payload entry.Payload

	path     string
	opened   *vault.Opened
	rawBytes []byte // the file's on-disk contents as of Open/last Save
	rekeyed  bool   // ChangePassword has superseded opened's key
}

// Init creates a new, empty vault at path. It fails if a file already
// exists there — overwriting is never implicit, per SPECIFICATION.md §6.
//
// The real no-overwrite guarantee comes from
// vault.WriteAtomicNoOverwrite, which fails atomically (via os.Link)
// rather than racing a stat check against a concurrent writer. The
// stat here is just a fast path so a doomed `init` fails before
// paying for a master-password prompt and an Argon2id derivation.
func Init(path, password string) (vault.WriteOutcome, error) {
	if _, err := os.Stat(path); err == nil {
		return vault.WriteFailed, fmt.Errorf("%w: vault already exists at %s", os.ErrExist, path)
	} else if !os.IsNotExist(err) {
		return vault.WriteFailed, err
	}

	data, err := entry.Marshal(entry.New())
	if err != nil {
		return vault.WriteFailed, err
	}
	fileBytes, err := vault.Create(password, data)
	if err != nil {
		return vault.WriteFailed, err
	}
	outcome, err := vault.WriteAtomicNoOverwrite(path, fileBytes)
	if os.IsExist(err) {
		return outcome, fmt.Errorf("%w: vault already exists at %s", os.ErrExist, path)
	}
	return outcome, err
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

// commit writes fileBytes over the vault: the pre-write conflict
// check, the atomic write, and recording what is now on disk.
//
// Save and ChangePassword end in exactly this sequence and differ
// only in how they produce fileBytes, so the bookkeeping that keeps a
// Store honest about the file lives here once. Splitting it between
// the two is what previously let them disagree about a committed but
// non-durable write: past the rename that write *is* the file on
// disk, so rawBytes must advance even though an error is returned. A
// Store that skipped it would go on believing in a file it had
// already replaced, and report a conflict against its own write.
//
// The conflict check sits here rather than in the callers so that it
// runs immediately before the write. ChangePassword derives a new key
// first, which costs roughly half a second (§4) — time that would
// otherwise sit between checking for a concurrent write and
// performing one.
func (s *Store) commit(fileBytes []byte) (vault.WriteOutcome, error) {
	current, err := os.ReadFile(s.path)
	if err != nil {
		return vault.WriteFailed, err
	}
	if !bytes.Equal(current, s.rawBytes) {
		return vault.WriteFailed, ErrConflict
	}

	outcome, err := vault.WriteAtomic(s.path, fileBytes)
	if outcome.Committed() {
		// Past the rename this write is the file on disk, durable or
		// not, so the snapshot advances on both committed outcomes.
		s.rawBytes = fileBytes
	}
	return outcome, err
}

// Save re-encrypts s.Payload and atomically writes it back to the
// vault file, under the same key and KDF parameters it was opened
// with — no re-derivation of the key from the master password.
//
// It refuses with ErrConflict if the file on disk no longer matches
// what this Store read at Open (or last wrote) — see ErrConflict.
func (s *Store) Save() (vault.WriteOutcome, error) {
	if s.rekeyed {
		return vault.WriteFailed, ErrRekeyed
	}

	data, err := entry.Marshal(s.Payload)
	if err != nil {
		return vault.WriteFailed, err
	}
	fileBytes, err := s.opened.Save(data)
	if err != nil {
		return vault.WriteFailed, err
	}
	return s.commit(fileBytes)
}

// ChangePassword re-encrypts the vault under newPassword and writes
// it back, per SPECIFICATION.md §6. The payload is re-serialized from
// s.Payload unchanged; only the key material differs.
//
// Unlike Save, which reuses the key and parameters the vault was
// opened with, this derives a fresh key under a freshly generated
// salt and nonce (§2.1), so nothing about the old password survives
// in the new file.
//
// It takes the same conflict check as Save and leaves the Store
// spent: see ErrRekeyed.
func (s *Store) ChangePassword(newPassword string) (vault.WriteOutcome, error) {
	if s.rekeyed {
		return vault.WriteFailed, ErrRekeyed
	}

	data, err := entry.Marshal(s.Payload)
	if err != nil {
		return vault.WriteFailed, err
	}
	fileBytes, err := vault.Create(newPassword, data)
	if err != nil {
		return vault.WriteFailed, err
	}

	outcome, err := s.commit(fileBytes)
	if outcome.Committed() {
		// Past the rename the vault already requires newPassword, so
		// this Store's key is superseded whether or not the write was
		// durable. A conflict, by contrast, wrote nothing.
		s.rekeyed = true
	}
	return outcome, err
}
