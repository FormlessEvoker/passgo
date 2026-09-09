package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/FormlessEvoker/passgo/entry"
)

func TestInitOpenSaveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "vault.pgv")

	if err := Init(path, "correct horse"); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if s.Payload.Version != entry.PayloadVersion {
		t.Errorf("Version = %d, want %d", s.Payload.Version, entry.PayloadVersion)
	}
	if len(s.Payload.Entries) != 0 {
		t.Errorf("expected a freshly initialized vault to be empty, got %d entries", len(s.Payload.Entries))
	}

	s.Payload.Entries = append(s.Payload.Entries, entry.Entry{
		Name: "github.com", Username: "me@example.com", Secret: "s3cr3t", Updated: entry.Now(),
	})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if len(s2.Payload.Entries) != 1 || s2.Payload.Entries[0].Name != "github.com" {
		t.Errorf("entries did not persist across Save/Open: %+v", s2.Payload.Entries)
	}
}

func TestInitFailsIfVaultExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pgv")
	if err := Init(path, "pw"); err != nil {
		t.Fatal(err)
	}

	err := Init(path, "pw")
	if err == nil {
		t.Fatal("expected Init to fail when a vault already exists")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Errorf("expected an os.ErrExist-wrapped error, got: %v", err)
	}
}

func TestOpenWrongPasswordFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pgv")
	if err := Init(path, "correct horse"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, "wrong password"); err == nil {
		t.Error("Open succeeded with the wrong password")
	}
}

func TestSaveDetectsConcurrentModification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pgv")
	if err := Init(path, "pw"); err != nil {
		t.Fatal(err)
	}

	s1, err := Open(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	s2, err := Open(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	// s1 saves first...
	s1.Payload.Entries = append(s1.Payload.Entries, entry.Entry{Name: "a.com", Secret: "1", Updated: entry.Now()})
	if err := s1.Save(); err != nil {
		t.Fatal(err)
	}

	// ...so s2's Save, still based on the original file, must be
	// refused rather than silently discarding s1's entry.
	s2.Payload.Entries = append(s2.Payload.Entries, entry.Entry{Name: "b.com", Secret: "2", Updated: entry.Now()})
	err = s2.Save()
	if !errors.Is(err, ErrConflict) {
		t.Errorf("s2.Save() after a concurrent write: err = %v, want ErrConflict", err)
	}

	// s1's write must have survived untouched.
	s3, err := Open(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if len(s3.Payload.Entries) != 1 || s3.Payload.Entries[0].Name != "a.com" {
		t.Errorf("vault contents after a refused conflicting save: %+v", s3.Payload.Entries)
	}
}

func TestSaveSortsAndPersistsEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pgv")
	if err := Init(path, "pw"); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	s.Payload.Entries = []entry.Entry{
		{Name: "b.com", Secret: "1", Updated: entry.Now()},
		{Name: "a.com", Secret: "2", Updated: entry.Now()},
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := Open(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if len(s2.Payload.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(s2.Payload.Entries))
	}
	if s2.Payload.Entries[0].Name != "a.com" || s2.Payload.Entries[1].Name != "b.com" {
		t.Errorf("entries not sorted by name after Save: %+v", s2.Payload.Entries)
	}
}
