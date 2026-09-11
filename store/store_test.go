package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/FormlessEvoker/passgo/entry"
	"github.com/FormlessEvoker/passgo/vault"
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

func TestChangePasswordRotatesAndPreservesEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pgv")
	if err := Init(path, "old pw"); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, "old pw")
	if err != nil {
		t.Fatal(err)
	}
	s.Payload.Entries = append(s.Payload.Entries, entry.Entry{Name: "a.com", Secret: "1", Updated: entry.Now()})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword("new pw"); err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := Open(path, "old pw"); err == nil {
		t.Error("old password still opens the vault after ChangePassword")
	}

	reopened, err := Open(path, "new pw")
	if err != nil {
		t.Fatalf("new password does not open the vault: %v", err)
	}
	defer reopened.Close()
	if len(reopened.Payload.Entries) != 1 || reopened.Payload.Entries[0].Secret != "1" {
		t.Errorf("entries after ChangePassword: %+v", reopened.Payload.Entries)
	}
}

// TestChangePasswordDetectsConcurrentModification is the rotation
// counterpart of TestSaveDetectsConcurrentModification: a rekey based
// on a stale read must be refused rather than re-encrypting an old
// snapshot over someone else's write — which would discard their
// entry *and* change the password needed to discover that.
func TestChangePasswordDetectsConcurrentModification(t *testing.T) {
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

	s1.Payload.Entries = append(s1.Payload.Entries, entry.Entry{Name: "a.com", Secret: "1", Updated: entry.Now()})
	if err := s1.Save(); err != nil {
		t.Fatal(err)
	}

	if err := s2.ChangePassword("new pw"); !errors.Is(err, ErrConflict) {
		t.Errorf("ChangePassword after a concurrent write: err = %v, want ErrConflict", err)
	}

	// The refusal must be total: s1's entry survives, and the password
	// must not have moved.
	s3, err := Open(path, "pw")
	if err != nil {
		t.Fatalf("vault no longer opens under the original password: %v", err)
	}
	defer s3.Close()
	if len(s3.Payload.Entries) != 1 || s3.Payload.Entries[0].Name != "a.com" {
		t.Errorf("vault contents after a refused rotation: %+v", s3.Payload.Entries)
	}
}

// TestSaveAfterChangePasswordIsRefused covers the spent-Store guard.
// The key held in memory no longer matches the file, so a Save would
// re-encrypt under the password the user just replaced.
func TestSaveAfterChangePasswordIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pgv")
	if err := Init(path, "old pw"); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, "old pw")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.ChangePassword("new pw"); err != nil {
		t.Fatal(err)
	}

	s.Payload.Entries = append(s.Payload.Entries, entry.Entry{Name: "late.com", Secret: "x", Updated: entry.Now()})
	if err := s.Save(); !errors.Is(err, ErrRekeyed) {
		t.Errorf("Save() after ChangePassword: err = %v, want ErrRekeyed", err)
	}
	if err := s.ChangePassword("third pw"); !errors.Is(err, ErrRekeyed) {
		t.Errorf("second ChangePassword: err = %v, want ErrRekeyed", err)
	}

	// The refused writes must have left the vault exactly as the
	// rotation wrote it.
	reopened, err := Open(path, "new pw")
	if err != nil {
		t.Fatalf("vault does not open under the rotated password: %v", err)
	}
	defer reopened.Close()
	if len(reopened.Payload.Entries) != 0 {
		t.Errorf("refused Save leaked an entry into the vault: %+v", reopened.Payload.Entries)
	}
	if _, err := Open(path, "third pw"); err == nil {
		t.Error("a refused second rotation still changed the password")
	}
}

// TestChangePasswordRecordsANonDurableRotation covers the window that
// can strand a user outside their own vault. vault.WriteAtomic can
// fail *after* the rename has installed the new file, meaning the
// vault already requires the new password even though an error comes
// back. ChangePassword must record the rotation anyway, so nothing
// downstream tells the user to keep using a password that no longer
// works.
func TestChangePasswordRecordsANonDurableRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pgv")
	if err := Init(path, "old pw"); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, "old pw")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// The real write runs and commits; only the directory sync fails.
	defer vault.FailSyncDir(errors.New("simulated"))()

	err = s.ChangePassword("new pw")
	if !errors.Is(err, vault.ErrNotDurable) {
		t.Fatalf("ChangePassword: err = %v, want ErrNotDurable", err)
	}

	// The vault really does require the new password now.
	if _, openErr := Open(path, "old pw"); openErr == nil {
		t.Error("old password still opens the vault; the rename did commit")
	}
	rotated, openErr := Open(path, "new pw")
	if openErr != nil {
		t.Fatalf("new password does not open the vault: %v", openErr)
	}
	rotated.Close()

	// And the Store knows it is spent, so a later Save cannot
	// re-encrypt under the password that was just replaced.
	if saveErr := s.Save(); !errors.Is(saveErr, ErrRekeyed) {
		t.Errorf("Save() after a non-durable rotation: err = %v, want ErrRekeyed", saveErr)
	}
}

// TestSaveAfterANonDurableWriteDoesNotConflictWithItself covers the
// asymmetry that commit() exists to prevent. A Save whose rename
// committed but whose directory sync failed has changed the file, so
// the Store must record it. Otherwise the next Save compares the file
// against a superseded snapshot and reports ErrConflict — a conflict
// with nobody, against its own write.
func TestSaveAfterANonDurableWriteDoesNotConflictWithItself(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pgv")
	if err := Init(path, "pw"); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// The first write commits, then reports a failed directory sync.
	restore := vault.FailSyncDir(errors.New("simulated"))
	s.Payload.Entries = append(s.Payload.Entries, entry.Entry{Name: "a.com", Secret: "1", Updated: entry.Now()})
	if err := s.Save(); !errors.Is(err, vault.ErrNotDurable) {
		restore()
		t.Fatalf("first Save: err = %v, want ErrNotDurable", err)
	}
	restore()

	// The same Store saving again must succeed. Before commit() was
	// shared, this returned ErrConflict.
	s.Payload.Entries = append(s.Payload.Entries, entry.Entry{Name: "b.com", Secret: "2", Updated: entry.Now()})
	if err := s.Save(); err != nil {
		t.Fatalf("second Save after a non-durable first: err = %v, want nil", err)
	}

	reopened, err := Open(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(reopened.Payload.Entries) != 2 {
		t.Errorf("entries after both saves: %+v, want a.com and b.com", reopened.Payload.Entries)
	}
}
