package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FormlessEvoker/passgo/crypto"
)

func TestCreateOpenRoundTrip(t *testing.T) {
	plaintext := []byte(`{"version":1,"entries":[{"name":"github.com","secret":"s3cr3t"}]}`)

	fileBytes, err := Create("correct horse", plaintext)
	if err != nil {
		t.Fatal(err)
	}

	o, err := Open(fileBytes, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()

	if !bytes.Equal(o.Plaintext, plaintext) {
		t.Errorf("round trip mismatch: got %q, want %q", o.Plaintext, plaintext)
	}
}

func TestOpenWrongPasswordFails(t *testing.T) {
	fileBytes, err := Create("correct horse", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(fileBytes, "wrong password"); err == nil {
		t.Error("Open succeeded with the wrong password")
	}
}

func TestOpenCorruptedVaultFails(t *testing.T) {
	fileBytes, err := Create("correct horse", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the ciphertext.
	fileBytes[len(fileBytes)-1] ^= 0xFF
	if _, err := Open(fileBytes, "correct horse"); err == nil {
		t.Error("Open succeeded on a corrupted vault")
	}
}

func TestOpenTamperedHeaderFails(t *testing.T) {
	fileBytes, err := Create("correct horse", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the Argon2id parallelism field — still
	// in-bounds, so ParseHeader accepts it, but it changes the AAD
	// and therefore must invalidate the GCM tag.
	fileBytes[16] ^= 0x01
	if _, err := Open(fileBytes, "correct horse"); err == nil {
		t.Error("Open succeeded after the header was tampered with")
	}
}

func TestOpenRejectsBadMagic(t *testing.T) {
	fileBytes, err := Create("correct horse", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	fileBytes[0] = 'X'
	if _, err := Open(fileBytes, "correct horse"); err == nil {
		t.Error("Open accepted a file with bad magic")
	}
}

func TestOpenRejectsTruncatedFile(t *testing.T) {
	if _, err := Open([]byte("too short"), "correct horse"); err == nil {
		t.Error("Open accepted a truncated file")
	}
}

func TestOpenRejectsNonZeroReservedByte(t *testing.T) {
	h := Header{Version: FormatV1, KDFID: KDFArgon2id, Params: crypto.DefaultParams}
	b := h.MarshalBinary()
	b[17] = 0x01 // reserved, spec requires 0x00
	if _, err := ParseHeader(b); err == nil {
		t.Error("ParseHeader accepted a nonzero reserved byte")
	}
}

func TestOpenRejectsCiphertextTooShortForTag(t *testing.T) {
	h := Header{Version: FormatV1, KDFID: KDFArgon2id, Params: crypto.DefaultParams}
	fileBytes := append(h.MarshalBinary(), make([]byte, crypto.TagSize-1)...) // one byte short of a full tag
	if _, err := Open(fileBytes, "correct horse"); !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("Open() on a too-short ciphertext: err = %v, want ErrCiphertextTooShort", err)
	}
}

func TestOpenRejectsOutOfBoundsParams(t *testing.T) {
	h := Header{
		Version: FormatV1,
		KDFID:   KDFArgon2id,
		Params:  crypto.Params{MemoryKiB: crypto.MaxMemoryKiB + 1, Iterations: 3, Parallelism: 4},
	}
	fileBytes := h.MarshalBinary() // no valid ciphertext needed; should fail before decrypting
	if _, err := Open(fileBytes, "correct horse"); err == nil {
		t.Error("Open accepted out-of-bounds KDF parameters")
	}
}

func TestSaveReusesKeyAndParamsWithFreshNonce(t *testing.T) {
	fileBytes, err := Create("correct horse", []byte("v1"))
	if err != nil {
		t.Fatal(err)
	}
	origHeader, err := ParseHeader(fileBytes[:HeaderSize])
	if err != nil {
		t.Fatal(err)
	}

	o, err := Open(fileBytes, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()

	updated, err := o.Save([]byte("v2"))
	if err != nil {
		t.Fatal(err)
	}
	newHeader, err := ParseHeader(updated[:HeaderSize])
	if err != nil {
		t.Fatal(err)
	}

	if newHeader.Salt != origHeader.Salt {
		t.Error("Save changed the salt; it should be reused from the original key derivation")
	}
	if newHeader.Nonce == origHeader.Nonce {
		t.Error("Save reused the nonce; every write must use a fresh nonce")
	}

	o2, err := Open(updated, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	defer o2.Close()
	if string(o2.Plaintext) != "v2" {
		t.Errorf("got %q after Save, want %q", o2.Plaintext, "v2")
	}
}

func TestWriteAtomicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "vault.pgv")

	data1 := []byte("first version")
	if _, err := WriteAtomic(path, data1); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data1) {
		t.Errorf("got %q, want %q", got, data1)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != vaultMode {
		t.Errorf("vault mode = %o, want %o", info.Mode().Perm(), vaultMode)
	}

	// A .bak from an earlier run, left group/other-readable. The
	// backup about to overwrite it must not inherit those bits.
	if err := os.WriteFile(path+".bak", []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	data2 := []byte("second version")
	if _, err := WriteAtomic(path, data2); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data2) {
		t.Errorf("got %q, want %q", got, data2)
	}

	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatal("expected a .bak file after the second write:", err)
	}
	if !bytes.Equal(bak, data1) {
		t.Errorf(".bak contents = %q, want %q (the pre-write version)", bak, data1)
	}
	// The backup is a whole vault, so it carries the vault's mode —
	// even when an earlier run left a .bak behind to be overwritten.
	bakInfo, err := os.Stat(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if bakInfo.Mode().Perm() != vaultMode {
		t.Errorf(".bak mode = %o, want %o", bakInfo.Mode().Perm(), vaultMode)
	}

	// No leftover temp files.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestWriteAtomicNoOverwriteRefusesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.pgv")

	if _, err := WriteAtomicNoOverwrite(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first" {
		t.Errorf("got %q, want %q", got, "first")
	}

	_, err = WriteAtomicNoOverwrite(path, []byte("second"))
	if !os.IsExist(err) {
		t.Errorf("WriteAtomicNoOverwrite over an existing file: err = %v, want an os.IsExist error", err)
	}
	// The original content must be untouched.
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first" {
		t.Errorf("content changed after a refused overwrite: got %q, want %q", got, "first")
	}

	// No leftover temp files, whichever branch ran.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestReadFileWarnsOnLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.pgv")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	var warnings bytes.Buffer
	if _, err := ReadFile(path, &warnings); err != nil {
		t.Fatal(err)
	}
	if warnings.Len() == 0 {
		t.Error("expected a warning for a group/world-readable vault file")
	}
}

func TestReadFileNoWarningWhenNotReadableByGroupOrOther(t *testing.T) {
	// Group-executable but not group-readable: the old &0o077 mask
	// warned here even though the file isn't "readable" by group/other,
	// which is what the warning message claims.
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.pgv")
	if err := os.WriteFile(path, []byte("data"), 0o610); err != nil {
		t.Fatal(err)
	}

	var warnings bytes.Buffer
	if _, err := ReadFile(path, &warnings); err != nil {
		t.Fatal(err)
	}
	if warnings.Len() != 0 {
		t.Errorf("unexpected warning for a non-readable-by-group mode: %s", warnings.String())
	}
}

func TestReadFileNoWarningOn0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.pgv")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	var warnings bytes.Buffer
	if _, err := ReadFile(path, &warnings); err != nil {
		t.Fatal(err)
	}
	if warnings.Len() != 0 {
		t.Errorf("unexpected warning for a 0600 vault file: %s", warnings.String())
	}
}

func TestResolvePathEnvOverride(t *testing.T) {
	t.Setenv("PASSGO_VAULT", "/custom/path/vault.pgv")
	p, err := ResolvePath()
	if err != nil {
		t.Fatal(err)
	}
	if p != "/custom/path/vault.pgv" {
		t.Errorf("ResolvePath() = %q, want %q", p, "/custom/path/vault.pgv")
	}
}

func TestResolvePathXDG(t *testing.T) {
	t.Setenv("PASSGO_VAULT", "")
	t.Setenv("XDG_DATA_HOME", "/xdg/data")
	p, err := ResolvePath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/xdg/data", "passgo", "vault.pgv")
	if p != want {
		t.Errorf("ResolvePath() = %q, want %q", p, want)
	}
}

// TestWriteAtomicReportsCommittedButNotDurable pins down the
// distinction ErrNotDurable exists to make: when the directory sync
// fails, the rename has already happened, so the new contents are
// live even though an error is returned. A caller that treated this
// like any other write failure would believe the old file still
// stood.
func TestWriteAtomicReportsCommittedButNotDurable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.pgv")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := syncDir
	syncDir = func(string) error { return errors.New("simulated fsync failure") }
	defer func() { syncDir = orig }()

	outcome, err := WriteAtomic(path, []byte("replacement"))
	if !errors.Is(err, ErrNotDurable) {
		t.Fatalf("WriteAtomic with a failing dir sync: err = %v, want ErrNotDurable", err)
	}
	if outcome != WriteCommittedNotDurable {
		t.Errorf("outcome = %v, want %v", outcome, WriteCommittedNotDurable)
	}

	// The whole point: despite the error, the new contents are live.
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "replacement" {
		t.Errorf("file contents = %q, want %q — the rename committed before the sync failed", got, "replacement")
	}

	// And no temp file was left behind by the cleanup path.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "vault.pgv") || e.Name() == "vault.pgv.bak" {
			continue
		}
		t.Errorf("stray file left in vault directory: %s", e.Name())
	}
}

// TestWriteAtomicNoOverwriteReportsCommittedButNotDurable is the
// init-path counterpart. os.Link is this function's commit point, so
// a directory sync failing after it leaves a created vault behind —
// not nothing. Reporting that as a plain failure would tell someone
// no vault exists while one sits on disk.
func TestWriteAtomicNoOverwriteReportsCommittedButNotDurable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.pgv")

	orig := syncDir
	syncDir = func(string) error { return errors.New("simulated fsync failure") }
	defer func() { syncDir = orig }()

	outcome, err := WriteAtomicNoOverwrite(path, []byte("fresh vault"))
	if !errors.Is(err, ErrNotDurable) {
		t.Fatalf("WriteAtomicNoOverwrite with a failing dir sync: err = %v, want ErrNotDurable", err)
	}
	if outcome != WriteCommittedNotDurable {
		t.Errorf("outcome = %v, want %v", outcome, WriteCommittedNotDurable)
	}

	// The link committed, so the vault must exist with its contents.
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("vault is missing after a committed link: %v", readErr)
	}
	if string(got) != "fresh vault" {
		t.Errorf("vault contents = %q, want %q", got, "fresh vault")
	}

	// The temp file is still cleaned up: os.Link leaves both names,
	// and only the vault name should survive.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "vault.pgv" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory contains %v, want only vault.pgv", names)
	}
}

// TestWriteOutcomeCommitted pins which outcomes count as committed.
// Committed drives whether a generated secret is printed, whether a
// Store's key is treated as superseded, and whether the stale-backup
// warning fires, so a value this package never produced must not fall
// on the committed side of it just by being non-zero.
func TestWriteOutcomeCommitted(t *testing.T) {
	cases := []struct {
		outcome WriteOutcome
		want    bool
	}{
		{WriteFailed, false},
		{WriteCommitted, true},
		{WriteCommittedNotDurable, true},
		{WriteOutcome(42), false},
		{WriteOutcome(-1), false},
	}
	for _, tc := range cases {
		if got := tc.outcome.Committed(); got != tc.want {
			t.Errorf("WriteOutcome(%d).Committed() = %v, want %v", int(tc.outcome), got, tc.want)
		}
	}
}

// TestWriteOutcomeStringRejectsUndefined keeps an undefined outcome
// from printing as a real one: a test failure reporting "failed" for
// a value that is not WriteFailed sends the reader after the wrong
// bug.
func TestWriteOutcomeStringRejectsUndefined(t *testing.T) {
	if got := WriteFailed.String(); got != "failed" {
		t.Errorf("WriteFailed.String() = %q, want %q", got, "failed")
	}
	got := WriteOutcome(42).String()
	if !strings.Contains(got, "42") || !strings.Contains(got, "invalid") {
		t.Errorf("WriteOutcome(42).String() = %q, want it to name itself invalid and show 42", got)
	}
}
