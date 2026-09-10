package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
	if err := WriteAtomic(path, data1); err != nil {
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

	data2 := []byte("second version")
	if err := WriteAtomic(path, data2); err != nil {
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

	if err := WriteAtomicNoOverwrite(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first" {
		t.Errorf("got %q, want %q", got, "first")
	}

	err = WriteAtomicNoOverwrite(path, []byte("second"))
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
