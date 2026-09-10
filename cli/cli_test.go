package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withTempVault points PASSGO_VAULT at a fresh temp path and sets
// PASSGO_MASTER so tests never need a real /dev/tty for the master
// password, per the sanctioned scripting/testing path in
// SPECIFICATION.md §4.
func withTempVault(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.pgv")
	t.Setenv("PASSGO_VAULT", path)
	t.Setenv("PASSGO_MASTER", "correct horse battery staple")
	return path
}

// withStdin substitutes stdin (used by promptSecret for -p prompts)
// with a reader yielding the given lines, and restores it afterward.
func withStdin(t *testing.T, text string) {
	t.Helper()
	orig := stdin
	stdin = strings.NewReader(text)
	t.Cleanup(func() { stdin = orig })
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// what was written to it, along with fn's return value.
func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w

	code := fn()

	w.Close()
	os.Stdout = orig

	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		buf.Write(tmp[:n])
		if err != nil {
			break
		}
	}
	return buf.String(), code
}

func TestInitCreatesVault(t *testing.T) {
	path := withTempVault(t)
	if code := Run([]string{"init"}); code != ExitOK {
		t.Fatalf("init exit code = %d, want %d", code, ExitOK)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("vault not created: %v", err)
	}
}

func TestInitTwiceFails(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})
	if code := Run([]string{"init"}); code != ExitGeneral {
		t.Errorf("second init exit code = %d, want %d", code, ExitGeneral)
	}
}

func TestAddAndGetRoundTrip(t *testing.T) {
	withTempVault(t)
	if code := Run([]string{"init"}); code != ExitOK {
		t.Fatalf("init failed: %d", code)
	}

	withStdin(t, "s3cr3t\n")
	if code := Run([]string{"add", "github.com", "-u", "me@example.com", "-p"}); code != ExitOK {
		t.Fatalf("add exit code = %d, want %d", code, ExitOK)
	}

	out, code := captureStdout(t, func() int {
		return Run([]string{"get", "github.com"})
	})
	if code != ExitOK {
		t.Fatalf("get exit code = %d, want %d", code, ExitOK)
	}
	if strings.TrimSpace(out) != "s3cr3t" {
		t.Errorf("get output = %q, want %q", out, "s3cr3t")
	}
}

func TestAddDuplicateRejected(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "first\n")
	if code := Run([]string{"add", "github.com", "-p"}); code != ExitOK {
		t.Fatalf("first add failed: %d", code)
	}

	withStdin(t, "second\n")
	if code := Run([]string{"add", "github.com", "-p"}); code != ExitGeneral {
		t.Errorf("duplicate add exit code = %d, want %d", code, ExitGeneral)
	}
}

func TestAddAllowsSameNameDifferentUsername(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "first\n")
	if code := Run([]string{"add", "github.com", "-u", "one", "-p"}); code != ExitOK {
		t.Fatalf("first add failed: %d", code)
	}
	withStdin(t, "second\n")
	if code := Run([]string{"add", "github.com", "-u", "two", "-p"}); code != ExitOK {
		t.Errorf("add with a different username should succeed, got exit code %d", code)
	}
}

func TestAddRequiresExactlyOneOfPasswordOrGen(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	if code := Run([]string{"add", "github.com"}); code != ExitUsage {
		t.Errorf("add with neither -p nor -g: exit code = %d, want %d", code, ExitUsage)
	}
	if code := Run([]string{"add", "github.com", "-p", "-g"}); code != ExitUsage {
		t.Errorf("add with both -p and -g: exit code = %d, want %d", code, ExitUsage)
	}
}

func TestAddGenPrintsGeneratedPassword(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	out, code := captureStdout(t, func() int {
		return Run([]string{"add", "github.com", "-g", "16"})
	})
	if code != ExitOK {
		t.Fatalf("add -g exit code = %d, want %d", code, ExitOK)
	}
	pw := strings.TrimSpace(out)
	if len(pw) != 16 {
		t.Errorf("generated password length = %d, want 16 (output: %q)", len(pw), out)
	}

	got, code := captureStdout(t, func() int {
		return Run([]string{"get", "github.com"})
	})
	if code != ExitOK {
		t.Fatalf("get exit code = %d, want %d", code, ExitOK)
	}
	if strings.TrimSpace(got) != pw {
		t.Errorf("stored secret = %q, want the generated password %q", got, pw)
	}
}

func TestGetNoMatch(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})
	if code := Run([]string{"get", "nope"}); code != ExitNotFound {
		t.Errorf("get with no match: exit code = %d, want %d", code, ExitNotFound)
	}
}

func TestGetAmbiguousMatch(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "github.com", "-u", "one", "-p"})
	withStdin(t, "b\n")
	Run([]string{"add", "gitlab.com", "-u", "two", "-p"})

	if code := Run([]string{"get", "git"}); code != ExitAmbiguous {
		t.Errorf("ambiguous get: exit code = %d, want %d", code, ExitAmbiguous)
	}
}

func TestGetDisambiguatedByUsername(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "example.com", "-u", "alice", "-p"})
	withStdin(t, "b\n")
	Run([]string{"add", "example.com", "-u", "bob", "-p"})

	out, code := captureStdout(t, func() int {
		return Run([]string{"get", "example.com", "-u", "bob"})
	})
	if code != ExitOK {
		t.Fatalf("get -u bob exit code = %d, want %d", code, ExitOK)
	}
	if strings.TrimSpace(out) != "b" {
		t.Errorf("get -u bob output = %q, want %q", out, "b")
	}
}

func TestGetWrongMasterPasswordFails(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	t.Setenv("PASSGO_MASTER", "wrong password")
	if code := Run([]string{"get", "anything"}); code != ExitAuthFailed {
		t.Errorf("get with wrong master password: exit code = %d, want %d", code, ExitAuthFailed)
	}
}

func TestVaultFlagOverridesEnv(t *testing.T) {
	t.Setenv("PASSGO_VAULT", "/should/not/be/used")
	t.Setenv("PASSGO_MASTER", "correct horse battery staple")
	path := filepath.Join(t.TempDir(), "explicit.pgv")

	if code := Run([]string{"--vault", path, "init"}); code != ExitOK {
		t.Fatalf("init with --vault failed: %d", code)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("vault not created at --vault path: %v", err)
	}
}

// writePasswordFile writes text as the contents of a fresh temp file
// and returns its path, for exercising --master-password-file /
// $PASSGO_MASTER_FILE without $PASSGO_MASTER set at all.
func writePasswordFile(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master.txt")
	if err := os.WriteFile(path, []byte(text+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMasterPasswordFileFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pgv")
	t.Setenv("PASSGO_VAULT", path)
	pwFile := writePasswordFile(t, "correct horse battery staple")

	if code := Run([]string{"--master-password-file", pwFile, "init"}); code != ExitOK {
		t.Fatalf("init with --master-password-file failed: %d", code)
	}

	if code := Run([]string{"--master-password-file", pwFile, "get", "anything"}); code != ExitNotFound {
		t.Errorf("get with --master-password-file: exit code = %d, want %d (auth should have succeeded)", code, ExitNotFound)
	}
}

func TestMasterPasswordFileEnvFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pgv")
	t.Setenv("PASSGO_VAULT", path)
	pwFile := writePasswordFile(t, "correct horse battery staple")
	t.Setenv("PASSGO_MASTER_FILE", pwFile)

	if code := Run([]string{"init"}); code != ExitOK {
		t.Fatalf("init with $PASSGO_MASTER_FILE failed: %d", code)
	}
}

func TestMasterPasswordFileOverridesEnvVar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pgv")
	t.Setenv("PASSGO_VAULT", path)
	t.Setenv("PASSGO_MASTER", "wrong password")
	pwFile := writePasswordFile(t, "correct horse battery staple")

	if code := Run([]string{"--master-password-file", pwFile, "init"}); code != ExitOK {
		t.Fatalf("init failed: %d", code)
	}
	// If --master-password-file had lost precedence to $PASSGO_MASTER,
	// this get would fail authentication instead of simply not finding
	// the (nonexistent) entry.
	if code := Run([]string{"--master-password-file", pwFile, "get", "anything"}); code != ExitNotFound {
		t.Errorf("get: exit code = %d, want %d (--master-password-file should win over $PASSGO_MASTER)", code, ExitNotFound)
	}
}
