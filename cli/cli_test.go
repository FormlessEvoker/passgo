package cli

import (
	"bytes"
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

func TestShowPrintsFieldsWithSecretMasked(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "s3cr3t\n")
	Run([]string{"add", "github.com", "-u", "alice", "-n", "personal account", "-p"})

	out, code := captureStdout(t, func() int {
		return Run([]string{"show", "github.com"})
	})
	if code != ExitOK {
		t.Fatalf("show exit code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(out, "github.com") || !strings.Contains(out, "alice") || !strings.Contains(out, "personal account") {
		t.Errorf("show output missing a field: %q", out)
	}
	if strings.Contains(out, "s3cr3t") {
		t.Errorf("show output leaked the secret: %q", out)
	}
	if !strings.Contains(out, secretMask) {
		t.Errorf("show output missing the secret mask: %q", out)
	}
}

func TestShowNoMatch(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})
	if code := Run([]string{"show", "nope"}); code != ExitNotFound {
		t.Errorf("show with no match: exit code = %d, want %d", code, ExitNotFound)
	}
}

func TestShowAmbiguousMatch(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "github.com", "-u", "one", "-p"})
	withStdin(t, "b\n")
	Run([]string{"add", "gitlab.com", "-u", "two", "-p"})

	if code := Run([]string{"show", "git"}); code != ExitAmbiguous {
		t.Errorf("ambiguous show: exit code = %d, want %d", code, ExitAmbiguous)
	}
}

func TestShowDisambiguatedByUsername(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "example.com", "-u", "alice", "-p"})
	withStdin(t, "b\n")
	Run([]string{"add", "example.com", "-u", "bob", "-p"})

	out, code := captureStdout(t, func() int {
		return Run([]string{"show", "example.com", "-u", "bob"})
	})
	if code != ExitOK {
		t.Fatalf("show -u bob exit code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(out, "bob") {
		t.Errorf("show -u bob output = %q, want it to contain %q", out, "bob")
	}
}

func TestShowWrongMasterPasswordFails(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	t.Setenv("PASSGO_MASTER", "wrong password")
	if code := Run([]string{"show", "anything"}); code != ExitAuthFailed {
		t.Errorf("show with wrong master password: exit code = %d, want %d", code, ExitAuthFailed)
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
	pwFile := writePasswordFile(t, "correct horse battery staple")

	// Vault is created with the file's password, with no conflicting
	// $PASSGO_MASTER yet — so an implementation that always preferred
	// $PASSGO_MASTER can't get lucky here by using the same value for
	// both init and get.
	if code := Run([]string{"--master-password-file", pwFile, "init"}); code != ExitOK {
		t.Fatalf("init failed: %d", code)
	}

	// Now introduce a conflicting $PASSGO_MASTER before get. If
	// --master-password-file had lost precedence to it, get would fail
	// authentication instead of simply not finding the (nonexistent)
	// entry.
	t.Setenv("PASSGO_MASTER", "wrong password")
	if code := Run([]string{"--master-password-file", pwFile, "get", "anything"}); code != ExitNotFound {
		t.Errorf("get: exit code = %d, want %d (--master-password-file should win over $PASSGO_MASTER)", code, ExitNotFound)
	}
}

func TestLsListsEverythingWithNoQuery(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "github.com", "-u", "alice", "-p"})
	withStdin(t, "b\n")
	Run([]string{"add", "gitlab.com", "-u", "bob", "-p"})

	out, code := captureStdout(t, func() int {
		return Run([]string{"ls"})
	})
	if code != ExitOK {
		t.Fatalf("ls exit code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(out, "github.com") || !strings.Contains(out, "gitlab.com") {
		t.Errorf("ls output missing an entry: %q", out)
	}
	if !strings.Contains(out, "alice") || !strings.Contains(out, "bob") {
		t.Errorf("ls output missing a username: %q", out)
	}
}

// seedLsFixture creates three entries spanning distinct names,
// usernames, and notes, for exercising every dimension resolve() can
// match a query on.
func seedLsFixture(t *testing.T) {
	t.Helper()
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "github.com", "-u", "alice", "-n", "personal account", "-p"})
	withStdin(t, "b\n")
	Run([]string{"add", "gitlab.com", "-u", "bob-work", "-n", "work ci token", "-p"})
	withStdin(t, "c\n")
	Run([]string{"add", "example.org", "-u", "carol", "-n", "recovery info", "-p"})
}

func TestLsQueryDimensions(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		want    []string // entry names expected in the output
		exclude []string // entry names that must not appear
	}{
		{"full name", "github.com", []string{"github.com"}, []string{"gitlab.com", "example.org"}},
		{"partial name", "git", []string{"github.com", "gitlab.com"}, []string{"example.org"}},
		{"full username", "alice", []string{"github.com"}, []string{"gitlab.com", "example.org"}},
		{"partial username", "work", []string{"gitlab.com"}, []string{"github.com", "example.org"}},
		{"partial notes", "recovery", []string{"example.org"}, []string{"github.com", "gitlab.com"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withTempVault(t)
			seedLsFixture(t)

			out, code := captureStdout(t, func() int {
				return Run([]string{"ls", c.query})
			})
			if code != ExitOK {
				t.Fatalf("ls %q exit code = %d, want %d", c.query, code, ExitOK)
			}
			for _, name := range c.want {
				if !strings.Contains(out, name) {
					t.Errorf("ls %q output missing %q: %q", c.query, name, out)
				}
			}
			for _, name := range c.exclude {
				if strings.Contains(out, name) {
					t.Errorf("ls %q output should not include %q: %q", c.query, name, out)
				}
			}
		})
	}
}

// TestLsOutputIsSortedByNameThenUsername pins down that ls need not
// sort its own output: entries come back from store.Open already
// sorted by name then username, per the invariant entry.Marshal
// enforces on every write (entry.go). Entries here are added in
// reverse-sorted order specifically to catch a regression if that
// invariant ever breaks, or if ls started relying on insertion order
// instead.
func TestLsOutputIsSortedByNameThenUsername(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "zsite.com", "-p"})
	withStdin(t, "b\n")
	Run([]string{"add", "asite.com", "-u", "b", "-p"})
	withStdin(t, "c\n")
	Run([]string{"add", "asite.com", "-u", "a", "-p"})

	out, code := captureStdout(t, func() int {
		return Run([]string{"ls"})
	})
	if code != ExitOK {
		t.Fatalf("ls exit code = %d, want %d", code, ExitOK)
	}

	wantOrder := []string{"asite.com", "asite.com", "zsite.com"}
	var gotOrder []string
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		gotOrder = append(gotOrder, strings.Fields(line)[0])
	}
	if len(gotOrder) != len(wantOrder) {
		t.Fatalf("ls output has %d lines, want %d: %q", len(gotOrder), len(wantOrder), out)
	}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Errorf("ls output order = %v, want %v", gotOrder, wantOrder)
			break
		}
	}
}

func TestLsFiltersByQuery(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "github.com", "-u", "alice", "-p"})
	withStdin(t, "b\n")
	Run([]string{"add", "gitlab.com", "-u", "bob", "-p"})

	out, code := captureStdout(t, func() int {
		return Run([]string{"ls", "github"})
	})
	if code != ExitOK {
		t.Fatalf("ls exit code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(out, "github.com") {
		t.Errorf("ls github output missing github.com: %q", out)
	}
	if strings.Contains(out, "gitlab.com") {
		t.Errorf("ls github output should not include gitlab.com: %q", out)
	}
}

func TestLsNoMatchPrintsNothingAndSucceeds(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	out, code := captureStdout(t, func() int {
		return Run([]string{"ls", "nope"})
	})
	if code != ExitOK {
		t.Fatalf("ls exit code = %d, want %d", code, ExitOK)
	}
	if out != "" {
		t.Errorf("ls with no match: output = %q, want empty", out)
	}
}

func TestLsTooManyArgsIsUsageError(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})
	if code := Run([]string{"ls", "one", "two"}); code != ExitUsage {
		t.Errorf("ls with two args: exit code = %d, want %d", code, ExitUsage)
	}
}

func TestReadPasswordFileWarnsOnLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.txt")
	if err := os.WriteFile(path, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var warnings bytes.Buffer
	if _, err := readPasswordFile(path, &warnings); err != nil {
		t.Fatal(err)
	}
	if warnings.Len() == 0 {
		t.Error("expected a warning for a group/world-readable password file")
	}
}

func TestReadPasswordFileNoWarningOn0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.txt")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var warnings bytes.Buffer
	if _, err := readPasswordFile(path, &warnings); err != nil {
		t.Fatal(err)
	}
	if warnings.Len() != 0 {
		t.Errorf("unexpected warning for a 0600 password file: %s", warnings.String())
	}
}

func TestStripOneTrailingNewline(t *testing.T) {
	cases := map[string]string{
		"secret\n":     "secret",
		"secret\r\n":   "secret",
		"secret":       "secret",
		"secret\n\n":   "secret\n",
		"secret\r\n\n": "secret\r\n",
		"secret\r":     "secret\r", // no LF was removed, so the lone CR stays
	}
	for in, want := range cases {
		if got := stripOneTrailingNewline(in); got != want {
			t.Errorf("stripOneTrailingNewline(%q) = %q, want %q", in, got, want)
		}
	}
}
