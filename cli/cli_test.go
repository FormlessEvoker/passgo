package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FormlessEvoker/passgo/crypto"
	"github.com/FormlessEvoker/passgo/vault"
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

// captureStderr redirects os.Stderr for the duration of fn and returns
// what was written to it, along with fn's return value. Diagnostics
// and warnings all go to stderr, so this is where their content is
// asserted.
func captureStderr(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w

	code := fn()

	w.Close()
	os.Stderr = orig

	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, readErr := r.Read(tmp)
		buf.Write(tmp[:n])
		if readErr != nil {
			break
		}
	}
	return buf.String(), code
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

// TestAddRejectsDuplicateNameRegardlessOfUsername pins down the
// identity rule in SPECIFICATION.md §3.2: name alone identifies an
// entry, so a second entry with the same name is a duplicate even
// when its username differs. Two accounts on one site are expected to
// be given distinct names.
func TestAddRejectsDuplicateNameRegardlessOfUsername(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	if code := Run([]string{"add", "github.com", "-u", "alice", "-p"}); code != ExitOK {
		t.Fatalf("first add exit code = %d, want %d", code, ExitOK)
	}
	withStdin(t, "b\n")
	if code := Run([]string{"add", "github.com", "-u", "bob", "-p"}); code != ExitGeneral {
		t.Errorf("add with duplicate name, different username: exit code = %d, want %d", code, ExitGeneral)
	}
}

// TestAddDistinctNamesForSameSite is the supported way to hold two
// accounts on one site under the §3.2 identity rule.
func TestAddDistinctNamesForSameSite(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	if code := Run([]string{"add", "github.com/alice", "-u", "alice", "-p"}); code != ExitOK {
		t.Fatalf("add github.com/alice exit code = %d, want %d", code, ExitOK)
	}
	withStdin(t, "b\n")
	if code := Run([]string{"add", "github.com/work", "-u", "bob", "-p"}); code != ExitOK {
		t.Fatalf("add github.com/work exit code = %d, want %d", code, ExitOK)
	}

	out, code := captureStdout(t, func() int {
		return Run([]string{"get", "github.com/work"})
	})
	if code != ExitOK {
		t.Fatalf("get github.com/work exit code = %d, want %d", code, ExitOK)
	}
	if strings.TrimSpace(out) != "b" {
		t.Errorf("get github.com/work output = %q, want %q", out, "b")
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

// TestGetExactNameBeatsAmbiguousSubstring pins down the guarantee
// SPECIFICATION.md §5 makes: because names are unique, the exact-match
// stage can never return more than one entry, so an ambiguous
// substring query is always resolvable by typing the exact name.
func TestGetExactNameBeatsAmbiguousSubstring(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "github.com", "-u", "alice", "-p"})
	withStdin(t, "b\n")
	Run([]string{"add", "github.com.backup", "-u", "bob", "-p"})

	// The substring "github.com" matches both entries...
	if code := Run([]string{"get", "github"}); code != ExitAmbiguous {
		t.Fatalf("get github exit code = %d, want %d", code, ExitAmbiguous)
	}

	// ...but the exact name resolves to exactly one, with no filter flag.
	out, code := captureStdout(t, func() int {
		return Run([]string{"get", "github.com"})
	})
	if code != ExitOK {
		t.Fatalf("get github.com exit code = %d, want %d", code, ExitOK)
	}
	if strings.TrimSpace(out) != "a" {
		t.Errorf("get github.com output = %q, want %q", out, "a")
	}
}

// TestUsernameFilterFlagIsGone guards the §5 decision to drop
// field-specific filter flags from the query-taking commands. -u is
// now a field-setting flag on add/edit only, so these must reject it
// as unknown rather than silently ignoring it.
func TestUsernameFilterFlagIsGone(t *testing.T) {
	for _, cmd := range []string{"get", "show", "rm"} {
		t.Run(cmd, func(t *testing.T) {
			withTempVault(t)
			Run([]string{"init"})

			withStdin(t, "a\n")
			Run([]string{"add", "example.com", "-u", "alice", "-p"})

			if code := Run([]string{cmd, "example.com", "-u", "alice"}); code != ExitUsage {
				t.Errorf("%s -u: exit code = %d, want %d", cmd, code, ExitUsage)
			}
		})
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

func TestShowWrongMasterPasswordFails(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	t.Setenv("PASSGO_MASTER", "wrong password")
	if code := Run([]string{"show", "anything"}); code != ExitAuthFailed {
		t.Errorf("show with wrong master password: exit code = %d, want %d", code, ExitAuthFailed)
	}
}

func TestRmForceDeletesEntry(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "github.com", "-u", "alice", "-p"})

	if code := Run([]string{"rm", "github.com", "-f"}); code != ExitOK {
		t.Fatalf("rm -f exit code = %d, want %d", code, ExitOK)
	}
	if code := Run([]string{"get", "github.com"}); code != ExitNotFound {
		t.Errorf("get after rm: exit code = %d, want %d (entry should be gone)", code, ExitNotFound)
	}
}

func TestRmWithoutForcePromptsAndRespectsAnswer(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "github.com", "-u", "alice", "-p"})

	// "n" (the default-equivalent explicit no) leaves the entry alone.
	withStdin(t, "n\n")
	if code := Run([]string{"rm", "github.com"}); code != ExitOK {
		t.Fatalf("rm (declined) exit code = %d, want %d", code, ExitOK)
	}
	if code := Run([]string{"get", "github.com"}); code != ExitOK {
		t.Errorf("get after declined rm: exit code = %d, want %d (entry should remain)", code, ExitOK)
	}

	// "y" confirms the deletion.
	withStdin(t, "y\n")
	if code := Run([]string{"rm", "github.com"}); code != ExitOK {
		t.Fatalf("rm (confirmed) exit code = %d, want %d", code, ExitOK)
	}
	if code := Run([]string{"get", "github.com"}); code != ExitNotFound {
		t.Errorf("get after confirmed rm: exit code = %d, want %d (entry should be gone)", code, ExitNotFound)
	}
}

func TestRmNoMatch(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})
	if code := Run([]string{"rm", "nope", "-f"}); code != ExitNotFound {
		t.Errorf("rm with no match: exit code = %d, want %d", code, ExitNotFound)
	}
}

func TestRmAmbiguousMatch(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "github.com", "-u", "one", "-p"})
	withStdin(t, "b\n")
	Run([]string{"add", "gitlab.com", "-u", "two", "-p"})

	if code := Run([]string{"rm", "git", "-f"}); code != ExitAmbiguous {
		t.Errorf("ambiguous rm: exit code = %d, want %d", code, ExitAmbiguous)
	}
	// Neither candidate should have been touched.
	if code := Run([]string{"get", "github.com"}); code != ExitOK {
		t.Errorf("get github.com after ambiguous rm: exit code = %d, want %d", code, ExitOK)
	}
	if code := Run([]string{"get", "gitlab.com"}); code != ExitOK {
		t.Errorf("get gitlab.com after ambiguous rm: exit code = %d, want %d", code, ExitOK)
	}
}

// TestRmRemovesOnlyTheMatchedEntry checks that removeEntry drops the
// resolved entry and nothing else, now that it keys on name alone.
func TestRmRemovesOnlyTheMatchedEntry(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "example.com/alice", "-u", "shared", "-p"})
	withStdin(t, "b\n")
	Run([]string{"add", "example.com/bob", "-u", "shared", "-p"})

	if code := Run([]string{"rm", "example.com/bob", "-f"}); code != ExitOK {
		t.Fatalf("rm exit code = %d, want %d", code, ExitOK)
	}
	if code := Run([]string{"get", "example.com/bob"}); code != ExitNotFound {
		t.Errorf("get removed entry: exit code = %d, want %d", code, ExitNotFound)
	}
	// The sibling shares a username but has its own name, so it survives.
	if code := Run([]string{"get", "example.com/alice"}); code != ExitOK {
		t.Errorf("get surviving entry: exit code = %d, want %d", code, ExitOK)
	}
}

// seedEditFixture creates one fully-populated entry for the edit and
// mv tests to operate on.
func seedEditFixture(t *testing.T) {
	t.Helper()
	Run([]string{"init"})
	withStdin(t, "original\n")
	Run([]string{"add", "github.com", "-u", "alice", "-n", "personal account", "-p"})
}

func TestEditChangesOnlyTheFlagsGiven(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)

	if code := Run([]string{"edit", "github.com", "-u", "bob"}); code != ExitOK {
		t.Fatalf("edit -u exit code = %d, want %d", code, ExitOK)
	}

	out, code := captureStdout(t, func() int {
		return Run([]string{"show", "github.com"})
	})
	if code != ExitOK {
		t.Fatalf("show exit code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(out, "bob") {
		t.Errorf("username was not updated: %q", out)
	}
	// Untouched fields survive.
	if !strings.Contains(out, "personal account") {
		t.Errorf("notes should have been left alone: %q", out)
	}
	secret, code := captureStdout(t, func() int {
		return Run([]string{"get", "github.com"})
	})
	if code != ExitOK || strings.TrimSpace(secret) != "original" {
		t.Errorf("secret should have been left alone, got %q (exit %d)", secret, code)
	}
}

func TestEditPasswordPrompts(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)

	withStdin(t, "rotated\n")
	if code := Run([]string{"edit", "github.com", "-p"}); code != ExitOK {
		t.Fatalf("edit -p exit code = %d, want %d", code, ExitOK)
	}

	out, code := captureStdout(t, func() int {
		return Run([]string{"get", "github.com"})
	})
	if code != ExitOK {
		t.Fatalf("get exit code = %d, want %d", code, ExitOK)
	}
	if strings.TrimSpace(out) != "rotated" {
		t.Errorf("secret = %q, want %q", strings.TrimSpace(out), "rotated")
	}
}

// TestEditGenPrintsAndStoresSameSecret pins down that `edit -g` prints
// the generated password, as `add -g` does — nothing else in the run
// reveals it — and that what it prints is what it stored.
func TestEditGenPrintsAndStoresSameSecret(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)

	printed, code := captureStdout(t, func() int {
		return Run([]string{"edit", "github.com", "-g", "32"})
	})
	if code != ExitOK {
		t.Fatalf("edit -g exit code = %d, want %d", code, ExitOK)
	}
	generated := strings.TrimSpace(printed)
	if len(generated) != 32 {
		t.Errorf("generated password length = %d, want 32: %q", len(generated), generated)
	}

	stored, code := captureStdout(t, func() int {
		return Run([]string{"get", "github.com"})
	})
	if code != ExitOK {
		t.Fatalf("get exit code = %d, want %d", code, ExitOK)
	}
	if strings.TrimSpace(stored) != generated {
		t.Errorf("stored secret %q != printed %q", strings.TrimSpace(stored), generated)
	}
}

// TestEditEmptyValueClearsField distinguishes "flag given as empty"
// from "flag omitted" — the former clears the field.
func TestEditEmptyValueClearsField(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)

	if code := Run([]string{"edit", "github.com", "-n", ""}); code != ExitOK {
		t.Fatalf("edit -n \"\" exit code = %d, want %d", code, ExitOK)
	}

	out, code := captureStdout(t, func() int {
		return Run([]string{"show", "github.com"})
	})
	if code != ExitOK {
		t.Fatalf("show exit code = %d, want %d", code, ExitOK)
	}
	if strings.Contains(out, "personal account") {
		t.Errorf("notes should have been cleared: %q", out)
	}
}

// updatedAt returns the `updated` timestamp ls prints for the named
// entry, parsed. ls writes name, username and an RFC 3339 stamp
// separated by tabwriter padding, and none of those can themselves
// contain whitespace, so the timestamp is always the final field —
// including when the username is empty and the line has only two.
//
// Reading the column directly, rather than diffing whole ls output,
// keeps a refresh assertion from being satisfied by some other field
// the edit happened to change.
func updatedAt(t *testing.T, name string) time.Time {
	t.Helper()

	out, code := captureStdout(t, func() int { return Run([]string{"ls"}) })
	if code != ExitOK {
		t.Fatalf("ls exit code = %d, want %d", code, ExitOK)
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == name {
			ts, err := time.Parse(time.RFC3339, fields[len(fields)-1])
			if err != nil {
				t.Fatalf("unparseable updated stamp in ls line %q: %v", line, err)
			}
			return ts
		}
	}
	t.Fatalf("no ls line for %q in output:\n%s", name, out)
	return time.Time{}
}

// waitForNextSecond sleeps past the next whole second. entry.Now()
// truncates to seconds, so an edit landing in the same second as the
// one before it produces an identical stamp and would prove nothing.
func waitForNextSecond() {
	time.Sleep(1100 * time.Millisecond)
}

func TestEditRefreshesUpdated(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)

	before := updatedAt(t, "github.com")

	// Notes deliberately: ls does not print them, so the only way this
	// entry's ls line can change is the timestamp itself.
	waitForNextSecond()
	if code := Run([]string{"edit", "github.com", "-n", "revised"}); code != ExitOK {
		t.Fatalf("edit exit code = %d, want %d", code, ExitOK)
	}

	after := updatedAt(t, "github.com")
	if !after.After(before) {
		t.Errorf("updated = %s, want later than %s", after.Format(time.RFC3339), before.Format(time.RFC3339))
	}
}

func TestMvRefreshesUpdated(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)

	before := updatedAt(t, "github.com")

	waitForNextSecond()
	if code := Run([]string{"mv", "github.com", "forge.example"}); code != ExitOK {
		t.Fatalf("mv exit code = %d, want %d", code, ExitOK)
	}

	after := updatedAt(t, "forge.example")
	if !after.After(before) {
		t.Errorf("updated = %s, want later than %s", after.Format(time.RFC3339), before.Format(time.RFC3339))
	}
}

func TestEditRequiresAtLeastOneFlag(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)

	if code := Run([]string{"edit", "github.com"}); code != ExitUsage {
		t.Errorf("edit with no flags: exit code = %d, want %d", code, ExitUsage)
	}
}

func TestEditRejectsBothPasswordAndGen(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)

	if code := Run([]string{"edit", "github.com", "-p", "-g"}); code != ExitUsage {
		t.Errorf("edit -p -g: exit code = %d, want %d", code, ExitUsage)
	}
}

func TestEditNoMatchAndAmbiguous(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)
	withStdin(t, "b\n")
	Run([]string{"add", "gitlab.com", "-u", "bob", "-p"})

	if code := Run([]string{"edit", "nope", "-u", "x"}); code != ExitNotFound {
		t.Errorf("edit no match: exit code = %d, want %d", code, ExitNotFound)
	}
	if code := Run([]string{"edit", "git", "-u", "x"}); code != ExitAmbiguous {
		t.Errorf("edit ambiguous: exit code = %d, want %d", code, ExitAmbiguous)
	}
}

// TestEditDoesNotTakeANameFlag guards the §6 decision to route
// renames through mv: -N and --name must not quietly become field
// edits if someone reaches for them out of habit.
func TestEditDoesNotTakeANameFlag(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)

	for _, flag := range []string{"--name", "-N"} {
		if code := Run([]string{"edit", "github.com", flag, "other.com"}); code != ExitUsage {
			t.Errorf("edit %s: exit code = %d, want %d", flag, code, ExitUsage)
		}
	}
}

func TestMvRenamesEntryPreservingOtherFields(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)

	// A new name disjoint from the old one, so that "the old name no
	// longer resolves" is a meaningful assertion. Renaming to
	// github.com/personal would leave `get github.com` still matching
	// via the §5 substring stage, which is correct but proves nothing
	// here.
	if code := Run([]string{"mv", "github.com", "forge.example"}); code != ExitOK {
		t.Fatalf("mv exit code = %d, want %d", code, ExitOK)
	}

	if code := Run([]string{"get", "github.com"}); code != ExitNotFound {
		t.Errorf("old name should be gone: exit code = %d, want %d", code, ExitNotFound)
	}

	out, code := captureStdout(t, func() int {
		return Run([]string{"show", "forge.example"})
	})
	if code != ExitOK {
		t.Fatalf("show new name exit code = %d, want %d", code, ExitOK)
	}
	// Everything except the name rides along.
	if !strings.Contains(out, "alice") || !strings.Contains(out, "personal account") {
		t.Errorf("mv did not preserve other fields: %q", out)
	}
	secret, code := captureStdout(t, func() int {
		return Run([]string{"get", "forge.example"})
	})
	if code != ExitOK || strings.TrimSpace(secret) != "original" {
		t.Errorf("mv did not preserve the secret, got %q (exit %d)", secret, code)
	}
}

func TestMvRejectsExistingName(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)
	withStdin(t, "b\n")
	Run([]string{"add", "gitlab.com", "-u", "bob", "-p"})

	if code := Run([]string{"mv", "github.com", "GITLAB.COM"}); code != ExitGeneral {
		t.Errorf("mv onto an existing name: exit code = %d, want %d", code, ExitGeneral)
	}
	// The rename was refused, so both entries keep their names.
	if code := Run([]string{"get", "github.com"}); code != ExitOK {
		t.Errorf("source should be unchanged: exit code = %d, want %d", code, ExitOK)
	}
}

// TestMvAllowsCaseOnlyRename covers the self-exemption in the
// collision check: an entry may be renamed to a different casing of
// its own name, which would otherwise collide with itself.
func TestMvAllowsCaseOnlyRename(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)

	if code := Run([]string{"mv", "github.com", "GitHub.com"}); code != ExitOK {
		t.Fatalf("case-only mv exit code = %d, want %d", code, ExitOK)
	}

	out, code := captureStdout(t, func() int { return Run([]string{"ls"}) })
	if code != ExitOK {
		t.Fatalf("ls exit code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(out, "GitHub.com") {
		t.Errorf("name was not recased: %q", out)
	}
}

func TestMvRejectsEmptyAndMissingArguments(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)

	cases := [][]string{
		{"mv"},
		{"mv", "github.com"},
		{"mv", "github.com", ""},
		{"mv", "github.com", "   "},
		{"mv", "github.com", "a", "b"},
	}
	for _, args := range cases {
		if code := Run(args); code != ExitUsage {
			t.Errorf("Run(%q): exit code = %d, want %d", args, code, ExitUsage)
		}
	}
}

func TestMvNoMatchAndAmbiguous(t *testing.T) {
	withTempVault(t)
	seedEditFixture(t)
	withStdin(t, "b\n")
	Run([]string{"add", "gitlab.com", "-u", "bob", "-p"})

	if code := Run([]string{"mv", "nope", "other.com"}); code != ExitNotFound {
		t.Errorf("mv no match: exit code = %d, want %d", code, ExitNotFound)
	}
	if code := Run([]string{"mv", "git", "other.com"}); code != ExitAmbiguous {
		t.Errorf("mv ambiguous: exit code = %d, want %d", code, ExitAmbiguous)
	}
}

func TestAddRejectsEmptyName(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	if code := Run([]string{"add", "", "-p"}); code != ExitUsage {
		t.Errorf("add with empty name: exit code = %d, want %d", code, ExitUsage)
	}
}

func TestGenDefaultLength(t *testing.T) {
	withTempVault(t)

	out, code := captureStdout(t, func() int { return Run([]string{"gen"}) })
	if code != ExitOK {
		t.Fatalf("gen exit code = %d, want %d", code, ExitOK)
	}
	if got := len(strings.TrimSpace(out)); got != crypto.DefaultGenLength {
		t.Errorf("generated length = %d, want %d", got, crypto.DefaultGenLength)
	}
}

func TestGenExplicitLength(t *testing.T) {
	withTempVault(t)

	out, code := captureStdout(t, func() int { return Run([]string{"gen", "48"}) })
	if code != ExitOK {
		t.Fatalf("gen 48 exit code = %d, want %d", code, ExitOK)
	}
	if got := len(strings.TrimSpace(out)); got != 48 {
		t.Errorf("generated length = %d, want 48", got)
	}
}

func TestGenUsesTheSpecifiedAlphabet(t *testing.T) {
	withTempVault(t)

	out, code := captureStdout(t, func() int { return Run([]string{"gen", "200"}) })
	if code != ExitOK {
		t.Fatalf("gen exit code = %d, want %d", code, ExitOK)
	}
	for _, r := range strings.TrimSpace(out) {
		if !strings.ContainsRune(crypto.GenAlphabet, r) {
			t.Errorf("generated password contains %q, which is outside GenAlphabet", r)
		}
	}
}

func TestGenProducesDifferentPasswords(t *testing.T) {
	withTempVault(t)

	first, _ := captureStdout(t, func() int { return Run([]string{"gen"}) })
	second, _ := captureStdout(t, func() int { return Run([]string{"gen"}) })
	if strings.TrimSpace(first) == strings.TrimSpace(second) {
		t.Errorf("two gen runs produced the same password: %q", strings.TrimSpace(first))
	}
}

func TestGenRejectsBadLength(t *testing.T) {
	withTempVault(t)

	for _, args := range [][]string{
		{"gen", "0"},
		{"gen", "-4"},
		{"gen", "abc"},
		{"gen", "3.5"},
		{"gen", "20", "30"},
	} {
		if code := Run(args); code != ExitUsage {
			t.Errorf("Run(%q): exit code = %d, want %d", args, code, ExitUsage)
		}
	}
}

// TestGenNeedsNoVault pins down the §6 guarantee that gen is a
// standalone generator: it must run with no vault present and, more
// pointedly, with no vault path resolvable at all.
func TestGenNeedsNoVault(t *testing.T) {
	// Point every source ResolvePath consults at nothing, so a command
	// that tried to resolve a vault here would fail.
	t.Setenv("PASSGO_VAULT", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("PASSGO_MASTER", "")

	out, code := captureStdout(t, func() int { return Run([]string{"gen"}) })
	if code != ExitOK {
		t.Fatalf("gen with no resolvable vault: exit code = %d, want %d", code, ExitOK)
	}
	if len(strings.TrimSpace(out)) != crypto.DefaultGenLength {
		t.Errorf("generated length = %d, want %d", len(strings.TrimSpace(out)), crypto.DefaultGenLength)
	}
}

// TestSecretsOmitTrailingNewlineWhenPiped covers the §6 rule for every
// path that writes a secret to stdout. captureStdout redirects to a
// pipe, so isTTY is false throughout — exactly the case the rule is
// about.
func TestSecretsOmitTrailingNewlineWhenPiped(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})
	withStdin(t, "known\n")
	Run([]string{"add", "example.com", "-p"})

	cases := []struct {
		name string
		args []string
	}{
		{"gen", []string{"gen"}},
		{"get", []string{"get", "example.com"}},
		{"add -g", []string{"add", "fresh.example", "-g"}},
		{"edit -g", []string{"edit", "example.com", "-g"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, code := captureStdout(t, func() int { return Run(c.args) })
			if code != ExitOK {
				t.Fatalf("%s exit code = %d, want %d", c.name, code, ExitOK)
			}
			if out == "" {
				t.Fatalf("%s wrote nothing to stdout", c.name)
			}
			if strings.HasSuffix(out, "\n") {
				t.Errorf("%s wrote a trailing newline to a pipe: %q", c.name, out)
			}
		})
	}
}

// TestPasswdRotatesTheMasterPassword is the core of the command: the
// old password must stop working and the new one must start.
func TestPasswdRotatesTheMasterPassword(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})
	withStdin(t, "s3cr3t\n")
	Run([]string{"add", "github.com", "-u", "alice", "-n", "notes here", "-p"})

	newFile := writePasswordFile(t, "a brand new master")
	if code := Run([]string{"passwd", "--new-master-password-file", newFile}); code != ExitOK {
		t.Fatalf("passwd exit code = %d, want %d", code, ExitOK)
	}

	// The old password no longer opens the vault.
	if code := Run([]string{"get", "github.com"}); code != ExitAuthFailed {
		t.Errorf("old password still opens the vault: exit code = %d, want %d", code, ExitAuthFailed)
	}

	// The new one does, and the entry survived intact.
	t.Setenv("PASSGO_MASTER", "a brand new master")
	out, code := captureStdout(t, func() int { return Run([]string{"get", "github.com"}) })
	if code != ExitOK {
		t.Fatalf("new password does not open the vault: exit code = %d, want %d", code, ExitOK)
	}
	if strings.TrimSpace(out) != "s3cr3t" {
		t.Errorf("secret = %q, want %q", strings.TrimSpace(out), "s3cr3t")
	}

	shown, code := captureStdout(t, func() int { return Run([]string{"show", "github.com"}) })
	if code != ExitOK {
		t.Fatalf("show exit code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(shown, "alice") || !strings.Contains(shown, "notes here") {
		t.Errorf("passwd did not leave entries unchanged: %q", shown)
	}
}

// TestPasswdGeneratesFreshSaltAndNonce checks §2.1's requirement
// directly against the file header, which is where it is observable.
func TestPasswdGeneratesFreshSaltAndNonce(t *testing.T) {
	path := withTempVault(t)
	Run([]string{"init"})

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	newFile := writePasswordFile(t, "replacement")
	if code := Run([]string{"passwd", "--new-master-password-file", newFile}); code != ExitOK {
		t.Fatalf("passwd exit code = %d, want %d", code, ExitOK)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Header layout per §3.1: salt at [18,34), nonce at [34,46).
	if bytes.Equal(before[18:34], after[18:34]) {
		t.Error("salt was not regenerated")
	}
	if bytes.Equal(before[34:46], after[34:46]) {
		t.Error("nonce was not regenerated")
	}
}

func TestPasswdWrongCurrentPasswordFails(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	t.Setenv("PASSGO_MASTER", "not the right one")
	newFile := writePasswordFile(t, "replacement")
	if code := Run([]string{"passwd", "--new-master-password-file", newFile}); code != ExitAuthFailed {
		t.Errorf("passwd with wrong current password: exit code = %d, want %d", code, ExitAuthFailed)
	}
}

// TestPasswdDoesNotReuseCurrentPasswordAsNew guards the §4 rule that
// the new password never falls back to $PASSGO_MASTER. Without a new
// password source and with no TTY, passwd must fail rather than
// "rotate" the vault to the password it already has.
func TestPasswdDoesNotReuseCurrentPasswordAsNew(t *testing.T) {
	// With no new-password source this falls through to promptTTY,
	// which blocks for input when /dev/tty is openable. Skip there
	// rather than hanging someone's local `go test`; the assertion
	// still runs anywhere without a controlling terminal, CI included.
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		f.Close()
		t.Skip("/dev/tty is available; passwd would prompt interactively and block")
	}

	withTempVault(t)
	Run([]string{"init"})

	// PASSGO_MASTER is set by withTempVault and supplies the current
	// password; nothing supplies a new one.
	if code := Run([]string{"passwd"}); code == ExitOK {
		t.Fatal("passwd succeeded with no new-password source; it must not reuse $PASSGO_MASTER")
	}

	// The vault must still open under the original password.
	if code := Run([]string{"ls"}); code != ExitOK {
		t.Errorf("vault no longer opens under the original password: exit code = %d", code)
	}
}

func TestPasswdNewPasswordFileEnvFallback(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	t.Setenv("PASSGO_NEW_MASTER_FILE", writePasswordFile(t, "from the environment"))
	if code := Run([]string{"passwd"}); code != ExitOK {
		t.Fatalf("passwd via $PASSGO_NEW_MASTER_FILE: exit code = %d, want %d", code, ExitOK)
	}

	t.Setenv("PASSGO_MASTER", "from the environment")
	if code := Run([]string{"ls"}); code != ExitOK {
		t.Errorf("new password from env file does not open the vault: exit code = %d", code)
	}
}

func TestPasswdRejectsUnknownFlagAndMissingValue(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	for _, args := range [][]string{
		{"passwd", "--nope"},
		{"passwd", "--new-master-password-file"},
		{"passwd", "extra-positional"},
	} {
		if code := Run(args); code != ExitUsage {
			t.Errorf("Run(%q): exit code = %d, want %d", args, code, ExitUsage)
		}
	}
}

// TestPasswdRejectsUnchangedPassword covers the §4 rule about the
// outcome rather than the source: pointing both flags at the same
// file is a route to rotating a vault to the password it already
// has, which must be refused rather than reported as a success.
func TestPasswdRejectsUnchangedPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pgv")
	t.Setenv("PASSGO_VAULT", path)
	// No $PASSGO_MASTER: both passwords come from files here.
	t.Setenv("PASSGO_MASTER", "")

	same := writePasswordFile(t, "one and the same")
	if code := Run([]string{"--master-password-file", same, "init"}); code != ExitOK {
		t.Fatalf("init exit code = %d, want %d", code, ExitOK)
	}

	code := Run([]string{"--master-password-file", same, "passwd", "--new-master-password-file", same})
	if code != ExitUsage {
		t.Errorf("passwd with the same file for both passwords: exit code = %d, want %d", code, ExitUsage)
	}

	// Distinct files holding identical text must be refused too — the
	// rule is about the value, not the path.
	twin := writePasswordFile(t, "one and the same")
	if code := Run([]string{"--master-password-file", same, "passwd", "--new-master-password-file", twin}); code != ExitUsage {
		t.Errorf("passwd with an identical new password: exit code = %d, want %d", code, ExitUsage)
	}

	// And the vault still opens under the original password.
	if code := Run([]string{"--master-password-file", same, "ls"}); code != ExitOK {
		t.Errorf("vault no longer opens after a refused rotation: exit code = %d", code)
	}
}

// TestPasswdReportsANonDurableRotation covers §6's MUST: when the
// write commits but the directory sync fails, the command must say
// the password DID change. Reporting a plain failure would send the
// user back to a password their vault no longer accepts.
func TestPasswdReportsANonDurableRotation(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	// The real rotation runs and commits; only the directory sync
	// fails, which is the condition §6 requires be reported.
	defer vault.FailSyncDir(errors.New("simulated"))()

	newFile := writePasswordFile(t, "the replacement")
	out, code := captureStderr(t, func() int {
		return Run([]string{"passwd", "--new-master-password-file", newFile})
	})
	if code != ExitGeneral {
		t.Fatalf("passwd exit code = %d, want %d", code, ExitGeneral)
	}
	if !strings.Contains(out, "WAS changed") {
		t.Errorf("stderr does not state that the password changed: %q", out)
	}

	// The claim has to be true: the vault really does want the new one.
	t.Setenv("PASSGO_MASTER", "the replacement")
	if code := Run([]string{"ls"}); code != ExitOK {
		t.Errorf("vault does not open under the new password: exit code = %d", code)
	}
}

// TestPasswdOrdinaryFailureOmitsTheChangedNotice is the other half:
// a failure that did not commit must not claim the password changed.
func TestPasswdOrdinaryFailureOmitsTheChangedNotice(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	// A real failure that never reaches the commit point: with the
	// vault's directory unwritable, the temp file cannot be created.
	// No hook needed, so this exercises the genuine error path.
	if os.Geteuid() == 0 {
		t.Skip("running as root; directory permissions would not be enforced")
	}
	dir := filepath.Dir(os.Getenv("PASSGO_VAULT"))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	newFile := writePasswordFile(t, "the replacement")
	out, code := captureStderr(t, func() int {
		return Run([]string{"passwd", "--new-master-password-file", newFile})
	})
	if code != ExitGeneral {
		t.Fatalf("passwd exit code = %d, want %d", code, ExitGeneral)
	}
	if strings.Contains(out, "WAS changed") {
		t.Errorf("a non-committing failure claimed the password changed: %q", out)
	}
}

// TestReportNotDurableStatesTheChangeTookEffect covers the wording
// both `init` and `passwd` depend on. The one thing it must never do
// is read as a failure, and it must not send the reader off to
// confirm the state — §3.4 notes that no read can distinguish it.
func TestReportNotDurableStatesTheChangeTookEffect(t *testing.T) {
	var buf bytes.Buffer
	reportNotDurable(&buf, "the thing WAS done.")
	out := buf.String()

	if !strings.Contains(out, "the thing WAS done.") {
		t.Errorf("caller's subject missing: %q", out)
	}
	for _, want := range []string{"IMPORTANT", "power loss", "sync"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %q", want, out)
		}
	}
	// Verifying by reading is exactly what cannot work here, so the
	// message must not suggest it.
	for _, forbidden := range []string{"passgo ls", "verify", "Verify"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("output tells the reader to verify by reading (%q): %q", forbidden, out)
		}
	}
}

// TestInitReportsANonDurableCreation covers runInit's half of the
// §3.4 MUST. os.Link commits before the directory sync, so a sync
// failure leaves a created vault behind; reporting a plain failure
// would tell the user no vault exists while one sits on disk.
func TestInitReportsANonDurableCreation(t *testing.T) {
	path := withTempVault(t)

	defer vault.FailSyncDir(errors.New("simulated"))()

	out, code := captureStderr(t, func() int { return Run([]string{"init"}) })
	if code != ExitGeneral {
		t.Fatalf("init exit code = %d, want %d", code, ExitGeneral)
	}
	if !strings.Contains(out, "WAS created") {
		t.Errorf("stderr does not say the vault was created: %q", out)
	}

	// And the claim must be true.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("vault is missing despite a committed link: %v", err)
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

// TestLsOutputIsSortedByName pins down that ls need not sort its own
// output: entries come back from store.Open already sorted by name
// then username, per the invariant entry.Marshal enforces on every
// write (entry.go). Entries here are added in reverse-sorted order
// specifically to catch a regression if that invariant ever breaks,
// or if ls started relying on insertion order instead.
//
// Only the name component is exercised here. Names are unique under
// SPECIFICATION.md §3.2, so `add` can no longer produce the duplicate
// names the username tiebreak exists to order; that tiebreak is
// covered directly in entry.TestMarshalSortsByNameThenUsername, where
// such a payload can still be constructed.
func TestLsOutputIsSortedByName(t *testing.T) {
	withTempVault(t)
	Run([]string{"init"})

	withStdin(t, "a\n")
	Run([]string{"add", "zsite.com", "-p"})
	withStdin(t, "b\n")
	Run([]string{"add", "msite.com", "-u", "b", "-p"})
	withStdin(t, "c\n")
	Run([]string{"add", "asite.com", "-u", "a", "-p"})

	out, code := captureStdout(t, func() int {
		return Run([]string{"ls"})
	})
	if code != ExitOK {
		t.Fatalf("ls exit code = %d, want %d", code, ExitOK)
	}

	wantOrder := []string{"asite.com", "msite.com", "zsite.com"}
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
