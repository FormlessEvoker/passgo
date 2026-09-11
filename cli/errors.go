package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/FormlessEvoker/passgo/crypto"
	"github.com/FormlessEvoker/passgo/vault"
)

// handleOpenError prints err to stderr and returns the exit code for a
// failed store.Open. A failed authentication (wrong master password or
// a corrupted vault — the two are indistinguishable, per the threat
// model) gets its own exit code so scripts can tell that apart from
// every other kind of failure to open the vault.
func handleOpenError(err error) int {
	fmt.Fprintln(os.Stderr, "error:", err)
	if errors.Is(err, crypto.ErrAuthFailed) {
		return ExitAuthFailed
	}
	return ExitGeneral
}

// reportNotDurable explains a write that reached its commit point but
// could not be confirmed durable. Both `init` and `passwd` can hit
// this, and both MUST say the change took effect (§3.4): the
// alternative reports a failure for a write that is already live.
//
// happened names what did take effect, since that differs per
// command; the rest is identical and lives here so the two cannot
// drift into describing the same condition differently.
func reportNotDurable(w io.Writer, happened string) {
	fmt.Fprintf(w, "IMPORTANT: %s\n", happened)
	fmt.Fprintln(w, "Only the directory sync failed, so it may not survive an immediate power loss.")
	fmt.Fprintln(w, "No command can show you this: the new state is already what every read sees.")
	fmt.Fprintln(w, "To force it to disk, run `sync`, or make another change to the vault.")
}

// reportWrite turns the outcome of a vault write into what the user
// is told and the code the process exits with. Every mutating command
// routes its failures through here, so the distinction between a write
// that changed nothing and one that changed everything is drawn once
// rather than six times — the split that five rounds of review kept
// finding re-implemented, differently, at each call site.
//
// It is called only when err is non-nil; a clean write has nothing to
// report and each command says its own piece.
//
// tookEffect names what did happen, in the command's own terms, and is
// used only for the outcome where a write both failed and took effect.
//
// A committed-but-not-durable write exits 0, because the command did
// what it was asked to do: the change is installed and every read
// already sees it. Only its survival of an immediate power loss is in
// doubt, and a write lost that way degrades to "the change did not
// happen" — the previous state is intact and still opens, so no
// outcome here strands anyone.
//
// Exiting non-zero broke `passgo init && passgo add ...` against a
// vault that had just been created. A distinct non-zero code would
// break it identically, since `&&` tests only for zero, so the choice
// is between 0 and leaving that harm in place. The caveat goes to
// stderr, where the tool's other advisories already go.
func reportWrite(outcome vault.WriteOutcome, err error, tookEffect string) int {
	if outcome == vault.WriteCommittedNotDurable {
		// Not "error:". The exit code says this succeeded; calling it
		// an error in the same breath would have the two channels
		// contradict each other.
		fmt.Fprintln(os.Stderr, "warning:", err)
		reportNotDurable(os.Stderr, tookEffect)
		return ExitOK
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	return ExitGeneral
}

// warnStaleBackup tells the user about the copy of the previous vault
// that §3.4 step 3 leaves at path+".bak" on every overwriting write.
//
// For add/edit/mv/rm that copy is harmless: a previous version under
// the same master password. After `passwd` it is not. It still opens
// with the password just replaced, so a rotation prompted by a
// suspected exposure has not actually ended that exposure — and §1
// puts a vault file in someone else's hands squarely in scope.
//
// The file is not deleted automatically. It is the user's only way
// back if the new password is lost, and removing a backup as a side
// effect of a password change is its own kind of surprise. Saying so
// and leaving the choice is the honest middle.
func warnStaleBackup(w io.Writer, vaultPath string) {
	backup := vaultPath + ".bak"
	if _, err := os.Stat(backup); err != nil {
		// No overwriting write happened, so there is no backup to warn
		// about — nothing to say rather than something untrue.
		return
	}
	fmt.Fprintf(w, "NOTE: %s still holds the previous vault and opens with your OLD master password.\n", backup)
	fmt.Fprintln(w, "If you rotated because that password may have been exposed, delete it.")
}
