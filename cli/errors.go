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
func reportWrite(outcome vault.WriteOutcome, err error, tookEffect string) int {
	fmt.Fprintln(os.Stderr, "error:", err)
	if outcome == vault.WriteCommittedNotDurable {
		reportNotDurable(os.Stderr, tookEffect)
	}
	return ExitGeneral
}
