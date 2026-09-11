package vault

import "fmt"

// WriteOutcome reports what a write did to the file on disk, which is
// a separate question from whether the write returned an error.
//
// A bare error cannot carry both answers. Go's universal idiom reads
// `err != nil` as "it did not happen", and for an atomic write that is
// wrong: past the commit point the new contents are already live and
// visible to every reader, error or no error. Every caller that
// branched on the error alone got that case backwards, each in its own
// way, so the two facts are separated here and travel up by type.
//
// Callers MUST branch on the outcome, not on errors.Is(err,
// ErrNotDurable). The sentinel still exists to explain what went wrong
// in the message; the outcome is what decides what to tell the user.
type WriteOutcome int

const (
	// WriteFailed means the write never reached its commit point.
	// Nothing changed: the previous file, if any, still stands. This
	// is the zero value, so an outcome returned alongside an error
	// from a function that failed before it could decide defaults to
	// the safe reading.
	WriteFailed WriteOutcome = iota

	// WriteCommitted means the write is installed and durable: the
	// rename or link happened and the containing directory was
	// synced. The ordinary success case.
	WriteCommitted

	// WriteCommittedNotDurable means the write is installed but its
	// survival is not guaranteed: the rename or link happened, so the
	// new contents are live, but the directory fsync that would make
	// that survive a power loss failed. Returned alongside an error
	// wrapping ErrNotDurable.
	//
	// This state cannot be detected by reading — the commit is
	// applied in the page cache, so every read on the running machine
	// resolves through it and sees the new file (§3.4).
	WriteCommittedNotDurable
)

// Committed reports whether the write reached its commit point, and so
// whether the new contents are what readers now see. True for both
// committed outcomes; the difference between them is durability, not
// visibility.
//
// The two are named rather than tested against WriteFailed, so that a
// value which is none of the three defined outcomes is not committed.
// Callers use this to decide whether to print a generated secret,
// whether a Store's key has been superseded, and whether a stale
// backup exists to warn about; none of those should be driven by a
// value this package never produced. A fourth outcome added later has
// to be classified here deliberately, rather than defaulting into the
// committed side by being merely non-zero.
func (o WriteOutcome) Committed() bool {
	return o == WriteCommitted || o == WriteCommittedNotDurable
}

// String renders the outcome for test failures and diagnostics. An
// undefined value is reported as such rather than borrowing the name
// of a real outcome, which would hide the bug that produced it.
func (o WriteOutcome) String() string {
	switch o {
	case WriteFailed:
		return "failed"
	case WriteCommitted:
		return "committed"
	case WriteCommittedNotDurable:
		return "committed but not durable"
	default:
		return fmt.Sprintf("invalid WriteOutcome(%d)", int(o))
	}
}
