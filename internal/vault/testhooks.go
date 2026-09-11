package vault

// FailSyncDir makes every subsequent directory sync fail with err,
// then returns a function restoring normal behaviour.
//
// It exists because one failure mode cannot be provoked by any real
// filesystem operation a test can perform: a directory sync failing
// *after* the rename or link has already committed. That window is
// the whole reason ErrNotDurable exists, and the branches guarding it
// reach from here up through store and into the commands — a vault
// that was created, or a master password that was changed, while an
// error was returned.
//
// It is deliberately the only such hook exported from the module.
// Faking each layer's own write call instead would let store and cli
// tests exercise their handlers while skipping the code that actually
// produces the condition; injecting here means every layer's test
// runs the real write path and the real error.
//
// The package also has an unexported syncFile seam (io.go) for the
// file syncs. That one stays unexported because everything it can
// provoke happens before the commit point, which needs no special
// handling anywhere above vault.
//
// Tests using it must not run in parallel with other vault writers,
// since it replaces process-wide state. Production code must never
// call it.
func FailSyncDir(err error) (restore func()) {
	prev := syncDir
	syncDir = func(string) error { return err }
	return func() { syncDir = prev }
}
