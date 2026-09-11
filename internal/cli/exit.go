package cli

// Exit codes, per docs/SPECIFICATION.md §6 "Exit codes".
const (
	ExitOK         = 0
	ExitGeneral    = 1 // I/O, vault exists, duplicate entry
	ExitUsage      = 2 // bad flags, no TTY available
	ExitAmbiguous  = 3 // multiple entries matched a query
	ExitNotFound   = 4 // no entry matched a query
	ExitAuthFailed = 5 // wrong master password or corrupted vault
)
