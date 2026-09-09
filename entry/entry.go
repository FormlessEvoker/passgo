// Package entry defines the plaintext payload stored inside a vault:
// the set of entries and the JSON encoding used for it, per
// SPECIFICATION.md §3.2.
package entry

import (
	"encoding/json"
	"sort"
	"time"
)

// PayloadVersion is the payload schema version written into every
// Payload. It is independent of the vault file format version in the
// header (vault.FormatV1) — this one versions the JSON shape, not the
// encryption envelope.
const PayloadVersion = 1

// Entry is a single stored secret.
type Entry struct {
	Name     string    `json:"name"`
	Username string    `json:"username,omitempty"`
	Secret   string    `json:"secret"`
	Notes    string    `json:"notes,omitempty"`
	Updated  time.Time `json:"updated"`
}

// Payload is the decrypted contents of a vault file.
type Payload struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// New returns an empty payload at the current schema version, as
// written by `passgo init`.
func New() Payload {
	return Payload{Version: PayloadVersion, Entries: []Entry{}}
}

// Now returns the current time truncated to whole seconds, UTC — the
// precision the vault's RFC 3339 timestamps are stored at.
func Now() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

// sortEntries sorts entries by name, then username, matching
// SPECIFICATION.md §3.2: "entries is sorted by name, then username, on
// every write."
func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Username < entries[j].Username
	})
}

// Marshal sorts p.Entries in place and encodes p as minified JSON.
func Marshal(p Payload) ([]byte, error) {
	sortEntries(p.Entries)
	return json.Marshal(p)
}

// Unmarshal decodes minified JSON into a Payload.
func Unmarshal(data []byte) (Payload, error) {
	var p Payload
	if err := json.Unmarshal(data, &p); err != nil {
		return Payload{}, err
	}
	return p, nil
}
