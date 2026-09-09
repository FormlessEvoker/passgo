package entry

import (
	"strings"
	"testing"
	"time"
)

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	p := Payload{
		Version: PayloadVersion,
		Entries: []Entry{
			{Name: "github.com", Username: "me@example.com", Secret: "s3cr3t", Notes: "recovery codes in the safe", Updated: Now()},
			{Name: "ansible-vault-prod", Secret: "other-secret", Updated: Now()},
		},
	}

	data, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != len(p.Entries) {
		t.Fatalf("got %d entries, want %d", len(got.Entries), len(p.Entries))
	}
	if got.Version != PayloadVersion {
		t.Errorf("Version = %d, want %d", got.Version, PayloadVersion)
	}
}

func TestMarshalIsMinified(t *testing.T) {
	p := New()
	p.Entries = append(p.Entries, Entry{Name: "x", Secret: "y", Updated: Now()})

	data, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(string(data), "\n\t") {
		t.Errorf("expected minified JSON, got: %s", data)
	}
}

func TestMarshalSortsByNameThenUsername(t *testing.T) {
	p := Payload{Entries: []Entry{
		{Name: "zsite.com", Username: "a", Updated: Now()},
		{Name: "asite.com", Username: "b", Updated: Now()},
		{Name: "asite.com", Username: "a", Updated: Now()},
	}}
	if _, err := Marshal(p); err != nil {
		t.Fatal(err)
	}

	want := []string{"asite.com|a", "asite.com|b", "zsite.com|a"}
	var got []string
	for _, e := range p.Entries {
		got = append(got, e.Name+"|"+e.Username)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sort order = %v, want %v", got, want)
			break
		}
	}
}

func TestUnmarshalRejectsWrongVersion(t *testing.T) {
	if _, err := Unmarshal([]byte(`{"version":2,"entries":[]}`)); err == nil {
		t.Error("Unmarshal accepted a payload with an unsupported version")
	}
	if _, err := Unmarshal([]byte(`{"entries":[]}`)); err == nil {
		t.Error("Unmarshal accepted a payload with no version field (defaults to 0)")
	}
}

func TestOptionalFieldsOmittedWhenEmpty(t *testing.T) {
	p := New()
	p.Entries = append(p.Entries, Entry{Name: "x", Secret: "y", Updated: Now()})

	data, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if strings.Contains(s, `"username"`) {
		t.Error("empty username should be omitted")
	}
	if strings.Contains(s, `"notes"`) {
		t.Error("empty notes should be omitted")
	}
}

func TestUpdatedEncodesAsPlainRFC3339(t *testing.T) {
	ts := time.Date(2026, 9, 6, 17, 20, 0, 0, time.UTC)
	p := Payload{Entries: []Entry{{Name: "x", Secret: "y", Updated: ts}}}

	data, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"2026-09-06T17:20:00Z"`) {
		t.Errorf("expected a plain RFC3339 timestamp with no fractional seconds, got: %s", data)
	}
}

func TestNowTruncatesToWholeSeconds(t *testing.T) {
	n := Now()
	if n.Nanosecond() != 0 {
		t.Errorf("Now() has non-zero nanoseconds: %v", n)
	}
	if n.Location() != time.UTC {
		t.Errorf("Now() is not UTC: %v", n.Location())
	}
}
