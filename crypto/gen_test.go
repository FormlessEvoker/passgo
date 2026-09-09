package crypto

import (
	"strings"
	"testing"
)

func TestGeneratePasswordLength(t *testing.T) {
	for _, n := range []int{1, 8, 20, 64} {
		pw, err := GeneratePassword(n)
		if err != nil {
			t.Fatalf("GeneratePassword(%d): %v", n, err)
		}
		if len(pw) != n {
			t.Errorf("len(GeneratePassword(%d)) = %d", n, len(pw))
		}
		for _, c := range pw {
			if !strings.ContainsRune(GenAlphabet, c) {
				t.Errorf("generated password contains character outside the alphabet: %q", c)
			}
		}
	}
}

func TestGeneratePasswordRejectsNonPositiveLength(t *testing.T) {
	if _, err := GeneratePassword(0); err == nil {
		t.Error("expected an error for length 0")
	}
	if _, err := GeneratePassword(-1); err == nil {
		t.Error("expected an error for a negative length")
	}
}

func TestGeneratePasswordVaries(t *testing.T) {
	a, err := GeneratePassword(20)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GeneratePassword(20)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two calls to GeneratePassword produced the same output (extremely unlikely if the generator is correct)")
	}
}
