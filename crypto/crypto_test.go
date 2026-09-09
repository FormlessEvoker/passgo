package crypto

import "testing"

func TestParamsValidate(t *testing.T) {
	cases := []struct {
		name    string
		p       Params
		wantErr bool
	}{
		{"defaults", DefaultParams, false},
		{"min bounds", Params{MinMemoryKiB, MinIterations, MinParallelism}, false},
		{"max bounds", Params{MaxMemoryKiB, MaxIterations, MaxParallelism}, false},
		{"memory too low", Params{MinMemoryKiB - 1, 3, 4}, true},
		{"memory too high", Params{MaxMemoryKiB + 1, 3, 4}, true},
		{"iterations zero", Params{65536, 0, 4}, true},
		{"iterations too high", Params{65536, MaxIterations + 1, 4}, true},
		{"parallelism zero", Params{65536, 3, 0}, true},
		{"parallelism too high", Params{65536, 3, MaxParallelism + 1}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	salt, err := RandomBytes(SaltSize)
	if err != nil {
		t.Fatal(err)
	}
	// Cheap params so the test doesn't pay the full ~64MiB/3-pass cost.
	p := Params{MemoryKiB: MinMemoryKiB, Iterations: 1, Parallelism: 1}

	k1 := DeriveKey("correct horse", salt, p)
	k2 := DeriveKey("correct horse", salt, p)
	if len(k1) != KeySize {
		t.Fatalf("key length = %d, want %d", len(k1), KeySize)
	}
	if string(k1) != string(k2) {
		t.Error("DeriveKey is not deterministic for the same password/salt/params")
	}

	k3 := DeriveKey("wrong password", salt, p)
	if string(k1) == string(k3) {
		t.Error("different passwords produced the same key")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := RandomBytesInto(key); err != nil {
		t.Fatal(err)
	}
	nonce, err := RandomBytes(NonceSize)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("header bytes used as AAD")
	plaintext := []byte(`{"version":1,"entries":[]}`)

	ct, err := Seal(key, nonce, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, nonce, aad, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	key2[0] = 1 // ensure it differs from the all-zero key1
	nonce, _ := RandomBytes(NonceSize)
	aad := []byte("aad")

	ct, err := Seal(key1, nonce, aad, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(key2, nonce, aad, ct); err == nil {
		t.Error("Open succeeded with the wrong key")
	}
}

func TestOpenTamperedAADFails(t *testing.T) {
	key := make([]byte, KeySize)
	nonce, _ := RandomBytes(NonceSize)

	ct, err := Seal(key, nonce, []byte("original header"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(key, nonce, []byte("tampered header"), ct); err == nil {
		t.Error("Open succeeded after the AAD was tampered with")
	}
}

func TestOpenTamperedCiphertextFails(t *testing.T) {
	key := make([]byte, KeySize)
	nonce, _ := RandomBytes(NonceSize)
	aad := []byte("aad")

	ct, err := Seal(key, nonce, aad, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xFF
	if _, err := Open(key, nonce, aad, ct); err == nil {
		t.Error("Open succeeded on tampered ciphertext")
	}
}

// RandomBytesInto fills b with random bytes, for tests that need a
// specific pre-sized slice (e.g. a key of exactly KeySize).
func RandomBytesInto(b []byte) (int, error) {
	r, err := RandomBytes(len(b))
	if err != nil {
		return 0, err
	}
	copy(b, r)
	return len(b), nil
}
