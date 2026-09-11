package crypto

import "golang.org/x/crypto/argon2"

// KeySize is the length in bytes of the key derived for AES-256-GCM.
const KeySize = 32

// DeriveKey derives a KeySize-byte key from password and salt using
// Argon2id under p. The caller must have called p.Validate first —
// DeriveKey does not check bounds itself, since a reader parsing an
// untrusted header needs to validate before this is ever called.
func DeriveKey(password string, salt []byte, p Params) []byte {
	return argon2.IDKey([]byte(password), salt, p.Iterations, p.MemoryKiB, p.Parallelism, KeySize)
}
