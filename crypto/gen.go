package crypto

import (
	"crypto/rand"
	"fmt"
)

// GenAlphabet is the default alphabet used for generated passwords:
// letters, digits, and ASCII-printable symbols, excluding space, quote,
// backslash, and backtick — characters prone to shell and copy-paste
// trouble. See SPECIFICATION.md §2.3.
const GenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" +
	"!#$%&()*+,-.:;<=>?@[]^_{|}~"

// DefaultGenLength is the default length of a generated password.
const DefaultGenLength = 20

// GeneratePassword returns a password of the given length drawn from
// GenAlphabet, using crypto/rand with rejection sampling so every
// character is uniformly distributed with no modulo bias.
func GeneratePassword(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("crypto: password length must be positive, got %d", length)
	}

	n := len(GenAlphabet)
	// The largest multiple of n that fits in a byte; a sampled byte at
	// or above this is rejected and resampled, so index := b % n never
	// favors the low end of the alphabet.
	limit := byte(256 - (256 % n))

	out := make([]byte, length)
	buf := make([]byte, 1)
	for i := 0; i < length; i++ {
		for {
			if _, err := rand.Read(buf); err != nil {
				return "", err
			}
			if buf[0] < limit {
				out[i] = GenAlphabet[int(buf[0])%n]
				break
			}
		}
	}
	return string(out), nil
}
