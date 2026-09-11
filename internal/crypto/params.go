// Package crypto provides the low-level primitives used to protect a
// passgo vault: Argon2id key derivation and AES-256-GCM authenticated
// encryption. It has no knowledge of the vault file format; see the
// vault package for that.
package crypto

import "fmt"

// Params holds the Argon2id cost parameters used to derive a vault key.
// They are stored in the vault header so they can be raised later
// without breaking existing vaults.
type Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

// DefaultParams are the Argon2id parameters used for newly created vaults.
var DefaultParams = Params{
	MemoryKiB:   65536, // 64 MiB
	Iterations:  3,
	Parallelism: 4,
}

// Bounds a reader MUST enforce on parameters read from a vault header
// before allocating memory for them, so a hostile file cannot request
// unbounded resources.
const (
	MinMemoryKiB   = 8192
	MaxMemoryKiB   = 1048576
	MinIterations  = 1
	MaxIterations  = 32
	MinParallelism = 1
	MaxParallelism = 16
)

// Validate reports whether p falls within the bounds a reader must
// enforce before deriving a key with it.
func (p Params) Validate() error {
	if p.MemoryKiB < MinMemoryKiB || p.MemoryKiB > MaxMemoryKiB {
		return fmt.Errorf("crypto: memory %d KiB out of bounds [%d, %d]", p.MemoryKiB, MinMemoryKiB, MaxMemoryKiB)
	}
	if p.Iterations < MinIterations || p.Iterations > MaxIterations {
		return fmt.Errorf("crypto: iterations %d out of bounds [%d, %d]", p.Iterations, MinIterations, MaxIterations)
	}
	if p.Parallelism < MinParallelism || p.Parallelism > MaxParallelism {
		return fmt.Errorf("crypto: parallelism %d out of bounds [%d, %d]", p.Parallelism, MinParallelism, MaxParallelism)
	}
	return nil
}
