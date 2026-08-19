// Package admission owns Provider protected-operation admission ports and
// value objects. It deliberately contains no HTTP, repository, or driver code.
package admission

import (
	"context"
	"crypto"
	"crypto/sha256"
	"time"
)

// Algorithm is a JWS algorithm accepted by the locked Provider Contract.
type Algorithm string

const (
	AlgorithmEdDSA Algorithm = "EdDSA"
	AlgorithmES256 Algorithm = "ES256"
)

// Supported reports whether algorithm is in the closed admission allowlist.
func (algorithm Algorithm) Supported() bool {
	return algorithm == AlgorithmEdDSA || algorithm == AlgorithmES256
}

// KeyID identifies a trusted public verification key.
type KeyID string

// TrustedKeySource resolves an immutable, operator-configured public key. It
// must honor ctx and must not use network discovery or a fallback key.
type TrustedKeySource interface {
	Lookup(ctx context.Context, keyID KeyID, algorithm Algorithm) (crypto.PublicKey, error)
}

// Clock makes time-based admission deterministic and testable.
type Clock interface {
	Now() time.Time
}

// MutationGuardRequest is the minimum non-secret data needed to atomically
// reject a replayed mutation JTI or stale fencing token. JTI itself is never
// passed to the guard or persisted by its implementations.
type MutationGuardRequest struct {
	ProviderRevisionID string
	SandboxID          string
	OperationID        string
	AttemptID          string
	FencingToken       int64
	JTIFingerprint     [sha256.Size]byte
	ExpiresAt          time.Time
}

// MutationGuardDecision describes an atomic replay/fencing comparison result.
type MutationGuardDecision uint8

const (
	MutationGuardAccepted MutationGuardDecision = iota
	MutationGuardReplayed
	MutationGuardStaleFencing
)

// MutationGuard atomically records or rejects a protected mutation before any
// application, repository, or driver dispatch. An unavailable or indeterminate
// guard returns an error so its caller can fail closed.
type MutationGuard interface {
	Reserve(ctx context.Context, request MutationGuardRequest) (MutationGuardDecision, error)
}
