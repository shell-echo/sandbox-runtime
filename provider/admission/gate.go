package admission

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"
)

var (
	// ErrUnauthenticated means the compact bearer value did not verify. It is
	// deliberately free of token, key, and signature details.
	ErrUnauthenticated = errors.New("provider admission is unauthenticated")
	// ErrForbidden means a verified token did not bind to the admitted request.
	ErrForbidden = errors.New("provider admission is forbidden")
	// ErrConflict means the mutation JTI was replayed or its fencing was stale.
	ErrConflict = errors.New("provider admission conflicts with a prior mutation")
	// ErrUnavailable means the local admission guard could not make a durable
	// decision. Callers must fail closed rather than dispatching the request.
	ErrUnavailable = errors.New("provider admission is unavailable")
)

// ProtectedOperationGate composes closed JWS verification, contextual token
// binding, and mutation replay/fencing admission before a caller can reach an
// application dispatcher. It has no HTTP, repository, or driver dependency.
type ProtectedOperationGate struct {
	keys  TrustedKeySource
	clock Clock
	guard MutationGuard
}

// ProtectedOperationRequest is the transient input to protected-operation
// admission. Binding facts originate at transport: Caller must be selected from
// a TLS-verified client leaf, while Document is the bounded request or read
// descriptor that must match the token's canonical digest.
type ProtectedOperationRequest struct {
	CompactToken string
	Binding      TokenBinding
	Document     []byte
}

// NewProtectedOperationGate freezes the collaborators required for every
// protected operation. A mutation guard is mandatory even when callers plan to
// admit only reads, so enabling a future mutation path cannot silently bypass
// durable replay and fencing checks.
func NewProtectedOperationGate(keys TrustedKeySource, clock Clock, guard MutationGuard) (*ProtectedOperationGate, error) {
	if keys == nil || clock == nil || guard == nil || clock.Now().IsZero() {
		return nil, errors.New("protected Provider admission requires keys, clock, and mutation guard")
	}
	return &ProtectedOperationGate{keys: keys, clock: clock, guard: guard}, nil
}

// AuthenticateBearer verifies the compact JWS authentication boundary and its
// self-contained short-lived credential window. Transport uses it before
// evaluating auxiliary Context or document input so malformed, inactive, or
// unverifiable bearer material cannot probe those validations. Contextual
// binding, digest, replay, and fencing checks remain in Admit.
func (g *ProtectedOperationGate) AuthenticateBearer(ctx context.Context, compactToken string) error {
	if g == nil || g.keys == nil || g.clock == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		return ErrUnauthenticated
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	token, err := VerifyCompactJWS(ctx, compactToken, g.keys)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return ErrUnauthenticated
	}
	if !validBearerLifetime(token.Claims, g.clock.Now()) {
		return ErrUnauthenticated
	}
	return nil
}

// Admit verifies one compact token against transport-normalized and
// TLS-verified binding facts, then verifies the actual canonical request or
// read-descriptor digest. The compact token and document are transient input
// only; neither the result nor any exported error retains them. The caller must
// invoke this before any application, repository, or driver dispatch.
func (g *ProtectedOperationGate) Admit(ctx context.Context, request ProtectedOperationRequest) error {
	if g == nil || g.keys == nil || g.clock == nil || g.guard == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		return ErrUnauthenticated
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	token, err := VerifyCompactJWS(ctx, request.CompactToken, g.keys)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return ErrUnauthenticated
	}
	if err := ValidateTokenBinding(token, request.Binding, g.clock); err != nil {
		if errors.Is(err, errInactiveBearer) {
			return ErrUnauthenticated
		}
		return ErrForbidden
	}
	if err := VerifyRequestDigest(token.Claims.RequestDigestProfile, token.Claims.RequestDigest, request.Document); err != nil {
		if errors.Is(err, ErrInvalidRequestDocument) {
			return errors.Join(ErrForbidden, ErrInvalidRequestDocument)
		}
		return ErrForbidden
	}
	if !token.Claims.Operation.Mutation() {
		return nil
	}

	decision, err := g.guard.Reserve(ctx, MutationGuardRequest{
		ProviderRevisionID: token.Claims.ProviderRevisionID,
		SandboxID:          token.Claims.SandboxID,
		OperationID:        token.Claims.OperationID,
		AttemptID:          token.Claims.AttemptID,
		FencingToken:       token.Claims.FencingToken,
		JTIFingerprint:     sha256.Sum256([]byte(token.Claims.JTI)),
		ExpiresAt:          time.Unix(token.Claims.ExpiresAt, 0).UTC(),
	})
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return ErrUnavailable
	}
	switch decision {
	case MutationGuardAccepted:
		return nil
	case MutationGuardReplayed, MutationGuardStaleFencing:
		return ErrConflict
	default:
		return ErrUnavailable
	}
}

// Mutation reports whether operation can cause Provider-local side effects and
// must therefore consume a JTI and update fencing state.
func (operation Operation) Mutation() bool {
	switch operation {
	case OperationCreate, OperationRestore, OperationSetDesiredState,
		OperationExtendLease, OperationExec, OperationCancelExec,
		OperationOpenRuntimeSession, OperationOpenBrowserSession, OperationStageArtifact, OperationSnapshot, OperationTerminate:
		return true
	default:
		return false
	}
}
