package codingcontrol

import (
	"context"
	"errors"
	"reflect"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

var ErrRuntimePreflight = errors.New("Coding runtime preflight unavailable")

// RuntimeSnapshot is a read-only projection from one PG snapshot. It contains
// no original Control authority or physical target. It is neither an admission
// nor a permit: a later mutation must atomically recheck the current allocation,
// completion, lease, generation and fence alongside its own durable intent.
type RuntimeSnapshot struct {
	Sandbox                 lifecycle.Sandbox
	Lease                   lifecycle.Lease
	ProfileDigest           string
	ControlPolicyDigest     string
	ProviderPrincipalDigest string
	ObservedAt              time.Time
}

type RuntimeReader interface {
	ReadCodingRuntime(context.Context, string) (RuntimeSnapshot, error)
}

// ExecPreflight checks only request support and read-time eligibility. It
// deliberately implements no Executor, Observer, Canceler or ResultCleaner.
// In particular CheckSupport success cannot authorize a later exec.Start.
type ExecPreflight struct {
	reader   RuntimeReader
	clock    Clock
	expected Expected
}

func NewExecPreflight(reader RuntimeReader, clock Clock, expected Expected) (*ExecPreflight, error) {
	if nilRuntimeDependency(reader) || nilRuntimeDependency(clock) || clock.Now().IsZero() ||
		lifecycle.ValidateDigest(expected.ProfileDigest) != nil || lifecycle.ValidateDigest(expected.ControlPolicyDigest) != nil ||
		lifecycle.ValidateDigest(expected.ProviderPrincipalDigest) != nil {
		return nil, ErrRuntimePreflight
	}
	return &ExecPreflight{reader: reader, clock: clock, expected: expected}, nil
}

func nilRuntimeDependency(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}

func (p *ExecPreflight) CheckSupport(ctx context.Context, request providerexec.Request) error {
	if ctx == nil || p == nil || nilRuntimeDependency(p.reader) || nilRuntimeDependency(p.clock) {
		return ErrRuntimePreflight
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	started := p.clock.Now().UTC()
	if started.IsZero() {
		return ErrRuntimePreflight
	}
	request = request.Clone()
	if err := request.Validate(started); err != nil {
		return err
	}
	// Match the currently implemented coding-shell feature subset. References
	// are not plaintext; no resolver or implicit reference fallback is added.
	if len(request.Environment) != 0 || len(request.SecretReferenceIDs) != 0 || request.SecretGrantID != "" || request.SecretGrantDigest != "" || request.StdinReference != "" {
		return providerexec.ErrUnsupportedRequest
	}
	readCtx, cancel := context.WithDeadline(ctx, request.Deadline)
	defer cancel()
	snapshot, err := p.reader.ReadCodingRuntime(readCtx, request.SandboxID)
	if readCtx.Err() != nil {
		return readCtx.Err()
	}
	if err != nil {
		return ErrRuntimePreflight
	}
	now := p.clock.Now().UTC()
	sb, lease := snapshot.Sandbox, snapshot.Lease
	if now.Before(started) || request.Validate(now) != nil || snapshot.ObservedAt.Before(started) || snapshot.ObservedAt.After(now) ||
		snapshot.ProfileDigest != p.expected.ProfileDigest || snapshot.ControlPolicyDigest != p.expected.ControlPolicyDigest || snapshot.ProviderPrincipalDigest != p.expected.ProviderPrincipalDigest ||
		sb.Validate() != nil || lease.Validate() != nil || sb.ID != request.SandboxID || sb.RuntimeProfile != "sandbox-runtime-coding-shell-v1" ||
		sb.Network != (lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}) || sb.Generation != uint64(request.ExpectedGeneration) ||
		sb.DesiredState != lifecycle.DesiredReady || sb.ObservedState != lifecycle.ObservedReady || sb.ObservedGeneration != sb.Generation ||
		sb.UpdatedAt.After(snapshot.ObservedAt) || lease.SandboxID != sb.ID || lease.Generation != sb.Generation ||
		!lease.ExpiresAt.Equal(sb.LeaseExpiresAt) || !lease.ExpiresAt.After(now) || uint64(request.FencingToken) < lease.FencingToken {
		return ErrRuntimePreflight
	}
	// A higher requested fence is only a prospective check. Nothing here
	// advances that fence or prevents a concurrent terminate after the SELECT.
	return readCtx.Err()
}

var _ providerexec.SupportChecker = (*ExecPreflight)(nil)
