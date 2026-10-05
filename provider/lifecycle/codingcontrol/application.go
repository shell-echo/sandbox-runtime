// Package codingcontrol coordinates repository-owned Coding state with one
// dedicated, authenticated Control observation port. It does not perform TLS
// itself and its value types are not cryptographic capabilities. Production
// composition must bind Observer to the frozen Profile-v2 mTLS/CRL adapter.
package codingcontrol

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
)

var ErrObservation = errors.New("untrusted Coding Control observation")

// Binding is a repository read hint, not authority over the later PG CAS.
// The repository must read the current original effect and, for Finish, the
// exact persisted retirement floor. A caller cannot supply this value to Run.
type Binding struct {
	Create             dockercontrol.CodingCreateAuthority
	Cleanup            *dockercontrol.CodingCleanupAuthority
	TerminationID      string
	ControlRevision    uint64
	ControlStateDigest string
}

type Repository interface {
	ReadBeginBinding(context.Context, string) (Binding, error)
	ReadFinishBinding(context.Context, string) (Binding, error)
	BeginWithObservation(context.Context, string, CompletedObservation) (dockercontrol.CodingCleanupAuthority, error)
	FinishWithObservation(context.Context, string, ReleasedObservation) error
}

// Observer is a private port. Only the dedicated production mTLS/CRL client
// may implement it in production; a test fake supplies component evidence.
type Observer interface {
	Observe(context.Context, codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error)
}

type Clock interface{ Now() time.Time }

type Expected struct {
	ProfileDigest           string
	ControlPolicyDigest     string
	ProviderPrincipalDigest string
}

func (e Expected) matches(create dockercontrol.CodingCreateAuthority) bool {
	return e.ProfileDigest != "" && e.ControlPolicyDigest != "" &&
		e.ProviderPrincipalDigest != "" && create.ProfileDigest == e.ProfileDigest &&
		create.ControlPolicyDigest == e.ControlPolicyDigest &&
		create.PeerPrincipalDigest == e.ProviderPrincipalDigest
}

type Coordinator struct {
	repository Repository
	observer   Observer
	clock      Clock
	expected   Expected
}

func New(repository Repository, observer Observer, clock Clock, expected Expected) (*Coordinator, error) {
	if repository == nil || observer == nil || clock == nil || clock.Now().IsZero() ||
		expected.ProfileDigest == "" || expected.ControlPolicyDigest == "" ||
		expected.ProviderPrincipalDigest == "" {
		return nil, ErrObservation
	}
	return &Coordinator{repository: repository, observer: observer, clock: clock, expected: expected}, nil
}

// CompletedObservation can only be produced by the application coordinator
// after its configured observation port returns an exact Completed read. PG
// must recheck the current tuple under its own row lock before consuming it.
type CompletedObservation struct {
	create   dockercontrol.CodingCreateAuthority
	response codingcontrolprotocol.Response
}

func (o CompletedObservation) Validate(create dockercontrol.CodingCreateAuthority) error {
	request := codingcontrolprotocol.Request{Protocol: codingcontrolprotocol.ProtocolID,
		Scope: codingcontrolprotocol.ScopeCoding, Action: codingcontrolprotocol.ActionStatus, Create: create}
	if o.create != create || o.response.Status != codingcontrolprotocol.StatusCompleted ||
		o.response.Validate(request) != nil {
		return ErrObservation
	}
	return nil
}

func (o CompletedObservation) ControlRevision() uint64                              { return o.response.ControlRevision }
func (o CompletedObservation) CreateAuthority() dockercontrol.CodingCreateAuthority { return o.create }
func (o CompletedObservation) ControlStateDigest() string                           { return o.response.ControlStateDigest }
func (o CompletedObservation) CompletionDigest() string                             { return o.response.CompletionDigest }
func (o CompletedObservation) CompletionEvidenceDigest() string {
	return o.response.CompletionEvidenceDigest
}
func (o CompletedObservation) UpdatedAt() time.Time { return o.response.UpdatedAt }

// ReleasedObservation is distinct from Completed; neither a pending nor an
// unknown/not-found response can be upgraded through a status cast.
type ReleasedObservation struct {
	create   dockercontrol.CodingCreateAuthority
	cleanup  dockercontrol.CodingCleanupAuthority
	response codingcontrolprotocol.Response
}

func (o ReleasedObservation) Validate(create dockercontrol.CodingCreateAuthority,
	cleanup dockercontrol.CodingCleanupAuthority, now time.Time,
	minimumControlRevision uint64, previousStateDigest string) error {
	request := codingcontrolprotocol.Request{Protocol: codingcontrolprotocol.ProtocolID,
		Scope: codingcontrolprotocol.ScopeCoding, Action: codingcontrolprotocol.ActionStatus,
		Create: create, Cleanup: &cleanup}
	if o.create != create || o.cleanup != cleanup ||
		o.response.ValidateReleaseObservation(request, now, minimumControlRevision,
			previousStateDigest) != nil {
		return ErrObservation
	}
	return nil
}

func (o ReleasedObservation) ControlRevision() uint64                              { return o.response.ControlRevision }
func (o ReleasedObservation) CreateAuthority() dockercontrol.CodingCreateAuthority { return o.create }
func (o ReleasedObservation) CleanupAuthority() dockercontrol.CodingCleanupAuthority {
	return o.cleanup
}
func (o ReleasedObservation) ControlStateDigest() string { return o.response.ControlStateDigest }
func (o ReleasedObservation) CompletionDigest() string   { return o.response.CompletionDigest }
func (o ReleasedObservation) CompletionEvidenceDigest() string {
	return o.response.CompletionEvidenceDigest
}
func (o ReleasedObservation) AbsenceDigest() string         { return o.response.AbsenceDigest }
func (o ReleasedObservation) AbsenceEvidenceDigest() string { return o.response.AbsenceEvidenceDigest }
func (o ReleasedObservation) UpdatedAt() time.Time          { return o.response.UpdatedAt }

// Begin observes outside the PG row lock. A failed/cancelled observation
// cannot produce a value for the repository's typed commit entry point.
func (c *Coordinator) Begin(ctx context.Context, terminationID string) (dockercontrol.CodingCleanupAuthority, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || terminationID == "" {
		return dockercontrol.CodingCleanupAuthority{}, ErrObservation
	}
	binding, err := c.repository.ReadBeginBinding(ctx, terminationID)
	if err != nil {
		return dockercontrol.CodingCleanupAuthority{}, err
	}
	if binding.Cleanup != nil || !c.expected.matches(binding.Create) ||
		binding.TerminationID != terminationID || binding.ControlRevision != 0 ||
		binding.ControlStateDigest != "" {
		return dockercontrol.CodingCleanupAuthority{}, ErrObservation
	}
	request := codingcontrolprotocol.Request{Protocol: codingcontrolprotocol.ProtocolID,
		Scope: codingcontrolprotocol.ScopeCoding, Action: codingcontrolprotocol.ActionStatus,
		Create: binding.Create}
	if request.Validate(c.clock.Now(), c.expected.ProviderPrincipalDigest) != nil {
		return dockercontrol.CodingCleanupAuthority{}, ErrObservation
	}
	response, err := c.observer.Observe(ctx, request)
	if err != nil {
		return dockercontrol.CodingCleanupAuthority{}, err
	}
	if ctx.Err() != nil {
		return dockercontrol.CodingCleanupAuthority{}, ctx.Err()
	}
	observation := CompletedObservation{create: binding.Create, response: response}
	if observation.Validate(binding.Create) != nil || response.UpdatedAt.After(c.clock.Now()) {
		return dockercontrol.CodingCleanupAuthority{}, ErrObservation
	}
	authority, err := c.repository.BeginWithObservation(ctx, terminationID, observation)
	if err != nil {
		return dockercontrol.CodingCleanupAuthority{}, err
	}
	if err := ctx.Err(); err != nil {
		return dockercontrol.CodingCleanupAuthority{}, err
	}
	if authority.Validate(c.clock.Now()) != nil {
		return dockercontrol.CodingCleanupAuthority{}, ErrObservation
	}
	return authority, nil
}

// Finish consumes only a sealed Released readback of the exact immutable
// cleanup intent. A historical expired intent may be queried read-only; this
// method never issues or renews a physical mutation permit.
func (c *Coordinator) Finish(ctx context.Context, terminationID string) error {
	if c == nil || ctx == nil || ctx.Err() != nil || terminationID == "" {
		return ErrObservation
	}
	binding, err := c.repository.ReadFinishBinding(ctx, terminationID)
	if err != nil {
		return err
	}
	if binding.Cleanup == nil || !c.expected.matches(binding.Create) ||
		binding.TerminationID != terminationID || binding.ControlRevision == 0 ||
		binding.ControlStateDigest == "" {
		return ErrObservation
	}
	request := codingcontrolprotocol.Request{Protocol: codingcontrolprotocol.ProtocolID,
		Scope: codingcontrolprotocol.ScopeCoding, Action: codingcontrolprotocol.ActionStatus,
		Create: binding.Create, Cleanup: binding.Cleanup}
	if request.Validate(c.clock.Now(), c.expected.ProviderPrincipalDigest) != nil {
		return ErrObservation
	}
	response, err := c.observer.Observe(ctx, request)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	observation := ReleasedObservation{create: binding.Create, cleanup: *binding.Cleanup, response: response}
	if observation.Validate(binding.Create, *binding.Cleanup, c.clock.Now(),
		binding.ControlRevision, binding.ControlStateDigest) != nil {
		return ErrObservation
	}
	return c.repository.FinishWithObservation(ctx, terminationID, observation)
}
