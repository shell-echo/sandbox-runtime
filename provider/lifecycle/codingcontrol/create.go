package codingcontrol

import (
	"context"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

// CreateRepository is a distinct, read/commit-only capability. It cannot
// mint or redispatch an original effect and does not widen the cleanup port.
type CreateRepository interface {
	ReadCreateBinding(context.Context, string) (dockercontrol.CodingCreateAuthority, error)
	CompleteCreateWithObservation(context.Context, string, CreateObservation) (lifecycle.Operation, lifecycle.Sandbox, error)
}

type CreateCoordinator struct {
	repository CreateRepository
	observer   Observer
	clock      Clock
	expected   Expected
}

func NewCreateReadback(repository CreateRepository, observer Observer, clock Clock, expected Expected) (*CreateCoordinator, error) {
	if repository == nil || observer == nil || clock == nil || clock.Now().IsZero() ||
		expected.ProfileDigest == "" || expected.ControlPolicyDigest == "" || expected.ProviderPrincipalDigest == "" {
		return nil, ErrObservation
	}
	return &CreateCoordinator{repository: repository, observer: observer, clock: clock, expected: expected}, nil
}

// CreateObservation has no public constructor. Only this configured observer
// can produce it. PG rechecks all current state in the same commit as Ready.
type CreateObservation struct{ completed CompletedObservation }

func (o CreateObservation) Validate(create dockercontrol.CodingCreateAuthority, now time.Time) error {
	if now.IsZero() || o.completed.Validate(create) != nil ||
		o.UpdatedAt().After(now) || create.Validate(o.UpdatedAt()) != nil {
		return ErrObservation
	}
	return nil
}
func (o CreateObservation) CreateAuthority() dockercontrol.CodingCreateAuthority {
	return o.completed.CreateAuthority()
}
func (o CreateObservation) ControlRevision() uint64    { return o.completed.ControlRevision() }
func (o CreateObservation) ControlStateDigest() string { return o.completed.ControlStateDigest() }
func (o CreateObservation) CompletionDigest() string   { return o.completed.CompletionDigest() }
func (o CreateObservation) CompletionEvidenceDigest() string {
	return o.completed.CompletionEvidenceDigest()
}
func (o CreateObservation) UpdatedAt() time.Time { return o.completed.UpdatedAt() }

func (c *CreateCoordinator) ReconcileCodingCreate(ctx context.Context, operationID string) (lifecycle.Operation, lifecycle.Sandbox, error) {
	fail := func(err error) (lifecycle.Operation, lifecycle.Sandbox, error) {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	if c == nil || ctx == nil || ctx.Err() != nil || lifecycle.ValidateIdentifier(operationID) != nil {
		return fail(ErrObservation)
	}
	create, err := c.repository.ReadCreateBinding(ctx, operationID)
	if err != nil {
		return fail(err)
	}
	if create.OperationID != operationID || !c.expected.matches(create) {
		return fail(ErrObservation)
	}
	request := codingcontrolprotocol.Request{Protocol: codingcontrolprotocol.ProtocolID, Scope: codingcontrolprotocol.ScopeCoding, Action: codingcontrolprotocol.ActionStatus, Create: create}
	if request.Validate(c.clock.Now(), c.expected.ProviderPrincipalDigest) != nil {
		return fail(ErrObservation)
	}
	response, err := c.observer.Observe(ctx, request)
	if err != nil {
		return fail(err)
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	observation := CreateObservation{completed: CompletedObservation{create: create, response: response}}
	if observation.Validate(create, c.clock.Now()) != nil {
		return fail(ErrObservation)
	}
	return c.repository.CompleteCreateWithObservation(ctx, operationID, observation)
}
