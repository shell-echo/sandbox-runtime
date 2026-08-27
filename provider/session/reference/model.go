// Package reference manages durable opaque terminal handoff references. It
// stores only provider-neutral session and terminal identities; backend
// endpoints and adapter-private state remain outside this package.
package reference

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
)

var (
	ErrInvalidReference = errors.New("invalid Provider terminal handoff reference")
	ErrInvalidRecord    = errors.New("invalid Provider terminal handoff reference record")
	ErrNotFound         = errors.New("Provider terminal handoff reference not found")
	ErrAlreadyExists    = errors.New("Provider terminal handoff reference already exists")
	ErrConflict         = errors.New("Provider terminal handoff reference conflict")
	ErrExpired          = errors.New("Provider terminal handoff reference has expired")
	ErrRevoked          = errors.New("Provider terminal handoff reference has been revoked")
	ErrUnavailable      = errors.New("Provider terminal handoff reference is unavailable")
	ErrStale            = errors.New("Provider terminal handoff reference is stale")
	ErrDurability       = errors.New("Provider terminal handoff reference durability failure")
	ErrClosed           = errors.New("Provider terminal handoff reference registry is closed")

	referencePattern  = regexp.MustCompile(`^ref:session:[0-9a-f]{32}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
)

// Record is the durable, private binding of one opaque ref:session value to a
// session allocation. Receipt.Reference is provider-neutral; the terminal
// adapter owns the backend data reached through that receipt.
type Record struct {
	Reference            string                    `json:"reference"`
	OperationID          string                    `json:"operation_id"`
	AttemptID            string                    `json:"attempt_id"`
	FencingToken         int64                     `json:"fencing_token"`
	SandboxID            string                    `json:"sandbox_id"`
	ProviderRevisionID   string                    `json:"provider_revision_id"`
	RuntimeSessionID     string                    `json:"runtime_session_id"`
	CapabilityProfileID  string                    `json:"capability_profile_id"`
	ConnectionGeneration int64                     `json:"connection_generation"`
	ExpiresAt            time.Time                 `json:"expires_at"`
	Receipt              session.AllocationReceipt `json:"receipt"`
	CreatedAt            time.Time                 `json:"created_at"`
	RevokedAt            *time.Time                `json:"revoked_at,omitempty"`
}

// NewRecord validates a currently running session before it receives an
// opaque reference. Registering the reference precedes session success and is
// intentionally not cross-repository atomic; Resolver validates the eventual
// successful handoff before allowing an attach.
func NewRecord(reference string, source session.Record, createdAt time.Time) (Record, error) {
	createdAt = createdAt.UTC()
	if !referencePattern.MatchString(reference) {
		return Record{}, ErrInvalidReference
	}
	if err := source.Validate(); err != nil || source.Status != session.StatusRunning || source.Allocation == nil || source.Allocation.State != session.AllocationRunning {
		return Record{}, ErrInvalidRecord
	}
	if createdAt.IsZero() || !createdAt.Before(source.Request.ExpiresAt) || createdAt.Before(source.Allocation.Receipt.AllocatedAt) {
		return Record{}, ErrExpired
	}
	record := Record{
		Reference:   reference,
		OperationID: source.Request.OperationID, AttemptID: source.Request.AttemptID,
		FencingToken: source.Request.FencingToken, SandboxID: source.Request.SandboxID,
		ProviderRevisionID: source.Request.ProviderRevisionID, RuntimeSessionID: source.Request.RuntimeSessionID,
		CapabilityProfileID:  source.Request.CapabilityProfileID,
		ConnectionGeneration: source.Allocation.Receipt.ConnectionGeneration,
		ExpiresAt:            source.Request.ExpiresAt.UTC(), Receipt: source.Allocation.Receipt,
		CreatedAt: createdAt,
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (r Record) Clone() Record {
	clone := r
	if r.RevokedAt != nil {
		revokedAt := r.RevokedAt.UTC()
		clone.RevokedAt = &revokedAt
	}
	return clone
}

func (r Record) Validate() error {
	if !referencePattern.MatchString(r.Reference) {
		return ErrInvalidReference
	}
	for _, value := range []string{
		r.OperationID, r.AttemptID, r.SandboxID, r.ProviderRevisionID,
		r.RuntimeSessionID, r.CapabilityProfileID,
	} {
		if !identifierPattern.MatchString(value) {
			return ErrInvalidRecord
		}
	}
	if r.FencingToken < 1 || r.ConnectionGeneration < 1 || r.ExpiresAt.IsZero() || r.CreatedAt.IsZero() || !r.CreatedAt.Before(r.ExpiresAt) {
		return ErrInvalidRecord
	}
	if err := r.Receipt.Validate(); err != nil ||
		r.Receipt.OperationID != r.OperationID || r.Receipt.AttemptID != r.AttemptID ||
		r.Receipt.FencingToken != r.FencingToken || r.Receipt.SandboxID != r.SandboxID ||
		r.Receipt.RuntimeSessionID != r.RuntimeSessionID ||
		r.Receipt.ConnectionGeneration != r.ConnectionGeneration || !r.Receipt.ExpiresAt.Equal(r.ExpiresAt) ||
		r.CreatedAt.Before(r.Receipt.AllocatedAt) {
		return ErrInvalidRecord
	}
	if r.RevokedAt != nil && (r.RevokedAt.IsZero() || r.RevokedAt.Before(r.CreatedAt)) {
		return ErrInvalidRecord
	}
	return nil
}

func (r Record) Evidence() session.EndpointEvidence {
	return session.EndpointEvidence{InternalEndpointReference: r.Reference, ConnectionGeneration: r.ConnectionGeneration}
}

func (r Record) activeAt(now time.Time) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.RevokedAt != nil {
		return ErrRevoked
	}
	if now.IsZero() || !now.Before(r.ExpiresAt) {
		return ErrExpired
	}
	return nil
}

func (r Record) matchesSucceeded(source session.Record) error {
	if err := source.Validate(); err != nil || source.Status != session.StatusSucceeded || source.Handoff == nil || source.Allocation == nil || source.Allocation.State != session.AllocationRunning {
		return ErrStale
	}
	handoff := source.Handoff
	if handoff.InternalEndpointReference != r.Reference || handoff.ConnectionGeneration != r.ConnectionGeneration ||
		source.Request.OperationID != r.OperationID || source.Request.AttemptID != r.AttemptID ||
		source.Request.FencingToken != r.FencingToken || source.Request.SandboxID != r.SandboxID ||
		source.Request.ProviderRevisionID != r.ProviderRevisionID || source.Request.RuntimeSessionID != r.RuntimeSessionID ||
		source.Request.CapabilityProfileID != r.CapabilityProfileID || !source.Request.ExpiresAt.Equal(r.ExpiresAt) ||
		!sameReceipt(source.Allocation.Receipt, r.Receipt) {
		return ErrStale
	}
	return nil
}

func sameReceipt(left, right session.AllocationReceipt) bool {
	return left.Reference == right.Reference && left.SandboxID == right.SandboxID &&
		left.RuntimeSessionID == right.RuntimeSessionID && left.OperationID == right.OperationID &&
		left.AttemptID == right.AttemptID && left.FencingToken == right.FencingToken &&
		left.ExpectedGeneration == right.ExpectedGeneration && left.ConnectionGeneration == right.ConnectionGeneration &&
		left.AllocatedAt.Equal(right.AllocatedAt) && left.ExpiresAt.Equal(right.ExpiresAt)
}

func invalidRecord(field string) error { return fmt.Errorf("%w: %s", ErrInvalidRecord, field) }
