// Package reference manages durable opaque desktop-session handoff records.
// The reference is never a URL, display endpoint, credential, or backend ID.
package reference

import (
	"errors"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
)

var (
	ErrInvalidReference = errors.New("invalid Provider desktop handoff reference")
	ErrInvalidRecord    = errors.New("invalid Provider desktop handoff reference record")
	ErrNotFound         = errors.New("Provider desktop handoff reference not found")
	ErrAlreadyExists    = errors.New("Provider desktop handoff reference already exists")
	ErrConflict         = errors.New("Provider desktop handoff reference conflict")
	ErrExpired          = errors.New("Provider desktop handoff reference has expired")
	ErrRevoked          = errors.New("Provider desktop handoff reference has been revoked")
	ErrUnavailable      = errors.New("Provider desktop handoff reference is unavailable")
	ErrStale            = errors.New("Provider desktop handoff reference is stale")
	ErrDurability       = errors.New("Provider desktop handoff reference durability failure")
	ErrClosed           = errors.New("Provider desktop handoff registry is closed")
	referencePattern    = regexp.MustCompile(`^ref:desktop-session:[0-9a-f]{32}$`)
	identifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
)

type Record struct {
	Reference            string                    `json:"reference"`
	OperationID          string                    `json:"operation_id"`
	AttemptID            string                    `json:"attempt_id"`
	FencingToken         int64                     `json:"fencing_token"`
	SandboxID            string                    `json:"sandbox_id"`
	ProviderRevisionID   string                    `json:"provider_revision_id"`
	DesktopSessionID     string                    `json:"desktop_session_id"`
	CapabilityProfileID  string                    `json:"capability_profile_id"`
	ConnectionGeneration int64                     `json:"connection_generation"`
	ExpiresAt            time.Time                 `json:"expires_at"`
	Receipt              desktop.AllocationReceipt `json:"receipt"`
	CreatedAt            time.Time                 `json:"created_at"`
	RevokedAt            *time.Time                `json:"revoked_at,omitempty"`
}

func NewRecord(reference string, source desktop.Record, createdAt time.Time) (Record, error) {
	createdAt = createdAt.UTC()
	if !referencePattern.MatchString(reference) {
		return Record{}, ErrInvalidReference
	}
	if err := source.Validate(); err != nil || source.Status != desktop.StatusRunning || source.Allocation == nil || source.Allocation.State != desktop.AllocationRunning {
		return Record{}, ErrInvalidRecord
	}
	if createdAt.IsZero() || !createdAt.Before(source.Request.ExpiresAt) || createdAt.Before(source.Allocation.Receipt.AllocatedAt) {
		return Record{}, ErrExpired
	}
	record := Record{Reference: reference, OperationID: source.Request.OperationID, AttemptID: source.Request.AttemptID, FencingToken: source.Request.FencingToken, SandboxID: source.Request.SandboxID, ProviderRevisionID: source.Request.ProviderRevisionID, DesktopSessionID: source.Request.DesktopSessionID, CapabilityProfileID: source.Request.CapabilityProfileID, ConnectionGeneration: source.Allocation.Receipt.ConnectionGeneration, ExpiresAt: source.Request.ExpiresAt.UTC(), Receipt: source.Allocation.Receipt, CreatedAt: createdAt}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (r Record) Clone() Record {
	clone := r
	if r.RevokedAt != nil {
		value := r.RevokedAt.UTC()
		clone.RevokedAt = &value
	}
	return clone
}

func (r Record) Validate() error {
	if !referencePattern.MatchString(r.Reference) {
		return ErrInvalidReference
	}
	for _, value := range []string{r.OperationID, r.AttemptID, r.SandboxID, r.ProviderRevisionID, r.DesktopSessionID, r.CapabilityProfileID} {
		if !identifierPattern.MatchString(value) {
			return ErrInvalidRecord
		}
	}
	if r.FencingToken < 1 || r.ConnectionGeneration < 1 || r.ExpiresAt.IsZero() || r.CreatedAt.IsZero() || !r.CreatedAt.Before(r.ExpiresAt) || r.CapabilityProfileID != desktop.CapabilityProfileID {
		return ErrInvalidRecord
	}
	if err := r.Receipt.Validate(); err != nil || r.Receipt.OperationID != r.OperationID || r.Receipt.AttemptID != r.AttemptID || r.Receipt.FencingToken != r.FencingToken || r.Receipt.SandboxID != r.SandboxID || r.Receipt.DesktopSessionID != r.DesktopSessionID || r.Receipt.ConnectionGeneration != r.ConnectionGeneration || !r.Receipt.ExpiresAt.Equal(r.ExpiresAt) || r.CreatedAt.Before(r.Receipt.AllocatedAt) {
		return ErrInvalidRecord
	}
	if r.RevokedAt != nil && (r.RevokedAt.IsZero() || r.RevokedAt.Before(r.CreatedAt)) {
		return ErrInvalidRecord
	}
	return nil
}

func (r Record) Evidence() desktop.EndpointEvidence {
	return desktop.EndpointEvidence{InternalEndpointReference: r.Reference, ConnectionGeneration: r.ConnectionGeneration}
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
func (r Record) matchesSucceeded(source desktop.Record) error {
	if err := source.Validate(); err != nil || source.Status != desktop.StatusSucceeded || source.Handoff == nil || source.Allocation == nil || source.Allocation.State != desktop.AllocationRunning {
		return ErrStale
	}
	h := source.Handoff
	if h.InternalEndpointReference != r.Reference || h.ConnectionGeneration != r.ConnectionGeneration || source.Request.OperationID != r.OperationID || source.Request.AttemptID != r.AttemptID || source.Request.FencingToken != r.FencingToken || source.Request.SandboxID != r.SandboxID || source.Request.ProviderRevisionID != r.ProviderRevisionID || source.Request.DesktopSessionID != r.DesktopSessionID || source.Request.CapabilityProfileID != r.CapabilityProfileID || !source.Request.ExpiresAt.Equal(r.ExpiresAt) || !sameReceipt(source.Allocation.Receipt, r.Receipt) {
		return ErrStale
	}
	return nil
}
func sameReceipt(left, right desktop.AllocationReceipt) bool {
	return left.Reference == right.Reference && left.SandboxID == right.SandboxID && left.DesktopSessionID == right.DesktopSessionID && left.OperationID == right.OperationID && left.AttemptID == right.AttemptID && left.FencingToken == right.FencingToken && left.ExpectedGeneration == right.ExpectedGeneration && left.ConnectionGeneration == right.ConnectionGeneration && left.AllocatedAt.Equal(right.AllocatedAt) && left.ExpiresAt.Equal(right.ExpiresAt)
}
