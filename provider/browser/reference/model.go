// Package reference manages durable opaque browser-session handoff records.
// The reference is never a URL, CDP endpoint, credential, or backend ID.
package reference

import (
	"errors"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

var (
	ErrInvalidReference = errors.New("invalid Provider browser handoff reference")
	ErrInvalidRecord    = errors.New("invalid Provider browser handoff reference record")
	ErrNotFound         = errors.New("Provider browser handoff reference not found")
	ErrAlreadyExists    = errors.New("Provider browser handoff reference already exists")
	ErrConflict         = errors.New("Provider browser handoff reference conflict")
	ErrExpired          = errors.New("Provider browser handoff reference has expired")
	ErrRevoked          = errors.New("Provider browser handoff reference has been revoked")
	ErrUnavailable      = errors.New("Provider browser handoff reference is unavailable")
	ErrStale            = errors.New("Provider browser handoff reference is stale")
	ErrDurability       = errors.New("Provider browser handoff reference durability failure")
	ErrClosed           = errors.New("Provider browser handoff registry is closed")
	referencePattern    = regexp.MustCompile(`^ref:browser-session:[0-9a-f]{32}$`)
	identifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	executorRequestID   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	executorDigest      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

const MaxExecutorReplayClaims = 4096

// ExecutorReplayClaim is Provider-local one-use evidence. It deliberately
// retains no raw capacity claim, backend coordinate or Gateway credential.
type ExecutorReplayClaim struct {
	RequestDigest string    `json:"request_digest"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type Record struct {
	Reference            string                         `json:"reference"`
	OperationID          string                         `json:"operation_id"`
	AttemptID            string                         `json:"attempt_id"`
	FencingToken         int64                          `json:"fencing_token"`
	SandboxID            string                         `json:"sandbox_id"`
	ProviderRevisionID   string                         `json:"provider_revision_id"`
	BrowserSessionID     string                         `json:"browser_session_id"`
	CapabilityProfileID  string                         `json:"capability_profile_id"`
	ConnectionGeneration int64                          `json:"connection_generation"`
	ExpiresAt            time.Time                      `json:"expires_at"`
	TenantBindingDigest  string                         `json:"tenant_binding_digest,omitempty"`
	ConnectionClaims     map[string]ConnectionClaim     `json:"connection_claims,omitempty"`
	ExecutorReplayClaims map[string]ExecutorReplayClaim `json:"executor_replay_claims,omitempty"`
	Receipt              browser.AllocationReceipt      `json:"receipt"`
	CreatedAt            time.Time                      `json:"created_at"`
	RevokedAt            *time.Time                     `json:"revoked_at,omitempty"`
}

func NewRecord(reference string, source browser.Record, createdAt time.Time) (Record, error) {
	createdAt = createdAt.UTC()
	if !referencePattern.MatchString(reference) {
		return Record{}, ErrInvalidReference
	}
	if err := source.Validate(); err != nil || source.Status != browser.StatusRunning || source.Allocation == nil || source.Allocation.State != browser.AllocationRunning {
		return Record{}, ErrInvalidRecord
	}
	if createdAt.IsZero() || !createdAt.Before(source.Request.ExpiresAt) || createdAt.Before(source.Allocation.Receipt.AllocatedAt) {
		return Record{}, ErrExpired
	}
	record := Record{Reference: reference, OperationID: source.Request.OperationID, AttemptID: source.Request.AttemptID, FencingToken: source.Request.FencingToken, SandboxID: source.Request.SandboxID, ProviderRevisionID: source.Request.ProviderRevisionID, BrowserSessionID: source.Request.BrowserSessionID, CapabilityProfileID: source.Request.CapabilityProfileID, ConnectionGeneration: source.Allocation.Receipt.ConnectionGeneration, ExpiresAt: source.Request.ExpiresAt.UTC(), Receipt: source.Allocation.Receipt, CreatedAt: createdAt}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func NewRecordWithTenantBinding(reference string, source browser.Record, tenantBindingDigest string, createdAt time.Time) (Record, error) {
	if handoff.ValidateTenantBindingDigest(tenantBindingDigest) != nil && browserbinding.ValidateDigest(tenantBindingDigest) != nil {
		return Record{}, ErrInvalidRecord
	}
	record, err := NewRecord(reference, source, createdAt)
	if err != nil {
		return Record{}, err
	}
	record.TenantBindingDigest = tenantBindingDigest
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (r Record) Clone() Record {
	clone := r
	if r.ConnectionClaims != nil {
		clone.ConnectionClaims = make(map[string]ConnectionClaim, len(r.ConnectionClaims))
		for epoch, claim := range r.ConnectionClaims {
			clone.ConnectionClaims[epoch] = claim
		}
	}
	if r.ExecutorReplayClaims != nil {
		clone.ExecutorReplayClaims = make(map[string]ExecutorReplayClaim, len(r.ExecutorReplayClaims))
		for id, claim := range r.ExecutorReplayClaims {
			clone.ExecutorReplayClaims[id] = claim
		}
	}
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
	for _, value := range []string{r.OperationID, r.AttemptID, r.SandboxID, r.ProviderRevisionID, r.BrowserSessionID, r.CapabilityProfileID} {
		if !identifierPattern.MatchString(value) {
			return ErrInvalidRecord
		}
	}
	if r.FencingToken < 1 || r.ConnectionGeneration < 1 || r.ExpiresAt.IsZero() || r.CreatedAt.IsZero() || !r.CreatedAt.Before(r.ExpiresAt) || r.CapabilityProfileID != browser.CapabilityProfileID {
		return ErrInvalidRecord
	}
	if err := r.Receipt.Validate(); err != nil || r.Receipt.OperationID != r.OperationID || r.Receipt.AttemptID != r.AttemptID || r.Receipt.FencingToken != r.FencingToken || r.Receipt.SandboxID != r.SandboxID || r.Receipt.BrowserSessionID != r.BrowserSessionID || r.Receipt.ConnectionGeneration != r.ConnectionGeneration || !r.Receipt.ExpiresAt.Equal(r.ExpiresAt) || r.CreatedAt.Before(r.Receipt.AllocatedAt) {
		return ErrInvalidRecord
	}
	if r.RevokedAt != nil && (r.RevokedAt.IsZero() || r.RevokedAt.Before(r.CreatedAt)) {
		return ErrInvalidRecord
	}
	if r.TenantBindingDigest != "" && handoff.ValidateTenantBindingDigest(r.TenantBindingDigest) != nil &&
		browserbinding.ValidateDigest(r.TenantBindingDigest) != nil {
		return ErrInvalidRecord
	}
	if len(r.ConnectionClaims) > MaxConnectionClaims || connectionClaimsBytes(r.ConnectionClaims) > MaxConnectionClaimsBytes {
		return ErrInvalidRecord
	}
	activeConnections := 0
	privateRequests := make(map[string]struct{}, len(r.ConnectionClaims))
	executorRequests := make(map[string]struct{}, len(r.ConnectionClaims))
	for epoch, claim := range r.ConnectionClaims {
		if claim.Validate(r, epoch) != nil {
			return ErrInvalidRecord
		}
		if _, exists := privateRequests[claim.PrivateRequestID]; exists {
			return ErrInvalidRecord
		}
		privateRequests[claim.PrivateRequestID] = struct{}{}
		if claim.ExecutorAttempt.RequestID != "" {
			if _, exists := executorRequests[claim.ExecutorAttempt.RequestID]; exists {
				return ErrInvalidRecord
			}
			executorRequests[claim.ExecutorAttempt.RequestID] = struct{}{}
			replay, replayed := r.ExecutorReplayClaims[claim.ExecutorAttempt.RequestID]
			if claim.Consumed != replayed ||
				replayed && (replay.RequestDigest != claim.ExecutorAttempt.RequestDigest ||
					!replay.ExpiresAt.Equal(claim.AuthorityExpiresAt)) {
				return ErrInvalidRecord
			}
		}
		if claim.Status != ConnectionClosed {
			activeConnections++
		}
	}
	if activeConnections > 1 {
		return ErrInvalidRecord
	}
	if len(r.ExecutorReplayClaims) > MaxExecutorReplayClaims {
		return ErrInvalidRecord
	}
	for id, claim := range r.ExecutorReplayClaims {
		if !executorRequestID.MatchString(id) || !executorDigest.MatchString(claim.RequestDigest) ||
			claim.ExpiresAt.IsZero() || claim.ExpiresAt.After(r.ExpiresAt) || !claim.ExpiresAt.After(r.CreatedAt) {
			return ErrInvalidRecord
		}
	}
	return nil
}

func (r Record) Evidence() browser.EndpointEvidence {
	return browser.EndpointEvidence{InternalEndpointReference: r.Reference, ConnectionGeneration: r.ConnectionGeneration}
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
func (r Record) matchesSucceeded(source browser.Record) error {
	if err := source.Validate(); err != nil || source.Status != browser.StatusSucceeded || source.Handoff == nil || source.Allocation == nil || source.Allocation.State != browser.AllocationRunning {
		return ErrStale
	}
	h := source.Handoff
	if h.InternalEndpointReference != r.Reference || h.ConnectionGeneration != r.ConnectionGeneration || source.Request.OperationID != r.OperationID || source.Request.AttemptID != r.AttemptID || source.Request.FencingToken != r.FencingToken || source.Request.SandboxID != r.SandboxID || source.Request.ProviderRevisionID != r.ProviderRevisionID || source.Request.BrowserSessionID != r.BrowserSessionID || source.Request.CapabilityProfileID != r.CapabilityProfileID || !source.Request.ExpiresAt.Equal(r.ExpiresAt) || !sameReceipt(source.Allocation.Receipt, r.Receipt) {
		return ErrStale
	}
	return nil
}
func sameReceipt(left, right browser.AllocationReceipt) bool {
	return left.Reference == right.Reference && left.SandboxID == right.SandboxID && left.BrowserSessionID == right.BrowserSessionID && left.OperationID == right.OperationID && left.AttemptID == right.AttemptID && left.FencingToken == right.FencingToken && left.ExpectedGeneration == right.ExpectedGeneration && left.ConnectionGeneration == right.ConnectionGeneration && left.AllocatedAt.Equal(right.AllocatedAt) && left.ExpiresAt.Equal(right.ExpiresAt)
}
