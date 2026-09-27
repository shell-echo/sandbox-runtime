package reference

import (
	"context"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

// Binding is the narrow, authenticated private-edge projection that pins an
// already-issued handoff reference to one caller-owned tenant authority. It
// cannot create, extend, or replace a Provider session or reference.
type Binding struct {
	Version              int
	Reference            string
	TenantBindingDigest  string
	SandboxID            string
	BrowserSessionID     string
	CapabilityProfileID  string
	ConnectionGeneration int64
	ExpiresAt            time.Time
}

func (b Binding) Validate(now time.Time) error {
	validDigest := b.Version == 2 && browserbinding.ValidateDigest(b.TenantBindingDigest) == nil ||
		b.Version == 1 && handoff.ValidateTenantBindingDigest(b.TenantBindingDigest) == nil
	if !referencePattern.MatchString(b.Reference) || !validDigest ||
		!identifierPattern.MatchString(b.SandboxID) || !identifierPattern.MatchString(b.BrowserSessionID) ||
		b.CapabilityProfileID != browser.CapabilityProfileID || b.ConnectionGeneration < 1 ||
		b.ExpiresAt.IsZero() || now.IsZero() || !b.ExpiresAt.After(now) || b.ExpiresAt.After(now.Add(handoff.MaxAuthorityWindow)) {
		return ErrInvalidRecord
	}
	return nil
}

func (b Binding) Matches(record Record, source browser.Record, authority browser.SandboxAuthority, now time.Time) error {
	if b.Validate(now) != nil || record.Validate() != nil || source.Validate() != nil || authority.Validate() != nil ||
		record.RevokedAt != nil || source.Status != browser.StatusSucceeded || source.Handoff == nil || source.Allocation == nil || source.Allocation.State != browser.AllocationRunning ||
		!authority.Ready || authority.SandboxID != record.SandboxID || authority.ProviderRevisionID != record.ProviderRevisionID ||
		authority.Generation != source.Request.ExpectedGeneration || authority.FencingToken != source.Request.FencingToken ||
		!authority.LeaseExpiresAt.After(now) || record.ExpiresAt.After(authority.LeaseExpiresAt) ||
		record.Reference != b.Reference || record.SandboxID != b.SandboxID || record.BrowserSessionID != b.BrowserSessionID ||
		record.CapabilityProfileID != b.CapabilityProfileID || record.ConnectionGeneration != b.ConnectionGeneration ||
		!record.ExpiresAt.Equal(b.ExpiresAt) || record.OperationID != source.Request.OperationID ||
		record.AttemptID != source.Request.AttemptID || record.FencingToken != source.Request.FencingToken ||
		record.ProviderRevisionID != source.Request.ProviderRevisionID || record.SandboxID != source.Request.SandboxID ||
		record.BrowserSessionID != source.Request.BrowserSessionID || record.CapabilityProfileID != source.Request.CapabilityProfileID ||
		record.ConnectionGeneration != source.Handoff.ConnectionGeneration || record.Reference != source.Handoff.InternalEndpointReference ||
		!record.ExpiresAt.Equal(source.Request.ExpiresAt) || !sameReceipt(record.Receipt, source.Allocation.Receipt) {
		return ErrStale
	}
	if record.TenantBindingDigest != "" && record.TenantBindingDigest != b.TenantBindingDigest {
		return ErrConflict
	}
	return nil
}

// BindingStore is optional and must be backed by an atomic Provider-owned
// state transition. Legacy file stores deliberately do not implement it.
type BindingStore interface {
	Bind(context.Context, Binding, time.Time) error
}
