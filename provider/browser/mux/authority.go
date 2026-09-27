package mux

import (
	"context"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

type SessionAuthority interface {
	GetOpenAt(context.Context, string, time.Time) (browser.Record, error)
	GetSandboxAuthority(context.Context, string) (browser.SandboxAuthority, error)
}

type ReferenceAuthority interface {
	Get(context.Context, string) (reference.Record, error)
	ClaimExecutorV2(context.Context, executorprotocol.Open, time.Time) error
}

type StatePinger interface{ Ping(context.Context) error }

// ProviderAuthority translates only a current durable Browser handoff to its
// Provider-owned allocation receipt. It never returns a container or endpoint.
// Connection-level fence/epoch authorization remains a separate v3 gate.
type ProviderAuthority struct {
	sessions   SessionAuthority
	references ReferenceAuthority
	state      StatePinger
}

func NewProviderAuthority(sessions SessionAuthority, references ReferenceAuthority, state StatePinger) (*ProviderAuthority, error) {
	if sessions == nil || references == nil || state == nil {
		return nil, ErrInvalidOptions
	}
	return &ProviderAuthority{sessions: sessions, references: references, state: state}, nil
}

func (a *ProviderAuthority) Ready(ctx context.Context) error {
	if a == nil || a.state == nil || a.state.Ping(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}

func (a *ProviderAuthority) Resolve(ctx context.Context, open executorprotocol.Open) (browser.AllocationReceipt, error) {
	now := time.Now().UTC()
	if a == nil || ctx == nil || open.Role != executorprotocol.RoleBrowser || open.Validate(now) != nil {
		return browser.AllocationReceipt{}, ErrUnavailable
	}
	record, err := a.references.Get(ctx, open.HandoffReference)
	if err != nil || record.Validate() != nil || record.TenantBindingDigest == "" ||
		record.TenantBindingDigest != open.TenantBindingDigest || record.ProviderRevisionID != open.ProviderRevisionID ||
		record.SandboxID != open.SandboxID || record.BrowserSessionID != open.RuntimeSessionID ||
		record.CapabilityProfileID != open.CapabilityProfileID || record.ConnectionGeneration != open.ConnectionGeneration ||
		record.ExpiresAt.Format(time.RFC3339Nano) != open.HandoffExpiresAt {
		return browser.AllocationReceipt{}, ErrUnavailable
	}
	authorityExpiry, err := time.Parse(time.RFC3339Nano, open.AuthorityExpiresAt)
	if err != nil || authorityExpiry.After(record.ExpiresAt) {
		return browser.AllocationReceipt{}, ErrUnavailable
	}
	source, err := a.sessions.GetOpenAt(ctx, record.OperationID, now)
	if err != nil {
		return browser.AllocationReceipt{}, ErrUnavailable
	}
	authority, err := a.sessions.GetSandboxAuthority(ctx, record.SandboxID)
	if err != nil {
		return browser.AllocationReceipt{}, ErrUnavailable
	}
	binding := reference.Binding{Version: 2, Reference: record.Reference, TenantBindingDigest: open.TenantBindingDigest,
		SandboxID: open.SandboxID, BrowserSessionID: open.RuntimeSessionID, CapabilityProfileID: open.CapabilityProfileID,
		ConnectionGeneration: open.ConnectionGeneration, ExpiresAt: record.ExpiresAt}
	if binding.Matches(record, source, authority, now) != nil {
		return browser.AllocationReceipt{}, ErrUnavailable
	}
	claim, exists := record.ConnectionClaims[open.ConnectionEpoch]
	if !exists || (claim.Status != reference.ConnectionReserved && claim.Status != reference.ConnectionConsumed) ||
		claim.ExecutorAttempt.RequestID != open.RequestID || claim.ExecutorAttempt.RequestDigest != open.RequestDigest ||
		claim.MatchesExecutor(record, open.ConnectionEpoch, open, now) != nil {
		return browser.AllocationReceipt{}, ErrUnavailable
	}
	return record.Receipt, nil
}

// Claim persists replay evidence before Docker attach. A mux or backend
// process restart cannot turn an already-attempted request into a fresh one.
func (a *ProviderAuthority) Claim(ctx context.Context, open executorprotocol.Open) error {
	if _, err := a.Resolve(ctx, open); err != nil {
		return ErrUnavailable
	}
	if a.references.ClaimExecutorV2(ctx, open, time.Now().UTC()) != nil {
		return ErrUnavailable
	}
	return nil
}
