package reference

import (
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
)

const (
	MaxConnectionClaims      = 256
	MaxConnectionClaimsBytes = 256 << 10
	ConnectionPending        = "pending"
	ConnectionReserved       = "reserved"
	ConnectionConsumed       = "consumed"
	ConnectionClosed         = "closed"
)

// ConnectionClaim is only the Provider's durable projection of one already
// authorized ingress activation. Product owns the grant/control lease and
// the unique action ingress owns the single-writer decision.
type ConnectionClaim struct {
	PrivateRequestID     string          `json:"private_request_id"`
	PrivateRequestDigest string          `json:"private_request_digest"`
	AuthorityDigest      string          `json:"authority_digest"`
	ControlLeaseDigest   string          `json:"control_lease_digest"`
	ControlFence         int64           `json:"control_fence"`
	AuthorityExpiresAt   time.Time       `json:"authority_expires_at"`
	Status               string          `json:"status"`
	Consumed             bool            `json:"consumed"`
	ExecutorAttempt      ExecutorAttempt `json:"executor_attempt"`
}

type ExecutorAttempt struct {
	RequestID     string `json:"request_id,omitempty"`
	RequestDigest string `json:"request_digest,omitempty"`
}

func ConnectionFromOpen(open browserhandoffv2.OpenRequest, now time.Time) (ConnectionClaim, error) {
	if open.Validate(now) != nil {
		return ConnectionClaim{}, ErrInvalidRecord
	}
	expires, _ := time.Parse(time.RFC3339Nano, open.AuthorityExpiresAt)
	return ConnectionClaim{PrivateRequestID: open.RequestID, PrivateRequestDigest: open.RequestDigest,
		AuthorityDigest: open.AuthorityDigest, ControlLeaseDigest: open.ControlLeaseDigest,
		ControlFence: open.ControlFence, AuthorityExpiresAt: expires, Status: ConnectionPending}, nil
}

func (c ConnectionClaim) Validate(record Record, epoch string) error {
	if !identifierPattern.MatchString(epoch) || !executorRequestID.MatchString(c.PrivateRequestID) ||
		!executorDigest.MatchString(c.PrivateRequestDigest) || !executorDigest.MatchString(c.AuthorityDigest) ||
		!executorDigest.MatchString(c.ControlLeaseDigest) || c.ControlFence < 1 ||
		c.AuthorityExpiresAt.IsZero() || c.AuthorityExpiresAt.After(record.ExpiresAt) ||
		!c.AuthorityExpiresAt.After(record.CreatedAt) {
		return ErrInvalidRecord
	}
	projection := browserhandoffv2.OpenRequest{
		BindingVersion: browserhandoffv2.BindingVersion, BindingIssuer: browserhandoffv2.BindingIssuer,
		Protocol: browserhandoffv2.ProtocolID, RequestID: c.PrivateRequestID,
		Resource: browserhandoffv2.ResourceBrowser, TenantBindingDigest: record.TenantBindingDigest,
		ProviderRevisionID: record.ProviderRevisionID, SandboxID: record.SandboxID,
		BrowserSessionID: record.BrowserSessionID, CapabilityProfileID: record.CapabilityProfileID,
		MediaProfileID: browserhandoffv2.MediaProfileID, ControlProfileID: browserhandoffv2.ControlProfileID,
		HandoffReference: record.Reference, HandoffDigest: browserhandoffv2.ReferenceDigest(record.Reference),
		ConnectionGeneration: record.ConnectionGeneration, ConnectionEpoch: epoch,
		ControlLeaseDigest: c.ControlLeaseDigest, ControlFence: c.ControlFence,
		AuthorityExpiresAt: c.AuthorityExpiresAt.UTC().Format(time.RFC3339Nano),
		HandoffExpiresAt:   record.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	projection.AuthorityDigest = browserhandoffv2.AuthorityDigest(projection)
	projection.RequestDigest = browserhandoffv2.RequestDigest(projection)
	if c.AuthorityDigest != projection.AuthorityDigest || c.PrivateRequestDigest != projection.RequestDigest {
		return ErrInvalidRecord
	}
	switch c.Status {
	case ConnectionPending:
		if c.Consumed || c.ExecutorAttempt != (ExecutorAttempt{}) {
			return ErrInvalidRecord
		}
	case ConnectionReserved, ConnectionConsumed:
		if !executorRequestID.MatchString(c.ExecutorAttempt.RequestID) ||
			!executorDigest.MatchString(c.ExecutorAttempt.RequestDigest) ||
			c.Consumed != (c.Status == ConnectionConsumed) {
			return ErrInvalidRecord
		}
	case ConnectionClosed:
		if c.Consumed && c.ExecutorAttempt == (ExecutorAttempt{}) ||
			c.ExecutorAttempt != (ExecutorAttempt{}) &&
				(!executorRequestID.MatchString(c.ExecutorAttempt.RequestID) ||
					!executorDigest.MatchString(c.ExecutorAttempt.RequestDigest)) {
			return ErrInvalidRecord
		}
	default:
		return ErrInvalidRecord
	}
	return nil
}

// MatchesExecutor ties the Provider-issued executor attempt to the complete
// private v2 authority and the original absolute expiry. The derived fence is
// opaque equality data, never an authorization or ordering source.
func (c ConnectionClaim) MatchesExecutor(record Record, epoch string, open executorprotocol.Open, now time.Time) error {
	fence, err := browserhandoffv2.ExecutorFence(c.AuthorityDigest)
	if err != nil || c.Validate(record, epoch) != nil || now.IsZero() || !c.AuthorityExpiresAt.After(now) ||
		c.Status == ConnectionClosed || open.Validate(now) != nil || open.Role != executorprotocol.RoleBrowser ||
		open.ConnectionEpoch != epoch || open.Fence != fence ||
		open.TenantBindingDigest != record.TenantBindingDigest || open.ProviderRevisionID != record.ProviderRevisionID ||
		open.SandboxID != record.SandboxID || open.RuntimeSessionID != record.BrowserSessionID ||
		open.CapabilityProfileID != record.CapabilityProfileID || open.HandoffReference != record.Reference ||
		open.ConnectionGeneration != record.ConnectionGeneration ||
		open.AuthorityExpiresAt != c.AuthorityExpiresAt.UTC().Format(time.RFC3339Nano) ||
		open.HandoffExpiresAt != record.ExpiresAt.UTC().Format(time.RFC3339Nano) {
		return ErrStale
	}
	return nil
}

func connectionClaimsBytes(claims map[string]ConnectionClaim) int {
	document, err := json.Marshal(claims)
	if err != nil {
		return MaxConnectionClaimsBytes + 1
	}
	return len(document)
}
