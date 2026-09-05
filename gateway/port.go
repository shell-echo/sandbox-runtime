package gateway

import (
	"context"
	"time"
)

// Authorizer belongs to the calling platform. It owns end-user identity,
// tenant policy, session authorization, and the grant lifetime.
type Authorizer interface {
	Authorize(context.Context, ConnectRequest) (Grant, error)
}

// ConnectionCapacity is a caller-owned capacity authority. Subject is derived
// only from an authorization grant that the Gateway has validated and bound to
// the original request.
type ConnectionCapacity interface {
	Acquire(context.Context, CapacitySubject) (ConnectionLease, error)
}

// ConnectionLease reserves authenticated capacity for one logical Gateway
// connection, including reconnect attempts. Events must remain open while the
// lease is healthy. Release must be idempotent.
type ConnectionLease interface {
	Events() <-chan CapacityEvent
	Release(context.Context) error
}

// FencedConnectionLease is the optional capability required by a downstream-
// fenced Browser Gateway. It does not broaden the base capacity contract used
// by terminal or unfenced reference compositions.
type FencedConnectionLease interface {
	ConnectionLease
	DownstreamFence() (DownstreamFence, error)
}

// DownstreamFenceAuthority is used inside the unique private Browser ingress.
// AuthorizeAction is the admission linearization point for one complete CDP
// message or a connection activation. minimumWindow is the remaining bounded
// ingress operation budget that the exact member must safely cover. Lost and
// unavailable decisions must fail closed before downstream dial or write.
type DownstreamFenceAuthority interface {
	AuthorizeAction(context.Context, DownstreamFenceSubject, DownstreamFence, time.Duration) (DownstreamFenceDecision, error)
}

// Endpoint is a resolved provider handoff. ReferenceResolver implementations
// must resolve the exact opaque reference and return a fresh Dial function for
// every reconnect attempt. No URL, host, port, or backend identifier crosses
// this boundary.
type Endpoint struct {
	Reference            string
	SandboxID            string
	RuntimeSessionID     string
	BrowserSessionID     string
	CapabilityProfileID  string
	ConnectionGeneration int64
	ExpiresAt            time.Time
	Dial                 func(context.Context) (Stream, error)
}

// ReferenceResolver belongs to the trusted Gateway/provider control channel.
// It must reject unknown, expired, or revoked references and never translate a
// reference into a public endpoint.
type ReferenceResolver interface {
	Resolve(context.Context, string) (Endpoint, error)
}

// FencedReferenceResolver resolves only to a private ingress that independently
// validates the opaque capacity claim for every downstream Browser action. It
// must never return a direct Chromium or raw Provider attachment.
type FencedReferenceResolver interface {
	ResolveFenced(context.Context, string, DownstreamFenceSubject, DownstreamFence) (Endpoint, error)
}

// RevocationWatch is a stable, level-triggered view of one exact grant. Done
// remains open while authority is healthy. After Done closes, Err must
// consistently return either ErrRevoked, ErrRevocationUnavailable, or the
// observing context error.
type RevocationWatch interface {
	Done() <-chan struct{}
	Err() error
}

// RevocationSource atomically establishes the initial point-in-time decision
// and an interrupt for one exact caller-owned grant. Durable implementations
// must retain a revocation long enough for a watch to catch up after restart.
type RevocationSource interface {
	Watch(context.Context, RevocationSubject) (RevocationWatch, error)
}

// RevocationWriter is the caller-owned control-plane mutation boundary. It is
// deliberately separate from Provider handoff-reference revocation.
type RevocationWriter interface {
	Revoke(context.Context, RevocationSubject) error
}

// Recorder owns the caller/platform audit sink. Events do not contain frame
// contents or Provider implementation details. A recording failure is
// fail-closed for connection establishment and terminates an active proxy.
type Recorder interface {
	Record(context.Context, AuditEvent) error
}
