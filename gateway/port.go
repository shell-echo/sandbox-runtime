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

// RevocationSource provides both a point-in-time check and an interrupt for a
// currently proxied session. Reconnects must re-check it before dialing.
type RevocationSource interface {
	IsRevoked(context.Context, string) (bool, error)
	Watch(context.Context, string) (<-chan struct{}, error)
}

// Recorder owns the caller/platform audit sink. Events do not contain frame
// contents or Provider implementation details. A recording failure is
// fail-closed for connection establishment and terminates an active proxy.
type Recorder interface {
	Record(context.Context, AuditEvent) error
}
