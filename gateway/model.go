// Package gateway contains the independently owned Runtime Gateway boundary.
// It consumes only caller authorization and opaque Provider handoff data. It
// does not import Provider repositories, runtime drivers, or backend models.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalidRequest        = errors.New("invalid Runtime Gateway connect request")
	ErrInvalidGrant          = errors.New("invalid Runtime Gateway authorization grant")
	ErrUnauthorized          = errors.New("Runtime Gateway caller is unauthorized")
	ErrRevoked               = errors.New("Runtime Gateway session has been revoked")
	ErrExpired               = errors.New("Runtime Gateway session has expired")
	ErrReferenceUnavailable  = errors.New("Runtime Gateway handoff reference is unavailable")
	ErrStaleReference        = errors.New("Runtime Gateway handoff reference is stale")
	ErrReconnectExhausted    = errors.New("Runtime Gateway reconnect attempts exhausted")
	ErrCapacityExhausted     = errors.New("Runtime Gateway connection capacity exhausted")
	ErrCapacityUnavailable   = errors.New("Runtime Gateway connection capacity is unavailable")
	ErrRevocationUnavailable = errors.New("Runtime Gateway revocation authority is unavailable")
	ErrDownstreamFenceLost   = errors.New("Runtime Gateway downstream action fence was lost")
	ErrDownstreamUnavailable = errors.New("Runtime Gateway downstream action fence is unavailable")
	ErrAuditUnavailable      = errors.New("Runtime Gateway audit recording is unavailable")
	ErrProxyUnavailable      = errors.New("Runtime Gateway proxy is unavailable")

	identifierPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	terminalReferencePattern = regexp.MustCompile(`^ref:session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
	browserReferencePattern  = regexp.MustCompile(`^ref:browser-session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
	downstreamFencePattern   = regexp.MustCompile(`^v1\.[A-Za-z0-9_-]+$`)
)

const (
	MaxReconnectAttempts       = 3
	MaxReconnectBackoff        = 30 * time.Second
	MaxConnectionCapacity      = 1_000
	MaxDownstreamFenceBytes    = 512
	MinDownstreamActionWindow  = 50 * time.Millisecond
	MaxDownstreamActionWindow  = 30 * time.Second
	MaxDownstreamClaimLifetime = 24 * time.Hour

	MinCapacityReleaseTimeout     = 100 * time.Millisecond
	DefaultCapacityReleaseTimeout = 5 * time.Second
	MaxCapacityReleaseTimeout     = 30 * time.Second
)

// CapacitySubject is the credential-free identity used by a caller-owned
// capacity authority. It deliberately excludes caller and grant identifiers,
// bearer credentials, and the opaque Provider reference so those values cannot
// create a fresh partition for the same session.
type CapacitySubject struct {
	TenantID            string
	SandboxID           string
	RuntimeSessionID    string
	BrowserSessionID    string
	CapabilityProfileID string
	ExpiresAt           time.Time
}

// DownstreamFence is an opaque, bearer-like claim for one exact acquired
// capacity lease. It is allowed only on the trusted Gateway-to-ingress path and
// must never be logged, audited, returned through a public API, or interpreted
// outside the capacity adapter that issued it.
type DownstreamFence struct {
	opaque string
}

func NewDownstreamFence(opaque string) (DownstreamFence, error) {
	if len(opaque) < len("v1.a") || len(opaque) > MaxDownstreamFenceBytes ||
		!downstreamFencePattern.MatchString(opaque) || strings.ContainsAny(opaque, "\r\n\t ") {
		return DownstreamFence{}, ErrDownstreamUnavailable
	}
	return DownstreamFence{opaque: opaque}, nil
}

// Opaque returns the claim only for a trusted internal transport or authority
// adapter. Callers must not place it in errors, audit events, or evidence.
func (f DownstreamFence) Opaque() string { return f.opaque }

func (f DownstreamFence) Validate() error {
	_, err := NewDownstreamFence(f.opaque)
	return err
}

func (f DownstreamFence) String() string   { return "[redacted downstream fence]" }
func (f DownstreamFence) GoString() string { return "gateway.DownstreamFence{[redacted]}" }

// DownstreamFenceSubject is the exact Browser binding supplied to the private
// ingress. ExpiresAt is the caller grant expiry, not the Provider handoff
// expiry. Provider mutation fencing and connection generation remain separate
// identities.
type DownstreamFenceSubject struct {
	TenantID             string
	SandboxID            string
	BrowserSessionID     string
	CapabilityProfileID  string
	ConnectionGeneration int64
	ExpiresAt            time.Time
}

// DownstreamFenceDecision reports whether this action installed a newer
// per-session high-water claim. The claim itself remains opaque and must not be
// copied into diagnostics or evidence.
type DownstreamFenceDecision struct {
	Activated bool
}

func (s DownstreamFenceSubject) Validate() error {
	for _, value := range []string{s.TenantID, s.SandboxID, s.BrowserSessionID, s.CapabilityProfileID} {
		if !identifierPattern.MatchString(value) {
			return ErrDownstreamUnavailable
		}
	}
	if s.ConnectionGeneration < 1 || s.ExpiresAt.IsZero() {
		return ErrDownstreamUnavailable
	}
	return nil
}

// RevocationSubject is the exact caller-owned grant identity observed by the
// Gateway. ExpiresAt lets a durable authority bound tombstone retention without
// moving grant ownership into the Provider.
type RevocationSubject struct {
	GrantID   string
	ExpiresAt time.Time
}

func (s RevocationSubject) Validate() error {
	if !identifierPattern.MatchString(s.GrantID) || s.ExpiresAt.IsZero() {
		return ErrInvalidGrant
	}
	return nil
}

type CapacityEventKind string

const (
	CapacityEventLost        CapacityEventKind = "lost"
	CapacityEventUnavailable CapacityEventKind = "unavailable"
)

// CapacityEvent reports that a previously acquired lease is no longer safe to
// use. Err is internal diagnostic context and must not be copied into a stable
// public response or audit message.
type CapacityEvent struct {
	Kind CapacityEventKind
	Err  error
}

// ConnectRequest is the public Gateway-side identity and session selection.
// It contains no bearer credential. Authorization is performed by the
// caller-owned Authorizer before the Provider handoff can be resolved.
type ConnectRequest struct {
	CallerID            string
	TenantID            string
	SandboxID           string
	RuntimeSessionID    string
	BrowserSessionID    string
	CapabilityProfileID string
	HandoffReference    string
}

func (r ConnectRequest) Validate() error {
	for name, value := range map[string]string{
		"caller_id":             r.CallerID,
		"tenant_id":             r.TenantID,
		"sandbox_id":            r.SandboxID,
		"capability_profile_id": r.CapabilityProfileID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%w: %s", ErrInvalidRequest, name)
		}
	}
	if !r.validSessionIdentity() {
		return fmt.Errorf("%w: session identity", ErrInvalidRequest)
	}
	if !r.validReference() {
		return fmt.Errorf("%w: handoff_reference", ErrInvalidRequest)
	}
	return nil
}

func (r ConnectRequest) validSessionIdentity() bool {
	switch {
	case r.RuntimeSessionID != "" && r.BrowserSessionID == "":
		return identifierPattern.MatchString(r.RuntimeSessionID)
	case r.BrowserSessionID != "" && r.RuntimeSessionID == "":
		return identifierPattern.MatchString(r.BrowserSessionID)
	default:
		return false
	}
}

func (r ConnectRequest) validReference() bool {
	if r.RuntimeSessionID != "" {
		return terminalReferencePattern.MatchString(r.HandoffReference)
	}
	return browserReferencePattern.MatchString(r.HandoffReference)
}

// Grant is the immutable result of caller authorization. The Gateway verifies
// that every identity and capability field is bound to the original request.
// HandoffReference remains opaque and is never interpreted as a URL or address.
type Grant struct {
	GrantID              string
	CallerID             string
	TenantID             string
	SandboxID            string
	RuntimeSessionID     string
	BrowserSessionID     string
	CapabilityProfileID  string
	HandoffReference     string
	ConnectionGeneration int64
	ExpiresAt            time.Time
}

func (g Grant) Validate(now time.Time) error {
	if now.IsZero() || !identifierPattern.MatchString(g.GrantID) {
		return fmt.Errorf("%w: grant_id", ErrInvalidGrant)
	}
	request := ConnectRequest{
		CallerID: g.CallerID, TenantID: g.TenantID, SandboxID: g.SandboxID,
		RuntimeSessionID: g.RuntimeSessionID, CapabilityProfileID: g.CapabilityProfileID,
		BrowserSessionID: g.BrowserSessionID, HandoffReference: g.HandoffReference,
	}
	if err := request.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidGrant, err)
	}
	if g.ConnectionGeneration < 1 || g.ExpiresAt.IsZero() || !g.ExpiresAt.After(now) {
		return fmt.Errorf("%w: expiry or connection generation", ErrInvalidGrant)
	}
	return nil
}

func (g Grant) matches(request ConnectRequest) bool {
	return g.CallerID == request.CallerID && g.TenantID == request.TenantID &&
		g.SandboxID == request.SandboxID && g.RuntimeSessionID == request.RuntimeSessionID &&
		g.BrowserSessionID == request.BrowserSessionID &&
		g.CapabilityProfileID == request.CapabilityProfileID && g.HandoffReference == request.HandoffReference
}

// Frame is an opaque WebSocket-like frame. Gateway policy never inspects or
// records Payload; the underlying transport adapter owns wire framing.
type Frame struct {
	Type    FrameType
	Payload []byte
}

type FrameType uint8

const (
	TextFrame FrameType = iota + 1
	BinaryFrame
	PingFrame
	PongFrame
	CloseFrame
)

func (f Frame) Clone() Frame {
	clone := f
	clone.Payload = append([]byte(nil), f.Payload...)
	return clone
}

// Stream is the narrow adapter used by the Gateway for a WebSocket or an
// equivalent bidirectional transport. Implementations must make Close
// idempotent and unblock Receive/Send when the stream is closed.
type Stream interface {
	Receive(context.Context) (Frame, error)
	Send(context.Context, Frame) error
	Close(context.Context) error
}

// AuditEvent is intentionally metadata-only. It excludes frame payloads,
// Provider endpoints, network addresses, credentials, and backend IDs.
type AuditEvent struct {
	Type                 AuditEventType
	At                   time.Time
	GrantID              string
	CallerID             string
	TenantID             string
	SandboxID            string
	RuntimeSessionID     string
	BrowserSessionID     string
	ConnectionGeneration int64
	Attempt              int
	Frames               uint64
	Bytes                uint64
	Reason               string
}

type AuditEventType string

const (
	AuditAuthorized            AuditEventType = "authorized"
	AuditDenied                AuditEventType = "denied"
	AuditConnected             AuditEventType = "connected"
	AuditReconnected           AuditEventType = "reconnected"
	AuditBackendClosed         AuditEventType = "backend_closed"
	AuditRevoked               AuditEventType = "revoked"
	AuditExpired               AuditEventType = "expired"
	AuditClientClosed          AuditEventType = "client_closed"
	AuditReconnectFailed       AuditEventType = "reconnect_failed"
	AuditCapacityRejected      AuditEventType = "capacity_rejected"
	AuditCapacityUnavailable   AuditEventType = "capacity_unavailable"
	AuditCapacityLost          AuditEventType = "capacity_lost"
	AuditCapacityReleaseFailed AuditEventType = "capacity_release_failed"
	AuditRevocationUnavailable AuditEventType = "revocation_unavailable"
	AuditDownstreamFenceLost   AuditEventType = "downstream_fence_lost"
	AuditDownstreamUnavailable AuditEventType = "downstream_fence_unavailable"
)
