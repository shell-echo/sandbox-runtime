// Package gateway contains the independently owned Runtime Gateway boundary.
// It consumes only caller authorization and opaque Provider handoff data. It
// does not import Provider repositories, runtime drivers, or backend models.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	ErrInvalidRequest       = errors.New("invalid Runtime Gateway connect request")
	ErrInvalidGrant         = errors.New("invalid Runtime Gateway authorization grant")
	ErrUnauthorized         = errors.New("Runtime Gateway caller is unauthorized")
	ErrRevoked              = errors.New("Runtime Gateway session has been revoked")
	ErrExpired              = errors.New("Runtime Gateway session has expired")
	ErrReferenceUnavailable = errors.New("Runtime Gateway handoff reference is unavailable")
	ErrStaleReference       = errors.New("Runtime Gateway handoff reference is stale")
	ErrReconnectExhausted   = errors.New("Runtime Gateway reconnect attempts exhausted")
	ErrCapacityExhausted    = errors.New("Runtime Gateway connection capacity exhausted")
	ErrAuditUnavailable     = errors.New("Runtime Gateway audit recording is unavailable")
	ErrProxyUnavailable     = errors.New("Runtime Gateway proxy is unavailable")

	identifierPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	terminalReferencePattern = regexp.MustCompile(`^ref:session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
	browserReferencePattern  = regexp.MustCompile(`^ref:browser-session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
)

const (
	MaxReconnectAttempts  = 3
	MaxReconnectBackoff   = 30 * time.Second
	MaxConnectionCapacity = 1_000
)

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
	AuditAuthorized       AuditEventType = "authorized"
	AuditDenied           AuditEventType = "denied"
	AuditConnected        AuditEventType = "connected"
	AuditReconnected      AuditEventType = "reconnected"
	AuditBackendClosed    AuditEventType = "backend_closed"
	AuditRevoked          AuditEventType = "revoked"
	AuditExpired          AuditEventType = "expired"
	AuditClientClosed     AuditEventType = "client_closed"
	AuditReconnectFailed  AuditEventType = "reconnect_failed"
	AuditCapacityRejected AuditEventType = "capacity_rejected"
)
