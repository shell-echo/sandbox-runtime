// Package desktophandoffv2 defines the explicit prepare/start boundary for
// the Provider-private Desktop bridge. It does not change the locked Provider
// API or the v1 handoff binding authority persisted by the Provider.
package desktophandoffv2

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

const (
	ProtocolID     = "sandbox-runtime.desktop-handoff.v2"
	StatusPrepared = "prepared"
	StatusStarted  = "started"
	StatusRejected = "rejected"
	TypeStart      = "start"
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	ErrInvalid    = errors.New("invalid private Desktop activation")
)

// OpenRequest retains the Provider's already-persisted v1 binding digest
// fields while binding a distinct v2 transport. The separate transport
// digest prevents a v1 accepted message from being interpreted as prepared.
type OpenRequest struct {
	desktophandoff.OpenRequest
	TransportDigest string `json:"transport_digest"`
}

func (o OpenRequest) Validate(now time.Time) error {
	if o.Protocol != ProtocolID || !digestPattern.MatchString(o.TransportDigest) ||
		o.TransportDigest != TransportDigest(o) {
		return ErrInvalid
	}
	legacy := o.OpenRequest
	legacy.Protocol = desktophandoff.ProtocolID
	if legacy.Validate(now) != nil {
		return ErrInvalid
	}
	return nil
}

func (o OpenRequest) Binding() desktophandoff.Binding {
	return o.OpenRequest.Binding()
}

func TransportDigest(o OpenRequest) string {
	projection := struct {
		Domain   string                     `json:"domain"`
		Protocol string                     `json:"protocol"`
		Open     desktophandoff.OpenRequest `json:"open"`
	}{"sandbox-runtime/desktop-private-transport/v2", ProtocolID, o.OpenRequest}
	return digest(projection)
}

type Prepared struct {
	Protocol        string `json:"protocol"`
	RequestID       string `json:"request_id"`
	Status          string `json:"status"`
	TransportDigest string `json:"transport_digest"`
}

func (r Prepared) Validate(o OpenRequest) error {
	if r.Protocol != ProtocolID || r.RequestID != o.RequestID || r.Status != StatusPrepared ||
		r.TransportDigest != o.TransportDigest {
		return ErrInvalid
	}
	return nil
}

func PreparedResponse(o OpenRequest) Prepared {
	return Prepared{Protocol: ProtocolID, RequestID: o.RequestID, Status: StatusPrepared,
		TransportDigest: o.TransportDigest}
}

// Start repeats the exact authority tuple instead of accepting an implicit
// resume command. Its digest is scoped to v2 and to this open connection.
type Start struct {
	Protocol             string `json:"protocol"`
	Type                 string `json:"type"`
	RequestID            string `json:"request_id"`
	DesktopSessionID     string `json:"desktop_session_id"`
	ConnectionGeneration int64  `json:"connection_generation"`
	ConnectionEpoch      string `json:"connection_epoch"`
	ControllerFence      string `json:"controller_fence"`
	AuthorityDigest      string `json:"authority_digest"`
	RequestDigest        string `json:"request_digest"`
	TransportDigest      string `json:"transport_digest"`
	StartDigest          string `json:"start_digest"`
}

func NewStart(o OpenRequest) Start {
	s := Start{Protocol: ProtocolID, Type: TypeStart, RequestID: o.RequestID,
		DesktopSessionID: o.DesktopSessionID, ConnectionGeneration: o.ConnectionGeneration,
		ConnectionEpoch: o.ConnectionEpoch, ControllerFence: o.ControllerFence,
		AuthorityDigest: o.AuthorityDigest, RequestDigest: o.RequestDigest,
		TransportDigest: o.TransportDigest}
	s.StartDigest = StartDigest(s)
	return s
}

func (s Start) Validate(o OpenRequest) error {
	if s.Protocol != ProtocolID || s.Type != TypeStart || s.RequestID != o.RequestID ||
		s.DesktopSessionID != o.DesktopSessionID || s.ConnectionGeneration != o.ConnectionGeneration ||
		s.ConnectionEpoch != o.ConnectionEpoch || s.ControllerFence != o.ControllerFence ||
		s.AuthorityDigest != o.AuthorityDigest || s.RequestDigest != o.RequestDigest ||
		s.TransportDigest != o.TransportDigest || !digestPattern.MatchString(s.StartDigest) ||
		s.StartDigest != StartDigest(s) {
		return ErrInvalid
	}
	return nil
}

func StartDigest(s Start) string {
	projection := struct {
		Domain               string `json:"domain"`
		Protocol             string `json:"protocol"`
		RequestID            string `json:"request_id"`
		DesktopSessionID     string `json:"desktop_session_id"`
		ConnectionGeneration int64  `json:"connection_generation"`
		ConnectionEpoch      string `json:"connection_epoch"`
		ControllerFence      string `json:"controller_fence"`
		AuthorityDigest      string `json:"authority_digest"`
		RequestDigest        string `json:"request_digest"`
		TransportDigest      string `json:"transport_digest"`
	}{"sandbox-runtime/desktop-private-start/v2", ProtocolID, s.RequestID, s.DesktopSessionID,
		s.ConnectionGeneration, s.ConnectionEpoch, s.ControllerFence, s.AuthorityDigest,
		s.RequestDigest, s.TransportDigest}
	return digest(projection)
}

type Started struct {
	Protocol    string `json:"protocol"`
	RequestID   string `json:"request_id"`
	Status      string `json:"status"`
	StartDigest string `json:"start_digest"`
}

func (r Started) Validate(s Start) error {
	if r.Protocol != ProtocolID || r.RequestID != s.RequestID || r.Status != StatusStarted ||
		r.StartDigest != s.StartDigest {
		return ErrInvalid
	}
	return nil
}

func StartedResponse(s Start) Started {
	return Started{Protocol: ProtocolID, RequestID: s.RequestID, Status: StatusStarted,
		StartDigest: s.StartDigest}
}

// Decode rejects unknown, repeated and noncanonical representations. Callers
// must subsequently validate the decoded message against their exact open.
func Decode(document []byte, target any) error {
	if handoff.Decode(document, target) != nil {
		return ErrInvalid
	}
	canonical, err := handoff.Encode(target)
	if err != nil || !bytes.Equal(document, canonical) {
		return ErrInvalid
	}
	return nil
}

func digest(value any) string {
	document, _ := json.Marshal(value)
	sum := sha256.Sum256(append([]byte("sandbox-runtime/desktop-private-activation/v2\x00"), document...))
	return fmt.Sprintf("sha256:%x", sum[:])
}
