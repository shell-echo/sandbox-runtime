// Package guestagent defines the isolated, outbound-only Guest Agent control
// protocol. It contains no Product repository or Provider runtime types.
package guestagent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	ProtocolVersion = "1.0.0"
	Subprotocol     = "sandbox-runtime-guest.v1"
	MaxMessageBytes = int64(64 << 10)
	MaxCapabilities = 32
	MaxInFlight     = 32
)

var (
	ErrInvalid           = errors.New("invalid Guest Agent protocol message")
	ErrUnauthorized      = errors.New("Guest Agent identity is unauthorized")
	ErrIncompatible      = errors.New("Guest Agent protocol version is incompatible")
	ErrUnavailable       = errors.New("Guest Agent channel is unavailable")
	ErrCapabilityMissing = errors.New("Guest Agent capability is unavailable")
	ErrRemote            = errors.New("Guest Agent operation failed")
)

type Challenge struct {
	Type      string `json:"type"`
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expires_at"`
}

type Hello struct {
	Type              string   `json:"type"`
	GuestID           string   `json:"guest_id"`
	BindingGeneration int64    `json:"binding_generation"`
	ProtocolVersion   string   `json:"protocol_version"`
	Capabilities      []string `json:"capabilities"`
	ClientNonce       string   `json:"client_nonce"`
	Signature         string   `json:"signature"`
}

type Welcome struct {
	Type              string   `json:"type"`
	ProtocolVersion   string   `json:"protocol_version"`
	Capabilities      []string `json:"capabilities"`
	BindingGeneration int64    `json:"binding_generation"`
}

type Request struct {
	Type       string          `json:"type"`
	RequestID  string          `json:"request_id"`
	Operation  string          `json:"operation"`
	DeadlineAt string          `json:"deadline_at"`
	Payload    json.RawMessage `json:"payload"`
}

type Cancel struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
}

type Response struct {
	Type      string          `json:"type"`
	RequestID string          `json:"request_id"`
	OK        bool            `json:"ok"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	ErrorCode string          `json:"error_code,omitempty"`
}

type AuthRequest struct {
	Hello     Hello
	Challenge Challenge
}

func (r AuthRequest) SigningBytes() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	capabilities := append([]string(nil), r.Hello.Capabilities...)
	sort.Strings(capabilities)
	return []byte(strings.Join([]string{
		"sandbox-runtime-guest-auth-v1", r.Challenge.Nonce, r.Challenge.ExpiresAt,
		r.Hello.ClientNonce, r.Hello.GuestID, fmt.Sprintf("%d", r.Hello.BindingGeneration),
		r.Hello.ProtocolVersion, strings.Join(capabilities, ","),
	}, "\n")), nil
}

func (r AuthRequest) SignatureBytes() ([]byte, error) {
	value, err := base64.RawURLEncoding.DecodeString(r.Hello.Signature)
	if err != nil || len(value) != ed25519.SignatureSize {
		return nil, ErrInvalid
	}
	return value, nil
}

func (r AuthRequest) Validate() error {
	if r.Challenge.Type != "challenge" || r.Hello.Type != "hello" || !validID(r.Hello.GuestID) ||
		r.Hello.BindingGeneration < 1 || r.Hello.ProtocolVersion == "" ||
		!validNonce(r.Challenge.Nonce) || !validNonce(r.Hello.ClientNonce) ||
		len(r.Hello.Capabilities) > MaxCapabilities || !uniqueCapabilities(r.Hello.Capabilities) {
		return ErrInvalid
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Challenge.ExpiresAt); err != nil {
		return ErrInvalid
	}
	return nil
}

func DecodeStrict(document []byte, value any) error {
	if len(document) == 0 || int64(len(document)) > MaxMessageBytes {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func validID(value string) bool {
	if len(value) < 1 || len(value) > 200 {
		return false
	}
	for i, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || (i > 0 && strings.ContainsRune("._:-", character)) {
			continue
		}
		return false
	}
	return true
}

func uniqueCapabilities(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validID(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func encodeMessage(value any) ([]byte, error) {
	document, err := json.Marshal(value)
	if err != nil || int64(len(document)) > MaxMessageBytes {
		return nil, ErrInvalid
	}
	return document, nil
}
