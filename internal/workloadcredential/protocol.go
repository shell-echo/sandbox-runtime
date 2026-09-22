// Package workloadcredential implements the repository-private control plane
// for short-lived workload-agent credentials. It is deliberately separate
// from the workload-material protocol consumed by role processes.
package workloadcredential

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const (
	ProtocolID = "sandbox-runtime.workload-credential.v1"

	IssueType  = "issue"
	RenewType  = "renew"
	RevokeType = "revoke"
	StatusType = "status"

	ResponseType = "response"

	StatusOK          = "ok"
	StatusDenied      = "denied"
	StatusUnavailable = "unavailable"
	StatusExpired     = "expired"
	StatusRevoked     = "revoked"

	MaxRequestBytes  = 32 << 10
	MaxResponseBytes = 256 << 10
)

var (
	ErrDenied      = errors.New("workload credential request denied")
	ErrUnavailable = errors.New("workload credential controller unavailable")
	ErrExpired     = errors.New("workload credential expired")
	ErrRevoked     = errors.New("workload credential revoked")

	identifierPattern   = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	leasePattern        = regexp.MustCompile(`^lease_[0-9a-f]{32}$`)
	backendLeasePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{8,256}$`)
)

type Request struct {
	Protocol       string            `json:"protocol"`
	Type           string            `json:"type"`
	AgentID        string            `json:"agent_id"`
	Role           secretref.Role    `json:"role"`
	Purpose        secretref.Purpose `json:"purpose"`
	PolicyID       string            `json:"policy_id"`
	BindingDigest  string            `json:"binding_digest"`
	BackendID      string            `json:"backend_id"`
	LeaseID        string            `json:"lease_id"`
	Revision       int64             `json:"revision"`
	RequestedTTL   int64             `json:"requested_ttl_seconds"`
	Deadline       string            `json:"deadline"`
	JTI            string            `json:"jti"`
	RequestDigest  string            `json:"request_digest"`
	AgentSignature string            `json:"agent_signature"`
}

type Response struct {
	Protocol      string `json:"protocol"`
	Type          string `json:"type"`
	Status        string `json:"status"`
	RequestDigest string `json:"request_digest"`
	AgentID       string `json:"agent_id"`
	LeaseID       string `json:"lease_id"`
	Revision      int64  `json:"revision"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
	Renewable     bool   `json:"renewable"`
	Credential    []byte `json:"credential"`
}

type requestDigestDocument struct {
	Protocol      string            `json:"protocol"`
	Type          string            `json:"type"`
	AgentID       string            `json:"agent_id"`
	Role          secretref.Role    `json:"role"`
	Purpose       secretref.Purpose `json:"purpose"`
	PolicyID      string            `json:"policy_id"`
	BindingDigest string            `json:"binding_digest"`
	BackendID     string            `json:"backend_id"`
	LeaseID       string            `json:"lease_id"`
	Revision      int64             `json:"revision"`
	RequestedTTL  int64             `json:"requested_ttl_seconds"`
	Deadline      string            `json:"deadline"`
	JTI           string            `json:"jti"`
}

func NewSignedRequest(value Request, privateKey ed25519.PrivateKey, now time.Time) (Request, error) {
	if len(privateKey) != ed25519.PrivateKeySize || now.IsZero() {
		return Request{}, ErrDenied
	}
	value.Protocol = ProtocolID
	value.RequestDigest = requestDigest(value)
	if value.RequestDigest == "" {
		return Request{}, ErrDenied
	}
	value.AgentSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(value.RequestDigest)))
	if value.Validate(now, privateKey.Public().(ed25519.PublicKey)) != nil {
		return Request{}, ErrDenied
	}
	return value, nil
}

func (r Request) Validate(now time.Time, publicKey ed25519.PublicKey) error {
	deadline, err := parseTime(r.Deadline)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(r.AgentSignature)
	if r.Protocol != ProtocolID || !validOperation(r.Type) || !identifierPattern.MatchString(r.AgentID) || !validRole(r.Role) ||
		!validPurpose(r.Purpose) || !identifierPattern.MatchString(r.PolicyID) || !validDigest(r.BindingDigest) ||
		!identifierPattern.MatchString(r.BackendID) || err != nil || now.IsZero() || !deadline.After(now) || deadline.After(now.Add(time.Minute)) ||
		!validJTI(r.JTI) || r.RequestDigest == "" || r.RequestDigest != requestDigest(r) || signatureErr != nil ||
		len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, []byte(r.RequestDigest), signature) {
		return ErrDenied
	}
	switch r.Type {
	case IssueType:
		if r.LeaseID != "" || r.Revision != 0 || r.RequestedTTL < 1 || r.RequestedTTL > 3600 {
			return ErrDenied
		}
	case RenewType:
		if !leasePattern.MatchString(r.LeaseID) || r.Revision < 1 || r.RequestedTTL < 1 || r.RequestedTTL > 3600 {
			return ErrDenied
		}
	case RevokeType, StatusType:
		if !leasePattern.MatchString(r.LeaseID) || r.Revision < 1 || r.RequestedTTL != 0 {
			return ErrDenied
		}
	}
	return nil
}

func (r Response) Validate(request Request, now time.Time) error {
	if r.Protocol != ProtocolID || r.Type != ResponseType || r.RequestDigest != request.RequestDigest || r.AgentID != request.AgentID || now.IsZero() {
		return ErrUnavailable
	}
	switch r.Status {
	case StatusOK:
		issuedAt, issuedErr := parseTime(r.IssuedAt)
		expiresAt, expiresErr := parseTime(r.ExpiresAt)
		if !leasePattern.MatchString(r.LeaseID) || r.Revision < 1 || issuedErr != nil || expiresErr != nil || expiresAt.Before(issuedAt) {
			return ErrUnavailable
		}
		if request.Type == IssueType || request.Type == RenewType {
			if len(r.Credential) < 1 || len(r.Credential) > secretref.MaxSecretBytes || !expiresAt.After(now) {
				return ErrUnavailable
			}
		} else if len(r.Credential) != 0 {
			return ErrUnavailable
		}
	case StatusDenied, StatusUnavailable, StatusExpired, StatusRevoked:
		if r.LeaseID != "" || r.Revision != 0 || r.IssuedAt != "" || r.ExpiresAt != "" || r.Renewable || len(r.Credential) != 0 {
			return ErrUnavailable
		}
	default:
		return ErrUnavailable
	}
	return nil
}

// EncodeSignedRequest performs structural/digest checks without pretending to
// possess the controller's configured copy of the agent public key.
func EncodeSignedRequest(request Request) ([]byte, error) {
	if request.Protocol != ProtocolID || request.RequestDigest == "" || request.RequestDigest != requestDigest(request) || request.AgentSignature == "" {
		return nil, ErrDenied
	}
	document, err := json.Marshal(request)
	if err != nil || len(document) > MaxRequestBytes {
		return nil, ErrDenied
	}
	return document, nil
}

func DecodeRequest(document []byte) (Request, error) {
	var value Request
	if len(document) < 1 || len(document) > MaxRequestBytes || decodeCanonical(document, &value) != nil {
		return Request{}, ErrDenied
	}
	return value, nil
}

func EncodeResponse(response Response, request Request, now time.Time) ([]byte, error) {
	if response.Validate(request, now) != nil {
		return nil, ErrUnavailable
	}
	document, err := json.Marshal(response)
	if err != nil || len(document) > MaxResponseBytes {
		return nil, ErrUnavailable
	}
	return document, nil
}

func DecodeResponse(document []byte, request Request, now time.Time) (Response, error) {
	var value Response
	if len(document) < 1 || len(document) > MaxResponseBytes || decodeCanonical(document, &value) != nil || value.Validate(request, now) != nil {
		return Response{}, ErrUnavailable
	}
	return value, nil
}

func requestDigest(request Request) string {
	document, err := json.Marshal(requestDigestDocument{
		Protocol: request.Protocol, Type: request.Type, AgentID: request.AgentID, Role: request.Role, Purpose: request.Purpose,
		PolicyID: request.PolicyID, BindingDigest: request.BindingDigest, BackendID: request.BackendID, LeaseID: request.LeaseID,
		Revision: request.Revision, RequestedTTL: request.RequestedTTL, Deadline: request.Deadline, JTI: request.JTI,
	})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(append([]byte("sandbox-runtime/workload-credential/request/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func decodeCanonical(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrDenied
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, document) {
		return ErrDenied
	}
	return nil
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || value != parsed.UTC().Format(time.RFC3339Nano) {
		return time.Time{}, ErrDenied
	}
	return parsed, nil
}

func validOperation(value string) bool {
	return value == IssueType || value == RenewType || value == RevokeType || value == StatusType
}

func validRole(role secretref.Role) bool {
	switch role {
	case secretref.RoleProduct, secretref.RoleProvider, secretref.RoleGateway, secretref.RoleGuest, secretref.RoleBrowser, secretref.RoleDesktop:
		return true
	default:
		return false
	}
}

func validPurpose(purpose secretref.Purpose) bool {
	return purpose != "" && len(purpose) <= 64 && identifierPattern.MatchString(string(purpose))
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func validJTI(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}
