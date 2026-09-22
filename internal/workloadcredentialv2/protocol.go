// Package workloadcredentialv2 implements the repository-private Principal-
// based short-lived backend credential protocol. Version 1 remains frozen in
// internal/workloadcredential for retained Slice 5 evidence.
package workloadcredentialv2

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
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

const (
	ProtocolID = "sandbox-runtime.workload-credential.v2"

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

	MaxRequestBytes  = 40 << 10
	MaxResponseBytes = 256 << 10
)

var (
	ErrDenied      = errors.New("workload credential v2 request denied")
	ErrUnavailable = errors.New("workload credential v2 controller unavailable")
	ErrExpired     = errors.New("workload credential v2 expired")
	ErrRevoked     = errors.New("workload credential v2 revoked")

	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	leasePattern      = regexp.MustCompile(`^lease2_[0-9a-f]{32}$`)
)

type Policy struct {
	ID            string
	Registry      *securityprincipal.Registry
	Principal     securityprincipal.Principal
	Purpose       secretref.Purpose
	BackendID     string
	BackendPolicy string
	MaxTTL        time.Duration
	Renewable     bool
	PublicKey     ed25519.PublicKey
	ExpectedUID   uint32
	ExpectedGID   uint32
}

type Request struct {
	Protocol       string                      `json:"protocol"`
	Type           string                      `json:"type"`
	Principal      securityprincipal.Principal `json:"principal"`
	Purpose        secretref.Purpose           `json:"purpose"`
	PolicyID       string                      `json:"policy_id"`
	PolicyDigest   string                      `json:"policy_digest"`
	BackendID      string                      `json:"backend_id"`
	LeaseID        string                      `json:"lease_id"`
	Revision       int64                       `json:"revision"`
	RequestedTTL   int64                       `json:"requested_ttl_seconds"`
	Deadline       string                      `json:"deadline"`
	JTI            string                      `json:"jti"`
	RequestDigest  string                      `json:"request_digest"`
	AgentSignature string                      `json:"agent_signature"`
}

type Response struct {
	Protocol        string `json:"protocol"`
	Type            string `json:"type"`
	Status          string `json:"status"`
	RequestDigest   string `json:"request_digest"`
	PrincipalDigest string `json:"principal_digest"`
	PolicyDigest    string `json:"policy_digest"`
	LeaseID         string `json:"lease_id"`
	Revision        int64  `json:"revision"`
	IssuedAt        string `json:"issued_at"`
	ExpiresAt       string `json:"expires_at"`
	Renewable       bool   `json:"renewable"`
	Credential      []byte `json:"credential"`
}

func (p Policy) Validate() error {
	if !identifierPattern.MatchString(p.ID) || p.Registry == nil || p.Registry.Validate(p.Principal) != nil || !validIssuancePrincipal(p.Principal) ||
		!validPurpose(p.Purpose) || !identifierPattern.MatchString(p.BackendID) || !identifierPattern.MatchString(p.BackendPolicy) ||
		p.MaxTTL < 5*time.Second || p.MaxTTL > 15*time.Minute || len(p.PublicKey) != ed25519.PublicKeySize ||
		(isMigrationAgent(p.Principal) && p.Renewable) ||
		(p.Principal.Kind == securityprincipal.KindController && p.Principal.Name == "certificate_controller" && p.BackendPolicy != "certificate-controller-pki") ||
		(p.Principal.Kind == securityprincipal.KindController && p.Principal.Name == "break_glass_controller" && p.BackendPolicy != "break-glass-controller") {
		return ErrDenied
	}
	return nil
}

func (p Policy) Digest() string {
	if p.Validate() != nil {
		return ""
	}
	document, _ := json.Marshal(struct {
		ID              string            `json:"id"`
		PrincipalDigest string            `json:"principal_digest"`
		Purpose         secretref.Purpose `json:"purpose"`
		BackendID       string            `json:"backend_id"`
		BackendPolicy   string            `json:"backend_policy"`
		MaxTTLSeconds   int64             `json:"max_ttl_seconds"`
		Renewable       bool              `json:"renewable"`
		ExpectedUID     uint32            `json:"expected_uid"`
		ExpectedGID     uint32            `json:"expected_gid"`
	}{p.ID, p.Principal.Digest(), p.Purpose, p.BackendID, p.BackendPolicy, int64(p.MaxTTL / time.Second), p.Renewable, p.ExpectedUID, p.ExpectedGID})
	digest := sha256.Sum256(append([]byte("sandbox-runtime/workload-credential/policy/v2\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func NewSignedRequest(policy Policy, operation, leaseID string, revision int64, ttl time.Duration, deadline time.Time, jti string, privateKey ed25519.PrivateKey, now time.Time) (Request, error) {
	if policy.Validate() != nil || len(privateKey) != ed25519.PrivateKeySize || !privateKey.Public().(ed25519.PublicKey).Equal(policy.PublicKey) {
		return Request{}, ErrDenied
	}
	request := Request{Protocol: ProtocolID, Type: operation, Principal: policy.Principal, Purpose: policy.Purpose, PolicyID: policy.ID,
		PolicyDigest: policy.Digest(), BackendID: policy.BackendID, LeaseID: leaseID, Revision: revision,
		RequestedTTL: int64(ttl / time.Second), Deadline: deadline.UTC().Format(time.RFC3339Nano), JTI: jti}
	request.RequestDigest = requestDigest(request)
	request.AgentSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(request.RequestDigest)))
	if request.Validate(policy, now) != nil {
		return Request{}, ErrDenied
	}
	return request, nil
}

func (r Request) Validate(policy Policy, now time.Time) error {
	deadline, err := parseTime(r.Deadline)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(r.AgentSignature)
	if policy.Validate() != nil || r.Protocol != ProtocolID || !validOperation(r.Type) || r.Principal.Digest() != policy.Principal.Digest() ||
		policy.Registry.Validate(r.Principal) != nil || r.Purpose != policy.Purpose || r.PolicyID != policy.ID || r.PolicyDigest != policy.Digest() ||
		r.BackendID != policy.BackendID || err != nil || now.IsZero() || !deadline.After(now) || deadline.After(now.Add(time.Minute)) ||
		!validJTI(r.JTI) || r.RequestDigest != requestDigest(r) || signatureErr != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(policy.PublicKey, []byte(r.RequestDigest), signature) {
		return ErrDenied
	}
	switch r.Type {
	case IssueType:
		if r.LeaseID != "" || r.Revision != 0 || r.RequestedTTL < 1 || r.RequestedTTL > int64(policy.MaxTTL/time.Second) {
			return ErrDenied
		}
	case RenewType:
		if !policy.Renewable || !leasePattern.MatchString(r.LeaseID) || r.Revision < 1 || r.RequestedTTL < 1 || r.RequestedTTL > int64(policy.MaxTTL/time.Second) {
			return ErrDenied
		}
	case RevokeType, StatusType:
		if !leasePattern.MatchString(r.LeaseID) || r.Revision < 1 || r.RequestedTTL != 0 {
			return ErrDenied
		}
	default:
		return ErrDenied
	}
	return nil
}

func (r Response) Validate(request Request, now time.Time) error {
	if r.Protocol != ProtocolID || r.Type != ResponseType || r.RequestDigest != request.RequestDigest ||
		r.PrincipalDigest != request.Principal.Digest() || r.PolicyDigest != request.PolicyDigest || now.IsZero() {
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

func EncodeRequest(request Request, policy Policy, now time.Time) ([]byte, error) {
	if request.Validate(policy, now) != nil {
		return nil, ErrDenied
	}
	document, err := json.Marshal(request)
	if err != nil || len(document) > MaxRequestBytes {
		return nil, ErrDenied
	}
	return document, nil
}

func DecodeRequest(document []byte, policies map[string]Policy, now time.Time) (Request, Policy, error) {
	var request Request
	if len(document) < 1 || len(document) > MaxRequestBytes || decodeCanonical(document, &request) != nil {
		return Request{}, Policy{}, ErrDenied
	}
	policy, ok := policies[request.PolicyID]
	if !ok || request.Validate(policy, now) != nil {
		return Request{}, Policy{}, ErrDenied
	}
	return request, policy, nil
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
	var response Response
	if len(document) < 1 || len(document) > MaxResponseBytes || decodeCanonical(document, &response) != nil || response.Validate(request, now) != nil {
		return Response{}, ErrUnavailable
	}
	return response, nil
}

func requestDigest(request Request) string {
	request.RequestDigest, request.AgentSignature = "", ""
	document, _ := json.Marshal(request)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/workload-credential/request/v2\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func decodeCanonical(document []byte, target any) error {
	if rejectDuplicateJSON(document) != nil {
		return ErrDenied
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrDenied
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

func rejectDuplicateJSON(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var scan func(json.Token) error
	scan = func(token json.Token) error {
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrDenied
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrDenied
				}
				seen[key] = struct{}{}
				value, err := decoder.Token()
				if err != nil || scan(value) != nil {
					return ErrDenied
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				value, err := decoder.Token()
				if err != nil || scan(value) != nil {
					return ErrDenied
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return ErrDenied
		}
	}
	first, err := decoder.Token()
	if err != nil || scan(first) != nil {
		return ErrDenied
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
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

func validIssuancePrincipal(principal securityprincipal.Principal) bool {
	switch principal.Kind {
	case securityprincipal.KindMaterialAgent:
		return true
	case securityprincipal.KindController:
		return principal.Name == "certificate_controller" || principal.Name == "break_glass_controller"
	default:
		return false
	}
}

func isMigrationAgent(principal securityprincipal.Principal) bool {
	return principal.Kind == securityprincipal.KindMaterialAgent &&
		(principal.Name == "product_migration_agent" || principal.Name == "provider_migration_agent")
}

func validPurpose(purpose secretref.Purpose) bool {
	return purpose != "" && len(purpose) <= 64 && identifierPattern.MatchString(string(purpose))
}

func validOperation(value string) bool {
	return value == IssueType || value == RenewType || value == RevokeType || value == StatusType
}

func validJTI(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}
