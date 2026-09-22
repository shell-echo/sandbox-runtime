// Package workloadagent implements the repository-private Unix workload
// material protocol. It is a SecretProvider client boundary, not a backend
// secret-manager or file reader.
package workloadagent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const (
	ProtocolID        = "sandbox-runtime.workload-material.v1"
	ResolveType       = "resolve"
	MaterialType      = "material"
	ErrorType         = "error"
	StatusOK          = "ok"
	StatusUnavailable = "unavailable"
	StatusRevoked     = "revoked"
	StatusExpired     = "expired"

	maxRequestBytes  = 16 << 10
	maxResponseBytes = 1536 << 10
	nonceSize        = 32
)

type Request struct {
	Protocol      string            `json:"protocol"`
	Type          string            `json:"type"`
	Nonce         string            `json:"nonce"`
	Binding       secretref.Binding `json:"binding"`
	Deadline      string            `json:"deadline"`
	RequestDigest string            `json:"request_digest"`
}

type Response struct {
	Protocol      string `json:"protocol"`
	Type          string `json:"type"`
	Status        string `json:"status"`
	Nonce         string `json:"nonce"`
	RequestDigest string `json:"request_digest"`
	BindingDigest string `json:"binding_digest"`
	Version       string `json:"version"`
	Revision      string `json:"revision"`
	Digest        string `json:"digest"`
	State         string `json:"state"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	Material      []byte `json:"material"`
}

type requestDigestDocument struct {
	Protocol      string `json:"protocol"`
	Type          string `json:"type"`
	Nonce         string `json:"nonce"`
	BindingDigest string `json:"binding_digest"`
	Deadline      string `json:"deadline"`
}

func NewRequest(binding secretref.Binding, nonce string, deadline time.Time) (Request, error) {
	request := Request{
		Protocol: ProtocolID, Type: ResolveType, Nonce: nonce, Binding: binding,
		Deadline: deadline.UTC().Format(time.RFC3339Nano),
	}
	request.RequestDigest = requestDigest(request)
	if request.Validate(time.Now().UTC()) != nil {
		return Request{}, secretref.ErrUnavailable
	}
	return request, nil
}

func (r Request) Validate(now time.Time) error {
	deadline, err := parseCanonicalTime(r.Deadline)
	if r.Protocol != ProtocolID || r.Type != ResolveType || !validNonce(r.Nonce) || r.Binding.Validate() != nil ||
		r.Binding.Kind != secretref.KindSecret || err != nil || now.IsZero() || !deadline.After(now) ||
		deadline.After(now.Add(time.Minute)) || r.RequestDigest != requestDigest(r) {
		return secretref.ErrUnavailable
	}
	return nil
}

func (r Response) Validate(request Request, now time.Time) error {
	if r.Protocol != ProtocolID || r.Nonce != request.Nonce || r.RequestDigest != request.RequestDigest || now.IsZero() {
		return secretref.ErrUnavailable
	}
	switch r.Status {
	case StatusOK:
		if r.Type != MaterialType || r.BindingDigest != request.Binding.Digest() || r.Version != request.Binding.Version ||
			!validDigest(r.Digest) || !validRevision(r.Revision) || r.State != string(secretref.KeyActive) ||
			len(r.Material) < 1 || len(r.Material) > secretref.MaxSecretBytes {
			return secretref.ErrUnavailable
		}
		notBefore, errBefore := parseCanonicalTime(r.NotBefore)
		notAfter, errAfter := parseCanonicalTime(r.NotAfter)
		window := secretref.RotationWindow{NotBefore: notBefore, NotAfter: notAfter, State: secretref.KeyState(r.State)}
		if errBefore != nil || errAfter != nil || window.Validate(now) != nil || now.Before(notBefore) || !now.Before(notAfter) {
			return secretref.ErrUnavailable
		}
		digest := sha256.Sum256(r.Material)
		if r.Digest != "sha256:"+hex.EncodeToString(digest[:]) {
			return secretref.ErrUnavailable
		}
	case StatusUnavailable, StatusRevoked, StatusExpired:
		if r.Type != ErrorType || r.BindingDigest != "" || r.Version != "" || r.Revision != "" || r.Digest != "" ||
			r.State != "" || r.NotBefore != "" || r.NotAfter != "" || len(r.Material) != 0 {
			return secretref.ErrUnavailable
		}
	default:
		return secretref.ErrUnavailable
	}
	return nil
}

func (r Response) MaterialFor(binding secretref.Binding) (secretref.SecretMaterial, error) {
	if r.Status != StatusOK || r.BindingDigest != binding.Digest() || r.Version != binding.Version {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	notBefore, err := parseCanonicalTime(r.NotBefore)
	if err != nil {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	notAfter, err := parseCanonicalTime(r.NotAfter)
	if err != nil {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	return secretref.SecretMaterial{
		Binding: binding, Bytes: append([]byte(nil), r.Material...), Digest: r.Digest,
		Window:   secretref.RotationWindow{NotBefore: notBefore, NotAfter: notAfter, State: secretref.KeyState(r.State)},
		Revision: r.Revision,
	}, nil
}

func requestDigest(request Request) string {
	document, err := json.Marshal(requestDigestDocument{
		Protocol: request.Protocol, Type: request.Type, Nonce: request.Nonce,
		BindingDigest: request.Binding.Digest(), Deadline: request.Deadline,
	})
	if err != nil || request.Binding.Digest() == "" {
		return ""
	}
	digest := sha256.Sum256(append([]byte("sandbox-runtime/workload-material/request/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == nonceSize && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func validRevision(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && !strings.ContainsRune("._-", character) {
			return false
		}
	}
	return true
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || value != parsed.UTC().Format(time.RFC3339Nano) {
		return time.Time{}, errors.New("invalid time")
	}
	return parsed, nil
}
