// Package desktopbridge defines the signed binding between an executor.v2
// capability and the separate Desktop broker.v2 authority domain.
package desktopbridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

const (
	ProtocolID        = "sandbox-runtime.desktop-bridge.v2"
	Version           = 2
	MaxDocumentBytes  = 32 << 10
	MaxSignatureBytes = 256
)

var (
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	noncePattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
	keyIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	ErrInvalid        = errors.New("invalid Desktop bridge statement")
)

// Statement is signed by Provider and consumed by the broker. It binds every
// value the broker uses, while retaining the executor authority digests as
// distinct, verifiable upstream facts.
type Statement struct {
	Protocol                string                   `json:"protocol"`
	Version                 int                      `json:"version"`
	KeyID                   string                   `json:"key_id"`
	ExecutorRole            string                   `json:"executor_role"`
	ExecutorIdentity        string                   `json:"executor_identity"`
	ProviderRevisionID      string                   `json:"provider_revision_id"`
	TenantBindingDigest     string                   `json:"tenant_binding_digest"`
	SandboxID               string                   `json:"sandbox_id"`
	RuntimeSessionID        string                   `json:"runtime_session_id"`
	HandoffReferenceDigest  string                   `json:"handoff_reference_digest"`
	AllocationReference     string                   `json:"allocation_reference"`
	MediaPolicy             desktopmedia.MediaPolicy `json:"media_policy"`
	ConnectionGeneration    int64                    `json:"connection_generation"`
	ConnectionEpoch         string                   `json:"connection_epoch"`
	Fence                   string                   `json:"fence"`
	AuthorityExpiresAt      string                   `json:"authority_expires_at"`
	HandoffExpiresAt        string                   `json:"handoff_expires_at"`
	NotBefore               string                   `json:"not_before"`
	ExecutorAuthorityDigest string                   `json:"executor_authority_digest"`
	ExecutorRequestDigest   string                   `json:"executor_request_digest"`
	BrokerRequestDigest     string                   `json:"broker_request_digest"`
	Nonce                   string                   `json:"nonce"`
}

type Envelope struct {
	Statement Statement `json:"statement"`
	Signature string    `json:"signature"`
}

func (s Statement) Validate(now time.Time) error {
	if s.Protocol != ProtocolID || s.Version != Version || !keyIDPattern.MatchString(s.KeyID) || s.ExecutorRole != "desktop" ||
		!identifierPattern.MatchString(s.ExecutorIdentity) || !identifierPattern.MatchString(s.ProviderRevisionID) ||
		handoff.ValidateTenantBindingDigest(s.TenantBindingDigest) != nil || !identifierPattern.MatchString(s.SandboxID) ||
		!identifierPattern.MatchString(s.RuntimeSessionID) || !digestPattern.MatchString(s.HandoffReferenceDigest) || !strings.HasPrefix(s.AllocationReference, "ref:desktop/") ||
		len(s.AllocationReference) != len("ref:desktop/")+32 || !desktopHex(s.AllocationReference[len("ref:desktop/"):]) ||
		!s.MediaPolicy.Validate() || s.ConnectionGeneration < 1 || !identifierPattern.MatchString(s.ConnectionEpoch) ||
		len(s.Fence) < 32 || len(s.Fence) > 512 || strings.ContainsAny(s.Fence, " \t\r\n\x00") ||
		!digestPattern.MatchString(s.ExecutorAuthorityDigest) || !digestPattern.MatchString(s.ExecutorRequestDigest) ||
		!digestPattern.MatchString(s.BrokerRequestDigest) || !noncePattern.MatchString(s.Nonce) || now.IsZero() {
		return ErrInvalid
	}
	authorityExpiry, authorityErr := time.Parse(time.RFC3339Nano, s.AuthorityExpiresAt)
	handoffExpiry, handoffErr := time.Parse(time.RFC3339Nano, s.HandoffExpiresAt)
	notBefore, notBeforeErr := time.Parse(time.RFC3339Nano, s.NotBefore)
	if authorityErr != nil || handoffErr != nil || notBeforeErr != nil || !authorityExpiry.After(now) || !handoffExpiry.After(now) || authorityExpiry.After(handoffExpiry) || notBefore.After(now) || handoffExpiry.After(now.Add(24*time.Hour)) {
		return ErrInvalid
	}
	if s.BrokerRequestDigest != s.CalculateBrokerRequestDigest() {
		return ErrInvalid
	}
	return nil
}

func (e Envelope) Validate(now time.Time) error {
	if e.Statement.Validate(now) != nil || len(e.Signature) == 0 || len(e.Signature) > MaxSignatureBytes {
		return ErrInvalid
	}
	if _, err := base64.RawURLEncoding.DecodeString(e.Signature); err != nil {
		return ErrInvalid
	}
	return nil
}

func (s Statement) CalculateBrokerRequestDigest() string {
	value := struct {
		Domain                  string                   `json:"domain"`
		Protocol                string                   `json:"protocol"`
		ExecutorRole            string                   `json:"executor_role"`
		ExecutorIdentity        string                   `json:"executor_identity"`
		ProviderRevisionID      string                   `json:"provider_revision_id"`
		TenantBindingDigest     string                   `json:"tenant_binding_digest"`
		SandboxID               string                   `json:"sandbox_id"`
		RuntimeSessionID        string                   `json:"runtime_session_id"`
		HandoffReferenceDigest  string                   `json:"handoff_reference_digest"`
		AllocationReference     string                   `json:"allocation_reference"`
		ConnectionEpoch         string                   `json:"connection_epoch"`
		Fence                   string                   `json:"fence"`
		AuthorityExpiresAt      string                   `json:"authority_expires_at"`
		HandoffExpiresAt        string                   `json:"handoff_expires_at"`
		NotBefore               string                   `json:"not_before"`
		ExecutorAuthorityDigest string                   `json:"executor_authority_digest"`
		ExecutorRequestDigest   string                   `json:"executor_request_digest"`
		Nonce                   string                   `json:"nonce"`
		Version                 int                      `json:"version"`
		ConnectionGeneration    int64                    `json:"connection_generation"`
		MediaPolicy             desktopmedia.MediaPolicy `json:"media_policy"`
	}{"sandbox-runtime/desktop-broker-request/v2", s.Protocol, s.ExecutorRole, s.ExecutorIdentity, s.ProviderRevisionID, s.TenantBindingDigest, s.SandboxID, s.RuntimeSessionID, s.HandoffReferenceDigest, s.AllocationReference, s.ConnectionEpoch, s.Fence, s.AuthorityExpiresAt, s.HandoffExpiresAt, s.NotBefore, s.ExecutorAuthorityDigest, s.ExecutorRequestDigest, s.Nonce, s.Version, s.ConnectionGeneration, s.MediaPolicy}
	return digest(value)
}

func (s Statement) Digest() string { return digest(s) }

func (s Statement) SigningBytes() []byte {
	document, _ := json.Marshal(struct {
		Domain string    `json:"domain"`
		Value  Statement `json:"value"`
	}{"sandbox-runtime/desktop-bridge-signature/v2", s})
	return append([]byte("sandbox-runtime/desktop-bridge-signature/v2\x00"), document...)
}

func Sign(s Statement, privateKey ed25519.PrivateKey) (Envelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize || s.Validate(time.Now().UTC()) != nil {
		return Envelope{}, ErrInvalid
	}
	return Envelope{Statement: s, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, s.SigningBytes()))}, nil
}

func (e Envelope) Verify(now time.Time, keys map[string]ed25519.PublicKey) error {
	if e.Validate(now) != nil {
		return ErrInvalid
	}
	key, ok := keys[e.Statement.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key, e.Statement.SigningBytes(), signature) {
		return ErrInvalid
	}
	return nil
}

func Encode(value any) ([]byte, error) {
	document, err := json.Marshal(value)
	if err != nil || len(document) > MaxDocumentBytes {
		return nil, ErrInvalid
	}
	return append(document, '\n'), nil
}

func Decode(document []byte, target any) error {
	if len(document) == 0 || len(document) > MaxDocumentBytes || target == nil || document[len(document)-1] != '\n' || rejectDuplicates(document[:len(document)-1]) != nil {
		return ErrInvalid
	}
	body := document[:len(document)-1]
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, body) {
		return ErrInvalid
	}
	return nil
}

func digest(value any) string {
	document, _ := json.Marshal(value)
	sum := sha256.Sum256(append([]byte("sandbox-runtime/desktop-bridge-digest/v2\x00"), document...))
	return fmt.Sprintf("sha256:%x", sum[:])
}

func rejectDuplicates(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return ErrInvalid
				}
				if _, exists := seen[name]; exists {
					return ErrInvalid
				}
				seen[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return ErrInvalid
		}
	}
	if err := walk(); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func desktopHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
