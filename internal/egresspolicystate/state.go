// Package egresspolicystate verifies operator-signed, short-lived state for one
// immutable Phase 6 egress policy. It cannot change a destination or widen a
// policy; loss of valid state is a revocation event for the broker process.
package egresspolicystate

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
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const (
	ProtocolID       = "sandbox-runtime.egress-policy-state.v1"
	Version          = 1
	MaxSnapshotBytes = 16 << 10
	MaxStateLifetime = 30 * time.Second
)

var (
	ErrInvalid  = errors.New("invalid egress policy state")
	ErrRevoked  = errors.New("egress policy revoked")
	nameRegex   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	digestRegex = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type BindingConfig struct {
	EnvironmentDigest string
	ProfileDigest     string
	Policy            phase6security.EgressPolicy
	OperatorKeyID     string
	OperatorPublicKey ed25519.PublicKey
	MaxAge            time.Duration
}

type Binding struct {
	environmentDigest string
	profileDigest     string
	policyID          string
	policyRevision    string
	policyDigest      string
	principalDigest   string
	brokerDigest      string
	operatorKeyID     string
	operatorPublicKey ed25519.PublicKey
	maxAge            time.Duration
}

type Snapshot struct {
	Protocol          string `json:"protocol"`
	Version           int    `json:"version"`
	EnvironmentDigest string `json:"environment_digest"`
	ProfileDigest     string `json:"profile_digest"`
	PolicyID          string `json:"policy_id"`
	PolicyRevision    string `json:"policy_revision"`
	PolicyDigest      string `json:"policy_digest"`
	PrincipalDigest   string `json:"principal_digest"`
	BrokerDigest      string `json:"broker_digest"`
	Generation        uint64 `json:"generation"`
	IssuedAt          string `json:"issued_at"`
	ExpiresAt         string `json:"expires_at"`
	Status            string `json:"status"`
	OperatorKeyID     string `json:"operator_key_id"`
	SnapshotDigest    string `json:"snapshot_digest"`
	Signature         string `json:"signature"`
}

func NewBinding(config BindingConfig) (Binding, error) {
	policy := config.Policy
	if !digestRegex.MatchString(config.EnvironmentDigest) || !digestRegex.MatchString(config.ProfileDigest) ||
		!nameRegex.MatchString(policy.ID) || !nameRegex.MatchString(policy.Revision) ||
		!digestRegex.MatchString(policy.PrincipalDigest) || !digestRegex.MatchString(policy.BrokerDigest) ||
		policy.PrincipalDigest == policy.BrokerDigest || !nameRegex.MatchString(config.OperatorKeyID) ||
		len(config.OperatorPublicKey) != ed25519.PublicKeySize || config.MaxAge < time.Second ||
		config.MaxAge > MaxStateLifetime {
		return Binding{}, ErrInvalid
	}
	return Binding{environmentDigest: config.EnvironmentDigest, profileDigest: config.ProfileDigest,
		policyID: policy.ID, policyRevision: policy.Revision, policyDigest: policy.Digest(),
		principalDigest: policy.PrincipalDigest, brokerDigest: policy.BrokerDigest,
		operatorKeyID: config.OperatorKeyID, operatorPublicKey: append(ed25519.PublicKey(nil), config.OperatorPublicKey...),
		maxAge: config.MaxAge}, nil
}

func NewSigned(binding Binding, generation uint64, issuedAt, expiresAt time.Time, status string, privateKey ed25519.PrivateKey) (Snapshot, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !privateKey.Public().(ed25519.PublicKey).Equal(binding.operatorPublicKey) {
		return Snapshot{}, ErrInvalid
	}
	snapshot := Snapshot{Protocol: ProtocolID, Version: Version, EnvironmentDigest: binding.environmentDigest,
		ProfileDigest: binding.profileDigest, PolicyID: binding.policyID, PolicyRevision: binding.policyRevision,
		PolicyDigest: binding.policyDigest, PrincipalDigest: binding.principalDigest, BrokerDigest: binding.brokerDigest,
		Generation: generation, IssuedAt: issuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano), Status: status, OperatorKeyID: binding.operatorKeyID}
	snapshot.SnapshotDigest = snapshot.digest()
	snapshot.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(snapshot.SnapshotDigest)))
	if snapshot.Verify(binding, issuedAt.UTC()) != nil {
		return Snapshot{}, ErrInvalid
	}
	return snapshot, nil
}

func Decode(document []byte, binding Binding, now time.Time) (Snapshot, error) {
	if len(document) < 1 || len(document) > MaxSnapshotBytes {
		return Snapshot{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if decoder.Decode(&snapshot) != nil {
		return Snapshot{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Snapshot{}, ErrInvalid
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil || !bytes.Equal(canonical, document) || snapshot.Verify(binding, now) != nil {
		return Snapshot{}, ErrInvalid
	}
	return snapshot, nil
}

func ReadFile(path string, binding Binding, now time.Time) (Snapshot, error) {
	document, err := secretfile.Read(path, MaxSnapshotBytes)
	if err != nil {
		return Snapshot{}, ErrInvalid
	}
	defer clear(document)
	return Decode(document, binding, now)
}

func (s Snapshot) Verify(binding Binding, now time.Time) error {
	issued, issueErr := canonicalTime(s.IssuedAt)
	expires, expiryErr := canonicalTime(s.ExpiresAt)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(s.Signature)
	if s.Protocol != ProtocolID || s.Version != Version || s.EnvironmentDigest != binding.environmentDigest ||
		len(binding.operatorPublicKey) != ed25519.PublicKeySize ||
		s.ProfileDigest != binding.profileDigest || s.PolicyID != binding.policyID ||
		s.PolicyRevision != binding.policyRevision || s.PolicyDigest != binding.policyDigest ||
		s.PrincipalDigest != binding.principalDigest || s.BrokerDigest != binding.brokerDigest ||
		s.OperatorKeyID != binding.operatorKeyID || s.Generation < 1 ||
		(s.Status != "active" && s.Status != "revoked") || issueErr != nil || expiryErr != nil ||
		now.IsZero() || issued.After(now) || !expires.After(now) || !expires.After(issued) ||
		expires.Sub(issued) > MaxStateLifetime || now.Sub(issued) > binding.maxAge ||
		s.SnapshotDigest != s.digest() || signatureErr != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != s.Signature ||
		!ed25519.Verify(binding.operatorPublicKey, []byte(s.SnapshotDigest), signature) {
		return ErrInvalid
	}
	return nil
}

func (s Snapshot) digest() string {
	s.SnapshotDigest, s.Signature = "", ""
	document, _ := json.Marshal(s)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/egress-policy-state/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func canonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, ErrInvalid
	}
	return parsed, nil
}

type Tracker struct {
	binding        Binding
	lastGeneration uint64
	lastDigest     string
	lastNow        time.Time
	terminated     bool
}

func NewTracker(binding Binding) *Tracker { return &Tracker{binding: binding} }

func (t *Tracker) Accept(document []byte, now time.Time) (Snapshot, error) {
	if t == nil || t.terminated {
		return Snapshot{}, ErrInvalid
	}
	if !t.lastNow.IsZero() && now.Before(t.lastNow) {
		t.terminated = true
		return Snapshot{}, ErrInvalid
	}
	snapshot, err := Decode(document, t.binding, now)
	if err != nil || snapshot.Generation < t.lastGeneration ||
		(snapshot.Generation == t.lastGeneration && snapshot.SnapshotDigest != t.lastDigest) {
		t.terminated = true
		return Snapshot{}, ErrInvalid
	}
	t.lastGeneration, t.lastDigest, t.lastNow = snapshot.Generation, snapshot.SnapshotDigest, now
	if snapshot.Status == "revoked" {
		t.terminated = true
		return snapshot, ErrRevoked
	}
	return snapshot, nil
}

func (t *Tracker) ReadFile(path string, now time.Time) (Snapshot, error) {
	document, err := secretfile.Read(path, MaxSnapshotBytes)
	if err != nil {
		// A same-directory atomic rename can race the file-identity check.
		// Retry once immediately; a persistent loss remains terminal.
		document, err = secretfile.Read(path, MaxSnapshotBytes)
	}
	if err != nil {
		if t != nil {
			t.terminated = true
		}
		return Snapshot{}, ErrInvalid
	}
	defer clear(document)
	return t.Accept(document, now)
}
