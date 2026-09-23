package egresspolicystate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func stateFixture(t *testing.T) (Binding, ed25519.PrivateKey, time.Time) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := func(char string) string { return "sha256:" + strings.Repeat(char, 64) }
	policy := phase6security.EgressPolicy{ID: "product-egress", Revision: "policy-1",
		PrincipalDigest: digest("c"), BrokerDigest: digest("d")}
	binding, err := NewBinding(BindingConfig{EnvironmentDigest: digest("a"), ProfileDigest: digest("b"),
		Policy: policy, OperatorKeyID: "operator-1", OperatorPublicKey: publicKey, MaxAge: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return binding, privateKey, time.Now().UTC().Truncate(time.Second)
}

func signedDocument(t *testing.T, binding Binding, key ed25519.PrivateKey, generation uint64, now time.Time, status string) []byte {
	t.Helper()
	snapshot, err := NewSigned(binding, generation, now, now.Add(10*time.Second), status, key)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestSignedStateBindsExactPolicyAndCanonicalDocument(t *testing.T) {
	binding, key, now := stateFixture(t)
	document := signedDocument(t, binding, key, 1, now, "active")
	if _, err := Decode(document, binding, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Snapshot){
		"environment": func(s *Snapshot) { s.EnvironmentDigest = strings.Replace(s.EnvironmentDigest, "a", "f", 1) },
		"profile":     func(s *Snapshot) { s.ProfileDigest = strings.Replace(s.ProfileDigest, "b", "f", 1) },
		"policy":      func(s *Snapshot) { s.PolicyDigest = "sha256:" + strings.Repeat("f", 64) },
		"principal":   func(s *Snapshot) { s.PrincipalDigest = strings.Replace(s.PrincipalDigest, "c", "f", 1) },
		"broker":      func(s *Snapshot) { s.BrokerDigest = strings.Replace(s.BrokerDigest, "d", "f", 1) },
		"status":      func(s *Snapshot) { s.Status = "active-expanded" },
		"generation":  func(s *Snapshot) { s.Generation++ },
		"signature":   func(s *Snapshot) { s.Signature = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			var candidate Snapshot
			if err := json.Unmarshal(document, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			encoded, _ := json.Marshal(candidate)
			if _, err := Decode(encoded, binding, now.Add(time.Second)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Decode() = %v", err)
			}
		})
	}
	for name, candidate := range map[string][]byte{
		"leading space": append([]byte(" "), document...),
		"trailing":      append(append([]byte(nil), document...), []byte("{}")...),
		"unknown":       bytes.Replace(document, []byte(`"protocol":`), []byte(`"extra":true,"protocol":`), 1),
		"duplicate":     bytes.Replace(document, []byte(`"protocol":`), []byte(`"protocol":"x","protocol":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(candidate, binding, now.Add(time.Second)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Decode() = %v", err)
			}
		})
	}
	if _, err := Decode(document, binding, now.Add(6*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stale signed state error = %v", err)
	}
	if _, err := Decode(document, binding, now.Add(-time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("future signed state error = %v", err)
	}
	if _, err := NewSigned(binding, 2, now, now.Add(MaxStateLifetime+time.Second), "active", key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded signed state error = %v", err)
	}
}

func TestStateTrackerRejectsRollbackMutationRevocationAndOutage(t *testing.T) {
	binding, key, now := stateFixture(t)
	first := signedDocument(t, binding, key, 1, now, "active")
	second := signedDocument(t, binding, key, 2, now.Add(time.Second), "active")
	tracker := NewTracker(binding)
	for _, document := range [][]byte{first, first, second} {
		if _, err := tracker.Accept(document, now.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tracker.Accept(first, now.Add(3*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rollback error = %v", err)
	}
	if _, err := tracker.Accept(second, now.Add(3*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("terminal rollback revived = %v", err)
	}
	tracker = NewTracker(binding)
	if _, err := tracker.Accept(first, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	changed := signedDocument(t, binding, key, 1, now.Add(time.Second), "active")
	if _, err := tracker.Accept(changed, now.Add(2*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("same generation mutation error = %v", err)
	}
	tracker = NewTracker(binding)
	if _, err := tracker.Accept(first, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := tracker.Accept(second, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("clock rollback error = %v", err)
	}
	tracker = NewTracker(binding)
	if _, err := tracker.Accept(first, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	revoked := signedDocument(t, binding, key, 2, now.Add(time.Second), "revoked")
	if _, err := tracker.Accept(revoked, now.Add(2*time.Second)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revocation error = %v", err)
	}
	if _, err := tracker.Accept(second, now.Add(2*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoked tracker revived = %v", err)
	}
	path := filepath.Join(t.TempDir(), "operator-state.json")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	tracker = NewTracker(binding)
	if _, err := tracker.ReadFile(path, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := tracker.ReadFile(path, now.Add(2*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("operator state outage error = %v", err)
	}
	if _, err := tracker.Accept(first, now.Add(2*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("outage tracker revived = %v", err)
	}
}
