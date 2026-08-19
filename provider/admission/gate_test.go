package admission

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestProtectedOperationGateAdmitsBoundMutationAndReservesJTI(t *testing.T) {
	fixture := newEdDSAFixture(t)
	token, binding, document, clock := gateTokenAndBinding()
	guard := &recordingMutationGuard{}
	gate, err := NewProtectedOperationGate(fixture.keys, &clock, guard)
	if err != nil {
		t.Fatal(err)
	}
	compact := fixture.token(t, JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: expectedJWSType}, token.Claims)
	if err := gate.Admit(context.Background(), ProtectedOperationRequest{CompactToken: compact, Binding: binding, Document: document}); err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	requests := guard.Requests()
	if len(requests) != 1 {
		t.Fatalf("guard calls = %d, want 1", len(requests))
	}
	wantFingerprint := sha256.Sum256([]byte(token.Claims.JTI))
	if requests[0].JTIFingerprint != wantFingerprint || requests[0].ExpiresAt != time.Unix(token.Claims.ExpiresAt, 0).UTC() {
		t.Fatalf("guard request = %#v", requests[0])
	}
}

func TestProtectedOperationGateRejectsBeforeGuardReservation(t *testing.T) {
	fixture := newEdDSAFixture(t)
	token, binding, document, clock := gateTokenAndBinding()
	compact := fixture.token(t, JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: expectedJWSType}, token.Claims)

	tests := []struct {
		name      string
		request   ProtectedOperationRequest
		guard     *recordingMutationGuard
		wantError error
	}{
		{name: "invalid compact token", request: ProtectedOperationRequest{CompactToken: "not-a-token", Binding: binding, Document: document}, guard: &recordingMutationGuard{}, wantError: ErrUnauthenticated},
		{name: "mismatched verified caller", request: ProtectedOperationRequest{CompactToken: compact, Binding: withGateCaller(binding, "spiffe://provider/other"), Document: document}, guard: &recordingMutationGuard{}, wantError: ErrForbidden},
		{name: "mismatched request digest", request: ProtectedOperationRequest{CompactToken: compact, Binding: binding, Document: []byte(`{"operation":"wrong"}`)}, guard: &recordingMutationGuard{}, wantError: ErrForbidden},
		{name: "replayed mutation", request: ProtectedOperationRequest{CompactToken: compact, Binding: binding, Document: document}, guard: &recordingMutationGuard{decision: MutationGuardReplayed}, wantError: ErrConflict},
		{name: "unavailable guard", request: ProtectedOperationRequest{CompactToken: compact, Binding: binding, Document: document}, guard: &recordingMutationGuard{err: errors.New("state failure")}, wantError: ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gate, err := NewProtectedOperationGate(fixture.keys, &clock, test.guard)
			if err != nil {
				t.Fatal(err)
			}
			if err := gate.Admit(context.Background(), test.request); !errors.Is(err, test.wantError) {
				t.Fatalf("Admit() error = %v, want %v", err, test.wantError)
			}
			if test.wantError == ErrUnauthenticated || test.wantError == ErrForbidden {
				if calls := len(test.guard.Requests()); calls != 0 {
					t.Fatalf("guard calls = %d, want 0", calls)
				}
			}
		})
	}
}

func TestProtectedOperationGateDoesNotConsumeReadJTI(t *testing.T) {
	fixture := newEdDSAFixture(t)
	token, binding, _, clock := gateTokenAndBinding()
	token.Claims.Operation = OperationReadSandbox
	token.Claims.RequestContractID = requestBindings[OperationReadSandbox].contractID
	token.Claims.RequestDigestProfile = requestBindings[OperationReadSandbox].profile
	binding.Operation = token.Claims.Operation
	binding.RequestContractID = token.Claims.RequestContractID
	binding.RequestDigestProfile = token.Claims.RequestDigestProfile
	document, digest := gateDocument(token.Claims.Operation, token.Claims.RequestDigestProfile)
	token.Claims.RequestDigest = digest
	binding.RequestDigest = digest
	guard := &recordingMutationGuard{err: errors.New("read must not reserve")}
	gate, err := NewProtectedOperationGate(fixture.keys, &clock, guard)
	if err != nil {
		t.Fatal(err)
	}
	compact := fixture.token(t, JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: expectedJWSType}, token.Claims)
	if err := gate.Admit(context.Background(), ProtectedOperationRequest{CompactToken: compact, Binding: binding, Document: document}); err != nil {
		t.Fatalf("Admit(read) error = %v", err)
	}
	if calls := len(guard.Requests()); calls != 0 {
		t.Fatalf("guard calls = %d, want 0", calls)
	}
}

func TestProtectedOperationGatePreservesCanceledContextAndRejectsIncompleteConstruction(t *testing.T) {
	_, _, _, clock := gateTokenAndBinding()
	if _, err := NewProtectedOperationGate(nil, &clock, &recordingMutationGuard{}); err == nil {
		t.Fatal("NewProtectedOperationGate accepted nil keys")
	}
	if _, err := NewProtectedOperationGate(keySource{}, nil, &recordingMutationGuard{}); err == nil {
		t.Fatal("NewProtectedOperationGate accepted nil clock")
	}
	if _, err := NewProtectedOperationGate(keySource{}, &clock, nil); err == nil {
		t.Fatal("NewProtectedOperationGate accepted nil guard")
	}

	fixture := newEdDSAFixture(t)
	gate, err := NewProtectedOperationGate(fixture.keys, &clock, &recordingMutationGuard{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := gate.Admit(ctx, ProtectedOperationRequest{CompactToken: "not-a-token"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Admit() error = %v, want context cancellation", err)
	}
}

func gateTokenAndBinding() (VerifiedToken, TokenBinding, []byte, fixedClock) {
	token, binding, clock := validTokenBindingForTest()
	document, digest := gateDocument(token.Claims.Operation, token.Claims.RequestDigestProfile)
	token.Claims.RequestDigest = digest
	binding.RequestDigest = digest
	return token, binding, document, clock
}

func gateDocument(operation Operation, profile DigestProfile) ([]byte, string) {
	document := []byte(`{"operation":"` + string(operation) + `"}`)
	digest := canonicalSHA256(document)
	if profile == DigestProfileRequestExcludingDigest {
		document = []byte(`{"operation":"` + string(operation) + `","request_digest":"` + digest + `"}`)
	}
	return document, digest
}

func withGateCaller(binding TokenBinding, caller string) TokenBinding {
	binding.Caller = caller
	return binding
}

type recordingMutationGuard struct {
	mu       sync.Mutex
	requests []MutationGuardRequest
	decision MutationGuardDecision
	err      error
}

func (g *recordingMutationGuard) Reserve(_ context.Context, request MutationGuardRequest) (MutationGuardDecision, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, request)
	return g.decision, g.err
}

func (g *recordingMutationGuard) Requests() []MutationGuardRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]MutationGuardRequest(nil), g.requests...)
}

var _ MutationGuard = (*recordingMutationGuard)(nil)
