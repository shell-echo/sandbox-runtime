package session

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var sessionTestNow = time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)

func validOpenRequest() OpenRequest {
	return OpenRequest{
		SandboxID:           "sandbox-1",
		ProviderRevisionID:  "provider-revision-local-v1",
		OperationID:         "operation-session-1",
		AttemptID:           "attempt-session-1",
		FencingToken:        1,
		IdempotencyKey:      "session-open-1",
		RequestDigest:       "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:            sessionTestNow.Add(5 * time.Minute),
		ExpectedGeneration:  1,
		RuntimeSessionID:    "session-1",
		RuntimeType:         RuntimeTerminal,
		CapabilityProfileID: "terminal-v1",
		ExpiresAt:           sessionTestNow.Add(4 * time.Minute),
	}
}

func TestOpenRequestValidateAcceptsLockedBounds(t *testing.T) {
	request := validOpenRequest()
	request.IdempotencyKey = strings.Repeat("界", MaxIdempotencyKeyRunes)
	request.ExpiresAt = request.Deadline
	if err := request.Validate(sessionTestNow); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestOpenRequestValidateRejectsInvalidBoundaries(t *testing.T) {
	tests := map[string]struct {
		mutate func(*OpenRequest)
		want   error
	}{
		"sandbox ID":            {func(r *OpenRequest) { r.SandboxID = "sandbox/value" }, ErrInvalidRequest},
		"provider revision":     {func(r *OpenRequest) { r.ProviderRevisionID = "" }, ErrInvalidRequest},
		"operation ID":          {func(r *OpenRequest) { r.OperationID = "operation value" }, ErrInvalidRequest},
		"attempt ID":            {func(r *OpenRequest) { r.AttemptID = "" }, ErrInvalidRequest},
		"runtime session ID":    {func(r *OpenRequest) { r.RuntimeSessionID = "session/value" }, ErrInvalidRequest},
		"capability profile":    {func(r *OpenRequest) { r.CapabilityProfileID = "" }, ErrInvalidRequest},
		"empty idempotency":     {func(r *OpenRequest) { r.IdempotencyKey = "" }, ErrInvalidRequest},
		"large idempotency":     {func(r *OpenRequest) { r.IdempotencyKey = strings.Repeat("x", MaxIdempotencyKeyRunes+1) }, ErrInvalidRequest},
		"invalid UTF-8":         {func(r *OpenRequest) { r.IdempotencyKey = string([]byte{0xff}) }, ErrInvalidRequest},
		"zero fence":            {func(r *OpenRequest) { r.FencingToken = 0 }, ErrInvalidRequest},
		"zero generation":       {func(r *OpenRequest) { r.ExpectedGeneration = 0 }, ErrInvalidRequest},
		"invalid digest":        {func(r *OpenRequest) { r.RequestDigest = "sha256:ABC" }, ErrInvalidRequest},
		"missing deadline":      {func(r *OpenRequest) { r.Deadline = time.Time{} }, ErrInvalidRequest},
		"expired deadline":      {func(r *OpenRequest) { r.Deadline = sessionTestNow }, ErrDeadlineExpired},
		"browser runtime":       {func(r *OpenRequest) { r.RuntimeType = "browser" }, ErrInvalidRequest},
		"missing expiry":        {func(r *OpenRequest) { r.ExpiresAt = time.Time{} }, ErrInvalidExpiry},
		"expired handoff":       {func(r *OpenRequest) { r.ExpiresAt = sessionTestNow }, ErrInvalidExpiry},
		"expiry after deadline": {func(r *OpenRequest) { r.ExpiresAt = r.Deadline.Add(time.Second) }, ErrInvalidExpiry},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := validOpenRequest()
			test.mutate(&request)
			if err := request.Validate(sessionTestNow); !errors.Is(err, test.want) {
				t.Fatalf("Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRecordTransitionsMintOnlySuccessfulOpaqueHandoff(t *testing.T) {
	record, err := NewRecord(validOpenRequest(), sessionTestNow.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	record, err = Transition(record, StatusRunning, sessionTestNow.Add(2*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &EndpointEvidence{InternalEndpointReference: "ref:session:opaque-1", ConnectionGeneration: 1}
	record, err = Transition(record, StatusSucceeded, sessionTestNow.Add(3*time.Second), evidence)
	if err != nil {
		t.Fatal(err)
	}
	if record.Handoff == nil {
		t.Fatal("successful record has no handoff")
	}
	handoff := record.Handoff
	if handoff.OperationID != record.Request.OperationID || handoff.AttemptID != record.Request.AttemptID ||
		handoff.FencingToken != record.Request.FencingToken || handoff.SandboxID != record.Request.SandboxID ||
		handoff.RuntimeSessionID != record.Request.RuntimeSessionID || handoff.RuntimeType != RuntimeTerminal ||
		handoff.CapabilityProfileID != "terminal-v1" || handoff.Protocol != ProtocolWebSocket ||
		handoff.InternalEndpointReference != evidence.InternalEndpointReference || handoff.ConnectionGeneration != 1 ||
		!handoff.ExpiresAt.Equal(record.Request.ExpiresAt) {
		t.Fatalf("handoff = %#v", handoff)
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("Record.Validate() error = %v", err)
	}
}

func TestOutcomeUnknownNeverMintsOrReopensHandoff(t *testing.T) {
	record, err := NewRecord(validOpenRequest(), sessionTestNow.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	record, err = Transition(record, StatusOutcomeUnknown, sessionTestNow.Add(2*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if record.Handoff != nil {
		t.Fatalf("outcome-unknown handoff = %#v", record.Handoff)
	}
	evidence := &EndpointEvidence{InternalEndpointReference: "ref:session:opaque-1", ConnectionGeneration: 1}
	if _, err := Transition(record, StatusSucceeded, sessionTestNow.Add(3*time.Second), evidence); !errors.Is(err, ErrTerminalOperation) {
		t.Fatalf("Transition(outcome_unknown, succeeded) error = %v", err)
	}
	if _, err := Transition(record, StatusOutcomeUnknown, sessionTestNow.Add(3*time.Second), evidence); !errors.Is(err, ErrTerminalOperation) {
		t.Fatalf("Transition(outcome_unknown replay with evidence) error = %v", err)
	}
}

func TestTransitionRejectsInvalidHandoffAndStateChanges(t *testing.T) {
	newRecord := func(t *testing.T) Record {
		t.Helper()
		record, err := NewRecord(validOpenRequest(), sessionTestNow.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	validEvidence := &EndpointEvidence{InternalEndpointReference: "ref:session:opaque-1", ConnectionGeneration: 1}
	tests := map[string]struct {
		prepare  func(*Record)
		next     Status
		when     time.Time
		evidence *EndpointEvidence
		want     error
	}{
		"accepted cannot succeed":    {next: StatusSucceeded, when: sessionTestNow.Add(2 * time.Second), evidence: validEvidence, want: ErrInvalidTransition},
		"non-success evidence":       {next: StatusFailed, when: sessionTestNow.Add(2 * time.Second), evidence: validEvidence, want: ErrHandoffUnavailable},
		"raw endpoint":               {prepare: beginRecord, next: StatusSucceeded, when: sessionTestNow.Add(3 * time.Second), evidence: &EndpointEvidence{InternalEndpointReference: "wss://10.0.0.1:8443/terminal", ConnectionGeneration: 1}, want: ErrInvalidHandoff},
		"zero connection generation": {prepare: beginRecord, next: StatusSucceeded, when: sessionTestNow.Add(3 * time.Second), evidence: &EndpointEvidence{InternalEndpointReference: "ref:session:opaque-1"}, want: ErrInvalidHandoff},
		"missing success evidence":   {prepare: beginRecord, next: StatusSucceeded, when: sessionTestNow.Add(3 * time.Second), want: ErrHandoffUnavailable},
		"expired before success":     {prepare: beginRecord, next: StatusSucceeded, when: sessionTestNow.Add(4 * time.Minute), evidence: validEvidence, want: ErrHandoffUnavailable},
		"time regression":            {next: StatusRunning, when: sessionTestNow, want: ErrInvalidTransition},
		"expired before running":     {next: StatusRunning, when: sessionTestNow.Add(5 * time.Minute), want: ErrDeadlineExpired},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			record := newRecord(t)
			if test.prepare != nil {
				test.prepare(&record)
			}
			if _, err := Transition(record, test.next, test.when, test.evidence); !errors.Is(err, test.want) {
				t.Fatalf("Transition() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRecordCloneDoesNotShareHandoff(t *testing.T) {
	record, err := NewRecord(validOpenRequest(), sessionTestNow.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	record, err = Transition(record, StatusRunning, sessionTestNow.Add(2*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	record, err = Transition(record, StatusSucceeded, sessionTestNow.Add(3*time.Second), &EndpointEvidence{InternalEndpointReference: "ref:session:opaque-1", ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	clone := record.Clone()
	record.Handoff.InternalEndpointReference = "ref:session:mutated"
	if clone.Handoff.InternalEndpointReference != "ref:session:opaque-1" {
		t.Fatalf("Clone() shares handoff: %#v", clone.Handoff)
	}
}

func TestRecordValidateRejectsMismatchedOrNonOpaqueHandoff(t *testing.T) {
	record, err := NewRecord(validOpenRequest(), sessionTestNow.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	record, err = Transition(record, StatusRunning, sessionTestNow.Add(2*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	record, err = Transition(record, StatusSucceeded, sessionTestNow.Add(3*time.Second), &EndpointEvidence{InternalEndpointReference: "ref:session:opaque-1", ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*Handoff){
		"operation identity": func(h *Handoff) { h.OperationID = "other-operation" },
		"runtime type":       func(h *Handoff) { h.RuntimeType = "browser" },
		"protocol":           func(h *Handoff) { h.Protocol = "webrtc" },
		"raw endpoint":       func(h *Handoff) { h.InternalEndpointReference = "http://127.0.0.1:8080" },
		"expiry":             func(h *Handoff) { h.ExpiresAt = h.ExpiresAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := record.Clone()
			mutate(invalid.Handoff)
			if err := invalid.Validate(); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Record.Validate() error = %v, want ErrInvalidRecord", err)
			}
		})
	}
}

func beginRecord(record *Record) {
	updated, err := Transition(*record, StatusRunning, sessionTestNow.Add(2*time.Second), nil)
	if err != nil {
		panic(err)
	}
	*record = updated
}
