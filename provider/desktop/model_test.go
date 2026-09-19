package desktop

import (
	"errors"
	"testing"
	"time"
)

var desktopTestNow = time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

func validOpenRequest() OpenRequest {
	return OpenRequest{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "open-operation-1",
		AttemptID: "open-attempt-1", FencingToken: 3, IdempotencyKey: "desktop-open-1",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:      desktopTestNow.Add(time.Hour), ExpectedGeneration: 1, DesktopSessionID: "desktop-session-1",
		CapabilityProfileID: CapabilityProfileID, ExpiresAt: desktopTestNow.Add(30 * time.Minute),
	}
}

func validReceipt(request OpenRequest) AllocationReceipt {
	return AllocationReceipt{
		Reference: "ref:desktop/00000000000000000000000000000001", SandboxID: request.SandboxID,
		DesktopSessionID: request.DesktopSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration, ConnectionGeneration: 1,
		AllocatedAt: desktopTestNow.Add(time.Second), ExpiresAt: request.ExpiresAt,
	}
}

func activeRecord(t *testing.T) Record {
	t.Helper()
	request := validOpenRequest()
	record, err := NewRecord(request, desktopTestNow)
	if err != nil {
		t.Fatal(err)
	}
	record, err = Transition(record, StatusRunning, desktopTestNow.Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	record, err = AttachAllocation(record, validReceipt(request))
	if err != nil {
		t.Fatal(err)
	}
	record, err = Transition(record, StatusSucceeded, desktopTestNow.Add(2*time.Second), &EndpointEvidence{InternalEndpointReference: "ref:desktop-session:opaque-1", ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestOpenStateMachineAndExactHandoff(t *testing.T) {
	record, err := NewRecord(validOpenRequest(), desktopTestNow)
	if err != nil || record.SessionState() != SessionRequested {
		t.Fatalf("new record = %#v, %v", record, err)
	}
	opening, err := Transition(record, StatusRunning, desktopTestNow.Add(time.Second), nil)
	if err != nil || opening.SessionState() != SessionOpening || opening.Allocation != nil {
		t.Fatalf("opening = %#v, %v", opening, err)
	}
	attached, err := AttachAllocation(opening, validReceipt(record.Request))
	if err != nil || attached.SessionState() != SessionOpening {
		t.Fatalf("attached = %#v, %v", attached, err)
	}
	active, err := Transition(attached, StatusSucceeded, desktopTestNow.Add(2*time.Second), &EndpointEvidence{InternalEndpointReference: "ref:desktop-session:opaque-1", ConnectionGeneration: 1})
	if err != nil || active.SessionState() != SessionActive || active.Handoff.MediaProfileID != MediaProfileID || active.Handoff.ControlProfileID != ControlProfileID || active.Handoff.Protocol != ProtocolWebRTC {
		t.Fatalf("active = %#v, %v", active, err)
	}
	bad := active.Clone()
	bad.Handoff.InternalEndpointReference = "https://10.0.0.1/session"
	if err := bad.Validate(); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("raw endpoint validation = %v", err)
	}
}

func TestOpenUnknownReconcilesWithoutChangingIdentity(t *testing.T) {
	record, err := NewRecord(validOpenRequest(), desktopTestNow)
	if err != nil {
		t.Fatal(err)
	}
	record, _ = Transition(record, StatusRunning, desktopTestNow.Add(time.Second), nil)
	unknown, err := Transition(record, StatusOutcomeUnknown, desktopTestNow.Add(2*time.Second), nil)
	if err != nil || unknown.SessionState() != SessionOpenOutcomeUnknown {
		t.Fatalf("unknown = %#v, %v", unknown, err)
	}
	reconciled, err := AttachAllocation(unknown, validReceipt(record.Request))
	if err != nil || reconciled.Status != StatusRunning || reconciled.Request != record.Request {
		t.Fatalf("reconciled = %#v, %v", reconciled, err)
	}
}

func TestCloseStateMachineRevokesBeforeTerminal(t *testing.T) {
	source := activeRecord(t)
	request := CloseRequest{
		SandboxID: source.Request.SandboxID, ProviderRevisionID: source.Request.ProviderRevisionID,
		OperationID: "close-operation-1", AttemptID: "close-attempt-1", FencingToken: source.Request.FencingToken,
		IdempotencyKey: "desktop-close-1", RequestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Deadline: desktopTestNow.Add(time.Hour), ExpectedGeneration: 1, DesktopSessionID: source.Request.DesktopSessionID,
		ConnectionGeneration: 1, Reason: "caller_complete",
	}
	closeRecord, revoked, err := NewCloseRecord(request, source, desktopTestNow.Add(3*time.Second), false)
	if err != nil || revoked.SessionState() != SessionClosing || revoked.RevokedAt == nil || revoked.ClosedAt != nil {
		t.Fatalf("reserve close = %#v / %#v, %v", closeRecord, revoked, err)
	}
	running, err := TransitionClose(closeRecord, StatusRunning, desktopTestNow.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := TransitionClose(running, StatusOutcomeUnknown, desktopTestNow.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	unknownSource, err := MarkCloseUnknown(revoked, unknown.ObservedAt)
	if err != nil || unknownSource.SessionState() != SessionCloseOutcomeUnknown {
		t.Fatalf("unknown close = %#v, %v", unknownSource, err)
	}
	resolved, err := TransitionClose(unknown, StatusSucceeded, desktopTestNow.Add(6*time.Second))
	if err != nil || resolved.Status != StatusSucceeded {
		t.Fatalf("resolved close = %#v, %v", resolved, err)
	}
	closed, err := CompleteClose(unknownSource, resolved.ObservedAt, false)
	if err != nil || closed.SessionState() != SessionClosed {
		t.Fatalf("closed = %#v, %v", closed, err)
	}
	if _, _, err := NewCloseRecord(request, closed, desktopTestNow.Add(7*time.Second), false); !errors.Is(err, ErrHandoffUnavailable) {
		t.Fatalf("terminal resurrection = %v", err)
	}
}

func TestRequestDeadlineFenceAndProfileMatrix(t *testing.T) {
	tests := []struct {
		name string
		edit func(*OpenRequest)
		want error
	}{
		{name: "deadline", edit: func(r *OpenRequest) { r.Deadline = desktopTestNow }, want: ErrDeadlineExpired},
		{name: "expiry", edit: func(r *OpenRequest) { r.ExpiresAt = r.Deadline.Add(time.Second) }, want: ErrInvalidExpiry},
		{name: "fence", edit: func(r *OpenRequest) { r.FencingToken = 0 }, want: ErrInvalidRequest},
		{name: "generation", edit: func(r *OpenRequest) { r.ExpectedGeneration = 0 }, want: ErrInvalidRequest},
		{name: "profile", edit: func(r *OpenRequest) { r.CapabilityProfileID = "browser-v1" }, want: ErrInvalidRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validOpenRequest()
			test.edit(&request)
			if err := request.Validate(desktopTestNow); !errors.Is(err, test.want) {
				t.Fatalf("Validate() = %v, want %v", err, test.want)
			}
		})
	}
}
