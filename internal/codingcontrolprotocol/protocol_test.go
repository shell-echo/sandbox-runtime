package codingcontrolprotocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

func wireDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func testWirePlan() codingidentity.Plan {
	return codingidentity.Plan{Protocol: codingidentity.Protocol, Version: codingidentity.Version,
		ProfileDigest: wireDigest("d"), OwnerDeployment: "provider-runtime",
		OwnerPrincipalDigest: wireDigest("f"), Namespace: "provider-coding",
		ControllerID: "provider-coding-controller", Template: "coding-sandbox-runtime",
		TemplateDigest: wireDigest("2"), ImageDigest: wireDigest("3"),
		ImageConfigDigest: wireDigest("4"), NetworkMode: "none",
		Limits:   codingidentity.Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64},
		Capacity: codingidentity.LocalCandidateCapacity,
		Slots: []codingidentity.Slot{
			{ID: "coding-0000", WorkloadUID: 57000, WorkloadGID: 58000,
				InputsVolume: "coding-0000-inputs", WorkspaceVolume: "coding-0000-workspace",
				OutputsVolume: "coding-0000-outputs"},
			{ID: "coding-0001", WorkloadUID: 57001, WorkloadGID: 58001,
				InputsVolume: "coding-0001-inputs", WorkspaceVolume: "coding-0001-workspace",
				OutputsVolume: "coding-0001-outputs"}}}
}

func testWireAuthorities(t *testing.T) (dockercontrol.CodingCreateAuthority,
	dockercontrol.CodingCleanupAuthority, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	request := lifecycle.CreateRequest{OperationID: "operation-1", AttemptID: "attempt-1",
		FencingToken: 7, IdempotencyKey: "key-1", RequestDigest: wireDigest("a"),
		Deadline: now.Add(time.Minute), Spec: lifecycle.SandboxSpec{
			SandboxID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1",
			WorkspaceID: "workspace-1", ProviderRevisionID: "revision-1",
			RuntimeProfile: "sandbox-runtime-coding-shell-v1",
			Network:        lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone},
			SandboxSlotKey: "coding/slot-1", LeaseExpiresAt: now.Add(time.Hour)}}
	sandbox, operation, err := lifecycle.StartCreate(request, now)
	if err != nil {
		t.Fatal(err)
	}
	operation.State = lifecycle.OperationRunning
	allocation, err := codingidentity.DeriveAllocationID(sandbox.ProviderRevisionID,
		sandbox.TenantID, sandbox.ID, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := codingidentity.TenantDigestForID(sandbox.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	plan := testWirePlan()
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ticket := codingidentity.Reservation{PlanDigest: planDigest, Slot: plan.Slots[0],
		Claim: codingidentity.Claim{TenantDigest: tenant, SandboxID: sandbox.ID,
			AllocationID: allocation, OperationID: operation.ID, AttemptID: operation.AttemptID,
			RequestDigest: request.RequestDigest, Generation: sandbox.Generation,
			Fence: operation.FencingToken}, SpecDigest: wireDigest("c"),
		Status: codingidentity.Creating}
	create, err := dockercontrol.NewCodingCreateAuthority(t.Context(), ticket, operation,
		sandbox, plan, wireDigest("e"), wireDigest("f"), now)
	if err != nil {
		t.Fatal(err)
	}
	ticket.Status = codingidentity.Cleaning
	sandbox.DesiredState = lifecycle.DesiredTerminated
	sandbox.Generation++
	sandbox.UpdatedAt = now.Add(time.Second)
	terminate := lifecycle.Operation{ID: "termination-1", AttemptID: "termination-attempt-1",
		FencingToken: create.Fence + 1, SandboxID: sandbox.ID,
		Type: lifecycle.OperationTerminate, State: lifecycle.OperationRunning,
		Deadline: now.Add(time.Minute), ObservedAt: now.Add(time.Second),
		IdempotencyKey: "termination-key", RequestDigest: wireDigest("b")}
	cleanup, err := dockercontrol.NewCodingCleanupAuthority(t.Context(), create, ticket,
		terminate, sandbox, plan, wireDigest("e"), wireDigest("f"), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return create, cleanup, now
}

func TestCodingControlWireCanonicalActionsAndHistoricalStatus(t *testing.T) {
	create, cleanup, now := testWireAuthorities(t)
	for _, action := range []struct {
		request Request
		at      time.Time
	}{
		{Request{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionCreate, Create: create}, now},
		{Request{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionCleanup, Create: create, Cleanup: &cleanup}, now.Add(time.Second)},
		{Request{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionStatus, Create: create}, create.ExpiresAt.Add(time.Hour)},
		{Request{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionStatus, Create: create, Cleanup: &cleanup}, cleanup.ExpiresAt.Add(time.Hour)},
	} {
		document, err := EncodeRequest(action.request)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeRequest(document, action.at, create.PeerPrincipalDigest)
		if err != nil || decoded.Action != action.request.Action || decoded.Create != create {
			t.Fatalf("canonical action rejected: %s: %v", action.request.Action, err)
		}
	}
	createRequest := Request{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionCreate, Create: create}
	document, _ := EncodeRequest(createRequest)
	for name, bad := range map[string][]byte{
		"unknown":   append(append([]byte{}, document[:len(document)-1]...), []byte(`,"docker_id":"hidden"}`)...),
		"duplicate": append(append([]byte{}, document[:len(document)-1]...), []byte(`,"action":"create"}`)...),
		"spacing":   append([]byte(" "), document...),
		"oversized": bytes.Repeat([]byte("x"), MaxRequestBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest(bad, now, create.PeerPrincipalDigest); !errors.Is(err, ErrInvalidWire) {
				t.Fatalf("invalid private wire admitted: %v", err)
			}
		})
	}
	if _, err := DecodeRequest(document, now, wireDigest("0")); !errors.Is(err, ErrInvalidWire) {
		t.Fatal("self-reported peer digest replaced authenticated peer")
	}
	if _, err := DecodeRequest(document, create.ExpiresAt, create.PeerPrincipalDigest); !errors.Is(err, ErrInvalidWire) {
		t.Fatal("expired create dispatched")
	}
	for name, changed := range map[string]Request{
		"wrong scope": {Protocol: ProtocolID, Scope: "desktop", Action: ActionCreate, Create: create},
		"cleanup missing authority": {Protocol: ProtocolID, Scope: ScopeCoding,
			Action: ActionCleanup, Create: create},
		"create carries cleanup": {Protocol: ProtocolID, Scope: ScopeCoding,
			Action: ActionCreate, Create: create, Cleanup: &cleanup},
	} {
		t.Run(name, func(t *testing.T) {
			bad, _ := EncodeRequest(changed)
			if _, err := DecodeRequest(bad, now.Add(time.Second), create.PeerPrincipalDigest); !errors.Is(err, ErrInvalidWire) {
				t.Fatalf("wrong action/scope admitted: %v", err)
			}
		})
	}
	cleanupRequest := Request{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionCleanup,
		Create: create, Cleanup: &cleanup}
	cleanupDocument, _ := EncodeRequest(cleanupRequest)
	if _, err := DecodeRequest(cleanupDocument, cleanup.ExpiresAt, create.PeerPrincipalDigest); !errors.Is(err, ErrInvalidWire) {
		t.Fatal("expired cleanup reauthorized physical work")
	}
	statusRequest := Request{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionStatus,
		Create: create}
	statusDocument, _ := EncodeRequest(statusRequest)
	if _, err := DecodeRequest(statusDocument, now.Add(-time.Millisecond), create.PeerPrincipalDigest); !errors.Is(err, ErrInvalidWire) {
		t.Fatal("future-issued status authority admitted")
	}
	badCleanup := cleanup
	badCleanup.EffectID = wireDigest("0")
	badRequest := Request{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionStatus,
		Create: create, Cleanup: &badCleanup}
	badDocument, _ := EncodeRequest(badRequest)
	if _, err := DecodeRequest(badDocument, now.Add(time.Second), create.PeerPrincipalDigest); !errors.Is(err, ErrInvalidWire) {
		t.Fatal("status cross-effect cleanup admitted")
	}
}

func TestCodingControlResponseIsMinimalAndBoundToRequest(t *testing.T) {
	create, cleanup, now := testWireAuthorities(t)
	request := Request{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionStatus,
		Create: create, Cleanup: &cleanup}
	response := Response{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionStatus,
		Status: StatusReleased, CreateAuthorityDigest: create.Digest(), EffectID: create.EffectID,
		CleanupAuthorityDigest: cleanup.Digest(), ControlRevision: 4,
		ControlStateDigest: wireDigest("1"), CompletionDigest: wireDigest("2"),
		CompletionEvidenceDigest: wireDigest("3"), AbsenceDigest: wireDigest("4"),
		AbsenceEvidenceDigest: wireDigest("5"), UpdatedAt: now.Add(time.Second)}
	document, err := EncodeResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResponse(document, request)
	if err != nil || decoded != response ||
		bytes.Contains(document, []byte("container_id")) || bytes.Contains(document, []byte("host_path")) {
		t.Fatalf("private response projection drift: %#v, %v", decoded, err)
	}
	pending := response
	pending.Status = StatusCleanupPending
	pending.AbsenceDigest, pending.AbsenceEvidenceDigest = "", ""
	pendingDocument, _ := EncodeResponse(pending)
	if _, err := DecodeResponse(pendingDocument, request); err != nil {
		t.Fatalf("durable intent without absence was not expressible: %v", err)
	}
	cleanupRequest := request
	cleanupRequest.Action = ActionCleanup
	pending.Action = ActionCleanup
	pendingDocument, _ = EncodeResponse(pending)
	if _, err := DecodeResponse(pendingDocument, cleanupRequest); err != nil {
		t.Fatalf("cleanup mutation cannot report pending: %v", err)
	}
	pending.Status = StatusCompleted
	pendingDocument, _ = EncodeResponse(pending)
	if _, err := DecodeResponse(pendingDocument, cleanupRequest); !errors.Is(err, ErrInvalidWire) {
		t.Fatalf("cleanup response falsely reported original completion as cleanup success: %v", err)
	}
	for name, mutate := range map[string]func(*Response){
		"wrong authority":    func(r *Response) { r.CreateAuthorityDigest = wireDigest("0") },
		"wrong cleanup":      func(r *Response) { r.CleanupAuthorityDigest = wireDigest("0") },
		"no absence seal":    func(r *Response) { r.AbsenceEvidenceDigest = "" },
		"not-found as proof": func(r *Response) { r.Status = StatusNotFound },
	} {
		t.Run(name, func(t *testing.T) {
			bad := response
			mutate(&bad)
			badDocument, _ := EncodeResponse(bad)
			if _, err := DecodeResponse(badDocument, request); !errors.Is(err, ErrInvalidWire) {
				t.Fatalf("invalid receipt projection admitted: %v", err)
			}
		})
	}
	for name, bad := range map[string][]byte{
		"backend id": append(append([]byte{}, document[:len(document)-1]...), []byte(`,"container_id":"hidden"}`)...),
		"duplicate":  append(append([]byte{}, document[:len(document)-1]...), []byte(`,"status":"released"}`)...),
		"spacing":    append([]byte(" "), document...),
		"oversized":  bytes.Repeat([]byte("x"), MaxResponseBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeResponse(bad, request); !errors.Is(err, ErrInvalidWire) {
				t.Fatalf("invalid response admitted: %v", err)
			}
		})
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(document, &raw) != nil || len(raw) != 14 {
		t.Fatalf("closed response field set changed: %d", len(raw))
	}
}

func TestCodingControlReleaseObservationRequiresOriginalWindowAndFreshRevision(t *testing.T) {
	create, cleanup, now := testWireAuthorities(t)
	request := Request{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionStatus,
		Create: create, Cleanup: &cleanup}
	released := Response{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionStatus,
		Status: StatusReleased, CreateAuthorityDigest: create.Digest(), EffectID: create.EffectID,
		CleanupAuthorityDigest: cleanup.Digest(), ControlRevision: 4,
		ControlStateDigest: wireDigest("1"), CompletionDigest: wireDigest("2"),
		CompletionEvidenceDigest: wireDigest("3"), AbsenceDigest: wireDigest("4"),
		AbsenceEvidenceDigest: wireDigest("5"), UpdatedAt: cleanup.IssuedAt}
	if err := released.ValidateReleaseObservation(request, now.Add(2*time.Second), 3, wireDigest("0")); err != nil {
		t.Fatalf("fresh exact observation rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Response){
		"before cleanup": func(r *Response) { r.UpdatedAt = cleanup.IssuedAt.Add(-time.Nanosecond) },
		"at expiry":      func(r *Response) { r.UpdatedAt = cleanup.ExpiresAt },
		"future":         func(r *Response) { r.UpdatedAt = now.Add(3 * time.Second) },
		"old revision":   func(r *Response) { r.ControlRevision = 3 },
		"same state":     func(r *Response) { r.ControlStateDigest = wireDigest("0") },
	} {
		t.Run(name, func(t *testing.T) {
			bad := released
			mutate(&bad)
			if err := bad.ValidateReleaseObservation(request, now.Add(2*time.Second), 3, wireDigest("0")); !errors.Is(err, ErrInvalidWire) {
				t.Fatalf("stale/wrong release observation admitted: %v", err)
			}
		})
	}
	createOnly := request
	createOnly.Cleanup = nil
	if released.ValidateReleaseObservation(createOnly, now.Add(2*time.Second), 3, wireDigest("0")) == nil {
		t.Fatal("create-only status became trusted release")
	}
	if released.ValidateReleaseObservation(request, now.Add(2*time.Second), 0, wireDigest("0")) == nil ||
		released.ValidateReleaseObservation(request, now.Add(2*time.Second), 3, "") == nil {
		t.Fatal("missing PG-sourced revision/state floor was accepted")
	}
}

func TestCodingControlReceiptProjectionKeepsCleanupPendingDistinct(t *testing.T) {
	create, cleanup, now := testWireAuthorities(t)
	request := Request{Protocol: ProtocolID, Scope: ScopeCoding, Action: ActionStatus,
		Create: create, Cleanup: &cleanup}
	receipt := dockercontrol.CodingReceipt{Authority: create, AuthorityDigest: create.Digest(),
		Status: dockercontrol.ReceiptCompleted, CompletionDigest: wireDigest("2"),
		CompletionEvidenceDigest: wireDigest("3"), CleanupAuthority: cleanup,
		UpdatedAt: cleanup.IssuedAt}
	projected, err := ProjectReceipt(request, receipt, 4, wireDigest("1"))
	if err != nil || projected.Status != StatusCleanupPending || projected.AbsenceDigest != "" {
		t.Fatalf("durable intent was projected as success: %#v %v", projected, err)
	}
	receipt.Status = dockercontrol.ReceiptReleased
	receipt.AbsenceDigest, receipt.AbsenceEvidenceDigest = wireDigest("4"), wireDigest("5")
	released, err := ProjectReceipt(request, receipt, 5, wireDigest("6"))
	if err != nil || released.Status != StatusReleased ||
		released.ValidateReleaseObservation(request, now.Add(2*time.Second), 4, wireDigest("1")) != nil {
		t.Fatalf("sealed release not projected: %#v %v", released, err)
	}
	receipt.UpdatedAt = cleanup.ExpiresAt
	if _, err := ProjectReceipt(request, receipt, 5, wireDigest("6")); !errors.Is(err, ErrInvalidWire) {
		t.Fatalf("late release admitted: %v", err)
	}
	receipt.Status = dockercontrol.ReceiptReserved
	if _, err := ProjectReceipt(request, receipt, 5, wireDigest("6")); !errors.Is(err, ErrInvalidWire) {
		t.Fatalf("reserved receipt projected: %v", err)
	}
}
