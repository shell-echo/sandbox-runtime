package dockercontrol

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

func testCodingCreate(t *testing.T) (codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox, codingidentity.Plan, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	request := lifecycle.CreateRequest{OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 7,
		IdempotencyKey: "key-1", RequestDigest: testControlDigest("a"), Deadline: now.Add(time.Minute),
		Spec: lifecycle.SandboxSpec{SandboxID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1",
			WorkspaceID: "workspace-1", ProviderRevisionID: "revision-1",
			RuntimeProfile: "sandbox-runtime-coding-shell-v1", Network: lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone},
			SandboxSlotKey: "coding/slot-1", LeaseExpiresAt: now.Add(time.Hour)}}
	sandbox, operation, err := lifecycle.StartCreate(request, now)
	if err != nil {
		t.Fatal(err)
	}
	operation.State = lifecycle.OperationRunning
	allocationID, err := codingidentity.DeriveAllocationID(sandbox.ProviderRevisionID, sandbox.TenantID, sandbox.ID, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	tenantDigest, err := codingidentity.TenantDigestForID(sandbox.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	plan := codingidentity.Plan{Protocol: codingidentity.Protocol, Version: codingidentity.Version,
		ProfileDigest: testControlDigest("d"), OwnerDeployment: "provider-runtime",
		OwnerPrincipalDigest: testControlDigest("f"), Namespace: "provider-coding",
		ControllerID: "provider-coding-controller", Template: "coding-sandbox-runtime",
		TemplateDigest: testControlDigest("2"), ImageDigest: testControlDigest("3"),
		ImageConfigDigest: testControlDigest("4"), NetworkMode: "none",
		Limits:   codingidentity.Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64},
		Capacity: codingidentity.LocalCandidateCapacity,
		Slots: []codingidentity.Slot{
			{ID: "coding-0000", WorkloadUID: 57000, WorkloadGID: 58000,
				InputsVolume: "coding-0000-inputs", WorkspaceVolume: "coding-0000-workspace", OutputsVolume: "coding-0000-outputs"},
			{ID: "coding-0001", WorkloadUID: 57001, WorkloadGID: 58001,
				InputsVolume: "coding-0001-inputs", WorkspaceVolume: "coding-0001-workspace", OutputsVolume: "coding-0001-outputs"},
		}}
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ticket := codingidentity.Reservation{PlanDigest: planDigest, Slot: plan.Slots[0],
		Claim: codingidentity.Claim{TenantDigest: tenantDigest, SandboxID: sandbox.ID,
			AllocationID: allocationID, OperationID: operation.ID, AttemptID: operation.AttemptID,
			RequestDigest: request.RequestDigest, Generation: sandbox.Generation, Fence: operation.FencingToken},
		SpecDigest: testControlDigest("c"), Status: codingidentity.Creating}
	return ticket, operation, sandbox, plan, now
}

func testControlDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func TestCodingCreateAuthorityCanonicalAndBound(t *testing.T) {
	ticket, operation, sandbox, plan, now := testCodingCreate(t)
	authority, err := NewCodingCreateAuthority(context.Background(), ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now)
	if err != nil || authority.Validate(now) != nil || authority.ExpiresAt != now.Add(MaxAuthorityAge) || authority.Digest() == "" {
		t.Fatalf("coding authority = %#v, %v", authority, err)
	}
	document, err := EncodeCodingCreateAuthority(authority)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCodingCreateAuthority(document, now)
	if err != nil || decoded != authority || decoded.BindProvider(ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now) != nil ||
		decoded.BindControl(plan, testControlDigest("e"), testControlDigest("f"),
			ticket.SpecDigest, now) != nil {
		t.Fatalf("canonical authority round trip = %#v, %v", decoded, err)
	}
	for name, changed := range map[string][]byte{
		"unknown field":   append(append([]byte{}, document[:len(document)-1]...), []byte(`,"docker_host":"/var/run/docker.sock"}`)...),
		"duplicate field": append(append([]byte{}, document[:len(document)-1]...), []byte(`,"fence":7}`)...),
		"noncanonical":    append([]byte(" "), document...),
		"oversized":       bytes.Repeat([]byte("x"), MaxAuthorityBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCodingCreateAuthority(changed, now); !errors.Is(err, ErrInvalidAuthority) {
				t.Fatalf("unsafe request accepted: %v", err)
			}
		})
	}
	if _, err := DecodeCodingCreateAuthority(document, authority.ExpiresAt); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatal("expired authority accepted")
	}
	for name, mutate := range map[string]func(*CodingCreateAuthority){
		"wrong peer":       func(a *CodingCreateAuthority) { a.PeerPrincipalDigest = testControlDigest("0") },
		"wrong tenant":     func(a *CodingCreateAuthority) { a.TenantDigest = testControlDigest("0") },
		"wrong allocation": func(a *CodingCreateAuthority) { a.AllocationID = "codingalloc-" + strings.Repeat("0", 64) },
		"wrong fence":      func(a *CodingCreateAuthority) { a.Fence++ },
		"wrong spec":       func(a *CodingCreateAuthority) { a.SpecDigest = testControlDigest("0") },
		"wrong mapping":    func(a *CodingCreateAuthority) { a.MappingDigest = testControlDigest("0") },
		"wrong creation":   func(a *CodingCreateAuthority) { a.CreationGeneration++ },
		"wrong authorized": func(a *CodingCreateAuthority) { a.AuthorizedGeneration++ },
		"wrong action":     func(a *CodingCreateAuthority) { a.Action = "coding.exec_create" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := authority
			mutate(&changed)
			if err := changed.BindProvider(ticket, operation, sandbox, plan, testControlDigest("e"), testControlDigest("f"), now); !errors.Is(err, ErrInvalidAuthority) {
				t.Fatalf("drifted authority accepted: %v", err)
			}
		})
	}
}

func TestCodingCreateAuthorityIndependentProviderAndControlBindings(t *testing.T) {
	ticket, operation, sandbox, plan, now := testCodingCreate(t)
	// The accepted idempotency record is the source when historical lifecycle
	// Operation.RequestDigest is empty; do not fill it from the wire.
	if operation.RequestDigest != "" {
		t.Fatal("fixture must exercise empty operation request digest")
	}
	a, err := NewCodingCreateAuthority(context.Background(), ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCodingCreateAuthority(context.Background(), ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("0"), now); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("plan owner/peer mismatch = %v", err)
	}
	wrongTicket := ticket
	wrongTicket.Claim.AllocationID = "codingalloc-" + strings.Repeat("0", 64)
	if _, err := NewCodingCreateAuthority(context.Background(), wrongTicket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("non-derived allocation = %v", err)
	}
	for name, mutate := range map[string]func(*lifecycle.Operation){
		"not running":      func(o *lifecycle.Operation) { o.State = lifecycle.OperationAccepted },
		"cancel requested": func(o *lifecycle.Operation) { o.CancelRequested = true },
		"wrong attempt":    func(o *lifecycle.Operation) { o.AttemptID += "-drift" },
		"wrong fence":      func(o *lifecycle.Operation) { o.FencingToken++ },
		"wrong digest":     func(o *lifecycle.Operation) { o.RequestDigest = testControlDigest("0") },
		"wrong deadline":   func(o *lifecycle.Operation) { o.Deadline = now },
	} {
		t.Run(name, func(t *testing.T) {
			changed := operation
			mutate(&changed)
			if _, err := NewCodingCreateAuthority(context.Background(), ticket, changed, sandbox, plan,
				testControlDigest("e"), testControlDigest("f"), now); !errors.Is(err, ErrInvalidAuthority) {
				t.Fatalf("unbound operation accepted: %v", err)
			}
		})
	}
	prolonged := a
	prolonged.OperationDeadline = operation.Deadline.Add(time.Hour)
	if prolonged.Validate(now) != nil || !errors.Is(prolonged.BindProvider(ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now), ErrInvalidAuthority) {
		t.Fatal("wire-supplied extended deadline passed Provider binding")
	}
	for name, check := range map[string]func() error{
		"wrong peer": func() error {
			return a.BindControl(plan, testControlDigest("e"), testControlDigest("0"), ticket.SpecDigest, now)
		},
		"wrong policy": func() error {
			return a.BindControl(plan, testControlDigest("0"), testControlDigest("f"), ticket.SpecDigest, now)
		},
		"wrong spec": func() error {
			return a.BindControl(plan, testControlDigest("e"), testControlDigest("f"), testControlDigest("0"), now)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(); !errors.Is(err, ErrInvalidAuthority) {
				t.Fatalf("wrong Control binding = %v", err)
			}
		})
	}
}

func TestCodingCreateAuthorityDeadlineAndCancellation(t *testing.T) {
	ticket, operation, sandbox, plan, _ := testCodingCreate(t)
	now := time.Now().UTC()
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(5*time.Second))
	defer cancel()
	operation.Deadline = now.Add(10 * time.Second)
	authority, err := NewCodingCreateAuthority(ctx, ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now)
	if err != nil || authority.ExpiresAt.After(now.Add(5*time.Second)) || authority.ExpiresAt.Before(now.Add(4*time.Second)) {
		t.Fatalf("context deadline not bounded: %#v, %v", authority, err)
	}
	cancel()
	if _, err := NewCodingCreateAuthority(ctx, ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatal("cancelled request authority accepted")
	}
}
