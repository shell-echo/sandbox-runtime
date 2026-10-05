package dockercontrol

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

func testCodingCleanup(t *testing.T) (CodingCreateAuthority, codingidentity.Reservation,
	lifecycle.Operation, lifecycle.Sandbox, codingidentity.Plan, time.Time) {
	t.Helper()
	ticket, _, sandbox, plan, now := testCodingCreate(t)
	create, err := NewCodingCreateAuthority(t.Context(), ticket,
		lifecycle.Operation{ID: ticket.Claim.OperationID, AttemptID: ticket.Claim.AttemptID,
			FencingToken: ticket.Claim.Fence, SandboxID: ticket.Claim.SandboxID,
			Type: lifecycle.OperationCreate, State: lifecycle.OperationRunning,
			Deadline: now.Add(time.Minute), ObservedAt: now,
			IdempotencyKey: "key-1", RequestDigest: ticket.Claim.RequestDigest},
		sandbox, plan, testControlDigest("e"), testControlDigest("f"), now)
	if err != nil {
		t.Fatal(err)
	}
	ticket.Status = codingidentity.Cleaning
	sandbox.DesiredState = lifecycle.DesiredTerminated
	sandbox.Generation++
	sandbox.UpdatedAt = now
	termination := lifecycle.Operation{ID: "termination-1", AttemptID: "termination-attempt-1",
		FencingToken: create.Fence + 1, SandboxID: sandbox.ID,
		Type: lifecycle.OperationTerminate, State: lifecycle.OperationRunning,
		Deadline: now.Add(time.Minute), ObservedAt: now,
		IdempotencyKey: "termination-key", RequestDigest: testControlDigest("b")}
	if termination.Validate() != nil || sandbox.Validate() != nil {
		t.Fatal("invalid termination fixture")
	}
	return create, ticket, termination, sandbox, plan, now
}

func TestCodingCleanupAuthorityBindsBirthToCurrentPGTermination(t *testing.T) {
	create, ticket, operation, sandbox, plan, now := testCodingCleanup(t)
	a, err := NewCodingCleanupAuthority(t.Context(), create, ticket, operation, sandbox,
		plan, testControlDigest("e"), testControlDigest("f"), now)
	if err != nil || a.Validate(now) != nil || a.EffectID != create.EffectID ||
		a.OriginalAuthorityDigest != create.Digest() || a.BirthGeneration != create.CreationGeneration ||
		a.CurrentGeneration != sandbox.Generation || a.CleanupFence != operation.FencingToken ||
		a.CleanupRequestDigest != operation.RequestDigest {
		t.Fatalf("cleanup authority = %#v, %v", a, err)
	}
	if a.BindProvider(create, ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now) != nil ||
		a.BindControl(create, plan, testControlDigest("e"), testControlDigest("f"),
			ticket.SpecDigest, now) != nil {
		t.Fatal("cleanup authority did not bind both sides")
	}
	document, err := EncodeCodingCleanupAuthority(a)
	if err != nil || len(document) > MaxCleanupBytes {
		t.Fatalf("encode cleanup authority: %v", err)
	}
	decoded, err := DecodeCodingCleanupAuthority(document, now)
	if err != nil || decoded != a {
		t.Fatalf("canonical cleanup roundtrip = %#v, %v", decoded, err)
	}
	for name, altered := range map[string][]byte{
		"unknown":   append(append([]byte{}, document[:len(document)-1]...), []byte(`,"docker_host":"/var/run/docker.sock"}`)...),
		"duplicate": append(append([]byte{}, document[:len(document)-1]...), []byte(`,"cleanup_fence":8}`)...),
		"spacing":   append([]byte(" "), document...),
		"oversize":  bytes.Repeat([]byte("x"), MaxCleanupBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCodingCleanupAuthority(altered, now); !errors.Is(err, ErrInvalidAuthority) {
				t.Fatalf("noncanonical cleanup admitted: %v", err)
			}
		})
	}
	if _, err := DecodeCodingCleanupAuthority(document, a.ExpiresAt); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatal("expired cleanup admitted")
	}
	blankDigest := a
	blankDigest.CleanupRequestDigest = ""
	blankDigest.RequestID = codingCleanupRequestID(blankDigest)
	blankDocument, err := EncodeCodingCleanupAuthority(blankDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCodingCleanupAuthority(blankDocument, now); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("canonical empty cleanup request digest admitted: %v", err)
	}
}

func TestCodingCleanupAuthorityAcceptsOnlyBoundedParentDeadline(t *testing.T) {
	create, ticket, operation, sandbox, plan, now := testCodingCleanup(t)
	parentDeadline := now.Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), parentDeadline)
	defer cancel()
	a, err := NewCodingCleanupAuthority(ctx, create, ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now)
	if err != nil || !a.ExpiresAt.Equal(parentDeadline) ||
		a.BindProvider(create, ticket, operation, sandbox, plan,
			testControlDigest("e"), testControlDigest("f"), now) != nil {
		t.Fatalf("legitimate shortened cleanup expiry rejected: %#v, %v", a, err)
	}
	if a.Validate(parentDeadline) == nil {
		t.Fatal("shortened cleanup remained live at expiry")
	}
	longer := a
	longer.ExpiresAt = now.Add(MaxAuthorityAge + time.Second)
	if longer.BindProvider(create, ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now) == nil {
		t.Fatal("expiry past maximum admitted")
	}
	drift := operation
	drift.Deadline = drift.Deadline.Add(time.Second)
	if a.BindProvider(create, ticket, drift, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now) == nil {
		t.Fatal("OperationDeadline drift admitted")
	}
}

func TestCodingCleanupAuthorityAllowsCurrentFenceEqualBirth(t *testing.T) {
	create, ticket, operation, sandbox, plan, now := testCodingCleanup(t)
	operation.FencingToken = create.Fence
	a, err := NewCodingCleanupAuthority(t.Context(), create, ticket, operation, sandbox,
		plan, testControlDigest("e"), testControlDigest("f"), now)
	if err != nil || a.CleanupFence != create.Fence || a.Validate(now) != nil ||
		a.BindProvider(create, ticket, operation, sandbox, plan,
			testControlDigest("e"), testControlDigest("f"), now) != nil {
		t.Fatalf("current same-fence terminate rejected: %#v, %v", a, err)
	}
	stale := operation
	stale.FencingToken = create.Fence - 1
	if _, err := NewCodingCleanupAuthority(t.Context(), create, ticket, stale, sandbox,
		plan, testControlDigest("e"), testControlDigest("f"), now); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("below-birth fence accepted: %v", err)
	}
}

func TestCodingCleanupAuthorityRejectsCreatingAndStaleTermination(t *testing.T) {
	create, ticket, operation, sandbox, plan, now := testCodingCleanup(t)
	check := func(name string, mutate func(*codingidentity.Reservation, *lifecycle.Operation, *lifecycle.Sandbox)) {
		t.Run(name, func(t *testing.T) {
			changedTicket, changedOperation, changedSandbox := ticket, operation, sandbox
			mutate(&changedTicket, &changedOperation, &changedSandbox)
			if _, err := NewCodingCleanupAuthority(context.Background(), create, changedTicket,
				changedOperation, changedSandbox, plan, testControlDigest("e"),
				testControlDigest("f"), now); !errors.Is(err, ErrInvalidAuthority) {
				t.Fatalf("unsafe cleanup admitted: %v", err)
			}
		})
	}
	check("creating", func(r *codingidentity.Reservation, _ *lifecycle.Operation, _ *lifecycle.Sandbox) {
		r.Status = codingidentity.Creating
	})
	check("wrong slot", func(r *codingidentity.Reservation, _ *lifecycle.Operation, _ *lifecycle.Sandbox) {
		r.Slot = plan.Slots[1]
	})
	check("stale fence", func(_ *codingidentity.Reservation, o *lifecycle.Operation, _ *lifecycle.Sandbox) {
		o.FencingToken = create.Fence - 1
	})
	check("same operation", func(_ *codingidentity.Reservation, o *lifecycle.Operation, _ *lifecycle.Sandbox) {
		o.ID = create.OperationID
	})
	check("wrong type", func(_ *codingidentity.Reservation, o *lifecycle.Operation, _ *lifecycle.Sandbox) {
		o.Type = lifecycle.OperationResume
	})
	check("missing request digest", func(_ *codingidentity.Reservation, o *lifecycle.Operation, _ *lifecycle.Sandbox) {
		o.RequestDigest = ""
	})
	check("both request fields empty", func(_ *codingidentity.Reservation, o *lifecycle.Operation, _ *lifecycle.Sandbox) {
		o.IdempotencyKey = ""
		o.RequestDigest = ""
	})
	check("accepted not running", func(_ *codingidentity.Reservation, o *lifecycle.Operation, _ *lifecycle.Sandbox) {
		o.State = lifecycle.OperationAccepted
	})
	check("not retired", func(_ *codingidentity.Reservation, _ *lifecycle.Operation, s *lifecycle.Sandbox) {
		s.DesiredState = lifecycle.DesiredReady
	})
	check("birth generation", func(_ *codingidentity.Reservation, _ *lifecycle.Operation, s *lifecycle.Sandbox) {
		s.Generation = create.CreationGeneration
	})
	check("wrong tenant", func(_ *codingidentity.Reservation, _ *lifecycle.Operation, s *lifecycle.Sandbox) {
		s.TenantID = "another-tenant"
	})
	check("expired operation", func(_ *codingidentity.Reservation, o *lifecycle.Operation, _ *lifecycle.Sandbox) {
		o.Deadline = now
	})
	valid, err := NewCodingCleanupAuthority(context.Background(), create, ticket, operation, sandbox,
		plan, testControlDigest("e"), testControlDigest("f"), now)
	if err != nil {
		t.Fatal(err)
	}
	late := valid
	late.CleanupFence++
	late.RequestID = codingCleanupRequestID(late)
	if late.BindControl(create, plan, testControlDigest("e"), testControlDigest("f"),
		ticket.SpecDigest, now) != nil {
		// A syntactically valid Control envelope is not enough; the next
		// Provider PG comparison below must reject it.
		t.Fatal("control should not claim current PG truth")
	}
	if late.BindProvider(create, ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now) == nil {
		t.Fatal("stale/different cleanup fence escaped Provider PG comparison")
	}
}
