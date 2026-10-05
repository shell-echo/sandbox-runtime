package providerpostgres

import (
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecycledocker "github.com/shell-echo/sandbox-runtime/provider/lifecycle/driver/docker"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

func testCodingAcceptedCreate(t *testing.T, now time.Time, revision, tenant, sandboxID, operationID string) lifecyclerepository.State {
	t.Helper()
	request := lifecycle.CreateRequest{
		OperationID: operationID, AttemptID: "attempt-1", FencingToken: 7,
		IdempotencyKey: "idempotency-1", RequestDigest: codingTestDigest("a"),
		Deadline: now.Add(time.Minute),
		Spec: lifecycle.SandboxSpec{SandboxID: sandboxID, TenantID: tenant,
			WorkOrderID: "work-order-1", WorkspaceID: "workspace-1", ProviderRevisionID: revision,
			RuntimeProfile: "sandbox-runtime-coding-shell-v1", Network: lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone},
			SandboxSlotKey: "coding/slot-1", LeaseExpiresAt: now.Add(time.Hour)},
	}
	sandbox, operation, err := lifecycle.StartCreate(request, now)
	if err != nil {
		t.Fatal(err)
	}
	state := lifecyclerepository.NewState()
	if _, err := state.ReserveCreate(request.IdempotencyKey, request.RequestDigest, sandbox, operation); err != nil {
		t.Fatal(err)
	}
	return state
}

func codingTestDigest(character string) string {
	result := "sha256:"
	for range 64 {
		result += character
	}
	return result
}

func TestCodingClaimRequiresExactAcceptedCreateLedger(t *testing.T) {
	if lifecycledocker.CodingShellRuntimeProfile != "sandbox-runtime-coding-shell-v1" {
		t.Fatal("coding accepted-create projection drifted from the Docker runtime profile")
	}
	now := time.Date(2026, time.October, 5, 0, 0, 0, 0, time.UTC)
	state := testCodingAcceptedCreate(t, now, "revision-1", "tenant-1", "sandbox-1", "operation-1")
	if state.Operations["operation-1"].RequestDigest != "" {
		t.Fatal("test no longer exercises StartCreate's empty Operation.RequestDigest")
	}
	claim, err := codingClaimFromAcceptedCreate(&state, "operation-1", now)
	if err != nil || claim.Validate() != nil || claim.Generation != 1 || claim.Fence != 7 ||
		claim.RequestDigest != codingTestDigest("a") {
		t.Fatalf("accepted create projection = %#v, %v", claim, err)
	}
	projection := state.Export()
	restarted := lifecyclerepository.NewState()
	if err := restarted.Import(projection); err != nil {
		t.Fatal(err)
	}
	replayed, err := codingClaimFromAcceptedCreate(&restarted, "operation-1", now)
	if err != nil || replayed != claim {
		t.Fatalf("restart changed accepted allocation = %#v, %v", replayed, err)
	}
	for _, scope := range []struct{ revision, tenant, sandbox, operation string }{
		{"revision-2", "tenant-1", "sandbox-1", "operation-1"},
		{"revision-1", "tenant-2", "sandbox-1", "operation-1"},
		{"revision-1", "tenant-1", "sandbox-2", "operation-1"},
		{"revision-1", "tenant-1", "sandbox-1", "operation-2"},
	} {
		other := testCodingAcceptedCreate(t, now, scope.revision, scope.tenant, scope.sandbox, scope.operation)
		projection, err := codingClaimFromAcceptedCreate(&other, scope.operation, now)
		if err != nil || projection.AllocationID == claim.AllocationID {
			t.Fatalf("cross-scope allocation alias = %#v, %v", projection, err)
		}
	}
}

func TestCodingClaimRejectsMissingMixedAndStaleLedger(t *testing.T) {
	now := time.Date(2026, time.October, 5, 0, 0, 0, 0, time.UTC)
	mutations := map[string]func(*lifecyclerepository.State){
		"missing operation": func(s *lifecyclerepository.State) { delete(s.Operations, "operation-1") },
		"running without ticket": func(s *lifecyclerepository.State) {
			op := s.Operations["operation-1"]
			op.State = lifecycle.OperationRunning
			s.Operations[op.ID] = op
		},
		"terminal operation": func(s *lifecyclerepository.State) {
			op := s.Operations["operation-1"]
			op.State = lifecycle.OperationSucceeded
			s.Operations[op.ID] = op
		},
		"cancelled": func(s *lifecyclerepository.State) {
			op := s.Operations["operation-1"]
			op.CancelRequested = true
			s.Operations[op.ID] = op
		},
		"expired": func(s *lifecyclerepository.State) {
			op := s.Operations["operation-1"]
			op.Deadline = now
			s.Operations[op.ID] = op
		},
		"attempt drift": func(s *lifecyclerepository.State) {
			op := s.Operations["operation-1"]
			op.AttemptID = "other-attempt"
			s.Operations[op.ID] = op
		},
		"request drift": func(s *lifecyclerepository.State) {
			op := s.Operations["operation-1"]
			op.RequestDigest = codingTestDigest("b")
			s.Operations[op.ID] = op
		},
		"missing accepted request": func(s *lifecyclerepository.State) { clear(s.Idempotency) },
		"ambiguous accepted request": func(s *lifecyclerepository.State) {
			for _, record := range s.Idempotency {
				record.Scope = "revision-1\x00idempotency-2"
				record.Key = "idempotency-2"
				s.Idempotency[record.Scope] = record
				break
			}
		},
		"wrong request digest": func(s *lifecyclerepository.State) {
			for key, record := range s.Idempotency {
				record.RequestDigest = "bad"
				s.Idempotency[key] = record
			}
		},
		"wrong request scope": func(s *lifecyclerepository.State) {
			for key, record := range s.Idempotency {
				delete(s.Idempotency, key)
				record.Scope = "revision-2\x00idempotency-1"
				s.Idempotency[record.Scope] = record
			}
		},
		"fence advanced": func(s *lifecyclerepository.State) { s.Fencing["revision-1\x00sandbox-1"]++ },
		"generation advanced": func(s *lifecyclerepository.State) {
			sandbox := s.Sandboxes["sandbox-1"]
			sandbox.Generation++
			s.Sandboxes[sandbox.ID] = sandbox
		},
		"provisioning without ticket": func(s *lifecyclerepository.State) {
			sandbox := s.Sandboxes["sandbox-1"]
			sandbox.ObservedState = lifecycle.ObservedProvisioning
			s.Sandboxes[sandbox.ID] = sandbox
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			state := testCodingAcceptedCreate(t, now, "revision-1", "tenant-1", "sandbox-1", "operation-1")
			mutate(&state)
			if _, err := codingClaimFromAcceptedCreate(&state, "operation-1", now); !errors.Is(err, codingidentity.ErrConflict) {
				t.Fatalf("invalid accepted-create ledger admitted: %v", err)
			}
		})
	}
}
