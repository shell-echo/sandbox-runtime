package providerpostgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

func TestCodingAtomicFirstPermitRetainsExactOriginalEnvelope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	plan := codingBoundTestPlan()
	slots, err := codingidentity.NewState(plan)
	if err != nil {
		t.Fatal(err)
	}
	ledger := testCodingAcceptedCreate(t, now, "revision-1", "tenant-1", "sandbox-1", "operation-1")
	deadline := now.Add(8 * time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	ticket, running, provisioning, authority, err := beginCodingFirstCreateWithAuthority(
		ctx, &slots, &ledger, plan, "operation-1", codingBoundSpecs(plan),
		codingTestDigest("f"), now)
	if err != nil || ticket.Status != codingidentity.Creating ||
		running.State != lifecycle.OperationRunning ||
		provisioning.ObservedState != lifecycle.ObservedProvisioning ||
		!authority.ExpiresAt.Equal(deadline) {
		t.Fatalf("atomic first permit/parent clamp: %#v %#v %v", ticket, authority, err)
	}
	record := slots.OriginalCreates[ticket.Claim.AllocationID]
	stored, err := decodeCodingOriginalCreate(record, now)
	if err != nil || stored != authority || record.Digest != authority.Digest() ||
		validateCodingOriginalCreate(slots, ledger, plan, authority, now) != nil {
		t.Fatalf("original envelope did not bind PG tuple: %#v %v", record, err)
	}
	if _, _, _, _, err := beginCodingFirstCreateWithAuthority(ctx, &slots, &ledger,
		plan, "operation-1", codingBoundSpecs(plan), codingTestDigest("f"), now); err == nil {
		t.Fatal("Running original create received a second first permit")
	}
	if decoded, err := decodeCodingOriginalCreate(record, authority.ExpiresAt.Add(time.Minute)); err != nil || decoded != authority || authority.Validate(authority.ExpiresAt) == nil {
		t.Fatalf("expired original was renewed or lost for historical status: %v", err)
	}
	clone := slots.Clone()
	changed := clone.OriginalCreates[ticket.Claim.AllocationID]
	changed.Digest = codingTestDigest("0")
	clone.OriginalCreates[ticket.Claim.AllocationID] = changed
	if slots.OriginalCreates[ticket.Claim.AllocationID] != record ||
		validateCodingOriginalCreate(clone, ledger, plan, authority, now) == nil {
		t.Fatal("clone aliased or accepted changed original digest")
	}
}

func TestCodingAtomicFirstPermitRejectsFullHistoricalLedger(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	plan := codingBoundTestPlan()
	slots, err := codingidentity.NewState(plan)
	if err != nil {
		t.Fatal(err)
	}
	ledger := testCodingAcceptedCreate(t, now, "revision-1", "tenant-1", "sandbox-1", "operation-1")
	slots.OriginalCreates = make(map[string]codingidentity.OriginalCreateEnvelope)
	for index := 0; index < codingidentity.MaxOriginalCreateEnvelopes; index++ {
		key := "codingalloc-" + fmt.Sprintf("%064x", index)
		slots.OriginalCreates[key] = codingidentity.OriginalCreateEnvelope{Document: `{}`, Digest: codingTestDigest("a")}
	}
	if _, _, _, _, err := beginCodingFirstCreateWithAuthority(t.Context(), &slots,
		&ledger, plan, "operation-1", codingBoundSpecs(plan), codingTestDigest("f"), now); !errors.Is(err, codingidentity.ErrInvalidState) ||
		ledger.Operations["operation-1"].State != lifecycle.OperationAccepted || len(slots.Reservations) != 0 {
		t.Fatalf("full history admitted first permit or changed ledger: %v", err)
	}
}

func codingBoundTestPlan() codingidentity.Plan {
	return codingidentity.Plan{Protocol: codingidentity.Protocol, Version: codingidentity.Version,
		ProfileDigest: codingTestDigest("a"), OwnerDeployment: "provider-runtime",
		OwnerPrincipalDigest: codingTestDigest("b"), Namespace: "provider-coding",
		ControllerID: "provider-coding-controller", Template: "coding-sandbox-runtime",
		TemplateDigest: codingTestDigest("c"), ImageDigest: codingTestDigest("d"),
		ImageConfigDigest: codingTestDigest("1"), NetworkMode: "none",
		Limits:   codingidentity.Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64},
		Capacity: codingidentity.LocalCandidateCapacity,
		Slots: []codingidentity.Slot{
			{ID: "coding-0000", WorkloadUID: 57000, WorkloadGID: 58000,
				InputsVolume: "coding-0000-inputs", WorkspaceVolume: "coding-0000-workspace", OutputsVolume: "coding-0000-outputs"},
			{ID: "coding-0001", WorkloadUID: 57001, WorkloadGID: 58001,
				InputsVolume: "coding-0001-inputs", WorkspaceVolume: "coding-0001-workspace", OutputsVolume: "coding-0001-outputs"},
		}}
}

func codingBoundSpecs(plan codingidentity.Plan) map[string]string {
	result := make(map[string]string, len(plan.Slots))
	for _, slot := range plan.Slots {
		result[slot.ID] = codingTestDigest("e")
	}
	return result
}

func TestCodingFirstCreateChangesSlotAndLedgerTogether(t *testing.T) {
	now := time.Date(2026, time.October, 5, 0, 0, 0, 0, time.UTC)
	plan := codingBoundTestPlan()
	slots, err := codingidentity.NewState(plan)
	if err != nil {
		t.Fatal(err)
	}
	ledger := testCodingAcceptedCreate(t, now, "revision-1", "tenant-1", "sandbox-1", "operation-1")
	ticket, running, provisioning, err := beginCodingFirstCreate(&slots, &ledger, plan, "operation-1", codingBoundSpecs(plan), now)
	if err != nil || ticket.Status != codingidentity.Creating || running.State != lifecycle.OperationRunning ||
		provisioning.ObservedState != lifecycle.ObservedProvisioning || len(slots.Reservations) != 1 {
		t.Fatalf("first permit = %#v, %#v, %#v, %v", ticket, running, provisioning, err)
	}
	storedOperation, err := ledger.GetOperation("operation-1")
	if err != nil || storedOperation.State != lifecycle.OperationRunning {
		t.Fatalf("running operation not recorded: %#v, %v", storedOperation, err)
	}
	storedSandbox, err := ledger.GetSandbox("sandbox-1")
	if err != nil || storedSandbox.ObservedState != lifecycle.ObservedProvisioning {
		t.Fatalf("provisioning sandbox not recorded: %#v, %v", storedSandbox, err)
	}
	events, err := ledger.ListEvents("sandbox-1", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "provisioning" ||
		events[0].OperationID != running.ID || events[0].FencingToken != running.FencingToken ||
		events[0].Generation != provisioning.Generation {
		t.Fatalf("first permit did not atomically record provisioning event: %#v", events)
	}
	if _, _, _, err := beginCodingFirstCreate(&slots, &ledger, plan, "operation-1", codingBoundSpecs(plan), now); !errors.Is(err, codingidentity.ErrConflict) {
		t.Fatalf("committed first permit replayed: %v", err)
	}
	restarted := lifecyclerepository.NewState()
	if err := restarted.Import(ledger.Export()); err != nil {
		t.Fatal(err)
	}
	restoredSlots := slots.Clone()
	if _, _, _, err := beginCodingFirstCreate(&restoredSlots, &restarted, plan, "operation-1", codingBoundSpecs(plan), now); !errors.Is(err, codingidentity.ErrConflict) ||
		len(restoredSlots.Reservations) != 1 || restoredSlots.Reservations[0] != ticket {
		t.Fatalf("restart replay reopened first permit: %v", err)
	}
}

func TestCodingFirstCreateRejectsBadPlanAndSpecBeforePermit(t *testing.T) {
	now := time.Date(2026, time.October, 5, 0, 0, 0, 0, time.UTC)
	plan := codingBoundTestPlan()
	slots, err := codingidentity.NewState(plan)
	if err != nil {
		t.Fatal(err)
	}
	ledger := testCodingAcceptedCreate(t, now, "revision-1", "tenant-1", "sandbox-1", "operation-1")
	badSpecs := codingBoundSpecs(plan)
	badSpecs[plan.Slots[0].ID] = "invalid"
	if _, _, _, err := beginCodingFirstCreate(&slots, &ledger, plan, "operation-1", badSpecs, now); !errors.Is(err, codingidentity.ErrInvalidPlan) {
		t.Fatalf("bad slot spec permitted: %v", err)
	}
	if len(slots.Reservations) != 0 || ledger.Operations["operation-1"].State != lifecycle.OperationAccepted {
		t.Fatal("failed admission mutated first-create authority")
	}
	wrongPlan := plan
	wrongPlan.ProfileDigest = codingTestDigest("f")
	if _, _, _, err := beginCodingFirstCreate(&slots, &ledger, wrongPlan, "operation-1", codingBoundSpecs(plan), now); !errors.Is(err, codingidentity.ErrInvalidState) {
		t.Fatalf("changed Profile permitted: %v", err)
	}
}
