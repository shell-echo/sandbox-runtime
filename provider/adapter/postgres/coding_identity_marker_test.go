package providerpostgres

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

func TestCodingMarkerFreezesAtomicModeWithoutChangingLegacyReader(t *testing.T) {
	if codingidentity.MaxOriginalCreateEnvelopes != dockercontrol.MaxRetainedReceipts ||
		codingidentity.MaxOriginalCreateBytes != dockercontrol.MaxAuthorityBytes {
		t.Fatal("Provider original-envelope capacity drifted from Control receipt ledger")
	}
	planDigest := codingTestDigest("a")
	policyDigest := codingTestDigest("b")
	legacy := codingIdentityMarker{Initialized: true, PlanDigest: planDigest}
	atomic := codingIdentityMarker{Initialized: true, PlanDigest: planDigest,
		AuthorityMode: codingAtomicOriginalMode, ControlPolicyDigest: policyDigest}
	for _, marker := range []codingIdentityMarker{legacy, atomic} {
		document, err := json.Marshal(marker)
		if err != nil {
			t.Fatal(err)
		}
		var decoded codingIdentityMarker
		if err := importCodingIdentityMarker(&decoded, document); err != nil || decoded != marker {
			t.Fatalf("exact Coding marker rejected: %#v, %v", decoded, err)
		}
		if marker == legacy {
			var browserDesktop identityMarker
			if err := importIdentityMarker(&browserDesktop, document); err != nil ||
				browserDesktop.PlanDigest != planDigest {
				t.Fatalf("legacy Browser/Desktop marker compatibility changed: %#v, %v",
					browserDesktop, err)
			}
		} else {
			var browserDesktop identityMarker
			if err := importIdentityMarker(&browserDesktop, document); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("old reader silently ignored v3 mode: %v", err)
			}
		}
	}
	if legacy.matchesAtomic(planDigest, policyDigest) ||
		!atomic.matchesAtomic(planDigest, policyDigest) ||
		atomic.matchesAtomic(planDigest, codingTestDigest("c")) {
		t.Fatal("Coding execution mode was inferred from local constructor")
	}
	for _, document := range [][]byte{
		[]byte(`{"initialized":true,"plan_digest":"` + planDigest + `","authority_mode":"future"}`),
		[]byte(`{"initialized":true,"plan_digest":"` + planDigest + `","authority_mode":"` + codingAtomicOriginalMode + `"}`),
		[]byte(`{"initialized":true,"plan_digest":"` + planDigest + `","control_policy_digest":"` + policyDigest + `"}`),
		[]byte(`{"initialized":false,"plan_digest":"","authority_mode":"` + codingAtomicOriginalMode + `","control_policy_digest":"` + policyDigest + `"}`),
		[]byte(`{"initialized":true,"plan_digest":"` + planDigest + `","docker_socket":"/var/run/docker.sock"}`),
		[]byte(`{"initialized":true,"plan_digest":"` + planDigest + `","plan_digest":"` + planDigest + `"}`),
	} {
		var decoded codingIdentityMarker
		if err := importCodingIdentityMarker(&decoded, document); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("damaged Coding marker admitted: %s", document)
		}
	}
}

func TestCodingAtomicMarkerRequiresOriginalForEveryLiveReservation(t *testing.T) {
	fixture, input, now := testCodingReleasePGFixture(t, lifecycle.OperationSucceeded)
	planDigest, err := fixture.plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	marker := codingIdentityMarker{Initialized: true, PlanDigest: planDigest,
		AuthorityMode:       codingAtomicOriginalMode,
		ControlPolicyDigest: input.Create.ControlPolicyDigest}
	if err := checkCodingRetirementBarrierWithMarker(marker, fixture.slots,
		fixture.ledger, fixture.ledger, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("v3 Cleaning without original passed generic guard: %v", err)
	}
	document, err := dockercontrol.EncodeCodingCreateAuthority(input.Create)
	if err != nil {
		t.Fatal(err)
	}
	fixture.slots.OriginalCreates = map[string]codingidentity.OriginalCreateEnvelope{
		input.Create.AllocationID: {Document: string(document), Digest: input.Create.Digest()},
	}
	legacy := codingIdentityMarker{Initialized: true, PlanDigest: planDigest}
	if err := checkCodingRetirementBarrierWithMarker(legacy, fixture.slots,
		fixture.ledger, fixture.ledger, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("legacy marker mixed with v3 originals passed: %v", err)
	}
	if err := checkCodingRetirementBarrierWithMarker(marker, fixture.slots,
		fixture.ledger, fixture.ledger, now); err != nil {
		t.Fatalf("exact original/retirement tuple rejected: %v", err)
	}
	wrongPolicy := marker
	wrongPolicy.ControlPolicyDigest = codingTestDigest("0")
	if err := checkCodingRetirementBarrierWithMarker(wrongPolicy, fixture.slots,
		fixture.ledger, fixture.ledger, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("v3 marker policy drift passed: %v", err)
	}
	bad := fixture.slots.Clone()
	record := bad.OriginalCreates[input.Create.AllocationID]
	record.Digest = codingTestDigest("0")
	bad.OriginalCreates[input.Create.AllocationID] = record
	if err := checkCodingRetirementBarrierWithMarker(marker, bad,
		fixture.ledger, fixture.ledger, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("damaged original passed generic guard: %v", err)
	}
}

func TestCodingRetirementFirstLeaseMutationWouldPassOrdinaryStateButNotBarrier(t *testing.T) {
	fixture, input, now := testCodingReleasePGFixture(t, lifecycle.OperationSucceeded)
	planDigest, err := fixture.plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	document, err := dockercontrol.EncodeCodingCreateAuthority(input.Create)
	if err != nil {
		t.Fatal(err)
	}
	fixture.slots.OriginalCreates = map[string]codingidentity.OriginalCreateEnvelope{
		input.Create.AllocationID: {Document: string(document), Digest: input.Create.Digest()},
	}
	marker := codingIdentityMarker{Initialized: true, PlanDigest: planDigest,
		AuthorityMode:       codingAtomicOriginalMode,
		ControlPolicyDigest: input.Create.ControlPolicyDigest}
	mutated := copyCodingBarrierLedger(t, fixture.ledger)
	lease := mutated.Leases[input.Create.SandboxID]
	lease.ExpiresAt = lease.ExpiresAt.Add(time.Minute)
	if err := mutated.ReplaceLease(lease, input.Cleanup.CleanupFence); err != nil {
		t.Fatalf("plain lifecycle mutation failed before retirement barrier: %v", err)
	}
	if err := checkCodingRetirementBarrierWithMarker(marker, fixture.slots,
		fixture.ledger, mutated, now); !errors.Is(err, lifecyclerepository.ErrRetirementBlocked) {
		t.Fatalf("retirement did not block otherwise-valid lease mutation: %v", err)
	}
}
