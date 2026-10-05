package codingcontrolprotocol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
)

func TestProjectLedgerStatusIsBoundToSealedOriginal(t *testing.T) {
	create, cleanup, _ := testWireAuthorities(t)
	plan := testWirePlan()
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	binding := dockercontrol.CodingReceiptBinding{Plan: plan,
		SpecBySlot: map[string]string{plan.Slots[0].ID: wireDigest("c"),
			plan.Slots[1].ID: wireDigest("c")},
		ProfileDigest: plan.ProfileDigest, DaemonDigest: wireDigest("6"),
		DaemonEnvironmentDigest: wireDigest("7"), EndpointScopeDigest: wireDigest("8"),
		RuntimePlatform: "linux/arm64/v8", ControlPolicyDigest: create.ControlPolicyDigest,
		PeerPrincipalDigest: plan.OwnerPrincipalDigest, PlanDigest: planDigest,
		Capacity: plan.Capacity}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	// Component-only fixture: no Docker resources are created here. A real
	// initializer must independently prove its physical namespace empty.
	ledger, err := dockercontrol.InitializeCodingReceiptLedger(t.Context(),
		filepath.Join(directory, "receipts.json"), binding,
		func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ledger.Close(); err != nil {
			t.Error(err)
		}
	})
	request := Request{Protocol: ProtocolID, Scope: ScopeCoding,
		Action: ActionStatus, Create: create}
	missing, err := ProjectLedgerStatus(ledger, request, create.PeerPrincipalDigest, time.Now())
	if err != nil || missing.Status != StatusNotFound || missing.ControlRevision != 0 ||
		missing.ControlStateDigest != "" {
		t.Fatalf("missing effect invented a Control state: %#v, %v", missing, err)
	}
	if _, err := ledger.DispatchCodingCreate(t.Context(), create,
		func(context.Context, dockercontrol.CodingCreateAuthority) error { return nil }); err != nil {
		t.Fatal(err)
	}
	unknown, err := ProjectLedgerStatus(ledger, request, create.PeerPrincipalDigest,
		create.ExpiresAt.Add(time.Second))
	if err != nil || unknown.Status != StatusUnknown || unknown.ControlRevision == 0 ||
		unknown.ControlStateDigest == "" || unknown.CompletionDigest != "" {
		t.Fatalf("expired historical status fabricated completion: %#v, %v", unknown, err)
	}
	cleanupBound := request
	cleanupBound.Cleanup = &cleanup
	if _, err := ProjectLedgerStatus(ledger, cleanupBound, create.PeerPrincipalDigest,
		cleanup.IssuedAt.Add(time.Second)); !errors.Is(err, ErrInvalidWire) {
		t.Fatalf("Unknown was promoted to cleanup-bound evidence: %v", err)
	}
	if _, err := ProjectLedgerStatus(ledger, request, wireDigest("0"), time.Now()); !errors.Is(err, ErrInvalidWire) {
		t.Fatalf("wrong authenticated peer read Control: %v", err)
	}
	mutated := request
	mutated.Create.ControlPolicyDigest = wireDigest("0")
	if _, err := ProjectLedgerStatus(ledger, mutated, create.PeerPrincipalDigest,
		time.Now()); !errors.Is(err, ErrInvalidWire) &&
		!errors.Is(err, dockercontrol.ErrInvalidAuthority) {
		t.Fatalf("altered original policy read Control: %v", err)
	}
}
