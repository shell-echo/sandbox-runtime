package usage

import (
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	providerusage "github.com/shell-echo/sandbox-runtime/provider/usage"
)

func usageRecord(t *testing.T, now time.Time) desktop.Record {
	t.Helper()
	request := desktop.OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, IdempotencyKey: "key-1", RequestDigest: "sha256:" + strings.Repeat("a", 64), Deadline: now.Add(time.Hour), ExpectedGeneration: 1, DesktopSessionID: "desktop-session-1", CapabilityProfileID: desktop.CapabilityProfileID, ExpiresAt: now.Add(30 * time.Minute)}
	record, err := desktop.NewRecord(request, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt := desktop.AllocationReceipt{Reference: "ref:desktop/11111111111111111111111111111111", SandboxID: request.SandboxID, DesktopSessionID: request.DesktopSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: 1, ExpectedGeneration: 1, ConnectionGeneration: 1, AllocatedAt: now.Add(time.Second), ExpiresAt: request.ExpiresAt}
	record, err = desktop.AttachAllocation(record, receipt)
	if err != nil {
		t.Fatal(err)
	}
	record, err = desktop.Transition(record, desktop.StatusSucceeded, now.Add(2*time.Second), &desktop.EndpointEvidence{InternalEndpointReference: "ref:desktop-session:opaque-1", ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestBuildEvidenceStartsAtHandoffAndStopsAtEarliestTermination(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	record := usageRecord(t, now)
	endpointEnded := now.Add(5 * time.Second)
	evidence, err := BuildEvidenceWithStops(record, now.Add(time.Minute), StopTimes{EndpointTerminatedAt: &endpointEnded}, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	entry := evidence.Entries[0]
	if entry.Meter != providerusage.MeterDesktopSession || entry.Unit != "milliseconds" || entry.Quantity != 3_000 || !entry.OccurredAt.Equal(endpointEnded) {
		t.Fatalf("entry = %#v", entry)
	}
	if err := evidence.Validate(endpointEnded); err != nil {
		t.Fatal(err)
	}
	if evidence.ReconciliationStatus != providerusage.ReconciliationComplete {
		t.Fatalf("status = %q", evidence.ReconciliationStatus)
	}
}

func TestBuildEvidenceMarksOngoingSessionPartial(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	record := usageRecord(t, now)
	evidence, err := BuildEvidence(record, now.Add(10*time.Second), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if evidence.ReconciliationStatus != providerusage.ReconciliationPartial || evidence.Entries[0].Quantity != 8_000 {
		t.Fatalf("ongoing evidence = %#v", evidence)
	}
	endedBeforeStart := now.Add(time.Second)
	if _, err := BuildEvidenceWithStops(record, now.Add(10*time.Second), StopTimes{EndpointTerminatedAt: &endedBeforeStart}, now.Add(time.Hour)); err == nil {
		t.Fatal("pre-handoff termination was accepted")
	}
	futureEnd := now.Add(11 * time.Second)
	if _, err := BuildEvidenceWithStops(record, now.Add(10*time.Second), StopTimes{EndpointTerminatedAt: &futureEnd}, now.Add(time.Hour)); err == nil {
		t.Fatal("future termination was accepted")
	}
	observedEnd := now.Add(10 * time.Second)
	complete, err := BuildEvidenceWithStops(record, observedEnd, StopTimes{EndpointTerminatedAt: &observedEnd}, now.Add(time.Hour))
	if err != nil || complete.ReconciliationStatus != providerusage.ReconciliationComplete {
		t.Fatalf("termination at observation = %#v, %v", complete, err)
	}
}

func TestBuildEvidenceStopsAtDurableRevocation(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	record := usageRecord(t, now)
	revokedAt := now.Add(7 * time.Second)
	record.RevokedAt = &revokedAt
	evidence, err := BuildEvidence(record, now.Add(time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if evidence.ReconciliationStatus != providerusage.ReconciliationComplete ||
		evidence.Entries[0].Quantity != 5_000 || !evidence.ObservedAt.Equal(revokedAt) {
		t.Fatalf("revoked evidence = %#v", evidence)
	}
}

func TestBuildEvidenceClampsToExpiryAndRejectsPending(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	record := usageRecord(t, now)
	evidence, err := BuildEvidence(record, now.Add(time.Hour), now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.ObservedAt.Equal(record.Request.ExpiresAt) {
		t.Fatalf("observed at = %s", evidence.ObservedAt)
	}
	pending, err := desktop.NewRecord(record.Request, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildEvidence(pending, now.Add(time.Second), now.Add(time.Hour)); err == nil {
		t.Fatal("pending evidence succeeded")
	}
}
