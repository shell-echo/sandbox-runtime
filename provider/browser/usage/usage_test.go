package usage

import (
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
	providerusage "github.com/shell-echo/sandbox-runtime/provider/usage"
)

func usageRecord(t *testing.T, now time.Time) browser.Record {
	t.Helper()
	request := browser.OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, IdempotencyKey: "key-1", RequestDigest: "sha256:" + strings.Repeat("a", 64), Deadline: now.Add(time.Hour), ExpectedGeneration: 1, BrowserSessionID: "browser-session-1", CapabilityProfileID: browser.CapabilityProfileID, ExpiresAt: now.Add(30 * time.Minute)}
	record, err := browser.NewRecord(request, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt := browser.AllocationReceipt{Reference: "ref:browser/11111111111111111111111111111111", SandboxID: request.SandboxID, BrowserSessionID: request.BrowserSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: 1, ExpectedGeneration: 1, ConnectionGeneration: 1, AllocatedAt: now.Add(time.Second), ExpiresAt: request.ExpiresAt}
	record, err = browser.AttachAllocation(record, receipt)
	if err != nil {
		t.Fatal(err)
	}
	record, err = browser.Transition(record, browser.StatusSucceeded, now.Add(2*time.Second), &browser.EndpointEvidence{InternalEndpointReference: "ref:browser-session:opaque-1", ConnectionGeneration: 1})
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
	if entry.Meter != providerusage.MeterBrowserSession || entry.Unit != "milliseconds" || entry.Quantity != 3_000 || !entry.OccurredAt.Equal(endpointEnded) {
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
	pending, err := browser.NewRecord(record.Request, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildEvidence(pending, now.Add(time.Second), now.Add(time.Hour)); err == nil {
		t.Fatal("pending evidence succeeded")
	}
}
