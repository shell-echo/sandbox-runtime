package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/durablerevocation/wire"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
)

func TestDurableControlRequestTimeoutTerminatesAmbiguousPipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX shell executable")
	}
	root := t.TempDir()
	fixture := filepath.Join(root, "blocking-control")
	if err := os.WriteFile(fixture, []byte("#!/bin/sh\nwhile IFS= read -r line; do while :; do :; done; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	process, err := startDurableControl("blocking", fixture, filepath.Join(root, "ignored.json"), filepath.Join(root, "process.log"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = process.request(ctx, wire.Command{Action: wire.ActionShutdown})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request error = %v, want deadline exceeded", err)
	}
	select {
	case <-process.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed-out durable control process was not terminated")
	}
	if _, err := process.request(context.Background(), wire.Command{Action: wire.ActionShutdown}); err == nil {
		t.Fatal("terminated durable control process accepted another request")
	}
}

func TestDecodeDurableResponseRejectsUnknownAndTrailingContent(t *testing.T) {
	valid := []byte(`{"version":1,"sequence":2,"ok":true,"outcome":"opened"}`)
	response, err := decodeDurableResponse(valid)
	if err != nil || response.Sequence != 2 {
		t.Fatalf("decode valid response = %#v, %v", response, err)
	}
	for _, content := range [][]byte{
		[]byte(`{"version":1,"sequence":2,"ok":true,"diagnostic":"secret"}`),
		[]byte(`{"version":1,"sequence":2,"ok":true} {}`),
	} {
		if _, err := decodeDurableResponse(content); err == nil {
			t.Fatalf("decodeDurableResponse(%s) succeeded", content)
		}
	}
}

func TestValidateDurableReportUsesAckToCloseMeasurements(t *testing.T) {
	report := wire.Report{EvidenceName: durableRevocationEvidenceName}
	for _, name := range lock.DurableRevocationScenarioNames() {
		report.Scenarios = append(report.Scenarios, wire.Scenario{
			Name: name, Status: "passed", DurationMillis: 25_000, GatewayProcesses: 2,
		})
	}
	report.Scenarios[0].Measurements = []wire.Measurement{
		{GatewayID: "a", AckToCloseMillis: 125},
		{GatewayID: "b", AckToCloseMillis: 175},
	}
	bounds := lock.DurableRevocationBounds{PropagationMillis: 2_000}
	if err := validateDurableReport(report, bounds); err != nil {
		t.Fatalf("valid report: %v", err)
	}
	report.Scenarios[0].Measurements[1].AckToCloseMillis = bounds.PropagationMillis + 1
	if err := validateDurableReport(report, bounds); err == nil {
		t.Fatal("report accepted an out-of-bound ack-to-close measurement")
	}
}

func TestValidateDurableEvidenceRecordsUsesExactSanitizedShapes(t *testing.T) {
	root := t.TempDir()
	writeTestEvidence(t, filepath.Join(root, "gateway-a-audit.jsonl"),
		`{"sequence":1,"type":"revocation_unavailable","timestamp":"2026-09-05T01:02:03Z","attempt":0,"frames":0,"bytes":0,"reason_code":"revocation_unavailable"}`+"\n")
	writeTestEvidence(t, filepath.Join(root, "gateway-b-audit.jsonl"),
		`{"sequence":1,"type":"revoked","timestamp":"2026-09-05T01:02:04Z","attempt":0,"frames":1,"bytes":2,"reason_code":"revoked"}`+"\n")
	for _, name := range []string{"gateway-a-observations.jsonl", "gateway-b-observations.jsonl"} {
		writeTestEvidence(t, filepath.Join(root, name),
			`{"sequence":1,"kind":"resolve"}`+"\n"+`{"sequence":2,"kind":"dial"}`+"\n")
	}
	writeTestEvidence(t, filepath.Join(root, "revoker-control.jsonl"),
		`{"sequence":1,"type":"revoke_committed","timestamp":"2026-09-05T01:02:03Z","duration_millis":2}`+"\n"+
			`{"sequence":2,"type":"revoke_committed","timestamp":"2026-09-05T01:02:04Z","duration_millis":3}`+"\n"+
			`{"sequence":3,"type":"revoke_committed","timestamp":"2026-09-05T01:02:05Z","duration_millis":4}`+"\n")
	if err := validateDurableEvidenceRecords(root,
		[]string{"gateway-a-audit.jsonl", "gateway-b-audit.jsonl"},
		[]string{"gateway-a-observations.jsonl", "gateway-b-observations.jsonl"},
		"revoker-control.jsonl"); err != nil {
		t.Fatalf("valid evidence: %v", err)
	}
	writeTestEvidence(t, filepath.Join(root, "gateway-a-audit.jsonl"),
		`{"sequence":1,"type":"revocation_unavailable","timestamp":"2026-09-05T01:02:03Z","attempt":0,"frames":0,"bytes":0,"reason_code":"revocation_unavailable","grant_id":"secret"}`+"\n")
	if _, err := readDurableAudit(filepath.Join(root, "gateway-a-audit.jsonl"), false); err == nil {
		t.Fatal("audit accepted a sensitive unknown field")
	}
}

func TestDurableRevocationIdentitiesShareOneAbsoluteExpiry(t *testing.T) {
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Nanosecond)
	principals, endpoints, bindings, sensitive, err := durableRevocationIdentities(expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(principals) != 2 || len(endpoints) != 2 || len(bindings) != 12 || len(sensitive) == 0 {
		t.Fatalf("identity counts = %d/%d/%d/%d", len(principals), len(endpoints), len(bindings), len(sensitive))
	}
	seen := make(map[string]bool)
	for _, binding := range bindings {
		if binding.ExpiresAt != expiresAt.Format(time.RFC3339Nano) || seen[binding.GrantID] {
			t.Fatalf("binding does not use one unique raw grant and shared expiry: %#v", binding)
		}
		seen[binding.GrantID] = true
	}
	if bindings[0].EndpointID != bindings[3].EndpointID || bindings[0].GrantID == bindings[3].GrantID {
		t.Fatal("same-session unaffected binding is not exact-grant scoped")
	}
}

func writeTestEvidence(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
