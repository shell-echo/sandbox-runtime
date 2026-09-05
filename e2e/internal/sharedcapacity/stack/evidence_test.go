package stack

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestAuditRecorderWritesOnlyBoundedMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writer, err := newEvidenceWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &auditRecorder{writer: writer}
	secret := "raw-secret-identity-and-endpoint"
	if err := recorder.Record(context.Background(), gateway.AuditEvent{
		Type: gateway.AuditCapacityUnavailable, At: time.Date(2026, 9, 5, 1, 2, 3, 4, time.UTC),
		GrantID: secret, CallerID: secret, TenantID: secret, SandboxID: secret,
		BrowserSessionID: secret, Reason: secret, Attempt: 2, Frames: 3, Bytes: 4,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), secret) {
		t.Fatalf("audit leaked raw data: %s", content)
	}
	var record map[string]any
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatal(err)
	}
	if len(record) != 7 || record["sequence"] != float64(1) || record["reason_code"] != "capacity_unavailable" {
		t.Fatalf("audit record = %#v", record)
	}
}

func TestEvidenceWriterContinuesSequenceAcrossProcessReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.jsonl")
	first, err := newEvidenceWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&observationRecorder{writer: first}).record("resolve"); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := newEvidenceWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&observationRecorder{writer: second}).record("dial"); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "{\"sequence\":1,\"kind\":\"resolve\"}\n{\"sequence\":2,\"kind\":\"dial\"}\n" {
		t.Fatalf("observation evidence = %q", content)
	}
}

func TestAuditRecorderRejectsUnknownTypeWithoutWritingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writer, err := newEvidenceWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&auditRecorder{writer: writer}).Record(context.Background(), gateway.AuditEvent{Type: "raw-secret"}); err == nil {
		t.Fatal("Record() accepted an unknown audit event")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 0 {
		t.Fatalf("unknown audit event was written: %q", content)
	}
}
