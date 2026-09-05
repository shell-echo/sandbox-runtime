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

func TestAuditRecorderSanitizesRevocationUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writer, err := newEvidenceWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	secret := "redis://credential@private-store:6379/ref:browser-session:secret/grant-secret"
	if err := (&auditRecorder{writer: writer}).Record(context.Background(), gateway.AuditEvent{
		Type: gateway.AuditRevocationUnavailable, At: time.Date(2026, 9, 5, 1, 2, 3, 4, time.UTC),
		GrantID: secret, CallerID: secret, TenantID: secret, SandboxID: secret,
		BrowserSessionID: secret, Reason: secret,
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
	if strings.Contains(string(content), secret) || strings.Contains(string(content), "redis://") {
		t.Fatalf("audit leaked sensitive input: %s", content)
	}
	var record map[string]any
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatal(err)
	}
	if len(record) != 7 || record["sequence"] != float64(1) || record["type"] != "revocation_unavailable" || record["reason_code"] != "revocation_unavailable" {
		t.Fatalf("audit record = %#v", record)
	}
}

func TestEvidenceWriterRetainsMonotonicSequenceAcrossGatewayRestart(t *testing.T) {
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

func TestAuditRecorderRejectsUnknownType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writer, err := newEvidenceWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&auditRecorder{writer: writer}).Record(context.Background(), gateway.AuditEvent{Type: "private-diagnostic"}); err == nil {
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
