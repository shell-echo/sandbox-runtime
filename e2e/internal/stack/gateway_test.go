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

func TestReferenceGatewayAuthorizationBindsCallerAndTenant(t *testing.T) {
	t.Parallel()
	principal := GatewayPrincipal{Token: "token-a", CallerID: "caller-a", TenantID: "tenant-a"}
	reference := &referenceGateway{principals: map[string]GatewayPrincipal{principal.Token: principal}}
	expiresAt := time.Now().UTC().Add(time.Minute)
	ctx := context.WithValue(context.Background(), principalContextKey{}, principal)
	ctx = context.WithValue(ctx, grantContextKey{}, grantInput{GrantID: "grant-1", ConnectionGeneration: 1, ExpiresAt: expiresAt})
	request := gateway.ConnectRequest{
		CallerID: principal.CallerID, TenantID: principal.TenantID, SandboxID: "sandbox-1",
		RuntimeSessionID: "session-1", CapabilityProfileID: "terminal-v1", HandoffReference: "ref:session:opaque-1",
	}
	grant, err := reference.Authorize(ctx, request)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if grant.CallerID != principal.CallerID || grant.TenantID != principal.TenantID || grant.ConnectionGeneration != 1 {
		t.Fatalf("Authorize() grant = %#v", grant)
	}

	request.TenantID = "tenant-b"
	if _, err := reference.Authorize(ctx, request); err == nil {
		t.Fatal("Authorize() accepted a cross-tenant request")
	}
}

func TestJSONLRecorderPersistsMetadataOnlyEvent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "gateway.jsonl")
	recorder, err := newJSONLRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	event := gateway.AuditEvent{Type: gateway.AuditConnected, At: time.Now().UTC(), GrantID: "grant-1", TenantID: "tenant-a", Frames: 2, Bytes: 12}
	if err := recorder.Record(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded gateway.AuditEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(content))), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Type != event.Type || decoded.TenantID != event.TenantID || decoded.Frames != event.Frames {
		t.Fatalf("recorded event = %#v", decoded)
	}
	for _, forbidden := range []string{"payload", "endpoint", "credential", "token"} {
		if strings.Contains(strings.ToLower(string(content)), forbidden) {
			t.Fatalf("audit contains forbidden field %q: %s", forbidden, content)
		}
	}
}
