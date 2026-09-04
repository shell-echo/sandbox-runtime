package orchestrator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/caller"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestImageDigestFromReference(t *testing.T) {
	imageID := "sha256:" + strings.Repeat("a", 64)
	gotDigest, err := imageDigestFromReference("example.invalid/reference:local@" + imageID)
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != imageID {
		t.Fatalf("digest = %q, want %q", gotDigest, imageID)
	}
	gotDigest, err = imageDigestFromReference(imageID)
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != imageID {
		t.Fatalf("raw digest = %q, want %q", gotDigest, imageID)
	}
}

func TestSelectCallerDefaultsToReference(t *testing.T) {
	kind, binary, packagePath, boundary, err := selectCaller("")
	if err != nil {
		t.Fatal(err)
	}
	if kind != CallerReference || binary != "caller" || packagePath != "./cmd/caller" || !strings.Contains(boundary, "reference external-caller") {
		t.Fatalf("selection = %q, %q, %q, %q", kind, binary, packagePath, boundary)
	}
}

func TestSelectCallerPlatformCandidateIsExplicit(t *testing.T) {
	kind, binary, packagePath, boundary, err := selectCaller(CallerPlatformCandidate)
	if err != nil {
		t.Fatal(err)
	}
	if kind != CallerPlatformCandidate || binary != "platform-caller" || packagePath != "./cmd/platform-caller" || !strings.Contains(boundary, "Agent Platform candidate integration only") {
		t.Fatalf("selection = %q, %q, %q, %q", kind, binary, packagePath, boundary)
	}
}

func TestSelectCallerRejectsUnknownKind(t *testing.T) {
	if _, _, _, _, err := selectCaller(CallerKind("unknown")); err == nil {
		t.Fatal("unknown caller kind was accepted")
	}
}

func TestImageDigestFromReferenceRejectsInvalidInputs(t *testing.T) {
	for _, test := range []struct {
		name, reference string
	}{
		{name: "missing digest", reference: "example.invalid/reference:local"},
		{name: "wrong digest length", reference: "sha256:" + strings.Repeat("a", 63)},
		{name: "non-hex digest", reference: "sha256:" + strings.Repeat("g", 64)},
		{name: "empty digest", reference: "example.invalid/reference:local@"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := imageDigestFromReference(test.reference); err == nil {
				t.Fatal("accepted invalid image identity")
			}
		})
	}
}

func TestWaitForRegistryAcceptsHealthyV2Endpoint(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/v2/" {
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	if err := waitForRegistryWithClient(context.Background(), "127.0.0.1:5000", httpClient); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForRegistryHonorsContext(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := waitForRegistryWithClient(ctx, "127.0.0.1:5000", httpClient); err == nil {
		t.Fatal("healthy registry wait accepted an unavailable endpoint")
	}
}

func TestWaitForListenersWithinRejectsInvalidTimeout(t *testing.T) {
	child := &childProcess{done: make(chan struct{})}
	if err := waitForListenersWithin(context.Background(), child, 0); err == nil {
		t.Fatal("listener readiness accepted a non-positive timeout")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestCleanupRunRootRestoresDirectoryPermissions(t *testing.T) {
	temporaryRoot := t.TempDir()
	runRoot, err := os.MkdirTemp(temporaryRoot, runRootPrefix)
	if err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(runRoot, "runtime", "sandbox", "inputs")
	if err := os.MkdirAll(inputs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inputs, "terminal-broker"), []byte("binary"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(inputs, 0o555); err != nil {
		t.Fatal(err)
	}

	if err := cleanupRunRoot(temporaryRoot, runRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(runRoot); !os.IsNotExist(err) {
		t.Fatalf("run root still exists: %v", err)
	}
}

func TestCleanupRunRootRejectsUnrecognizedTarget(t *testing.T) {
	temporaryRoot := t.TempDir()
	target := filepath.Join(temporaryRoot, "unrelated")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := cleanupRunRoot(temporaryRoot, target); err == nil {
		t.Fatal("cleanup accepted an unrecognized target")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("rejected target was changed: %v", err)
	}
}

func TestAssertNoBrowserEdgeAuditEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "browser-gateway-audit.jsonl")
	events := []gateway.AuditEvent{
		{Type: gateway.AuditAuthorized, GrantID: "grant-browser-normal-1", BrowserSessionID: "browser-session-1"},
		{Type: gateway.AuditClientClosed, GrantID: "grant-browser-normal-1", BrowserSessionID: "browser-session-1"},
	}
	writeAudit := func(events []gateway.AuditEvent) {
		t.Helper()
		var content strings.Builder
		for _, event := range events {
			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			content.Write(encoded)
			content.WriteByte('\n')
		}
		if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeAudit(events)
	if err := assertNoBrowserEdgeAuditEvents(path); err != nil {
		t.Fatalf("ordinary audit rejected: %v", err)
	}
	events = append(events, gateway.AuditEvent{
		Type: gateway.AuditDenied, GrantID: caller.BrowserEdgeGrantPrefix + "burst-01", BrowserSessionID: "browser-session-1",
	})
	writeAudit(events)
	if err := assertNoBrowserEdgeAuditEvents(path); err == nil {
		t.Fatal("edge request was accepted in Gateway audit")
	}
	if err := os.WriteFile(path, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := assertNoBrowserEdgeAuditEvents(path); err == nil {
		t.Fatal("malformed Gateway audit was accepted")
	}
}
