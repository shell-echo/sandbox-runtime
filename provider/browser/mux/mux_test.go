package mux

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

type fakeAuthority struct {
	revoked  atomic.Bool
	receipts map[string]browser.AllocationReceipt
}

func (a *fakeAuthority) Ready(context.Context) error {
	if a.revoked.Load() {
		return ErrUnavailable
	}
	return nil
}

func (a *fakeAuthority) Resolve(_ context.Context, open executorprotocol.Open) (browser.AllocationReceipt, error) {
	if a.revoked.Load() || open.TenantBindingDigest != browserbinding.Prefix+strings.Repeat("a", 64) {
		return browser.AllocationReceipt{}, ErrUnavailable
	}
	receipt, ok := a.receipts[open.RuntimeSessionID]
	if !ok || receipt.SandboxID != open.SandboxID || receipt.BrowserSessionID != open.RuntimeSessionID ||
		receipt.ConnectionGeneration != open.ConnectionGeneration {
		return browser.AllocationReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (a *fakeAuthority) Claim(context.Context, executorprotocol.Open) error {
	if a.revoked.Load() {
		return ErrUnavailable
	}
	return nil
}

type fakeRuntime struct {
	mu      sync.Mutex
	targets []string
}

func (r *fakeRuntime) Ready(context.Context) error { return nil }

func (r *fakeRuntime) Attach(_ context.Context, receipt browser.AllocationReceipt) (browser.Stream, error) {
	r.mu.Lock()
	r.targets = append(r.targets, receipt.Reference)
	r.mu.Unlock()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		for {
			_, opcode, err := wsutil.ReadClientData(server)
			if err != nil || opcode != ws.OpText {
				return
			}
			if err := wsutil.WriteServerText(server, []byte(`{"target":"`+receipt.Reference+`"}`)); err != nil {
				return
			}
		}
	}()
	return &pipeStream{Conn: client}, nil
}

type pipeStream struct{ net.Conn }

func (s *pipeStream) Read(ctx context.Context, p []byte) (int, error) {
	stop := context.AfterFunc(ctx, func() { _ = s.SetReadDeadline(time.Now()) })
	defer func() { stop(); _ = s.SetReadDeadline(time.Time{}) }()
	return s.Conn.Read(p)
}

func (s *pipeStream) Write(ctx context.Context, p []byte) (int, error) {
	stop := context.AfterFunc(ctx, func() { _ = s.SetWriteDeadline(time.Now()) })
	defer func() { stop(); _ = s.SetWriteDeadline(time.Time{}) }()
	return s.Conn.Write(p)
}

func muxOpen(session, suffix string, now time.Time) executorprotocol.Open {
	open := executorprotocol.Open{Protocol: executorprotocol.ProtocolID, Role: executorprotocol.RoleBrowser,
		RequestID: "mux-request-" + suffix, TenantBindingDigest: browserbinding.Prefix + strings.Repeat("a", 64),
		ProviderRevisionID: "provider-revision-1", SandboxID: "sandbox-1", RuntimeSessionID: session,
		CapabilityProfileID: browser.CapabilityProfileID, MediaProfileID: "browser-cdp-v1", ControlProfileID: "browser-control-v1",
		HandoffReference: "ref:browser-session:" + strings.Repeat(suffix, 32), ConnectionGeneration: 1,
		ConnectionEpoch: "generation-1", Fence: strings.Repeat("b", 32),
		AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), HandoffExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Codec: "application/json"}
	open.HandoffDigest = executorprotocol.ReferenceDigest(open.HandoffReference)
	open.AuthorityDigest = open.CalculateAuthorityDigest()
	open.RequestDigest = open.CalculateRequestDigest()
	return open
}

func muxReceipt(session, suffix string, now time.Time) browser.AllocationReceipt {
	return browser.AllocationReceipt{Reference: "ref:browser/" + strings.Repeat(suffix, 32), SandboxID: "sandbox-1",
		BrowserSessionID: session, OperationID: "operation-" + suffix, AttemptID: "attempt-" + suffix,
		FencingToken: 1, ExpectedGeneration: 1, ConnectionGeneration: 1, AllocatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
}

func TestMuxBindsTwoOpaqueSessionsToDistinctCDPTargetsAndDrains(t *testing.T) {
	now := time.Now().UTC()
	path, layout := testSocket(t)
	authority := &fakeAuthority{receipts: map[string]browser.AllocationReceipt{
		"browser-one": muxReceipt("browser-one", "1", now), "browser-two": muxReceipt("browser-two", "2", now)}}
	runtime := &fakeRuntime{}
	m, err := New(Options{SocketPath: path, Layout: layout, AllowedPeerUID: uint32(os.Getuid()),
		MaxSessions: 2, OperationTimeout: time.Second, AuthorityPollInterval: 20 * time.Millisecond,
		Authority: authority, Runtime: runtime})
	if err != nil {
		t.Fatalf("%v (socket length=%d parent_valid=%t)", err, len(path), restrictedunix.ValidateParent(path, layout))
	}
	if m.Ready(context.Background()) == nil {
		t.Fatal("Browser mux was ready before its Unix listener started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- m.Startup(ctx) }()
	awaitSocket(t, path, layout)
	if err := m.Ready(context.Background()); err != nil {
		t.Fatalf("Browser mux readiness after start: %v", err)
	}
	client := unixHTTPClient(path)
	probe, err := client.Get("http://browser-mux/readyz")
	if err != nil || probe.StatusCode != http.StatusNoContent {
		t.Fatalf("Browser mux readiness = %#v, %v", probe, err)
	}
	probe.Body.Close()
	for _, entry := range []struct{ session, suffix string }{{"browser-one", "1"}, {"browser-two", "2"}} {
		open := muxOpen(entry.session, entry.suffix, now)
		connection, _, err := websocket.Dial(context.Background(), "ws://browser-mux/session", &websocket.DialOptions{
			HTTPClient: client, Subprotocols: []string{executorprotocol.ProtocolID}})
		if err != nil {
			t.Fatal(err)
		}
		document, _ := executorprotocol.Encode(open)
		if err := connection.Write(context.Background(), websocket.MessageText, document); err != nil {
			t.Fatal(err)
		}
		readCtx, stop := context.WithTimeout(context.Background(), time.Second)
		_, accepted, err := connection.Read(readCtx)
		stop()
		if err != nil || !strings.Contains(string(accepted), `"status":"accepted"`) {
			t.Fatalf("Browser mux accepted = %q, %v", accepted, err)
		}
		if err := connection.Write(context.Background(), websocket.MessageText, []byte(`{"id":1,"method":"Browser.getVersion"}`)); err != nil {
			t.Fatal(err)
		}
		readCtx, stop = context.WithTimeout(context.Background(), time.Second)
		_, response, err := connection.Read(readCtx)
		stop()
		if err != nil || string(response) != `{"target":"`+authority.receipts[entry.session].Reference+`"}` {
			t.Fatalf("Browser mux target = %q, %v", response, err)
		}
		if entry.session == "browser-one" {
			authority.revoked.Store(true)
			if m.Ready(context.Background()) == nil {
				t.Fatal("Browser mux remained ready after authority revocation")
			}
			readCtx, stop = context.WithTimeout(context.Background(), time.Second)
			_, _, err = connection.Read(readCtx)
			stop()
			if err == nil {
				t.Fatal("revoked Browser mux stream remained live")
			}
			authority.revoked.Store(false)
		}
		connection.CloseNow()
	}
	runtime.mu.Lock()
	if len(runtime.targets) != 2 || runtime.targets[0] == runtime.targets[1] {
		t.Fatalf("Browser mux target selection = %#v", runtime.targets)
	}
	runtime.mu.Unlock()
	cancel()
	shutdownCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := m.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	if m.Ready(context.Background()) == nil {
		t.Fatal("Browser mux remained ready after shutdown")
	}
	if err := <-served; !errors.Is(err, context.Canceled) {
		t.Fatalf("Browser mux serve = %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Browser mux socket retained: %v", err)
	}
}

func TestMuxReplayClaimsAreBoundedAndDoNotEvictLiveClaims(t *testing.T) {
	now := time.Now().UTC()
	m := &Mux{replayed: make(map[string]time.Time)}
	for index := range maxReplayClaims {
		if !m.claim("request-"+strconv.Itoa(index), now, now.Add(time.Minute)) {
			t.Fatalf("claim %d unexpectedly denied", index)
		}
	}
	if m.claim("overflow", now, now.Add(time.Minute)) || m.claim("request-0", now, now.Add(time.Minute)) ||
		len(m.replayed) != maxReplayClaims {
		t.Fatal("Browser mux replay capacity evicted a live claim or grew without bound")
	}
	if !m.claim("after-expiry", now.Add(2*time.Minute), now.Add(3*time.Minute)) || len(m.replayed) != 1 {
		t.Fatal("Browser mux did not reclaim only expired replay claims")
	}
}

func testSocket(t *testing.T) (string, restrictedunix.Layout) {
	t.Helper()
	realTemp, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.MkdirTemp(realTemp, "bm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(parent) })
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}
	owner := info.Sys().(*syscall.Stat_t)
	return filepath.Join(parent, "browser-mux-"+strings.Repeat("a", 32)+".sock"), restrictedunix.Layout{
		DirectoryMode: 0o700, SocketMode: 0o600, OwnerUID: uint32(os.Getuid()), DirectoryGID: owner.Gid}
}

func awaitSocket(t *testing.T, path string, layout restrictedunix.Layout) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if restrictedunix.ValidateSocket(path, layout) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("Browser mux socket did not become ready")
}

func unixHTTPClient(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUnavailable }}
}
