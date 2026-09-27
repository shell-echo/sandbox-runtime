package cdpfence

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/browseringress"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func v2IngressOpenFixture(now time.Time) browseringress.Open {
	return browseringress.Open{
		Protocol: browseringress.ProtocolID, RequestID: "gateway-request-1",
		CapacityClaim: "v1.opaque-capacity-claim", TenantID: "tenant-1", SandboxID: "sandbox-1",
		BrowserSessionID: "browser-1", CapabilityProfileID: browserhandoffv2.CapabilityProfileID,
		ConnectionGeneration: 2, AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		HandoffReference: "ref:browser-session:" + strings.Repeat("a", 32),
		HandoffExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano),
		ProviderAudience: "browser-provider-1", ProviderRevisionID: "revision-1",
		TenantBindingDigest: browserbinding.Prefix + strings.Repeat("b", 64),
		GrantConnectionID:   "connection-1", ControlLeaseDigest: "sha256:" + strings.Repeat("c", 64),
		ControlFence: 7,
	}
}

func TestAdmittedBrowserProviderOpenIsStablePerAttemptAndSeparatesReconnect(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	open := v2IngressOpenFixture(now)
	first, err := admittedProviderOpen(open, now)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := admittedProviderOpen(open, now)
	if err != nil || duplicate != first {
		t.Fatalf("duplicate attempt minted another Provider identity: %+v, %v", duplicate, err)
	}
	reconnect := open
	reconnect.RequestID = "gateway-request-2"
	second, err := admittedProviderOpen(reconnect, now)
	if err != nil || second.ConnectionEpoch == first.ConnectionEpoch || second.RequestID == first.RequestID ||
		second.TenantBindingDigest != first.TenantBindingDigest || second.ControlLeaseDigest != first.ControlLeaseDigest {
		t.Fatalf("bounded reconnect identity: %+v, %v", second, err)
	}
	if first.CapabilityProfileID != browserhandoffv2.CapabilityProfileID || first.AuthorityDigest == "" || first.RequestDigest == "" {
		t.Fatal("Provider v2 binding incomplete")
	}
	encoded, _ := handoff.Encode(first)
	if strings.Contains(string(encoded), open.CapacityClaim) || strings.Contains(string(encoded), open.GrantConnectionID) {
		t.Fatal("capacity claim or Product grant ID leaked into Provider Open")
	}
}

type browserV2DialerSpy struct {
	mu       sync.Mutex
	seen     map[string]struct{}
	accepted []browserhandoffv2.OpenRequest
	streams  []*blockingStream
}

func (d *browserV2DialerSpy) Open(_ context.Context, open browserhandoffv2.OpenRequest) (gateway.Stream, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = make(map[string]struct{})
	}
	if _, replay := d.seen[open.ConnectionEpoch]; replay {
		return nil, gateway.ErrDownstreamUnavailable
	}
	d.seen[open.ConnectionEpoch] = struct{}{}
	d.accepted = append(d.accepted, open)
	stream := newBlockingStream()
	d.streams = append(d.streams, stream)
	return stream, nil
}

func TestBrowserV2NetworkAdmitsBeforeProviderAndRejectsReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	var authorityMu sync.Mutex
	admissions := 0
	allowed := true
	ingress := newTestIngress(t, Options{Authority: authorityFunc(func(_ context.Context, _ gateway.DownstreamFenceSubject, _ gateway.DownstreamFence, _ time.Duration) (gateway.DownstreamFenceDecision, error) {
		authorityMu.Lock()
		defer authorityMu.Unlock()
		admissions++
		if !allowed {
			return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
		}
		return gateway.DownstreamFenceDecision{Activated: admissions == 1}, nil
	})})
	dialer := &browserV2DialerSpy{}
	server := httptest.NewUnstartedServer(nil)
	handler, err := NewV2NetworkHandler(V2NetworkOptions{Ingress: ingress, Provider: dialer,
		ExpectedHost: server.Listener.Addr().String(), ExpectedProviderAudience: "browser-provider-1",
		AllowInsecureHTTPForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.Start()
	defer server.Close()
	dial := func(open browseringress.Open) (browseringress.OpenResponse, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+BrowserActionV2Path,
			&websocket.DialOptions{Subprotocols: []string{browseringress.ProtocolID}})
		if err != nil {
			return browseringress.OpenResponse{}, err
		}
		defer conn.CloseNow()
		document, _ := handoff.Encode(open)
		if err := conn.Write(ctx, websocket.MessageText, document); err != nil {
			return browseringress.OpenResponse{}, err
		}
		kind, response, err := conn.Read(ctx)
		if err != nil || kind != websocket.MessageText {
			return browseringress.OpenResponse{}, errors.New("missing private response")
		}
		var result browseringress.OpenResponse
		if handoff.Decode(response, &result) != nil || result.Validate() != nil {
			return browseringress.OpenResponse{}, errors.New("invalid private response")
		}
		return result, nil
	}
	open := v2IngressOpenFixture(now)
	wrong := open
	wrong.ProviderAudience = "other-provider"
	response, err := dial(wrong)
	authorityMu.Lock()
	wrongAdmissions := admissions
	allowed = false
	authorityMu.Unlock()
	if err != nil || response.Status != browseringress.StatusRejected || wrongAdmissions != 0 {
		t.Fatalf("wrong audience reached authority: %+v, %v, admissions=%d", response, err, wrongAdmissions)
	}
	response, err = dial(open)
	dialer.mu.Lock()
	acceptedBeforeAdmission := len(dialer.accepted)
	dialer.mu.Unlock()
	if err != nil || response.Status != browseringress.StatusRejected || acceptedBeforeAdmission != 0 {
		t.Fatalf("denied capacity reached Provider: %+v, %v", response, err)
	}
	authorityMu.Lock()
	allowed = true
	authorityMu.Unlock()
	if response, err := dial(open); err != nil || response.Status != browseringress.StatusAccepted {
		t.Fatalf("admitted open: %+v, %v", response, err)
	}
	waitV2StreamClosed(t, dialer, 0)
	// A duplicate Gateway attempt has the same Provider epoch. The fake
	// models Provider's durable one-use reservation, including after close.
	if response, err := dial(open); err != nil || response.Status != browseringress.StatusRejected {
		t.Fatalf("duplicate attempt reattached: %+v, %v", response, err)
	}
	reconnect := open
	reconnect.RequestID = "gateway-request-2"
	if response, err := dial(reconnect); err != nil || response.Status != browseringress.StatusAccepted {
		t.Fatalf("new admitted internal attempt: %+v, %v", response, err)
	}
	waitV2StreamClosed(t, dialer, 1)
}

func waitV2StreamClosed(t *testing.T, dialer *browserV2DialerSpy, index int) {
	t.Helper()
	dialer.mu.Lock()
	if len(dialer.streams) <= index {
		dialer.mu.Unlock()
		t.Fatal("Provider stream not opened")
	}
	closed := dialer.streams[index].closed
	dialer.mu.Unlock()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Provider stream not closed after Gateway disconnect")
	}
}

func TestBrowserV2NetworkBoundsPendingAndActiveConnections(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ingress := newTestIngress(t, Options{MaxSessions: 1, Authority: authorityFunc(func(_ context.Context, _ gateway.DownstreamFenceSubject, _ gateway.DownstreamFence, _ time.Duration) (gateway.DownstreamFenceDecision, error) {
		return gateway.DownstreamFenceDecision{Activated: true}, nil
	})})
	dialer := &browserV2DialerSpy{}
	server := httptest.NewUnstartedServer(nil)
	handler, err := NewV2NetworkHandler(V2NetworkOptions{Ingress: ingress, Provider: dialer,
		ExpectedHost: server.Listener.Addr().String(), ExpectedProviderAudience: "browser-provider-1",
		AllowInsecureHTTPForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.Start()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	origin := "ws" + strings.TrimPrefix(server.URL, "http") + BrowserActionV2Path
	first, _, err := websocket.Dial(ctx, origin, &websocket.DialOptions{Subprotocols: []string{browseringress.ProtocolID}})
	if err != nil {
		t.Fatal(err)
	}
	defer first.CloseNow()
	document, _ := handoff.Encode(v2IngressOpenFixture(now))
	if err := first.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	_, responseDocument, err := first.Read(ctx)
	var response browseringress.OpenResponse
	if err != nil || handoff.Decode(responseDocument, &response) != nil || response.Status != browseringress.StatusAccepted {
		t.Fatalf("first admission: %+v, %v", response, err)
	}
	second, httpResponse, err := websocket.Dial(ctx, origin, &websocket.DialOptions{Subprotocols: []string{browseringress.ProtocolID}})
	if second != nil {
		_ = second.CloseNow()
	}
	if err == nil || httpResponse == nil || httpResponse.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("capacity allowed a second pending socket: response=%v err=%v", httpResponse, err)
	}
	_ = first.CloseNow()
	waitV2StreamClosed(t, dialer, 0)
}

func TestBrowserV2NetworkMakesActionAuthorityLossTerminal(t *testing.T) {
	for name, failure := range map[string]struct {
		err  error
		code websocket.StatusCode
	}{
		"fence lost":          {gateway.ErrDownstreamFenceLost, BrowserActionFenceLostCloseCode},
		"witness unavailable": {gateway.ErrDownstreamUnavailable, BrowserActionUnavailableCloseCode},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			ingress := newTestIngress(t, Options{Authority: authorityFunc(func(_ context.Context, _ gateway.DownstreamFenceSubject, _ gateway.DownstreamFence, _ time.Duration) (gateway.DownstreamFenceDecision, error) {
				calls++
				if calls == 1 {
					return gateway.DownstreamFenceDecision{Activated: true}, nil
				}
				return gateway.DownstreamFenceDecision{}, failure.err
			})})
			server := httptest.NewUnstartedServer(nil)
			handler, err := NewV2NetworkHandler(V2NetworkOptions{Ingress: ingress,
				Provider: &browserV2DialerSpy{}, ExpectedHost: server.Listener.Addr().String(),
				ExpectedProviderAudience: "browser-provider-1", AllowInsecureHTTPForTests: true})
			if err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = handler
			server.Start()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+BrowserActionV2Path,
				&websocket.DialOptions{Subprotocols: []string{browseringress.ProtocolID}})
			if err != nil {
				t.Fatal(err)
			}
			defer connection.CloseNow()
			document, _ := handoff.Encode(v2IngressOpenFixture(time.Now().UTC().Truncate(time.Second)))
			if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
				t.Fatal(err)
			}
			_, acceptedDocument, err := connection.Read(ctx)
			var accepted browseringress.OpenResponse
			if err != nil || handoff.Decode(acceptedDocument, &accepted) != nil || accepted.Status != browseringress.StatusAccepted {
				t.Fatalf("initial attach: %+v, %v", accepted, err)
			}
			if err := connection.Write(ctx, websocket.MessageText, []byte(`{"id":1,"method":"Runtime.evaluate"}`)); err != nil {
				t.Fatal(err)
			}
			_, _, err = connection.Read(ctx)
			if websocket.CloseStatus(err) != failure.code {
				t.Fatalf("authority loss was an ordinary close: %v", err)
			}
		})
	}
}
