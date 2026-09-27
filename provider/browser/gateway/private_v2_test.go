package browsergateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

type v2Store struct {
	mu     sync.Mutex
	bound  browserhandoffv2.OpenRequest
	closed chan struct{}
	once   sync.Once
}

func (s *v2Store) BindConnectionWithOwnership(_ context.Context, open browserhandoffv2.OpenRequest, _ time.Time) (bool, error) {
	s.mu.Lock()
	created := s.bound == (browserhandoffv2.OpenRequest{})
	s.bound = open
	s.mu.Unlock()
	return created, nil
}
func (s *v2Store) CloseConnection(_ context.Context, ref, epoch, digest string) error {
	s.mu.Lock()
	match := s.bound.HandoffReference == ref && s.bound.ConnectionEpoch == epoch && s.bound.AuthorityDigest == digest
	s.mu.Unlock()
	if match {
		s.once.Do(func() { close(s.closed) })
	}
	return nil
}

type v2Resolver struct {
	store  *v2Store
	dialed chan struct{}
	once   sync.Once
}

func (r *v2Resolver) ResolveConnection(_ context.Context, open browserhandoffv2.OpenRequest) (reference.Endpoint, error) {
	r.store.mu.Lock()
	bound := r.store.bound
	r.store.mu.Unlock()
	if bound != open {
		return reference.Endpoint{}, reference.ErrStale
	}
	expires, _ := time.Parse(time.RFC3339Nano, open.HandoffExpiresAt)
	return reference.Endpoint{Reference: open.HandoffReference, SandboxID: open.SandboxID,
		BrowserSessionID: open.BrowserSessionID, CapabilityProfileID: open.CapabilityProfileID,
		ConnectionGeneration: open.ConnectionGeneration, TenantBindingDigest: open.TenantBindingDigest,
		ExpiresAt: expires, Dial: func(context.Context) (browser.Stream, error) {
			r.once.Do(func() { close(r.dialed) })
			return &v2Stream{}, nil
		}}, nil
}

type v2Stream struct{}

func (*v2Stream) Read(ctx context.Context, _ []byte) (int, error)      { <-ctx.Done(); return 0, ctx.Err() }
func (*v2Stream) Write(_ context.Context, payload []byte) (int, error) { return len(payload), nil }
func (*v2Stream) Close() error                                         { return nil }

func v2OpenFixture() browserhandoffv2.OpenRequest {
	now := time.Now().UTC()
	referenceID := "ref:browser-session:" + strings.Repeat("1", 32)
	open := browserhandoffv2.OpenRequest{BindingVersion: browserhandoffv2.BindingVersion,
		BindingIssuer: browserhandoffv2.BindingIssuer, Protocol: browserhandoffv2.ProtocolID,
		RequestID: "private-request-1", Resource: browserhandoffv2.ResourceBrowser,
		TenantBindingDigest: browserbinding.Prefix + strings.Repeat("b", 64),
		ProviderRevisionID:  "revision-1", SandboxID: "sandbox-1", BrowserSessionID: "browser-1",
		CapabilityProfileID: browser.CapabilityProfileID, MediaProfileID: browserhandoffv2.MediaProfileID,
		ControlProfileID: browserhandoffv2.ControlProfileID, HandoffReference: referenceID,
		HandoffDigest: browserhandoffv2.ReferenceDigest(referenceID), ConnectionGeneration: 1,
		ConnectionEpoch: "epoch-1", ControlLeaseDigest: "sha256:" + strings.Repeat("c", 64),
		ControlFence: 1, AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		HandoffExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano)}
	open.AuthorityDigest = browserhandoffv2.AuthorityDigest(open)
	open.RequestDigest = browserhandoffv2.RequestDigest(open)
	return open
}

func TestV2PrivateRouteExactPeerAndCleanup(t *testing.T) {
	peerURI, _ := url.Parse("spiffe://sandbox.test/browser-action-ingress")
	leaf := &x509.Certificate{URIs: []*url.URL{peerURI}}
	tlsState := &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	if !exactV2Peer(tlsState, peerURI.String()) {
		t.Fatal("exact verified peer rejected")
	}
	for _, invalid := range []*tls.ConnectionState{
		nil,
		{HandshakeComplete: true, Version: tls.VersionTLS12, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}},
		{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}},
		{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{{Scheme: "spiffe", Host: "other.test", Path: "/browser-action-ingress"}}}}, VerifiedChains: [][]*x509.Certificate{{leaf}}},
	} {
		if exactV2Peer(invalid, peerURI.String()) {
			t.Fatal("wrong or unverified peer accepted")
		}
	}
	store := &v2Store{closed: make(chan struct{})}
	resolver := &v2Resolver{store: store, dialed: make(chan struct{})}
	handler, err := NewV2(V2Options{Resolver: resolver, Store: store, ExpectedPeerURI: peerURI.String(),
		ExpectedHost: "provider.test", MaxSessions: 1, OperationTimeout: time.Second,
		AuthorityPollInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.TLS = tlsState // Component-only transport fixture; process gate must use real mTLS.
		request.Host = "provider.test"
		handler.ServeHTTP(writer, request)
	}))
	defer server.Close()
	open := v2OpenFixture()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + PrivateV2Path
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, response, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{browserhandoffv2.ProtocolID}})
	if err != nil {
		t.Fatalf("v2 private dial: %v response=%v", err, response)
	}
	document, _ := handoff.Encode(open)
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	kind, accepted, err := connection.Read(ctx)
	var result browserhandoffv2.OpenResponse
	if err != nil || kind != websocket.MessageText || handoff.Decode(accepted, &result) != nil ||
		result.Validate() != nil || result.Status != browserhandoffv2.StatusAccepted || result.RequestID != open.RequestID {
		t.Fatalf("v2 private accept: %s, %v", accepted, err)
	}
	<-resolver.dialed
	_ = connection.CloseNow()
	select {
	case <-store.closed:
	case <-ctx.Done():
		t.Fatal("accepted v2 connection did not close its exact Provider claim")
	}
	for _, path := range []string{"/private/browser/v1/session", PrivateV2Path + "?fallback=1"} {
		request := httptest.NewRequest(http.MethodGet, "http://provider.test"+path, nil)
		request.TLS = tlsState
		request.Header.Set("Sec-WebSocket-Protocol", browserhandoffv2.ProtocolID)
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Code != http.StatusForbidden {
			t.Fatalf("alternate private route %q status=%d", path, writer.Code)
		}
	}
	duplicate := httptest.NewRequest(http.MethodGet, "http://provider.test"+PrivateV2Path, nil)
	duplicate.TLS = tlsState
	duplicate.Header.Add("Sec-WebSocket-Protocol", browserhandoffv2.ProtocolID)
	duplicate.Header.Add("Sec-WebSocket-Protocol", browserhandoffv2.ProtocolID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, duplicate)
	if w.Code != http.StatusForbidden {
		t.Fatal("duplicate private subprotocol header admitted")
	}
	wrongPeer := httptest.NewRequest(http.MethodGet, "http://provider.test"+PrivateV2Path, nil)
	wrongPeer.Header.Set("Sec-WebSocket-Protocol", browserhandoffv2.ProtocolID)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, wrongPeer)
	if w.Code != http.StatusForbidden {
		t.Fatal("missing verified mTLS peer admitted")
	}
}
