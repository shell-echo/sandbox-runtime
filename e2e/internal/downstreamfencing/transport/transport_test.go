package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/wire"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/testenv"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/adapter"
	"github.com/shell-echo/sandbox-runtime/gateway/cdpfence"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserreference "github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

func TestResolverAndHandlerKeepResolveReadOnlyAndAcknowledgeCompletedAction(t *testing.T) {
	material, err := testenv.GeneratePKI(t.TempDir(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	roots := loadTestRoots(t, material.CAFile)
	ingressCertificate, err := tls.LoadX509KeyPair(material.IngressCertificateFile, material.IngressPrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	gatewayCertificate, err := tls.LoadX509KeyPair(material.GatewayA.CertificateFile, material.GatewayA.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := NewServerTLSConfig(ingressCertificate, roots, wire.GatewayARoleURI, wire.GatewayBRoleURI)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := NewClientTLSConfig(gatewayCertificate, roots, "localhost", wire.GatewayARoleURI)
	if err != nil {
		t.Fatal(err)
	}

	subject := gateway.DownstreamFenceSubject{
		TenantID: "tenant-1", SandboxID: "sandbox-1", BrowserSessionID: "browser-1",
		CapabilityProfileID: "browser-v1", ConnectionGeneration: 7,
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Truncate(time.Microsecond),
	}
	fence, err := gateway.NewDownstreamFence("v1.private_claim")
	if err != nil {
		t.Fatal(err)
	}
	browser := newControlledBrowserStream()
	providerExpiry := subject.ExpiresAt.Add(5 * time.Minute)
	providerResolver := &testProviderResolver{endpoint: browserreference.Endpoint{
		Reference: "ref:browser-session:opaque-1", SandboxID: subject.SandboxID,
		BrowserSessionID: subject.BrowserSessionID, CapabilityProfileID: subject.CapabilityProfileID,
		ConnectionGeneration: subject.ConnectionGeneration, ExpiresAt: providerExpiry,
		Dial: func(context.Context) (providerbrowser.Stream, error) { return browser, nil },
	}}
	authority := &testFenceAuthority{}
	ingress, err := cdpfence.New(cdpfence.Options{Authority: authority, MaxActionBytes: wire.MaxMessageBytes})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{
		Ingress: ingress, Resolver: providerResolver,
		GatewayRoles: []string{wire.GatewayARoleURI, wire.GatewayBRoleURI},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolveBodies := make(chan []byte, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == wire.ResolvePath {
			encoded, readErr := io.ReadAll(request.Body)
			if readErr == nil {
				resolveBodies <- append([]byte(nil), encoded...)
				request.Body = io.NopCloser(bytes.NewReader(encoded))
			}
		}
		handler.ServeHTTP(response, request)
	}))
	server.EnableHTTP2 = false
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	resolver, err := NewResolver(ResolverOptions{Address: server.Listener.Addr().String(), TLSConfig: clientTLS})
	if err != nil {
		t.Fatal(err)
	}
	redirect := httptest.NewRequest(http.MethodPost, "https://localhost/redirected", nil)
	request := httptest.NewRequest(http.MethodPost, "https://localhost/private", nil)
	if resolver.client.CheckRedirect == nil || !errors.Is(resolver.client.CheckRedirect(redirect, []*http.Request{request}), http.ErrUseLastResponse) {
		t.Fatal("private resolver does not reject redirects")
	}
	endpoint, err := resolver.ResolveFenced(t.Context(), providerResolver.endpoint.Reference, subject, fence)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case encoded := <-resolveBodies:
		if strings.Contains(string(encoded), fence.Opaque()) || strings.Contains(string(encoded), `"fence"`) || strings.Contains(string(encoded), `"subject"`) {
			t.Fatal("read-only resolution transmitted activation-only material")
		}
		if _, err := wire.DecodeResolutionRequest(encoded); err != nil {
			t.Fatalf("resolution request is not the strict bounded wire shape: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("private resolve request was not observed")
	}
	if !endpoint.ExpiresAt.Equal(providerExpiry) {
		t.Fatalf("resolved expiry = %s; want Provider expiry %s", endpoint.ExpiresAt, providerExpiry)
	}
	if calls := authority.Calls(); calls != 0 {
		t.Fatalf("read-only resolve made %d authority calls", calls)
	}
	if calls := providerResolver.Calls(); calls != 1 {
		t.Fatalf("Provider resolve calls after private resolve = %d", calls)
	}

	privateStream, err := endpoint.Dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer privateStream.Close()
	if calls := authority.Calls(); calls != 1 {
		t.Fatalf("activation authority calls = %d", calls)
	}
	if calls := providerResolver.Calls(); calls != 2 {
		t.Fatalf("Provider resolve calls after connect = %d", calls)
	}
	adapted, err := adapter.NewBrowserStream(privateStream, adapter.BrowserOptions{MaxFrameBytes: wire.MaxMessageBytes})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-privateStream.(*clientStream).done:
		t.Fatalf("private stream closed before first action: %v", privateStream.(*clientStream).terminalError())
	case <-time.After(25 * time.Millisecond):
	}

	sendDone := make(chan error, 1)
	payload := []byte(`{"id":1,"method":"Page.navigate"}`)
	go func() {
		sendDone <- adapted.Send(t.Context(), gateway.Frame{Type: gateway.TextFrame, Payload: payload})
	}()
	select {
	case err := <-sendDone:
		t.Fatalf("Send returned before downstream write was released: %v (authority=%d provider=%d terminal=%v browser=%v)", err, authority.Calls(), providerResolver.Calls(), privateStream.(*clientStream).terminalError(), browser.LastReadError())
	case <-time.After(75 * time.Millisecond):
	}
	close(browser.writeGate)
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Send did not return after downstream completion ACK")
	}
	written := browser.Written()
	innerPayload, operation, err := wsutil.ReadClientData(bytes.NewBuffer(written))
	if err != nil || operation != ws.OpText || !bytes.Equal(innerPayload, payload) {
		t.Fatalf("downstream action = %q, %v, %v", innerPayload, operation, err)
	}
	if calls := authority.Calls(); calls != 2 {
		t.Fatalf("activation plus action authority calls = %d", calls)
	}

	responsePayload := []byte(`{"id":1,"result":{"frameId":"frame-1"}}`)
	var responseWire bytes.Buffer
	if err := wsutil.WriteServerMessage(&responseWire, ws.OpText, responsePayload); err != nil {
		t.Fatal(err)
	}
	browser.responses <- responseWire.Bytes()
	receiveCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	frame, err := adapted.Receive(receiveCtx)
	if err != nil || frame.Type != gateway.TextFrame || !bytes.Equal(frame.Payload, responsePayload) {
		t.Fatalf("relayed response = %#v, %v", frame, err)
	}
	authority.SetError(gateway.ErrDownstreamFenceLost)
	if err := adapted.Send(t.Context(), gateway.Frame{Type: gateway.TextFrame, Payload: []byte(`{"id":2,"method":"Page.stopLoading"}`)}); !errors.Is(err, gateway.ErrDownstreamFenceLost) {
		t.Fatalf("active downstream-fence loss error = %v", err)
	}

	lowerFence, err := gateway.NewDownstreamFence("v1.lower_claim")
	if err != nil {
		t.Fatal(err)
	}
	lowerEndpoint, err := resolver.ResolveFenced(t.Context(), providerResolver.endpoint.Reference, subject, lowerFence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lowerEndpoint.Dial(t.Context()); !errors.Is(err, gateway.ErrDownstreamFenceLost) || strings.Contains(err.Error(), lowerFence.Opaque()) {
		t.Fatalf("lower-fence Dial() error = %v", err)
	}
}

func TestHandlerBoundsResolveAndRejectsTypedNilDependencies(t *testing.T) {
	ingress, err := cdpfence.New(cdpfence.Options{Authority: &testFenceAuthority{}})
	if err != nil {
		t.Fatal(err)
	}
	var typedNilResolver *testProviderResolver
	if _, err := NewHandler(HandlerOptions{
		Ingress: ingress, Resolver: typedNilResolver, GatewayRoles: []string{wire.GatewayARoleURI},
	}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("typed-nil resolver error = %v", err)
	}

	requestValue, err := wire.NewResolutionRequest("ref:browser-session:opaque-1")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := wire.EncodeResolutionRequest(requestValue)
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{resolver: blockingProviderResolver{}, resolveTimeout: 50 * time.Millisecond}
	request := httptest.NewRequest(http.MethodPost, wire.ResolvePath, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	response := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	started := time.Now()
	handler.serveResolve(response, request)
	if response.Code != http.StatusServiceUnavailable || time.Since(started) > time.Second {
		t.Fatalf("bounded resolve status=%d elapsed=%s", response.Code, time.Since(started))
	}

	var typedNilStream *controlledBrowserStream
	if _, err := adaptBrowserDownstream(typedNilStream, wire.MaxMessageBytes); !errors.Is(err, gateway.ErrDownstreamUnavailable) {
		t.Fatalf("typed-nil downstream error = %v", err)
	}
}

func TestResolveBodyReadIsBounded(t *testing.T) {
	handler := &Handler{resolver: blockingProviderResolver{}, resolveTimeout: 50 * time.Millisecond}
	finished := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		defer close(finished)
		handler.serveResolve(response, request)
	}))
	defer server.Close()
	connection, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, "POST "+wire.ResolvePath+" HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	select {
	case <-finished:
		if time.Since(started) > time.Second {
			t.Fatalf("slow body handler elapsed=%s", time.Since(started))
		}
	case <-time.After(time.Second):
		t.Fatal("slow body kept the resolve handler occupied past its budget")
	}
}

func TestActiveControlAndCloseMappingsAreBounded(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	started := time.Now()
	err := handleClientControl(context.Background(), server, &sync.Mutex{}, ws.Header{OpCode: ws.OpPing}, bytes.NewReader([]byte("ping")), 50*time.Millisecond)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("blocked Ping error=%v elapsed=%s", err, time.Since(started))
	}

	stream := &clientStream{}
	for reason, want := range map[string]error{
		"downstream fence lost":  gateway.ErrDownstreamFenceLost,
		"downstream unavailable": gateway.ErrDownstreamUnavailable,
	} {
		if err := stream.handleControl(ws.OpClose, ws.NewCloseFrameBody(ws.StatusInternalServerError, reason)); !errors.Is(err, want) {
			t.Fatalf("close reason %q error = %v, want %v", reason, err, want)
		}
	}
}

func TestHandlerRejectsSecretsInURLBeforeResolution(t *testing.T) {
	handler := &Handler{}
	for name, target := range map[string]string{
		"query":        wire.ResolvePath + "?fence=v1.secret",
		"encoded path": "/private/v1/browser/downstream-fence/%72esolve",
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest("POST", target, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("non-exact request status = %d", response.Code)
			}
		})
	}
}

func TestDeadlineCleanupWaitsForCancellationCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	var mu sync.Mutex
	var last time.Time
	cleanup := applyDeadlineContext(ctx, func(value time.Time) error {
		if !value.IsZero() {
			close(callbackStarted)
			<-releaseCallback
		}
		mu.Lock()
		last = value
		mu.Unlock()
		return nil
	})
	cancel()
	<-callbackStarted
	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("deadline cleanup returned before cancellation callback")
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseCallback)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deadline cleanup did not complete")
	}
	mu.Lock()
	defer mu.Unlock()
	if !last.IsZero() {
		t.Fatalf("deadline cleanup left stale deadline %s", last)
	}
}

func TestDecodeRawClientFrame(t *testing.T) {
	payload := []byte(`{"id":1,"method":"Page.navigate"}`)
	var encoded bytes.Buffer
	if err := wsutil.WriteClientMessage(&encoded, ws.OpText, payload); err != nil {
		t.Fatal(err)
	}
	operation, decoded, consumed, complete, err := decodeRawClientFrame(encoded.Bytes(), wire.MaxMessageBytes)
	if err != nil || !complete || consumed != encoded.Len() || operation != ws.OpText || !bytes.Equal(decoded, payload) {
		t.Fatalf("decodeRawClientFrame() = %v, %q, %d, %t, %v", operation, decoded, consumed, complete, err)
	}
	for split := 1; split < encoded.Len(); split++ {
		if _, _, _, complete, err := decodeRawClientFrame(encoded.Bytes()[:split], wire.MaxMessageBytes); err != nil || complete {
			t.Fatalf("split %d decoded partial frame: complete=%t error=%v", split, complete, err)
		}
	}
}

type testFenceAuthority struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (a *testFenceAuthority) AuthorizeAction(ctx context.Context, _ gateway.DownstreamFenceSubject, fence gateway.DownstreamFence, _ time.Duration) (gateway.DownstreamFenceDecision, error) {
	if err := ctx.Err(); err != nil {
		return gateway.DownstreamFenceDecision{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.err != nil {
		return gateway.DownstreamFenceDecision{}, a.err
	}
	if fence.Opaque() == "v1.lower_claim" {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamFenceLost
	}
	return gateway.DownstreamFenceDecision{Activated: a.calls == 1}, nil
}

func (a *testFenceAuthority) SetError(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.err = err
}

func (a *testFenceAuthority) Calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

type testProviderResolver struct {
	mu       sync.Mutex
	calls    int
	endpoint browserreference.Endpoint
}

type blockingProviderResolver struct{}

func (blockingProviderResolver) Resolve(ctx context.Context, _ string) (browserreference.Endpoint, error) {
	<-ctx.Done()
	return browserreference.Endpoint{}, ctx.Err()
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
}

func (r *deadlineRecorder) SetReadDeadline(time.Time) error { return nil }

func (r *testProviderResolver) Resolve(ctx context.Context, reference string) (browserreference.Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return browserreference.Endpoint{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if reference != r.endpoint.Reference {
		return browserreference.Endpoint{}, errors.New("unavailable")
	}
	return r.endpoint, nil
}

func (r *testProviderResolver) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type controlledBrowserStream struct {
	writeGate  chan struct{}
	responses  chan []byte
	closed     chan struct{}
	closeOnce  sync.Once
	writeMu    sync.Mutex
	written    bytes.Buffer
	readMu     sync.Mutex
	remaining  []byte
	readFailed chan error
}

func newControlledBrowserStream() *controlledBrowserStream {
	return &controlledBrowserStream{
		writeGate: make(chan struct{}), responses: make(chan []byte, 4), closed: make(chan struct{}), readFailed: make(chan error, 1),
	}
}

func (s *controlledBrowserStream) Write(ctx context.Context, value []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-s.closed:
		return 0, io.ErrClosedPipe
	case <-s.writeGate:
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.written.Write(value)
}

func (s *controlledBrowserStream) Read(ctx context.Context, target []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for len(s.remaining) == 0 {
		select {
		case <-ctx.Done():
			select {
			case s.readFailed <- ctx.Err():
			default:
			}
			return 0, ctx.Err()
		case <-s.closed:
			select {
			case s.readFailed <- io.EOF:
			default:
			}
			return 0, io.EOF
		case s.remaining = <-s.responses:
		}
	}
	count := copy(target, s.remaining)
	s.remaining = s.remaining[count:]
	return count, nil
}

func (s *controlledBrowserStream) LastReadError() error {
	select {
	case err := <-s.readFailed:
		return err
	default:
		return nil
	}
}

func (s *controlledBrowserStream) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *controlledBrowserStream) Written() []byte {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return append([]byte(nil), s.written.Bytes()...)
}

var _ gateway.DownstreamFenceAuthority = (*testFenceAuthority)(nil)
var _ ProviderResolver = (*testProviderResolver)(nil)
var _ providerbrowser.Stream = (*controlledBrowserStream)(nil)
