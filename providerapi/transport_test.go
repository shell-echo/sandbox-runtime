package providerapi

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestProviderServerReconcilesHTTP11CapabilityInputTransport(t *testing.T) {
	tests := []struct {
		name            string
		request         string
		wantStatus      int
		wantEmptyBody   bool
		wantHandlerCall int64
	}{
		{
			name:            "bare trailing question mark reaches handler",
			request:         "GET /v1/capabilities? HTTP/1.1\r\nHost: provider.test\r\nConnection: close\r\n\r\n",
			wantStatus:      http.StatusBadRequest,
			wantEmptyBody:   true,
			wantHandlerCall: 1,
		},
		{
			name:            "unknown query reaches handler",
			request:         "GET /v1/capabilities?unexpected=value HTTP/1.1\r\nHost: provider.test\r\nConnection: close\r\n\r\n",
			wantStatus:      http.StatusBadRequest,
			wantEmptyBody:   true,
			wantHandlerCall: 1,
		},
		{
			name:            "explicit nonzero content length reaches handler",
			request:         "GET /v1/capabilities HTTP/1.1\r\nHost: provider.test\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
			wantStatus:      http.StatusBadRequest,
			wantEmptyBody:   true,
			wantHandlerCall: 1,
		},
		{
			name:            "chunked nonempty body reaches handler",
			request:         "GET /v1/capabilities HTTP/1.1\r\nHost: provider.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n0\r\n\r\n",
			wantStatus:      http.StatusBadRequest,
			wantEmptyBody:   true,
			wantHandlerCall: 1,
		},
		{
			name:            "unsupported transfer coding is rejected by parser",
			request:         "GET /v1/capabilities HTTP/1.1\r\nHost: provider.test\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n",
			wantStatus:      http.StatusNotImplemented,
			wantHandlerCall: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := startTransportTestProviderServer(t)
			response, body := server.roundTrip(t, test.request)
			if response.StatusCode != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.wantStatus)
			}
			if test.wantEmptyBody && len(body) != 0 {
				t.Fatalf("response body = %q, want empty", body)
			}
			if calls := server.handler.calls.Load(); calls != test.wantHandlerCall {
				t.Fatalf("handler calls = %d, want %d", calls, test.wantHandlerCall)
			}
			if calls := server.source.callCount(); calls != 1 {
				t.Fatalf("capability source calls = %d, want construction read only", calls)
			}
		})
	}
}

type transportTestProviderServer struct {
	address  string
	material testMTLSMaterial
	source   *capabilityReaderSpy
	handler  *countingHandler
}

func startTransportTestProviderServer(t *testing.T) transportTestProviderServer {
	t.Helper()
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	listener, port := reserveProviderListener(t)
	source := &capabilityReaderSpy{snapshot: validSnapshot(t, nil, nil)}
	server, err := NewServer(context.Background(), validTransportOptions(material, port), source)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	handler := &countingHandler{next: server.http.Handler}
	server.http.Handler = handler
	server.listen = func(context.Context, string, string) (net.Listener, error) { return listener, nil }

	startupContext, cancelStartup := context.WithCancel(context.Background())
	startupResult := make(chan error, 1)
	go func() { startupResult <- server.Startup(startupContext) }()
	t.Cleanup(func() {
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()
		if err := server.Shutdown(shutdownContext); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		cancelStartup()
		select {
		case err := <-startupResult:
			if err != nil {
				t.Errorf("Startup: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Provider server did not stop")
		}
	})

	return transportTestProviderServer{
		address:  listener.Addr().String(),
		material: material,
		source:   source,
		handler:  handler,
	}
}

func (s transportTestProviderServer) roundTrip(t *testing.T, request string) (*http.Response, []byte) {
	t.Helper()
	config := clientTLSConfig(s.material, &s.material.client)
	config.NextProtos = []string{"http/1.1"}

	var connection *tls.Conn
	var err error
	for attempt := 0; attempt < 100; attempt++ {
		connection, err = tls.Dial("tcp", s.address, config)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial Provider server: %v", err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatalf("write HTTP/1.1 request: %v", err)
	}

	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read HTTP/1.1 response: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return response, body
}

type countingHandler struct {
	next  http.Handler
	calls atomic.Int64
}

func (h *countingHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	h.calls.Add(1)
	h.next.ServeHTTP(response, request)
}
