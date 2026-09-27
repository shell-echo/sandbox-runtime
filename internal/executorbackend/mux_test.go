package executorbackend

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
)

func TestBrowserBackendForwardsExactAuthorityToProviderMux(t *testing.T) {
	parent, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(parent, "bm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	layout := restrictedunix.Layout{DirectoryMode: 0o700, SocketMode: 0o600,
		OwnerUID: uint32(os.Getuid()), DirectoryGID: info.Sys().(*syscall.Stat_t).Gid}
	path := filepath.Join(directory, "browser-mux-"+strings.Repeat("a", 32)+".sock")
	listener, inode, err := restrictedunix.Listen(path, layout)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { listener.Close(); restrictedunix.RemoveIfSame(path, inode) }()
	observed := make(chan executorprotocol.Open, 1)
	mux := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/readyz" {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		if request.URL.Path != "/session" {
			http.NotFound(writer, request)
			return
		}
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{executorprotocol.ProtocolID}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		_, document, err := connection.Read(request.Context())
		var open executorprotocol.Open
		if err != nil || executorprotocol.Decode(document, &open) != nil || open.Validate(time.Now().UTC()) != nil {
			return
		}
		observed <- open
		accepted, _ := executorprotocol.Encode(executorprotocol.Accepted(open.RequestID))
		if connection.Write(request.Context(), websocket.MessageText, accepted) != nil {
			return
		}
		for {
			kind, payload, err := connection.Read(request.Context())
			if err != nil || connection.Write(request.Context(), kind, payload) != nil {
				return
			}
		}
	})}
	go func() { _ = mux.Serve(listener) }()
	defer mux.Close()
	material := writeTLSMaterial(t, t.TempDir())
	address := freeListenerAddress(t)
	backend, err := New(Config{Role: executorprotocol.RoleBrowser, ListenAddress: address, MuxSocketPath: path, MuxLayout: layout,
		ServerCertificateFile: material.serverCertificate, ServerPrivateKeyFile: material.serverKey, ClientCABundleFile: material.ca,
		AllowedClientIdentities: []string{"spiffe://sandbox-runtime/browser-role"}, MaxSessions: 2, OperationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Ready(context.Background()); err != nil {
		t.Fatalf("Browser Provider mux readiness: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- backend.Serve(ctx) }()
	waitListener(t, address)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		RootCAs: material.pool, Certificates: []tls.Certificate{material.client}, ServerName: "127.0.0.1"}}}
	connection, _, err := websocket.Dial(ctx, "wss://"+address+"/executor", &websocket.DialOptions{
		HTTPClient: client, Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		t.Fatal(err)
	}
	open := testOpen()
	document, _ := executorprotocol.Encode(open)
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	readCtx, stop := context.WithTimeout(ctx, time.Second)
	_, accepted, err := connection.Read(readCtx)
	stop()
	if err != nil || !strings.Contains(string(accepted), `"status":"accepted"`) {
		t.Fatalf("Browser backend mux acceptance = %q, %v", accepted, err)
	}
	select {
	case forwarded := <-observed:
		if forwarded.AuthorityDigest != open.AuthorityDigest || forwarded.HandoffReference != open.HandoffReference || forwarded.Fence != open.Fence {
			t.Fatalf("Browser backend changed forwarded authority: %#v", forwarded)
		}
	case <-time.After(time.Second):
		t.Fatal("Browser backend did not forward authority to Provider mux")
	}
	payload := []byte(`{"id":1,"method":"Browser.getVersion"}`)
	if err := connection.Write(ctx, websocket.MessageText, payload); err != nil {
		t.Fatal(err)
	}
	readCtx, stop = context.WithTimeout(ctx, time.Second)
	_, echoed, err := connection.Read(readCtx)
	stop()
	if err != nil || string(echoed) != string(payload) {
		t.Fatalf("Browser backend mux CDP frame = %q, %v", echoed, err)
	}
	connection.CloseNow()
	cancel()
	select {
	case err := <-served:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Browser backend serve = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Browser backend did not stop")
	}
	providerConnection, err := net.DialTimeout("unix", path, 50*time.Millisecond)
	if err != nil {
		// The Provider mux is deliberately still serving until this test's
		// deferred cleanup; backend shutdown must not own its socket.
		t.Fatalf("Browser backend destroyed Provider mux: %v", err)
	}
	providerConnection.Close()
}

func TestBrowserBackendReplayClaimsAreBoundedAndDoNotEvictLiveClaims(t *testing.T) {
	now := time.Now().UTC()
	b := &Backend{replayed: make(map[string]time.Time)}
	for index := range maxReplayClaims {
		if !b.claim("request-"+strconv.Itoa(index), now, now.Add(time.Minute)) {
			t.Fatalf("claim %d unexpectedly denied", index)
		}
	}
	if b.claim("overflow", now, now.Add(time.Minute)) || b.claim("request-0", now, now.Add(time.Minute)) ||
		len(b.replayed) != maxReplayClaims {
		t.Fatal("Browser backend replay capacity evicted a live claim or grew without bound")
	}
	if !b.claim("after-expiry", now.Add(2*time.Minute), now.Add(3*time.Minute)) || len(b.replayed) != 1 {
		t.Fatal("Browser backend did not reclaim only expired replay claims")
	}
}
