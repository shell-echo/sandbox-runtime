//go:build integration

package executorbackend

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
)

func TestBrowserBackendRealCDP(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_EXECUTOR_BACKEND_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_EXECUTOR_BACKEND_INTEGRATION=1")
	}
	upstreamURL := os.Getenv("SANDBOX_RUNTIME_BROWSER_CDP_URL")
	if upstreamURL == "" {
		t.Fatal("SANDBOX_RUNTIME_BROWSER_CDP_URL is required")
	}
	directory := t.TempDir()
	material := writeTLSMaterial(t, directory)
	listener := freeListenerAddress(t)
	backend, err := New(Config{
		Role: executorprotocol.RoleBrowser, ListenAddress: listener, UpstreamURL: upstreamURL,
		ServerCertificateFile: material.serverCertificate, ServerPrivateKeyFile: material.serverKey, ClientCABundleFile: material.ca,
		AllowedClientIdentities: []string{"spiffe://sandbox-runtime/browser-role"}, MaxSessions: 2, OperationTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = backend.Serve(ctx) }()
	waitListener(t, listener)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: material.clientTLS("127.0.0.1")}}
	connection, _, err := websocket.Dial(ctx, "wss://"+listener+"/executor", &websocket.DialOptions{HTTPClient: client, Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	open := testOpen()
	document, _ := executorprotocol.Encode(open)
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	_, responseDocument, err := connection.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var response executorprotocol.Response
	if err := executorprotocol.Decode(responseDocument, &response); err != nil || response.Status != executorprotocol.StatusAccepted {
		t.Fatalf("executor response=%#v err=%v", response, err)
	}
	if err := connection.Write(ctx, websocket.MessageText, []byte(`{"id":1,"method":"Browser.getVersion"}`)); err != nil {
		t.Fatal(err)
	}
	_, payload, err := connection.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var version struct {
		ID     int `json:"id"`
		Result struct {
			Product string `json:"product"`
		} `json:"result"`
	}
	if json.Unmarshal(payload, &version) != nil || version.ID != 1 || !strings.HasPrefix(version.Result.Product, "Chrome/151.") {
		t.Fatalf("unexpected real CDP response: %s", payload)
	}
}

func (m tlsMaterial) clientTLS(serverName string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: m.pool, Certificates: []tls.Certificate{m.client}, ServerName: serverName}
}
