package executorbackend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func TestBrowserBackendValidatesAuthorityAndRelaysCDP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		for {
			kind, payload, err := connection.Read(request.Context())
			if err != nil {
				return
			}
			if err := connection.Write(request.Context(), kind, payload); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()

	directory := t.TempDir()
	material := writeTLSMaterial(t, directory)
	listener := freeListenerAddress(t)
	backend, err := New(Config{
		Role: executorprotocol.RoleBrowser, ListenAddress: listener, UpstreamURL: "ws" + strings.TrimPrefix(upstream.URL, "http") + "/cdp",
		ServerCertificateFile: material.serverCertificate, ServerPrivateKeyFile: material.serverKey, ClientCABundleFile: material.ca,
		AllowedClientIdentities: []string{"spiffe://sandbox-runtime/browser-role"}, MaxSessions: 2, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- backend.Serve(ctx) }()
	waitListener(t, listener)
	tlsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: material.pool, Certificates: []tls.Certificate{material.client}, ServerName: "127.0.0.1"}}}
	endpoint := "wss://" + listener + "/executor"
	connection, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPClient: tlsClient, Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	open := testOpen()
	document, _ := executorprotocol.Encode(open)
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	kind, responseDocument, err := connection.Read(ctx)
	if err != nil || kind != websocket.MessageText {
		t.Fatalf("authority response kind=%v err=%v", kind, err)
	}
	var response executorprotocol.Response
	if err := executorprotocol.Decode(responseDocument, &response); err != nil || response.Status != executorprotocol.StatusAccepted {
		t.Fatalf("authority response=%#v err=%v", response, err)
	}
	payload := []byte(`{"id":1,"method":"Browser.getVersion"}`)
	if err := connection.Write(ctx, websocket.MessageText, payload); err != nil {
		t.Fatal(err)
	}
	_, echoed, err := connection.Read(ctx)
	if err != nil || string(echoed) != string(payload) {
		t.Fatalf("CDP relay payload=%q err=%v", echoed, err)
	}
	_ = connection.CloseNow()

	replay, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPClient: tlsClient, Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		t.Fatal(err)
	}
	defer replay.CloseNow()
	if err := replay.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	_, rejectedDocument, err := replay.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var rejected executorprotocol.Response
	if err := executorprotocol.Decode(rejectedDocument, &rejected); err != nil || rejected.Status != executorprotocol.StatusRejected {
		t.Fatalf("replay response=%#v err=%v", rejected, err)
	}
	cancel()
	select {
	case <-serveErr:
	case <-time.After(time.Second):
		t.Fatal("backend did not stop")
	}
}

type tlsMaterial struct {
	ca, serverCertificate, serverKey string
	client                           tls.Certificate
	pool                             *x509.CertPool
}

func writeTLSMaterial(t *testing.T, directory string) tlsMaterial {
	t.Helper()
	now := time.Now().UTC()
	caKey := rsaKey(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "phase6-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPath := filepath.Join(directory, "ca.pem")
	writePrivate(t, caPath, caPEM)
	pool := x509.NewCertPool()
	pool.AddCert(caTemplateWithDER(t, caDER))
	issue := func(name, uri string, usages []x509.ExtKeyUsage, server bool) (string, string, tls.Certificate) {
		key := rsaKey(t)
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(len(name) + 2)), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: usages, KeyUsage: x509.KeyUsageDigitalSignature}
		if uri != "" {
			template.URIs = []*url.URL{mustURL(t, uri)}
		}
		if server {
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, createErr := x509.CreateCertificate(rand.Reader, template, caTemplate, &key.PublicKey, caKey)
		if createErr != nil {
			t.Fatal(createErr)
		}
		certificate := tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
		certPath := filepath.Join(directory, name+".pem")
		keyPath := filepath.Join(directory, name+".key")
		certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), caPEM...)
		writePrivate(t, certPath, certificatePEM)
		keyDER, keyErr := x509.MarshalPKCS8PrivateKey(key)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		writePrivate(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
		return certPath, keyPath, certificate
	}
	serverCertificate, serverKey, _ := issue("server", "", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, true)
	_, _, client := issue("client", "spiffe://sandbox-runtime/browser-role", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false)
	return tlsMaterial{ca: caPath, serverCertificate: serverCertificate, serverKey: serverKey, client: client, pool: pool}
}

func testOpen() executorprotocol.Open {
	now := time.Now().UTC()
	open := executorprotocol.Open{Protocol: executorprotocol.ProtocolID, Role: executorprotocol.RoleBrowser, RequestID: "request-browser-1", TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), ProviderRevisionID: "provider-revision-1", SandboxID: "sandbox-1", RuntimeSessionID: "browser-session-1", CapabilityProfileID: "browser-v1", MediaProfileID: "browser-cdp-v1", ControlProfileID: "browser-control-v1", HandoffReference: "ref:browser-session:opaque-1", ConnectionGeneration: 1, ConnectionEpoch: "epoch-1", Fence: strings.Repeat("b", handoff.MinFenceBytes), AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), HandoffExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano), Codec: "application/json"}
	open.HandoffDigest = executorprotocol.ReferenceDigest(open.HandoffReference)
	open.AuthorityDigest = open.CalculateAuthorityDigest()
	open.RequestDigest = open.CalculateRequestDigest()
	return open
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func caTemplateWithDER(t *testing.T, der []byte) *x509.Certificate {
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func mustURL(t *testing.T, value string) *url.URL {
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func writePrivate(t *testing.T, path string, value []byte) {
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
}

func freeListenerAddress(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func waitListener(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener %s did not start", address)
}
