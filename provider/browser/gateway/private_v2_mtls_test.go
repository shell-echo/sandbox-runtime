package browsergateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func v2TestPKI(t *testing.T) (*x509.CertPool, tls.Certificate, tls.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "v2 test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(serial int64, uri string, server bool) tls.Certificate {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "v2 test workload"},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.DNSNames = []string{"provider.test"}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			parsed, err := url.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			template.URIs = []*url.URL{parsed}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caPrivate)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: private}
	}
	return pool, issue(2, "", true), issue(3, "spiffe://sandbox.test/browser-action-ingress", false),
		issue(4, "spiffe://sandbox.test/other-role", false)
}

func TestV2PrivateRouteRealMTLSOnlyExactIngress(t *testing.T) {
	roots, serverIdentity, ingressIdentity, otherIdentity := v2TestPKI(t)
	store := &v2Store{closed: make(chan struct{})}
	resolver := &v2Resolver{store: store, dialed: make(chan struct{})}
	var handler *V2Handler
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handler.ServeHTTP(writer, request)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverIdentity}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewV2(V2Options{Resolver: resolver, Store: store,
		ExpectedPeerURI: "spiffe://sandbox.test/browser-action-ingress", ExpectedHost: parsed.Host,
		MaxSessions: 1, OperationTimeout: time.Second, AuthorityPollInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	client := func(identity tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots,
			ServerName: "provider.test", Certificates: []tls.Certificate{identity}}}}
	}
	wsURL := "wss" + strings.TrimPrefix(server.URL, "https") + PrivateV2Path
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if wrong, response, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: client(otherIdentity), Subprotocols: []string{browserhandoffv2.ProtocolID}}); err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		if wrong != nil {
			_ = wrong.CloseNow()
		}
		t.Fatalf("wrong verified principal: response=%v err=%v", response, err)
	}
	connection, response, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: client(ingressIdentity), Subprotocols: []string{browserhandoffv2.ProtocolID}})
	if err != nil {
		t.Fatalf("real mTLS ingress rejected: response=%v err=%v", response, err)
	}
	open := v2OpenFixture()
	document, _ := handoff.Encode(open)
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	kind, responseDocument, err := connection.Read(ctx)
	var accepted browserhandoffv2.OpenResponse
	if err != nil || kind != websocket.MessageText || handoff.Decode(responseDocument, &accepted) != nil ||
		accepted.Validate() != nil || accepted.Status != browserhandoffv2.StatusAccepted {
		t.Fatalf("real mTLS v2 acceptance = %s, %v", responseDocument, err)
	}
	_ = connection.CloseNow()
	select {
	case <-store.closed:
	case <-ctx.Done():
		t.Fatal("real mTLS connection did not close exact claim")
	}
}
