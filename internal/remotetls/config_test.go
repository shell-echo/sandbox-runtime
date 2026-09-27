package remotetls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testServerURI = "spiffe://sandbox-runtime.test/role/browser"
	testClientURI = "spiffe://sandbox-runtime.test/role/provider"
	testServerDNS = "browser.test"
)

type testIssuer struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	roots       *x509.CertPool
}

type failingSigner struct{ public crypto.PublicKey }

func (s failingSigner) Public() crypto.PublicKey { return s.public }
func (failingSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signer unavailable")
}

func newTestIssuer(t *testing.T) testIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return testIssuer{certificate: certificate, key: key, roots: roots}
}

func issueTestLeaf(t *testing.T, issuer testIssuer, identity Identity, serial int64) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity.URI)
	if err != nil {
		t.Fatal(err)
	}
	usages, err := requiredUsages(identity.Usages)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(19 * time.Minute), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
		URIs: []*url.URL{uri}, DNSNames: slices.Clone(identity.DNSNames)}
	raw, err := x509.CreateCertificate(rand.Reader, template, issuer.certificate, &key.PublicKey, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{raw, issuer.certificate.Raw}, PrivateKey: key}
}

func testIdentities() (Identity, Identity) {
	return Identity{URI: testServerURI, DNSNames: []string{testServerDNS}, Usages: []string{"server_auth"}, MaxTTL: time.Hour},
		Identity{URI: testClientURI, Usages: []string{"client_auth"}, MaxTTL: time.Hour}
}

func testHandshake(server, client *tls.Config) (error, error) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	_ = serverConn.SetDeadline(time.Now().Add(2 * time.Second))
	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	result := make(chan error, 1)
	go func() { result <- tls.Server(serverConn, server).Handshake() }()
	clientError := tls.Client(clientConn, client).Handshake()
	serverError := <-result
	return serverError, clientError
}

func TestClientCertificateValidatesFreshSignerForEveryRequest(t *testing.T) {
	issuer := newTestIssuer(t)
	_, identity := testIdentities()
	valid := issueTestLeaf(t, issuer, identity, 601)
	wrong := issueTestLeaf(t, issuer, Identity{URI: testServerURI,
		Usages: []string{"client_auth"}, MaxTTL: time.Hour}, 602)
	current := valid
	loads := 0
	certificate, err := NewClientCertificate(context.Background(), issuer.roots, identity,
		func(context.Context) (tls.Certificate, error) { loads++; return current, nil }, time.Now)
	if err != nil || loads != 1 {
		t.Fatalf("bootstrap certificate = %v, loads=%d", err, loads)
	}
	if _, err := certificate(nil); err == nil {
		t.Fatal("missing TLS request accepted")
	}
	serverIssuer := newTestIssuer(t)
	serverIdentity, _ := testIdentities()
	server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{
		issueTestLeaf(t, serverIssuer, serverIdentity, 603)},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: issuer.roots}
	client := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: serverIssuer.roots,
		ServerName: testServerDNS, GetClientCertificate: certificate}
	serverErr, clientErr := testHandshake(server, client)
	if serverErr != nil || clientErr != nil || loads != 2 {
		t.Fatalf("fresh valid certificate = server=%v, client=%v, loads=%d", serverErr, clientErr, loads)
	}
	current = wrong
	_, clientErr = testHandshake(server, client)
	if clientErr == nil || loads != 3 {
		t.Fatalf("drifted certificate accepted or not reloaded: %v, loads=%d", clientErr, loads)
	}
}

func TestClientCertificateRespectsCanceledStartup(t *testing.T) {
	issuer := newTestIssuer(t)
	_, identity := testIdentities()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if _, err := NewClientCertificate(ctx, issuer.roots, identity,
		func(context.Context) (tls.Certificate, error) {
			called = true
			return tls.Certificate{}, nil
		}, time.Now); err == nil || called {
		t.Fatalf("canceled startup used signer: error=%v called=%t", err, called)
	}
}

func TestLiveMutualTLSRotatesAndFailsClosed(t *testing.T) {
	serverIssuer := newTestIssuer(t)
	clientIssuer := newTestIssuer(t)
	serverIdentity, clientIdentity := testIdentities()
	serverOne := issueTestLeaf(t, serverIssuer, serverIdentity, 2)
	serverTwo := issueTestLeaf(t, serverIssuer, serverIdentity, 3)
	client := issueTestLeaf(t, clientIssuer, clientIdentity, 4)
	var selected atomic.Int32
	var serverCalls atomic.Int32
	var clientCalls atomic.Int32
	serverTLS, probe, err := NewServerWithProbe(ServerOptions{IssuerRoots: serverIssuer.roots, ClientRoots: clientIssuer.roots,
		Identity: serverIdentity, Client: &clientIdentity, Now: time.Now,
		Source: func(context.Context) (tls.Certificate, error) {
			serverCalls.Add(1)
			switch selected.Load() {
			case 0:
				return serverOne, nil
			case 1:
				return serverTwo, nil
			default:
				return tls.Certificate{}, errors.New("signer lost")
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := NewClient(ClientOptions{IssuerRoots: clientIssuer.roots, ServerRoots: serverIssuer.roots,
		Identity: clientIdentity, Server: serverIdentity, ServerName: testServerDNS, Now: time.Now,
		Source: func(context.Context) (tls.Certificate, error) {
			clientCalls.Add(1)
			return client, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if serverTLS.MinVersion != tls.VersionTLS13 || serverTLS.MaxVersion != tls.VersionTLS13 || !serverTLS.SessionTicketsDisabled ||
		clientTLS.MinVersion != tls.VersionTLS13 || clientTLS.MaxVersion != tls.VersionTLS13 || serverCalls.Load() != 1 || clientCalls.Load() != 1 {
		t.Fatal("live TLS bootstrap or version is invalid")
	}
	if err := probe(context.Background()); err != nil {
		t.Fatalf("live readiness probe: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probe(canceled); err == nil {
		t.Fatal("cancelled readiness probe was accepted")
	}
	for _, generation := range []int32{0, 1} {
		selected.Store(generation)
		serverError, clientError := testHandshake(serverTLS, clientTLS)
		if serverError != nil || clientError != nil {
			t.Fatalf("generation %d: server=%v client=%v", generation, serverError, clientError)
		}
	}
	if serverCalls.Load() != 4 || clientCalls.Load() != 3 {
		t.Fatalf("certificates not fetched for every handshake: server=%d client=%d", serverCalls.Load(), clientCalls.Load())
	}
	selected.Store(2)
	if err := probe(context.Background()); err == nil {
		t.Fatal("readiness retained a stale signer")
	}
	serverError, clientError := testHandshake(serverTLS, clientTLS)
	if serverError == nil && clientError == nil {
		t.Fatal("signer loss retained stale certificate")
	}
}

func TestLiveMutualTLSKeepsOwnIssuerAndPeerRootsSeparate(t *testing.T) {
	serverIssuer := newTestIssuer(t)
	clientIssuer := newTestIssuer(t)
	serverIdentity, clientIdentity := testIdentities()
	serverLeaf := issueTestLeaf(t, serverIssuer, serverIdentity, 51)
	clientLeaf := issueTestLeaf(t, clientIssuer, clientIdentity, 52)
	serverTLS, err := NewServer(ServerOptions{IssuerRoots: serverIssuer.roots, ClientRoots: clientIssuer.roots,
		Identity: serverIdentity, Client: &clientIdentity, Now: time.Now,
		Source: func(context.Context) (tls.Certificate, error) { return serverLeaf, nil }})
	if err != nil {
		t.Fatal(err)
	}
	clientOptions := ClientOptions{IssuerRoots: clientIssuer.roots, ServerRoots: serverIssuer.roots,
		Identity: clientIdentity, Server: serverIdentity, ServerName: testServerDNS, Now: time.Now,
		Source: func(context.Context) (tls.Certificate, error) { return clientLeaf, nil }}
	clientTLS, err := NewClient(clientOptions)
	if err != nil {
		t.Fatal(err)
	}
	if serverError, clientError := testHandshake(serverTLS, clientTLS); serverError != nil || clientError != nil {
		t.Fatalf("separate roots rejected: server=%v client=%v", serverError, clientError)
	}
	wrongOwnIssuer := clientOptions
	wrongOwnIssuer.IssuerRoots = serverIssuer.roots
	if _, err := NewClient(wrongOwnIssuer); err == nil {
		t.Fatal("client accepted the server root as its own issuer")
	}
	wrongPeerRoot := clientOptions
	wrongPeerRoot.ServerRoots = clientIssuer.roots
	wrongPeerTLS, err := NewClient(wrongPeerRoot)
	if err != nil {
		t.Fatal(err)
	}
	if serverError, clientError := testHandshake(serverTLS, wrongPeerTLS); serverError == nil && clientError == nil {
		t.Fatal("client accepted its own issuer as the remote server root")
	}
	wrongSigner := clientOptions
	wrongClientLeaf := clientLeaf
	wrongClientLeaf.PrivateKey = issueTestLeaf(t, clientIssuer, clientIdentity, 53).PrivateKey
	wrongSigner.Source = func(context.Context) (tls.Certificate, error) { return wrongClientLeaf, nil }
	if _, err := NewClient(wrongSigner); err == nil {
		t.Fatal("client accepted a signer that did not match its issued leaf")
	}
}

func TestLiveTLSRejectsLocalAuthorityDrift(t *testing.T) {
	issuer := newTestIssuer(t)
	other := newTestIssuer(t)
	serverIdentity, clientIdentity := testIdentities()
	valid := issueTestLeaf(t, issuer, serverIdentity, 5)
	wrongIssuer := valid
	wrongIssuer.Certificate = slices.Clone(valid.Certificate)
	wrongIssuer.Certificate[1] = other.certificate.Raw
	wrongSigner := valid
	wrongSigner.PrivateKey = issueTestLeaf(t, issuer, serverIdentity, 6).PrivateKey
	lostSigner := valid
	lostSigner.PrivateKey = failingSigner{public: valid.PrivateKey.(crypto.Signer).Public()}
	wrongURI := issueTestLeaf(t, issuer, Identity{URI: testClientURI, DNSNames: []string{testServerDNS}, Usages: []string{"server_auth"}, MaxTTL: time.Hour}, 7)
	wrongUsage := issueTestLeaf(t, issuer, Identity{URI: testServerURI, DNSNames: []string{testServerDNS}, Usages: []string{"client_auth"}, MaxTTL: time.Hour}, 8)
	wrongLeaf := valid
	wrongLeaf.Leaf, _ = x509.ParseCertificate(wrongURI.Certificate[0])
	oversized := valid
	oversized.Certificate = [][]byte{bytes.Repeat([]byte{1}, (64<<10)+1), issuer.certificate.Raw}
	for _, candidate := range []struct {
		name string
		cert tls.Certificate
		root *x509.CertPool
	}{
		{"issuer", wrongIssuer, issuer.roots}, {"signer", wrongSigner, issuer.roots},
		{"signer loss", lostSigner, issuer.roots},
		{"URI", wrongURI, issuer.roots}, {"EKU", wrongUsage, issuer.roots},
		{"cached leaf", wrongLeaf, issuer.roots},
		{"oversized leaf", oversized, issuer.roots},
		{"root", valid, other.roots},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			_, err := NewServer(ServerOptions{IssuerRoots: candidate.root, Identity: serverIdentity, Now: time.Now,
				Source: func(context.Context) (tls.Certificate, error) { return candidate.cert, nil }})
			if err == nil {
				t.Fatal("drift accepted")
			}
		})
	}
	// A declared peer identity is mandatory for mTLS; public servers may omit it.
	if _, err := NewServer(ServerOptions{IssuerRoots: issuer.roots, ClientRoots: issuer.roots,
		Identity: serverIdentity, Now: time.Now,
		Source: func(context.Context) (tls.Certificate, error) { return valid, nil }}); err == nil {
		t.Fatal("client CA without peer identity accepted")
	}
	if _, err := NewClient(ClientOptions{IssuerRoots: issuer.roots, ServerRoots: issuer.roots,
		Identity: clientIdentity, Server: serverIdentity, ServerName: "wrong.test", Now: time.Now,
		Source: func(context.Context) (tls.Certificate, error) {
			return issueTestLeaf(t, issuer, clientIdentity, 9), nil
		}}); err == nil {
		t.Fatal("unbound server name accepted")
	}
}

func TestLiveTLSRejectsPeerDriftAndMutableIdentity(t *testing.T) {
	issuer := newTestIssuer(t)
	serverIdentity, clientIdentity := testIdentities()
	serverCert := issueTestLeaf(t, issuer, serverIdentity, 10)
	clientCert := issueTestLeaf(t, issuer, clientIdentity, 11)
	serverTLS, err := NewServer(ServerOptions{IssuerRoots: issuer.roots, ClientRoots: issuer.roots,
		Identity: serverIdentity, Client: &clientIdentity, Now: time.Now,
		Source: func(context.Context) (tls.Certificate, error) { return serverCert, nil }})
	if err != nil {
		t.Fatal(err)
	}
	serverIdentity.DNSNames[0] = "mutated.test"
	clientIdentity.URI = "spiffe://sandbox-runtime.test/role/other"
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: issuer.roots, ServerName: testServerDNS,
		Certificates: []tls.Certificate{clientCert}}
	serverError, clientError := testHandshake(serverTLS, clientTLS)
	if serverError != nil || clientError != nil {
		t.Fatalf("caller mutated bound identity: server=%v client=%v", serverError, clientError)
	}
	extraIdentity := Identity{URI: testClientURI, DNSNames: []string{"extra.test"}, Usages: []string{"client_auth"}, MaxTTL: time.Hour}
	clientTLS.Certificates = []tls.Certificate{issueTestLeaf(t, issuer, extraIdentity, 12)}
	serverError, clientError = testHandshake(serverTLS, clientTLS)
	if serverError == nil && clientError == nil {
		t.Fatal("peer with extra DNS identity was admitted")
	}
}

func TestLiveTLSRejectsServerPeerDrift(t *testing.T) {
	issuer := newTestIssuer(t)
	serverIdentity, clientIdentity := testIdentities()
	clientCert := issueTestLeaf(t, issuer, clientIdentity, 13)
	clientTLS, err := NewClient(ClientOptions{IssuerRoots: issuer.roots, ServerRoots: issuer.roots,
		Identity: clientIdentity, Server: serverIdentity, ServerName: testServerDNS, Now: time.Now,
		Source: func(context.Context) (tls.Certificate, error) { return clientCert, nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		name     string
		identity Identity
	}{
		{"extra DNS", Identity{URI: testServerURI, DNSNames: []string{testServerDNS, "extra.test"}, Usages: []string{"server_auth"}, MaxTTL: time.Hour}},
		{"wrong DNS", Identity{URI: testServerURI, DNSNames: []string{"wrong.test"}, Usages: []string{"server_auth"}, MaxTTL: time.Hour}},
		{"wrong URI", Identity{URI: "spiffe://sandbox-runtime.test/role/other", DNSNames: []string{testServerDNS}, Usages: []string{"server_auth"}, MaxTTL: time.Hour}},
		{"extra EKU", Identity{URI: testServerURI, DNSNames: []string{testServerDNS}, Usages: []string{"client_auth", "server_auth"}, MaxTTL: time.Hour}},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			certificate := issueTestLeaf(t, issuer, candidate.identity, 14)
			serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
			serverError, clientError := testHandshake(serverTLS, clientTLS)
			if serverError == nil && clientError == nil {
				t.Fatal("drifted server peer accepted")
			}
		})
	}
}

func TestLiveTLSNumericDialUsesPinnedServerName(t *testing.T) {
	issuer := newTestIssuer(t)
	serverIdentity, clientIdentity := testIdentities()
	serverCert := issueTestLeaf(t, issuer, serverIdentity, 91)
	clientCert := issueTestLeaf(t, issuer, clientIdentity, 92)
	serverTLS, err := NewServer(ServerOptions{IssuerRoots: issuer.roots, ClientRoots: issuer.roots,
		Identity: serverIdentity, Client: &clientIdentity, Now: time.Now,
		Source: func(context.Context) (tls.Certificate, error) { return serverCert, nil }})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := NewClient(ClientOptions{IssuerRoots: issuer.roots, ServerRoots: issuer.roots,
		Identity: clientIdentity, Server: serverIdentity, ServerName: testServerDNS, Now: time.Now,
		Source: func(context.Context) (tls.Certificate, error) { return clientCert, nil }})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer connection.Close()
		serverResult <- tls.Server(connection, serverTLS).Handshake()
	}()
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("numeric dial with pinned DNS identity: %v", err)
	}
	_ = connection.Close()
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestLiveTLSPublicServerExpiryAndSignerLoss(t *testing.T) {
	issuer := newTestIssuer(t)
	serverIdentity, _ := testIdentities()
	certificate := issueTestLeaf(t, issuer, serverIdentity, 15)
	current := time.Now()
	var lost atomic.Bool
	serverTLS, err := NewServer(ServerOptions{IssuerRoots: issuer.roots, Identity: serverIdentity,
		Now: func() time.Time { return current },
		Source: func(ctx context.Context) (tls.Certificate, error) {
			if lost.Load() || ctx.Err() != nil {
				return tls.Certificate{}, errors.New("signer unavailable")
			}
			return certificate, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: issuer.roots, ServerName: testServerDNS}
	serverError, clientError := testHandshake(serverTLS, clientTLS)
	if serverError != nil || clientError != nil {
		t.Fatalf("public server handshake: server=%v client=%v", serverError, clientError)
	}
	lost.Store(true)
	serverError, clientError = testHandshake(serverTLS, clientTLS)
	if serverError == nil && clientError == nil {
		t.Fatal("public server reused certificate after signer loss")
	}
	lost.Store(false)
	current = time.Now().Add(21 * time.Minute)
	serverError, clientError = testHandshake(serverTLS, clientTLS)
	if serverError == nil && clientError == nil {
		t.Fatal("expired certificate was accepted")
	}
}

func TestLiveTLSRejectsInvalidIdentity(t *testing.T) {
	serverIdentity, _ := testIdentities()
	for _, mutation := range []func(*Identity){
		func(identity *Identity) { identity.URI = "https://sandbox-runtime.test/role/browser" },
		func(identity *Identity) { identity.DNSNames = []string{"Browser.test"} },
		func(identity *Identity) { identity.DNSNames = []string{"-bad.test"} },
		func(identity *Identity) { identity.DNSNames = []string{"127.0.0.1"} },
		func(identity *Identity) { identity.Usages = []string{"server_auth", "client_auth"} },
		func(identity *Identity) { identity.MaxTTL = 2 * time.Hour },
	} {
		candidate := cloneIdentity(serverIdentity)
		mutation(&candidate)
		if err := validateIdentity(candidate); err == nil {
			t.Fatalf("invalid identity accepted: %+v", candidate)
		}
	}
}

func TestLiveTLSComparesEKUAsExactSet(t *testing.T) {
	expected := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	if !equalUsages([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, expected) {
		t.Fatal("equivalent dual-use certificate rejected because of encoding order")
	}
	if equalUsages([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageServerAuth}, expected) {
		t.Fatal("duplicate EKU replaced a required usage")
	}
}
