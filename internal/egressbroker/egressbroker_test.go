package egressbroker

import (
	"context"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

type staticResolver struct {
	answers []net.IPAddr
	err     error
}

func (r staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return append([]net.IPAddr(nil), r.answers...), r.err
}

type pipeDialer struct {
	mu        sync.Mutex
	addresses []string
	peers     chan net.Conn
}

func (d *pipeDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addresses = append(d.addresses, address)
	d.mu.Unlock()
	client, peer := net.Pipe()
	select {
	case d.peers <- peer:
		return client, nil
	case <-ctx.Done():
		_ = client.Close()
		_ = peer.Close()
		return nil, ctx.Err()
	}
}

type brokerFixture struct {
	policy       Policy
	server       *Server
	client       *Client
	serverTLS    *tls.Config
	clientTLS    *tls.Config
	dialer       *pipeDialer
	cancel       context.CancelFunc
	done         chan error
	principalURI string
	brokerURI    string
}

func newBrokerFixture(t *testing.T, resolver staticResolver, maximumConnections int) *brokerFixture {
	t.Helper()
	policy := testPolicy(t)
	return newBrokerFixtureWithPolicy(t, policy, resolver, maximumConnections)
}

func newBrokerFixtureWithPolicy(t *testing.T, policy Policy, resolver staticResolver, maximumConnections int) *brokerFixture {
	return newBrokerFixtureWithMonitor(t, policy, resolver, maximumConnections, nil)
}

func newBrokerFixtureWithMonitor(t *testing.T, policy Policy, resolver staticResolver,
	maximumConnections int, monitor PeerRevocationMonitor) *brokerFixture {
	t.Helper()
	serverTLS, clientTLS := testTLS(t, policy.Principal.Digest(), policy.Broker.Digest(), policy.Principal.Name, policy.Broker.Name)
	dialer := &pipeDialer{peers: make(chan net.Conn, 16)}
	principalURI := "spiffe://sandbox-runtime.test/" + policy.Principal.Name
	brokerURI := "spiffe://sandbox-runtime.test/" + policy.Broker.Name
	server, err := Listen(ServerConfig{Address: "127.0.0.1:0", TLSConfig: serverTLS, Policy: policy,
		PrincipalURI: principalURI, PrincipalUsages: []string{"client_auth"}, Resolver: resolver, Dialer: dialer, MaxConnections: maximumConnections,
		ReplayCapacity: 128, Now: time.Now, PeerRevocation: monitor})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client, err := NewClient(ClientConfig{Address: server.Addr().String(), TLSConfig: clientTLS, Policy: policy,
		BrokerURI: brokerURI, BrokerDNSNames: []string{"broker.internal.test"}, BrokerUsages: []string{"server_auth"}, OperationTimeout: 3 * time.Second,
		Now: time.Now, Random: rand.Reader})
	if err != nil {
		cancel()
		_ = server.Close()
		t.Fatal(err)
	}
	return &brokerFixture{policy: policy, server: server, client: client, serverTLS: serverTLS, clientTLS: clientTLS,
		dialer: dialer, cancel: cancel, done: done, principalURI: principalURI, brokerURI: brokerURI}
}

type testPeerRevocationMonitor struct {
	mu      sync.Mutex
	ready   bool
	tracked map[net.Conn]struct{}
	checks  int
}

func (m *testPeerRevocationMonitor) Ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ready
}

func (m *testPeerRevocationMonitor) CheckHandshake(_ context.Context, state tls.ConnectionState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checks++
	if !m.ready || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		return ErrDenied
	}
	return nil
}

func (m *testPeerRevocationMonitor) Track(connection net.Conn, _ tls.ConnectionState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready {
		return ErrDenied
	}
	m.tracked[connection] = struct{}{}
	return nil
}

func (m *testPeerRevocationMonitor) Forget(connection net.Conn) {
	m.mu.Lock()
	delete(m.tracked, connection)
	m.mu.Unlock()
}

func (m *testPeerRevocationMonitor) revoke() {
	m.mu.Lock()
	m.ready = false
	for connection := range m.tracked {
		_ = connection.Close()
	}
	m.mu.Unlock()
}

func TestInboundPeerRevocationRejectsBeforeRequestAndDrainsTunnel(t *testing.T) {
	policy := testPolicy(t)
	monitor := &testPeerRevocationMonitor{ready: true, tracked: make(map[net.Conn]struct{})}
	fixture := newBrokerFixtureWithMonitor(t, policy,
		staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}}, 4, monitor)
	defer fixture.close(t)
	connection, err := fixture.client.Dial(t.Context(), "packages", time.Second)
	if err != nil {
		t.Fatalf("fresh TLS peer was not admitted: %v", err)
	}
	defer connection.Close()
	upstream := <-fixture.dialer.peers
	defer upstream.Close()
	monitor.revoke()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked inbound peer retained an established tunnel")
	}
	if _, err := fixture.client.Dial(t.Context(), "packages", time.Second); err == nil {
		t.Fatal("revoked inbound peer opened a new tunnel")
	}
	deadline := time.Now().Add(time.Second)
	for {
		monitor.mu.Lock()
		checks, remaining := monitor.checks, len(monitor.tracked)
		monitor.mu.Unlock()
		if checks < 1 {
			t.Fatal("inbound peer guard did not check the verified TLS handshake")
		}
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer guard retained %d closed TLS connections", remaining)
		}
		time.Sleep(10 * time.Millisecond)
	}
	fixture.dialer.mu.Lock()
	dials := len(fixture.dialer.addresses)
	fixture.dialer.mu.Unlock()
	if dials != 1 {
		t.Fatalf("revoked TLS peer reached external dial %d times", dials)
	}
}

func TestBrokerSixteenAnswerPolicyRejectsSeventeenthAndPoisonedLast(t *testing.T) {
	policy := testPolicy(t)
	var err error
	policy, err = NewPolicy(policy.ID, policy.Revision, policy.Registry, policy.Principal, policy.Broker,
		policy.Lease, 16, policy.Targets)
	if err != nil {
		t.Fatal(err)
	}
	answers := make([]net.IPAddr, 16)
	for index := range answers {
		answers[index] = net.IPAddr{IP: net.IPv4(34, 238, 55, byte(index+1))}
	}
	valid := newBrokerFixtureWithPolicy(t, policy, staticResolver{answers: answers}, 4)
	connection, err := valid.client.Dial(context.Background(), "packages", time.Second)
	if err != nil {
		valid.close(t)
		t.Fatalf("16 valid public answers could not reach broker numeric dial: %v", err)
	}
	peer := <-valid.dialer.peers
	_ = connection.Close()
	_ = peer.Close()
	valid.dialer.mu.Lock()
	count := len(valid.dialer.addresses)
	valid.dialer.mu.Unlock()
	if count != 1 {
		t.Errorf("valid 16-answer broker connection used %d numeric dials", count)
	}
	valid.close(t)

	for name, bad := range map[string][]net.IPAddr{
		"seventeenth":   append(append([]net.IPAddr(nil), answers...), net.IPAddr{IP: net.IPv4(34, 238, 55, 17)}),
		"poisoned last": append(append([]net.IPAddr(nil), answers[:15]...), net.IPAddr{IP: net.ParseIP("169.254.169.254")}),
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newBrokerFixtureWithPolicy(t, policy, staticResolver{answers: bad}, 4)
			defer fixture.close(t)
			if _, err := fixture.client.Dial(context.Background(), "packages", time.Second); !errors.Is(err, ErrDenied) {
				t.Fatalf("broker accepted unreviewed DNS answer set: %v", err)
			}
			fixture.dialer.mu.Lock()
			count := len(fixture.dialer.addresses)
			fixture.dialer.mu.Unlock()
			if count != 0 {
				t.Fatalf("broker opened %d numeric sockets before rejecting DNS", count)
			}
		})
	}
}

func (f *brokerFixture) close(t *testing.T) {
	t.Helper()
	f.cancel()
	_ = f.server.Close()
	select {
	case err := <-f.done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Serve() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("broker did not stop")
	}
}

func TestBrokerTunnelsOnlyProfileAliasAndBindsNumericDial(t *testing.T) {
	fixture := newBrokerFixture(t, staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}}, 4)
	defer fixture.close(t)
	connection, err := fixture.client.Dial(context.Background(), "packages", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	peer := <-fixture.dialer.peers
	defer peer.Close()
	if _, err := connection.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 7)
	if _, err := io.ReadFull(peer, buffer); err != nil || string(buffer) != "request" {
		t.Fatalf("upstream read = %q, %v", buffer, err)
	}
	if _, err := peer.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	buffer = make([]byte, 5)
	if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != "reply" {
		t.Fatalf("client read = %q, %v", buffer, err)
	}
	fixture.dialer.mu.Lock()
	addresses := append([]string(nil), fixture.dialer.addresses...)
	fixture.dialer.mu.Unlock()
	if len(addresses) != 1 || addresses[0] != "93.184.216.34:443" {
		t.Fatalf("numeric dial addresses = %v", addresses)
	}
	for _, alias := range []string{"93.184.216.34", "unknown", "packages.internal.test"} {
		if _, err := fixture.client.Dial(context.Background(), alias, time.Second); !errors.Is(err, ErrDenied) {
			t.Fatalf("alias %q error = %v", alias, err)
		}
	}
}

func TestBrokerRejectsRebindingDNSOutageReplayRevisionAndWrongPrincipal(t *testing.T) {
	rebinding := newBrokerFixture(t, staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("169.254.169.254")}}}, 4)
	if _, err := rebinding.client.Dial(context.Background(), "packages", time.Second); !errors.Is(err, ErrDenied) {
		t.Fatalf("rebinding error = %v", err)
	}
	if len(rebinding.dialer.addresses) != 0 {
		t.Fatal("rebinding opened a socket")
	}
	rebinding.close(t)
	outage := newBrokerFixture(t, staticResolver{err: errors.New("DNS unavailable")}, 4)
	if _, err := outage.client.Dial(context.Background(), "packages", time.Second); !errors.Is(err, ErrDenied) {
		t.Fatalf("DNS outage error = %v", err)
	}
	outage.close(t)

	fixture := newBrokerFixture(t, staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}}, 4)
	defer fixture.close(t)
	request, err := fixture.client.newOpen(context.Background(), "packages", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := fixture.client.execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-fixture.dialer.peers
	_ = connection.Close()
	_ = peer.Close()
	if _, err := fixture.client.execute(context.Background(), request); !errors.Is(err, ErrDenied) {
		t.Fatalf("replay error = %v", err)
	}
	driftPolicy := fixture.policy
	driftPolicy.Revision = "policy-2"
	driftClient, err := NewClient(ClientConfig{Address: fixture.server.Addr().String(), TLSConfig: fixture.clientTLS,
		Policy: driftPolicy, BrokerURI: fixture.brokerURI, BrokerDNSNames: []string{"broker.internal.test"},
		BrokerUsages: []string{"server_auth"}, OperationTimeout: 3 * time.Second, Now: time.Now, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driftClient.Dial(context.Background(), "packages", time.Second); err == nil {
		t.Fatal("policy revision drift accepted")
	}
	fixture.server.principalURI = "spiffe://sandbox-runtime.test/wrong-principal"
	if _, err := fixture.client.Dial(context.Background(), "packages", time.Second); err == nil {
		t.Fatal("wrong mTLS principal accepted")
	}
}

func TestBrokerCapacityLeaseRevocationAndCleanup(t *testing.T) {
	fixture := newBrokerFixture(t, staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}}, 1)
	blocker, err := tls.Dial("tcp", fixture.server.Addr().String(), fixture.clientTLS)
	if err != nil {
		fixture.close(t)
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(fixture.server.capacity) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, err := fixture.client.Dial(context.Background(), "packages", time.Second); err == nil {
		_ = blocker.Close()
		fixture.close(t)
		t.Fatal("capacity overflow accepted")
	}
	_ = blocker.Close()
	deadline = time.Now().Add(time.Second)
	for len(fixture.server.capacity) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	connection, err := fixture.client.Dial(context.Background(), "packages", time.Second)
	if err != nil {
		fixture.close(t)
		t.Fatal(err)
	}
	peer := <-fixture.dialer.peers
	if err := fixture.server.RevokePolicy(fixture.policy.Revision); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err := connection.Write([]byte("denied")); err == nil {
		buffer := make([]byte, 1)
		if _, readErr := connection.Read(buffer); readErr == nil {
			t.Fatal("revoked session remained usable")
		}
	}
	_ = peer.Close()
	_ = connection.Close()
	if _, err := fixture.client.Dial(context.Background(), "packages", time.Second); !errors.Is(err, ErrDenied) {
		t.Fatalf("post-revocation dial error = %v", err)
	}
	fixture.close(t)
}

func testPolicy(t *testing.T) Policy {
	t.Helper()
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	registry, err := securityprincipal.NewRegistry(digest("a"), digest("b"), map[string]securityprincipal.Role{"product_egress_broker": securityprincipal.RoleProduct})
	if err != nil {
		t.Fatal(err)
	}
	principal, _ := registry.New(securityprincipal.KindRuntimeRole, "product", securityprincipal.RoleProduct, digest("c"))
	broker, _ := registry.New(securityprincipal.KindEgressBroker, "product_egress_broker", securityprincipal.RoleProduct, digest("d"))
	policy, err := NewPolicy("product-egress", "policy-1", registry, principal, broker, 2*time.Second, 4,
		[]Target{{Alias: "packages", Host: "packages.example.test", Port: 443, Protocol: "https"}})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testTLS(t *testing.T, principalDigest, brokerDigest, principalName, brokerName string) (*tls.Config, *tls.Config) {
	t.Helper()
	_ = principalDigest
	_ = brokerDigest
	now := time.Now().UTC()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "egress test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(serial int64, uriValue string, dns []string, usage x509.ExtKeyUsage) tls.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		identity, _ := url.Parse(uriValue)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			URIs: []*url.URL{identity}, DNSNames: dns}
		der, _ := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}
	clientCertificate := issue(2, "spiffe://sandbox-runtime.test/"+principalName, nil, x509.ExtKeyUsageClientAuth)
	serverCertificate := issue(3, "spiffe://sandbox-runtime.test/"+brokerName, []string{"broker.internal.test"}, x509.ExtKeyUsageServerAuth)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: roots, Certificates: []tls.Certificate{serverCertificate}, NextProtos: []string{ProtocolID}}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "broker.internal.test",
		Certificates: []tls.Certificate{clientCertificate}, NextProtos: []string{ProtocolID}}
	return serverTLS, clientTLS
}

func TestTLSIdentityDuringVerifyConnectionKeepsPostHandshakeBoundary(t *testing.T) {
	server, client := testTLS(t, "", "", "client", "broker")
	leaf, err := x509.ParseCertificate(server.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(server.Certificates[0].Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	other, err := x509.ParseCertificate(client.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	otherURI, err := url.Parse("spiffe://sandbox-runtime.test/other")
	if err != nil {
		t.Fatal(err)
	}
	const uri = "spiffe://sandbox-runtime.test/broker"
	state := tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf, issuer},
		VerifiedChains: [][]*x509.Certificate{{leaf, issuer}}}
	verify := func(candidate tls.ConnectionState) error {
		return ValidateTLSIdentityInVerifyConnection(candidate, uri,
			[]string{"broker.internal.test"}, []string{"server_auth"})
	}
	if err := verify(state); err != nil {
		t.Fatalf("standard-verified handshake callback rejected: %v", err)
	}
	if err := ValidateTLSIdentity(state, uri, []string{"broker.internal.test"}, []string{"server_auth"}); err == nil {
		t.Fatal("post-handshake identity check accepted an unfinished handshake")
	}
	completed := state
	completed.HandshakeComplete = true
	if err := ValidateTLSIdentity(completed, uri, []string{"broker.internal.test"}, []string{"server_auth"}); err != nil {
		t.Fatalf("completed connection identity rejected: %v", err)
	}
	for name, mutate := range map[string]func(*tls.ConnectionState){
		"completed early":   func(c *tls.ConnectionState) { c.HandshakeComplete = true },
		"resumed":           func(c *tls.ConnectionState) { c.DidResume = true },
		"wrong version":     func(c *tls.ConnectionState) { c.Version = tls.VersionTLS12 },
		"missing chain":     func(c *tls.ConnectionState) { c.VerifiedChains = nil },
		"short chain":       func(c *tls.ConnectionState) { c.VerifiedChains = [][]*x509.Certificate{{leaf}} },
		"nil issuer":        func(c *tls.ConnectionState) { c.VerifiedChains[0][1] = nil },
		"empty issuer DER":  func(c *tls.ConnectionState) { changed := *issuer; changed.Raw = nil; c.VerifiedChains[0][1] = &changed },
		"ambiguous chains":  func(c *tls.ConnectionState) { c.VerifiedChains = append(c.VerifiedChains, c.VerifiedChains[0]) },
		"unbound peer leaf": func(c *tls.ConnectionState) { c.PeerCertificates = []*x509.Certificate{other, issuer} },
		"missing peer leaf": func(c *tls.ConnectionState) { c.PeerCertificates = nil },
		"extra subject": func(c *tls.ConnectionState) {
			changed := *leaf
			changed.Subject.CommonName = "extra"
			c.PeerCertificates[0] = &changed
			c.VerifiedChains[0][0] = &changed
		},
		"missing URI": func(c *tls.ConnectionState) {
			changed := *leaf
			changed.URIs = nil
			c.PeerCertificates[0] = &changed
			c.VerifiedChains[0][0] = &changed
		},
		"wrong URI": func(c *tls.ConnectionState) {
			changed := *leaf
			changed.URIs = []*url.URL{otherURI}
			c.PeerCertificates[0] = &changed
			c.VerifiedChains[0][0] = &changed
		},
		"extra URI": func(c *tls.ConnectionState) {
			changed := *leaf
			changed.URIs = []*url.URL{leaf.URIs[0], otherURI}
			c.PeerCertificates[0] = &changed
			c.VerifiedChains[0][0] = &changed
		},
		"extra DNS": func(c *tls.ConnectionState) {
			changed := *leaf
			changed.DNSNames = []string{"broker.internal.test", "other.test"}
			c.PeerCertificates[0] = &changed
			c.VerifiedChains[0][0] = &changed
		},
		"wrong EKU": func(c *tls.ConnectionState) {
			changed := *leaf
			changed.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			c.PeerCertificates[0] = &changed
			c.VerifiedChains[0][0] = &changed
		},
		"wrong key usage": func(c *tls.ConnectionState) {
			changed := *leaf
			changed.KeyUsage = x509.KeyUsageKeyEncipherment
			c.PeerCertificates[0] = &changed
			c.VerifiedChains[0][0] = &changed
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := state
			candidate.PeerCertificates = append([]*x509.Certificate(nil), state.PeerCertificates...)
			candidate.VerifiedChains = [][]*x509.Certificate{append([]*x509.Certificate(nil), state.VerifiedChains[0]...)}
			mutate(&candidate)
			if err := verify(candidate); err == nil {
				t.Fatal("unsafe handshake identity admitted")
			}
		})
	}
}
