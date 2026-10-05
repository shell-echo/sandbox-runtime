package artifactscanner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

const testScannerURI = "spiffe://sandbox-runtime/provider-runtime"
const testScannerServerURI = "spiffe://sandbox-runtime/provider-artifact-scanner"

type scannerTestRules struct {
	mu      sync.Mutex
	digest  string
	err     error
	started chan struct{}
	release chan struct{}
}

type scannerTestPeer struct {
	mu          sync.Mutex
	ready       bool
	connections map[net.Conn]struct{}
}

func (p *scannerTestPeer) Track(connection net.Conn, _ tls.ConnectionState) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ready {
		return ErrInvalidScanProtocol
	}
	if p.connections == nil {
		p.connections = make(map[net.Conn]struct{})
	}
	p.connections[connection] = struct{}{}
	return nil
}
func (p *scannerTestPeer) Forget(connection net.Conn) {
	p.mu.Lock()
	delete(p.connections, connection)
	p.mu.Unlock()
}
func (p *scannerTestPeer) Poll(context.Context) error {
	if !p.Ready() {
		return ErrInvalidScanProtocol
	}
	return nil
}
func (*scannerTestPeer) PollInterval() time.Duration { return time.Second }
func (p *scannerTestPeer) Ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ready
}
func (p *scannerTestPeer) Close() { p.revoke() }
func (p *scannerTestPeer) revoke() {
	p.mu.Lock()
	p.ready = false
	connections := make([]net.Conn, 0, len(p.connections))
	for connection := range p.connections {
		connections = append(connections, connection)
	}
	p.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (r *scannerTestRules) Verify(ctx context.Context, _ time.Time) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r.mu.Lock()
	digest, err, started, release := r.digest, r.err, r.started, r.release
	r.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return digest, err
}

type scannerTestEngine struct {
	mu      sync.Mutex
	verdict MalwareVerdict
	err     error
	calls   int
	content []byte
	started chan struct{}
	release chan struct{}
}

func (*scannerTestEngine) Ready(context.Context) error { return nil }

func (e *scannerTestEngine) Scan(ctx context.Context, content []byte) (MalwareVerdict, error) {
	e.mu.Lock()
	e.calls++
	e.content = append([]byte(nil), content...)
	verdict, err, started, release := e.verdict, e.err, e.started, e.release
	e.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return verdict, err
}

type scannerTestTLS struct {
	server *tls.Config
	client *tls.Config
	wrong  *tls.Config
}

func newScannerTestTLS(t *testing.T) scannerTestTLS {
	t.Helper()
	now := time.Now().UTC()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "scanner-test-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(serial int64, uri string, server bool) tls.Certificate {
		leafPublic, leafPrivate, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			t.Fatal(genErr)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute),
			NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			leaf.DNSNames = []string{"scanner.sandbox-runtime.test"}
			parsed, parseErr := url.Parse(testScannerServerURI)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			leaf.URIs = []*url.URL{parsed}
		} else {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			parsed, parseErr := url.Parse(uri)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			leaf.URIs = []*url.URL{parsed}
		}
		der, issueErr := x509.CreateCertificate(rand.Reader, leaf, ca, leafPublic, private)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: leafPrivate}
	}
	server := issue(2, "", true)
	client := issue(3, testScannerURI, false)
	wrong := issue(4, "spiffe://sandbox-runtime/provider-browser-runtime", false)
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: pool, Certificates: []tls.Certificate{server}}
	serverTLS.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 ||
			len(state.PeerCertificates[0].URIs) != 1 ||
			state.PeerCertificates[0].URIs[0].String() != testScannerURI {
			return ErrInvalidScanProtocol
		}
		return nil
	}
	return scannerTestTLS{server: serverTLS,
		client: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "scanner.sandbox-runtime.test",
			Certificates: []tls.Certificate{client}},
		wrong: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "scanner.sandbox-runtime.test",
			Certificates: []tls.Certificate{wrong}}}
}

func scannerTestRequest(content []byte) artifact.Request {
	return artifact.Request{SandboxID: "sandbox-1", TenantID: "tenant-1", OperationID: "operation-1",
		AttemptID: "attempt-1", FencingToken: 2, ExpectedGeneration: 1, IdempotencyKey: "key-1",
		RequestDigest: "sha256:" + strings.Repeat("a", 64), Deadline: time.Now().UTC().Add(time.Minute),
		ArtifactReference: "artifact-ref:platform/artifact-1", SourcePath: "/outputs/report.json",
		ExpectedDigest: scanDigest(content), ExpectedMediaType: "application/json",
		MaxBytes: artifact.MaxArtifactBytes, Retention: 30 * time.Second}
}

func startScannerTestService(t *testing.T, engine *scannerTestEngine, rules *scannerTestRules) (string, scannerTestTLS, func()) {
	t.Helper()
	material := newScannerTestTLS(t)
	service, err := NewService(ServiceConfig{TLSConfig: material.server, ExpectedClientURI: testScannerURI,
		ProfileDigest: scanDigest([]byte("profile")), OperationTimeout: 5 * time.Second,
		Engine: engine, Rules: rules, Peer: &scannerTestPeer{ready: true},
		Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- service.Serve(ctx, listener) }()
	stop := func() {
		cancel()
		_ = service.Close()
		select {
		case err := <-finished:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("scanner Serve = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("scanner service did not drain")
		}
	}
	return "https://" + listener.Addr().String(), material, stop
}

func testRemoteScanner(t *testing.T, base string, material *tls.Config, rules string) *RemoteMalwareChecker {
	t.Helper()
	transportTLS := material.Clone()
	transportTLS.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 ||
			len(state.PeerCertificates[0].URIs) != 1 ||
			state.PeerCertificates[0].URIs[0].String() != testScannerServerURI {
			return ErrInvalidScanProtocol
		}
		return nil
	}
	address := strings.TrimPrefix(base, "https://")
	transport := &http.Transport{TLSClientConfig: transportTLS, DisableKeepAlives: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, ErrInvalidScanProtocol
		},
		DialTLSContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if network != "tcp" || target != address {
				return nil, ErrInvalidScanProtocol
			}
			return (&tls.Dialer{Config: transportTLS}).DialContext(ctx, network, target)
		}}
	remote, err := NewRemoteMalwareChecker(RemoteConfig{BaseURL: base, GuardedTransport: transport,
		Peer:          &scannerTestPeer{ready: true},
		ProfileDigest: scanDigest([]byte("profile")), ExpectedRuleSetDigest: rules,
		OperationTimeout: 5 * time.Second, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = remote.Close() })
	return remote
}

func TestScannerPrivateMTLSBenignInfectedAndWrongPeer(t *testing.T) {
	rulesDigest := scanDigest([]byte("verified-rules"))
	rules := &scannerTestRules{digest: rulesDigest}
	engine := &scannerTestEngine{verdict: MalwareClean}
	base, material, stop := startScannerTestService(t, engine, rules)
	defer stop()
	remote := testRemoteScanner(t, base, material.client, rulesDigest)
	content := []byte(`{"ok":true}`)
	request := scannerTestRequest(content)
	if err := remote.CheckSupport(context.Background(), request); err != nil {
		t.Fatalf("scanner readiness = %v", err)
	}
	if status, err := remote.CheckContent(context.Background(), request, content); err != nil || status != artifact.CheckPassed {
		t.Fatalf("benign scan = %s, %v", status, err)
	}
	engine.mu.Lock()
	engine.verdict = MalwareInfected
	engine.mu.Unlock()
	if status, err := remote.CheckContent(context.Background(), request, content); err != nil || status != artifact.CheckFailed {
		t.Fatalf("infected verdict = %s, %v", status, err)
	}
	engine.mu.Lock()
	if engine.calls != 2 || !bytes.Equal(engine.content, content) {
		t.Errorf("engine calls/content = %d, %q", engine.calls, engine.content)
	}
	engine.mu.Unlock()
	wrong := testRemoteScanner(t, base, material.wrong, rulesDigest)
	if err := wrong.CheckSupport(context.Background(), request); !errors.Is(err, artifact.ErrUnsupportedChecks) {
		t.Fatalf("wrong mTLS peer readiness = %v", err)
	}
}

func TestScannerRuleLossAndCanceledScanNeverReturnClean(t *testing.T) {
	rulesDigest := scanDigest([]byte("verified-rules"))
	rules := &scannerTestRules{digest: rulesDigest}
	engine := &scannerTestEngine{verdict: MalwareClean, started: make(chan struct{}, 1), release: make(chan struct{})}
	base, material, stop := startScannerTestService(t, engine, rules)
	defer stop()
	remote := testRemoteScanner(t, base, material.client, rulesDigest)
	content := []byte(`{"ok":true}`)
	request := scannerTestRequest(content)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { _, err := remote.CheckContent(ctx, request, content); finished <- err }()
	select {
	case <-engine.started:
	case <-time.After(time.Second):
		t.Fatal("scan did not enter engine")
	}
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled scan became clean")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled remote scan did not stop")
	}
	close(engine.release)
	rules.mu.Lock()
	rules.err = errors.New("stale rules")
	rules.mu.Unlock()
	if err := remote.CheckSupport(context.Background(), request); !errors.Is(err, artifact.ErrUnsupportedChecks) {
		t.Fatalf("stale rule readiness = %v", err)
	}
	if status, err := remote.CheckContent(context.Background(), request, content); status != artifact.CheckNotRun || err == nil {
		t.Fatalf("stale rule scan = %s, %v", status, err)
	}
}

func TestScannerPolicyRejectsBeforeEngineAndCapacityIsBounded(t *testing.T) {
	rulesDigest := scanDigest([]byte("verified-rules"))
	rules := &scannerTestRules{digest: rulesDigest}
	engine := &scannerTestEngine{verdict: MalwareClean, started: make(chan struct{}, 1), release: make(chan struct{})}
	base, material, stop := startScannerTestService(t, engine, rules)
	defer stop()
	remote := testRemoteScanner(t, base, material.client, rulesDigest)
	malformed := []byte(`{"duplicate":1,"duplicate":2}`)
	status, err := remote.CheckContent(context.Background(), scannerTestRequest(malformed), malformed)
	if status != artifact.CheckNotRun || !errors.Is(err, artifact.ErrUnsupportedChecks) {
		t.Fatalf("active-content rejection = %s, %v", status, err)
	}
	engine.mu.Lock()
	calls := engine.calls
	engine.mu.Unlock()
	if calls != 0 {
		t.Fatalf("malware engine called after policy rejection: %d", calls)
	}
	content := []byte(`{"safe":true}`)
	request := scannerTestRequest(content)
	finished := make(chan error, 1)
	go func() {
		_, scanErr := remote.CheckContent(context.Background(), request, content)
		finished <- scanErr
	}()
	select {
	case <-engine.started:
	case <-time.After(time.Second):
		t.Fatal("first scan did not enter engine")
	}
	second := testRemoteScanner(t, base, material.client, rulesDigest)
	status, err = second.CheckContent(context.Background(), request, content)
	if status != artifact.CheckNotRun || !errors.Is(err, artifact.ErrUnsupportedChecks) {
		t.Fatalf("over-capacity scan = %s, %v", status, err)
	}
	close(engine.release)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("first scan after capacity release = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first scan did not finish")
	}
}

func TestScannerBodyDeadlineReleasesCapacity(t *testing.T) {
	rulesDigest := scanDigest([]byte("verified-rules"))
	material := newScannerTestTLS(t)
	service, err := NewService(ServiceConfig{TLSConfig: material.server, ExpectedClientURI: testScannerURI,
		ProfileDigest: scanDigest([]byte("profile")), OperationTimeout: time.Second,
		Engine: &scannerTestEngine{verdict: MalwareClean}, Rules: &scannerTestRules{digest: rulesDigest},
		Peer:  &scannerTestPeer{ready: true},
		Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- service.Serve(ctx, listener) }()
	defer func() {
		cancel()
		_ = service.Close()
		select {
		case err := <-finished:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("drained scanner = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("scanner drain did not finish")
		}
	}()
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), material.client)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	content := []byte(`{"safe":true}`)
	request := scannerTestRequest(content)
	authority, err := NewAuthority(context.Background(), request, scanDigest([]byte("profile")), time.Now().UTC(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeAuthority(authority)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintf(connection, "POST /scan HTTP/1.1\r\nHost: scanner.sandbox-runtime.test\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n%s: %s\r\nConnection: close\r\n\r\n%s",
		len(content), scanAuthorityHeader, base64.RawURLEncoding.EncodeToString(encoded), content[:1])
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for len(service.active) == 0 && time.Now().Before(until) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(service.active) != 1 {
		t.Fatal("partial body was not admitted")
	}
	remote := testRemoteScanner(t, "https://"+listener.Addr().String(), material.client, rulesDigest)
	if status, err := remote.CheckContent(context.Background(), request, content); status != artifact.CheckNotRun || !errors.Is(err, artifact.ErrUnsupportedChecks) {
		t.Fatalf("partial-body capacity = %s, %v", status, err)
	}
	until = time.Now().Add(2 * time.Second)
	for len(service.active) != 0 && time.Now().Before(until) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(service.active) != 0 {
		t.Fatal("expired partial body retained scan capacity")
	}
	if status, err := remote.CheckContent(context.Background(), request, content); status != artifact.CheckPassed || err != nil {
		t.Fatalf("capacity after body timeout = %s, %v", status, err)
	}
}

func TestScannerReadinessRuleVerificationIsCapacityBounded(t *testing.T) {
	rulesDigest := scanDigest([]byte("verified-rules"))
	rules := &scannerTestRules{digest: rulesDigest, started: make(chan struct{}, 1), release: make(chan struct{})}
	base, material, stop := startScannerTestService(t, &scannerTestEngine{verdict: MalwareClean}, rules)
	defer stop()
	first := testRemoteScanner(t, base, material.client, rulesDigest)
	second := testRemoteScanner(t, base, material.client, rulesDigest)
	result := make(chan error, 1)
	go func() { result <- first.CheckSupport(context.Background(), artifact.Request{}) }()
	select {
	case <-rules.started:
	case <-time.After(time.Second):
		t.Fatal("first readiness did not begin rule verification")
	}
	if err := second.CheckSupport(context.Background(), artifact.Request{}); !errors.Is(err, artifact.ErrUnsupportedChecks) {
		t.Fatalf("concurrent readiness = %v", err)
	}
	close(rules.release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("first readiness after release = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first readiness did not finish")
	}
}

func TestScannerTransportRequiresExplicitPeerGuardAndFailsClosedOnLoss(t *testing.T) {
	rulesDigest := scanDigest([]byte("verified-rules"))
	base, material, stop := startScannerTestService(t,
		&scannerTestEngine{verdict: MalwareClean}, &scannerTestRules{digest: rulesDigest})
	defer stop()
	if _, err := NewRemoteMalwareChecker(RemoteConfig{BaseURL: base, ProfileDigest: scanDigest([]byte("profile")),
		ExpectedRuleSetDigest: rulesDigest, OperationTimeout: time.Second,
		Clock: func() time.Time { return time.Now().UTC() }}); !errors.Is(err, ErrInvalidScanProtocol) {
		t.Fatalf("implicit/default transport = %v", err)
	}
	remote := testRemoteScanner(t, base, material.client, rulesDigest)
	content := []byte(`{"safe":true}`)
	request := scannerTestRequest(content)
	remote.config.Peer = &scannerTestPeer{ready: false}
	if err := remote.CheckSupport(context.Background(), request); !errors.Is(err, artifact.ErrUnsupportedChecks) {
		t.Fatalf("peer-source-loss readiness = %v", err)
	}
	if status, err := remote.CheckContent(context.Background(), request, content); status != artifact.CheckNotRun ||
		!errors.Is(err, artifact.ErrUnsupportedChecks) {
		t.Fatalf("peer-source-loss scan = %s, %v", status, err)
	}
}

func TestScannerEstablishedPeerLossClosesScanAndReleasesCapacity(t *testing.T) {
	rulesDigest := scanDigest([]byte("verified-rules"))
	material := newScannerTestTLS(t)
	peer := &scannerTestPeer{ready: true}
	engine := &scannerTestEngine{verdict: MalwareClean, started: make(chan struct{}, 1), release: make(chan struct{})}
	service, err := NewService(ServiceConfig{TLSConfig: material.server, ExpectedClientURI: testScannerURI,
		ProfileDigest: scanDigest([]byte("profile")), OperationTimeout: 5 * time.Second,
		Engine: engine, Rules: &scannerTestRules{digest: rulesDigest}, Peer: peer,
		Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- service.Serve(ctx, listener) }()
	defer func() {
		cancel()
		_ = service.Close()
		close(engine.release)
		select {
		case err := <-finished:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("scanner drain after peer loss = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("scanner did not drain after peer loss")
		}
	}()
	remote := testRemoteScanner(t, "https://"+listener.Addr().String(), material.client, rulesDigest)
	content := []byte(`{"safe":true}`)
	request := scannerTestRequest(content)
	result := make(chan error, 1)
	go func() {
		_, scanErr := remote.CheckContent(context.Background(), request, content)
		result <- scanErr
	}()
	select {
	case <-engine.started:
	case <-time.After(time.Second):
		t.Fatal("established scan did not enter engine")
	}
	peer.revoke()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("established peer loss returned a clean scan")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("established scan survived peer loss")
	}
	until := time.Now().Add(time.Second)
	for len(service.active) != 0 && time.Now().Before(until) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(service.active) != 0 {
		t.Fatal("peer loss retained scanner capacity")
	}
	if err := remote.CheckSupport(context.Background(), request); err == nil {
		t.Fatal("revoked scanner peer remained ready")
	}
}
