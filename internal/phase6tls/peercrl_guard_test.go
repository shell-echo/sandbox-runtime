package phase6tls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type testGuardClient struct {
	response        workloadtlsagent.PeerCRLResponse
	responseForCall func(int32) workloadtlsagent.PeerCRLResponse
	calls           atomic.Int32
	err             error
}

func (c *testGuardClient) PeerCRL(ctx context.Context, binding workloadtlsagent.PeerCRLBinding,
	issuerDER []byte) (workloadtlsagent.PeerCRLResponse, error) {
	call := c.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return workloadtlsagent.PeerCRLResponse{}, err
	}
	r := c.response
	if c.responseForCall != nil {
		r = c.responseForCall(call)
	}
	r.IssuerDER = append([]byte(nil), r.IssuerDER...)
	r.CRLDER = append([]byte(nil), r.CRLDER...)
	return r, c.err
}

func TestPeerCRLGuardSerializesConcurrentPullsWithoutFalseRollback(t *testing.T) {
	f := newGuardFixture(t)
	first, second := f.response(t, 1, false, "fixed-source"), f.response(t, 2, false, "fixed-source")
	started := make(chan struct{})
	f.client.responseForCall = func(call int32) workloadtlsagent.PeerCRLResponse {
		if call == 1 {
			close(started)
			time.Sleep(40 * time.Millisecond)
			return first
		}
		return second
	}
	result := make(chan error, 2)
	go func() { result <- f.guard.CheckHandshake(t.Context(), f.state) }()
	<-started
	go func() { result <- f.guard.CheckHandshake(t.Context(), f.state) }()
	for range 2 {
		if err := <-result; err != nil {
			t.Fatalf("concurrent fresh pull falsely rolled back: %v", err)
		}
	}
	if !f.guard.Ready() || f.guard.number.Cmp(big.NewInt(2)) != 0 {
		t.Fatal("latest CRL was not retained")
	}
}

func (c *testGuardClient) BootstrapPeerCRL(ctx context.Context, binding workloadtlsagent.PeerCRLBinding,
	issuerDigest string) (workloadtlsagent.PeerCRLResponse, error) {
	return c.PeerCRL(ctx, binding, nil)
}

type guardFixture struct {
	now       time.Time
	issuer    *x509.Certificate
	issuerKey *ecdsa.PrivateKey
	leafKey   *ecdsa.PrivateKey
	leaf      *x509.Certificate
	state     tls.ConnectionState
	guard     *PeerCRLGuard
	client    *testGuardClient
	clock     *time.Time
}

func newGuardFixture(t *testing.T) guardFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "guard issuer"},
		SubjectKeyId: []byte{1, 2, 3, 4}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(10 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	clock := &now
	client := &testGuardClient{}
	guard := &PeerCRLGuard{binding: workloadtlsagent.PeerCRLBinding{
		ProfileDigest: "sha256:" + hex.EncodeToString(make([]byte, 32)), EdgeID: "test-edge",
		SourceMappingDigest:  "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		LocalPrincipalDigest: "sha256:" + hex.EncodeToString(make([]byte, 32)), Direction: "inbound",
		PeerAnchorID: "client-ca"}, expectedIssuerDigest: peerCRLIssuerDigest(issuer.Raw),
		client: client, pullPermit: make(chan struct{}, 1), maxStaleness: 30 * time.Second,
		timeout: time.Second, pollInterval: 2 * time.Second, closeBudget: time.Second,
		now:             func() time.Time { return *clock },
		observedRevoked: make(map[string]revokedPeerObservation), active: make(map[net.Conn]tls.ConnectionState)}
	t.Cleanup(guard.Close)
	return guardFixture{now: now, issuer: issuer, issuerKey: issuerKey, leaf: leaf, leafKey: leafKey,
		state: tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf, issuer},
			VerifiedChains: [][]*x509.Certificate{{leaf, issuer}}}, guard: guard, client: client, clock: clock}
}

func (f guardFixture) response(t *testing.T, number int64, revoked bool, sourceID string) workloadtlsagent.PeerCRLResponse {
	t.Helper()
	list := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: f.now.Add(-time.Minute),
		NextUpdate: f.now.Add(5 * time.Minute)}
	if revoked {
		list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: f.leaf.SerialNumber,
			RevocationTime: f.now.Add(-time.Second)}}
	}
	der, err := x509.CreateRevocationList(rand.Reader, list, f.issuer, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerHash, crlHash := sha256.Sum256(f.issuer.Raw), sha256.Sum256(der)
	return workloadtlsagent.PeerCRLResponse{Protocol: workloadtlsagent.PeerCRLProtocolID,
		Type: workloadtlsagent.PeerCRLSnapshotType, ProfileDigest: f.guard.binding.ProfileDigest,
		SourceMappingDigest: f.guard.binding.SourceMappingDigest,
		EdgeID:              f.guard.binding.EdgeID, Direction: f.guard.binding.Direction,
		PeerAnchorID: f.guard.binding.PeerAnchorID, IssuerDigest: "sha256:" + hex.EncodeToString(issuerHash[:]),
		SourceID: sourceID, IssuerDER: append([]byte(nil), f.issuer.Raw...),
		CRLDER: der, CRLDigest: "sha256:" + hex.EncodeToString(crlHash[:]),
		CRLNumber: big.NewInt(number).String(), ThisUpdate: list.ThisUpdate.UTC().Format(time.RFC3339Nano),
		NextUpdate: list.NextUpdate.UTC().Format(time.RFC3339Nano), CollectedAt: f.clock.UTC().Format(time.RFC3339Nano)}
}

func TestPeerCRLGuardRequiresFreshEvidenceAndRejectsRevokedPeer(t *testing.T) {
	f := newGuardFixture(t)
	if f.guard.Ready() {
		t.Fatal("new process inherited good revocation state")
	}
	f.client.response = f.response(t, 1, false, "fixed-source")
	if err := f.guard.CheckHandshake(t.Context(), f.state); err != nil || !f.guard.Ready() || f.client.calls.Load() != 1 {
		t.Fatalf("fresh good peer admission failed: %v", err)
	}
	f.client.response = f.response(t, 2, true, "fixed-source")
	if err := f.guard.CheckHandshake(t.Context(), f.state); !errors.Is(err, workloadpki.ErrPeerRevoked) {
		t.Fatalf("revoked verified peer accepted: %v", err)
	}
	f.client.response = f.response(t, 3, false, "fixed-source")
	if err := f.guard.CheckHandshake(t.Context(), f.state); !errors.Is(err, ErrPeerCRLUnavailable) || f.guard.Ready() {
		t.Fatalf("revoked-to-good resurrection admitted: %v", err)
	}
}

func TestPeerCRLGuardBootstrapWithoutPeerAndPinnedIssuer(t *testing.T) {
	f := newGuardFixture(t)
	f.client.response = f.response(t, 1, false, "fixed-source")
	if err := f.guard.Bootstrap(t.Context()); err != nil || !f.guard.Ready() || f.client.calls.Load() != 1 {
		t.Fatalf("zero-peer bootstrap failed: %v", err)
	}
	f.guard.expectedIssuerDigest = "sha256:" + hex.EncodeToString(make([]byte, 32))
	if err := f.guard.CheckHandshake(t.Context(), f.state); !errors.Is(err, ErrPeerCRLUnavailable) {
		t.Fatalf("actual peer issuer escaped pinned binding: %v", err)
	}
	f.guard.expectedIssuerDigest = peerCRLIssuerDigest(f.issuer.Raw)
	f.client.response = f.response(t, 2, false, "fixed-source")
	f.client.response.IssuerDER[0] ^= 1
	if err := f.guard.Bootstrap(t.Context()); !errors.Is(err, ErrPeerCRLUnavailable) {
		t.Fatalf("mismatched bootstrap issuer accepted: %v", err)
	}
}

func TestPeerCRLGuardRejectsAgentSourceMappingDrift(t *testing.T) {
	f := newGuardFixture(t)
	f.client.response = f.response(t, 1, false, "fixed-source")
	f.client.response.SourceMappingDigest = "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{2}, 32))
	if err := f.guard.Bootstrap(t.Context()); !errors.Is(err, ErrPeerCRLUnavailable) || f.guard.Ready() {
		t.Fatalf("agent mapping drift admitted at zero-peer bootstrap: %v", err)
	}
}

func TestPeerCRLGuardPollBootstrapsWithoutActiveConnection(t *testing.T) {
	f := newGuardFixture(t)
	f.client.response = f.response(t, 1, false, "fixed-source")
	if err := f.guard.Poll(t.Context()); err != nil || !f.guard.Ready() {
		t.Fatalf("zero-connection poll did not establish readiness: %v", err)
	}
	f.client.err = workloadpki.ErrUnavailable
	if err := f.guard.Poll(t.Context()); !errors.Is(err, ErrPeerCRLUnavailable) || f.guard.Ready() {
		t.Fatalf("zero-connection source loss retained readiness: %v", err)
	}
}

func TestGuardedClientTransportDrainsRevokedRealHTTPSConnection(t *testing.T) {
	f := newGuardFixture(t)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: new(big.Int).Set(f.leaf.SerialNumber),
		NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(10 * time.Minute),
		DNSNames: []string{"provider.example.test"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, f.issuer, &serverKey.PublicKey, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("open"))
		writer.(http.Flusher).Flush()
		<-request.Context().Done()
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER, f.issuer.Raw}, PrivateKey: serverKey}}}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(f.issuer)
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: "provider.example.test"}
	f.client.response = f.response(t, 1, false, "fixed-source")
	transport := guardedClientTransport(clientTLS, func(tls.ConnectionState) error { return nil }, f.guard,
		server.Listener.Addr().String())
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("real HTTPS peer admission: %v", err)
	}
	defer response.Body.Close()
	f.guard.mu.Lock()
	activeBefore := len(f.guard.active)
	f.guard.mu.Unlock()
	if activeBefore != 1 {
		t.Fatalf("HTTPS connection not tracked: %d", activeBefore)
	}
	f.client.response = f.response(t, 2, true, "fixed-source")
	if err := f.guard.Poll(t.Context()); err != nil {
		t.Fatalf("signed revocation poll: %v", err)
	}
	f.guard.mu.Lock()
	activeAfter := len(f.guard.active)
	f.guard.mu.Unlock()
	if activeAfter != 0 {
		t.Fatalf("revoked HTTPS connection remained tracked: %d", activeAfter)
	}
}

func TestPeerCRLGuardLatchesRollbackSourceAndClockDrift(t *testing.T) {
	for name, change := range map[string]func(*guardFixture, *testing.T){
		"CRL number rollback": func(f *guardFixture, t *testing.T) { f.client.response = f.response(t, 1, false, "fixed-source") },
		"same number changed": func(f *guardFixture, t *testing.T) { f.client.response = f.response(t, 2, true, "fixed-source") },
		"source switched":     func(f *guardFixture, t *testing.T) { f.client.response = f.response(t, 3, false, "other-source") },
		"clock rollback":      func(f *guardFixture, t *testing.T) { *f.clock = f.now.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newGuardFixture(t)
			f.client.response = f.response(t, 2, false, "fixed-source")
			if err := f.guard.CheckHandshake(t.Context(), f.state); err != nil {
				t.Fatal(err)
			}
			change(&f, t)
			if err := f.guard.CheckHandshake(t.Context(), f.state); !errors.Is(err, ErrPeerCRLUnavailable) || f.guard.Ready() {
				t.Fatalf("rollback/source drift admitted: %v", err)
			}
		})
	}
}

func TestPeerCRLGuardRejectsStaleCollectionAndAuthorityLoss(t *testing.T) {
	f := newGuardFixture(t)
	f.client.response = f.response(t, 1, false, "fixed-source")
	f.client.response.CollectedAt = f.now.Add(-time.Minute).Format(time.RFC3339Nano)
	if err := f.guard.CheckHandshake(t.Context(), f.state); !errors.Is(err, ErrPeerCRLUnavailable) || f.guard.Ready() {
		t.Fatalf("stale source collection admitted: %v", err)
	}
	f.client.response = f.response(t, 1, false, "fixed-source")
	f.client.err = workloadpki.ErrUnavailable
	if err := f.guard.CheckHandshake(t.Context(), f.state); !errors.Is(err, ErrPeerCRLUnavailable) || f.guard.Ready() {
		t.Fatalf("authority loss admitted: %v", err)
	}
	f.client.err = nil
	if err := f.guard.CheckHandshake(t.Context(), f.state); err != nil || !f.guard.Ready() {
		t.Fatalf("fresh source recovery rejected: %v", err)
	}
}

func TestPeerCRLGuardRealTLSHandshakeAdmission(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "good", true: "revoked"}[revoked], func(t *testing.T) {
			f := newGuardFixture(t)
			f.client.response = f.response(t, 1, revoked, "fixed-source")
			serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(900), NotBefore: f.now.Add(-time.Minute),
				NotAfter: f.now.Add(10 * time.Minute), DNSNames: []string{"provider.example.test"},
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, f.issuer, &serverKey.PublicKey, f.issuerKey)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(f.issuer)
			serverConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
				Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER, f.issuer.Raw}, PrivateKey: serverKey}},
				ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: roots,
				VerifyConnection: func(state tls.ConnectionState) error {
					return f.guard.CheckHandshake(t.Context(), state)
				}}
			clientConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
				RootCAs: roots, ServerName: "provider.example.test",
				Certificates: []tls.Certificate{{Certificate: [][]byte{f.leaf.Raw, f.issuer.Raw}, PrivateKey: f.leafKey}}}
			serverPipe, clientPipe := net.Pipe()
			defer serverPipe.Close()
			defer clientPipe.Close()
			deadline := time.Now().Add(3 * time.Second)
			_ = serverPipe.SetDeadline(deadline)
			_ = clientPipe.SetDeadline(deadline)
			server := tls.Server(serverPipe, serverConfig)
			client := tls.Client(clientPipe, clientConfig)
			serverDone := make(chan error, 1)
			go func() {
				err := server.Handshake()
				if err != nil {
					_ = serverPipe.Close()
				}
				serverDone <- err
			}()
			clientErr := client.Handshake()
			serverErr := <-serverDone
			if !revoked && (clientErr != nil || serverErr != nil || f.client.calls.Load() != 1) {
				t.Fatalf("fresh good TLS peer rejected: client=%v server=%v calls=%d", clientErr, serverErr, f.client.calls.Load())
			}
			if revoked && (!errors.Is(serverErr, workloadpki.ErrPeerRevoked) || f.client.calls.Load() != 1) {
				t.Fatalf("revoked verified TLS peer admitted: client=%v server=%v calls=%d", clientErr, serverErr, f.client.calls.Load())
			}
		})
	}
}

func TestPeerCRLGuardConcurrentFreshPullsDoNotInventClockRollback(t *testing.T) {
	f := newGuardFixture(t)
	f.client.response = f.response(t, 1, false, "fixed-source")
	var ticks atomic.Int64
	f.guard.now = func() time.Time { return f.now.Add(time.Duration(ticks.Add(1)) * time.Nanosecond) }
	const concurrent = 96
	var group sync.WaitGroup
	errorsSeen := make(chan error, concurrent)
	for range concurrent {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsSeen <- f.guard.CheckHandshake(t.Context(), f.state)
		}()
	}
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("valid concurrent pull falsely marked rollback: %v", err)
		}
	}
	if !f.guard.Ready() || f.client.calls.Load() != concurrent {
		t.Fatal("concurrent fresh authority reads did not preserve readiness")
	}
}

func TestPeerCRLGuardPollDrainsRevokedAndUnavailableConnections(t *testing.T) {
	for name, fail := range map[string]bool{"revoke": false, "authority loss": true} {
		t.Run(name, func(t *testing.T) {
			f := newGuardFixture(t)
			f.client.response = f.response(t, 1, false, "fixed-source")
			if err := f.guard.CheckHandshake(t.Context(), f.state); err != nil {
				t.Fatal(err)
			}
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			if err := f.guard.Track(local, f.state); err != nil {
				t.Fatal(err)
			}
			if fail {
				f.client.err = workloadpki.ErrUnavailable
			} else {
				f.client.response = f.response(t, 2, true, "fixed-source")
			}
			err := f.guard.Poll(t.Context())
			if fail && !errors.Is(err, ErrPeerCRLUnavailable) {
				t.Fatalf("authority loss did not fail closed: %v", err)
			}
			if !fail && err != nil {
				t.Fatalf("revocation poll failed: %v", err)
			}
			_ = remote.SetReadDeadline(time.Now().Add(time.Second))
			var one [1]byte
			if _, readErr := remote.Read(one[:]); readErr == nil {
				t.Fatal("revoked or unverifiable live connection remained open")
			}
			f.guard.mu.Lock()
			active := len(f.guard.active)
			f.guard.mu.Unlock()
			if active != 0 {
				t.Fatalf("tracked connections retained after drain: %d", active)
			}
		})
	}
}

func TestPeerCRLBudgetRespectsDeclaredDrain(t *testing.T) {
	budget, err := derivePeerCRLBudget(30*time.Second, 10*time.Second, 3*time.Second)
	if err != nil || budget.timeout != 2*time.Second || budget.interval != 2*time.Second ||
		budget.close != time.Second {
		t.Fatalf("10s drain budget = %+v, %v", budget, err)
	}
	if 2*budget.timeout+budget.interval+budget.close+2*time.Second >= 10*time.Second {
		t.Fatal("budget lacks strict 10s margin")
	}
	for _, candidate := range []struct{ stale, drain, timeout time.Duration }{
		{30 * time.Second, 0, 3 * time.Second},
		{30 * time.Second, 500 * time.Millisecond, 3 * time.Second},
		{30 * time.Second, 10 * time.Second, 31 * time.Second},
	} {
		if _, err := derivePeerCRLBudget(candidate.stale, candidate.drain, candidate.timeout); err == nil {
			t.Fatalf("unsafe drain budget accepted: %+v", candidate)
		}
	}
}

func TestPeerCRLGuardPermitWaitConsumesSinglePullDeadline(t *testing.T) {
	f := newGuardFixture(t)
	f.guard.timeout = 50 * time.Millisecond
	f.guard.pullPermit <- struct{}{}
	start := time.Now()
	if err := f.guard.Bootstrap(t.Context()); !errors.Is(err, ErrPeerCRLUnavailable) {
		t.Fatalf("occupied permit did not fail closed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("permit wait reset pull deadline: %v", elapsed)
	}
	<-f.guard.pullPermit
	if f.guard.Ready() {
		t.Fatal("timed-out permit wait advertised readiness")
	}
}

func TestPeerCRLGuardLateOldPullCannotResurrectAfterPermitTimeout(t *testing.T) {
	f := newGuardFixture(t)
	good := f.response(t, 1, false, "fixed-source")
	f.guard.timeout = 500 * time.Millisecond
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	f.client.responseForCall = func(call int32) workloadtlsagent.PeerCRLResponse {
		if call == 1 {
			close(started)
			<-release
		}
		return good
	}
	first := make(chan error, 1)
	go func() { first <- f.guard.CheckHandshake(t.Context(), f.state) }()
	<-started
	f.guard.timeout = 50 * time.Millisecond
	if err := f.guard.Poll(t.Context()); !errors.Is(err, ErrPeerCRLUnavailable) {
		t.Fatalf("contended poll did not fail closed: %v", err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-first; !errors.Is(err, ErrPeerCRLUnavailable) {
		t.Fatalf("old in-flight pull resurrected authority: %v", err)
	}
	if f.guard.Ready() {
		t.Fatal("old response restored readiness after newer failure")
	}
	f.guard.timeout = time.Second
	f.client.responseForCall = nil
	f.client.response = good
	if err := f.guard.Bootstrap(t.Context()); err != nil || !f.guard.Ready() {
		t.Fatalf("fresh post-failure pull did not recover: %v", err)
	}
}

func TestPeerCRLGuardEvidenceExpiryDrainsBeforeNextPoll(t *testing.T) {
	now := time.Now()
	first, second := net.Pipe()
	defer second.Close()
	guard := &PeerCRLGuard{maxStaleness: time.Second, pollInterval: 2 * time.Second,
		collectedAt: now, nextUpdate: now.Add(40 * time.Millisecond),
		active: map[net.Conn]tls.ConnectionState{first: {}}, now: time.Now}
	guard.mu.Lock()
	guard.scheduleEvidenceExpiryLocked(now)
	guard.mu.Unlock()
	defer guard.Close()
	_ = second.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var one [1]byte
	if _, err := second.Read(one[:]); err == nil {
		t.Fatal("expired CRL retained active connection")
	}
	guard.mu.Lock()
	active, unavailable := len(guard.active), guard.unavailable
	guard.mu.Unlock()
	if active != 0 || !unavailable {
		t.Fatalf("expiry did not clear guard state: active=%d unavailable=%v", active, unavailable)
	}
}

type blockingCloseConn struct {
	net.Conn
	release <-chan struct{}
}

func (c blockingCloseConn) Close() error {
	<-c.release
	return c.Conn.Close()
}

func TestPeerCRLCloseBudgetDoesNotSeriallyBlockOtherPeers(t *testing.T) {
	blocked, blockedPeer := net.Pipe()
	defer blockedPeer.Close()
	other, otherPeer := net.Pipe()
	defer otherPeer.Close()
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	if closeTrackedConnections([]net.Conn{blockingCloseConn{Conn: blocked, release: release}, other}, 50*time.Millisecond) {
		t.Fatal("blocked collection reported within total close budget")
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("collection close waited beyond budget: %v", elapsed)
	}
	_ = otherPeer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var one [1]byte
	if _, err := otherPeer.Read(one[:]); err == nil {
		t.Fatal("one slow close blocked another peer")
	}
}
