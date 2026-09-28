package phase6egress

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
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type fakePostgresOwnSource struct {
	mu       sync.Mutex
	snapshot workloadtlsagent.Snapshot
	err      error
}

func (s *fakePostgresOwnSource) Snapshot(context.Context) (workloadtlsagent.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return workloadtlsagent.Snapshot{}, s.err
	}
	copy := s.snapshot
	copy.CertificateDER = make([][]byte, len(s.snapshot.CertificateDER))
	for index, item := range s.snapshot.CertificateDER {
		copy.CertificateDER[index] = append([]byte(nil), item...)
	}
	copy.PublicKeyDER = append([]byte(nil), s.snapshot.PublicKeyDER...)
	return copy, nil
}

func ownGuardTestMaterial(t *testing.T, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey,
	workloadpki.PostgresClientIdentity) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1000), Subject: pkix.Name{CommonName: "PostgreSQL client CA"},
		SubjectKeyId: []byte{1, 2, 3, 4, 5}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	identity := workloadpki.PostgresClientIdentity{OwnerDeployment: "provider-browser-runtime",
		DatabaseName: "provider_browser", RuntimeRole: "browser_provider_runtime", ServiceName: "postgres",
		URI:        "spiffe://sandbox-runtime.test/provider-browser-runtime",
		CommonName: workloadpki.PostgresClientCommonName("browser_provider_runtime"), MaxTTL: 15 * time.Minute}
	return ca, key, identity
}

func ownGuardTestSnapshot(t *testing.T, now time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey,
	identity workloadpki.PostgresClientIdentity, serial int64) (workloadtlsagent.Snapshot, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity.URI)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: identity.CommonName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := workloadtlsagent.Snapshot{Generation: serial, IssuerRevision: "vault-test",
		Serial: postgresOwnSerial(leaf), CertificateDER: [][]byte{der, ca.Raw}, PublicKeyDER: publicDER,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, RevocationSafeTo: now.Add(20 * time.Second)}
	return snapshot, tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key, Leaf: leaf}
}

func ownGuardFixture(t *testing.T) (*PostgresOwnGuard, *fakePostgresOwnSource, *time.Time,
	*x509.Certificate, *ecdsa.PrivateKey, workloadpki.PostgresClientIdentity, tls.Certificate) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	ca, caKey, identity := ownGuardTestMaterial(t, now)
	snapshot, certificate := ownGuardTestSnapshot(t, now, ca, caKey, identity, 1)
	source := &fakePostgresOwnSource{snapshot: snapshot}
	guard := &PostgresOwnGuard{source: source, identity: identity, issuerDER: ca.Raw,
		maximumStaleness: 30 * time.Second, timeout: time.Second, interval: 100 * time.Millisecond,
		closeBudget: time.Second, now: func() time.Time { return now },
		active: make(map[net.Conn]postgresOwnSelection)}
	return guard, source, &now, ca, caKey, identity, certificate
}

func TestPostgresOwnGuardRotationLossAndExactDrain(t *testing.T) {
	guard, source, now, ca, caKey, identity, firstCertificate := ownGuardFixture(t)
	defer guard.Close()
	if err := guard.Refresh(t.Context()); err != nil || !guard.Ready() {
		t.Fatalf("bootstrap: %v", err)
	}
	first, peer := net.Pipe()
	defer peer.Close()
	selected := postgresOwnSelection{leafDigest: postgresOwnDigest(firstCertificate.Leaf.Raw),
		issuerDigest: postgresOwnDigest(ca.Raw), serial: postgresOwnSerial(firstCertificate.Leaf)}
	if err := guard.track(first, selected); err != nil {
		t.Fatal(err)
	}
	secondSnapshot, secondCertificate := ownGuardTestSnapshot(t, *now, ca, caKey, identity, 2)
	source.mu.Lock()
	source.snapshot = secondSnapshot
	source.mu.Unlock()
	if err := guard.Refresh(t.Context()); err != nil {
		t.Fatalf("rotation refresh: %v", err)
	}
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("old leaf socket not closed: %v", err)
	}
	if err := guard.track(first, selected); err == nil {
		t.Fatal("old leaf was re-admitted after rotation")
	}
	second, secondPeer := net.Pipe()
	defer secondPeer.Close()
	selected = postgresOwnSelection{leafDigest: postgresOwnDigest(secondCertificate.Leaf.Raw),
		issuerDigest: postgresOwnDigest(ca.Raw), serial: postgresOwnSerial(secondCertificate.Leaf)}
	if err := guard.track(second, selected); err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	source.err = ErrUnavailable
	source.mu.Unlock()
	if err := guard.Refresh(t.Context()); err == nil || guard.Ready() {
		t.Fatal("signer source loss left guard ready")
	}
	if _, err := secondPeer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("source loss did not drain socket: %v", err)
	}
	source.mu.Lock()
	source.err = nil
	source.mu.Unlock()
	if err := guard.Refresh(t.Context()); err != nil || !guard.Ready() {
		t.Fatalf("fresh source recovery: %v", err)
	}
	if len(guard.active) != 0 {
		t.Fatal("drained sockets retained")
	}
}

func TestPostgresOwnGuardRejectsUnboundOrExpiredSignerSnapshot(t *testing.T) {
	guard, source, now, ca, _, _, _ := ownGuardFixture(t)
	defer guard.Close()
	source.mu.Lock()
	source.snapshot.Serial = "01:ff"
	source.mu.Unlock()
	if err := guard.Refresh(t.Context()); err == nil {
		t.Fatal("serial unbound to leaf admitted")
	}
	source.mu.Lock()
	source.snapshot.Serial = "01"
	source.snapshot.CertificateDER[1] = []byte{1}
	source.mu.Unlock()
	if err := guard.Refresh(t.Context()); err == nil {
		t.Fatal("wrong issuer admitted")
	}
	source.mu.Lock()
	source.snapshot.CertificateDER[1] = ca.Raw
	source.snapshot.RevocationSafeTo = now.Add(-time.Second)
	source.mu.Unlock()
	if err := guard.Refresh(t.Context()); err == nil {
		t.Fatal("expired signer CRL evidence admitted")
	}
}

func TestPostgresOwnGuardHardDeadlineDrainsWithoutPoll(t *testing.T) {
	guard, source, _, ca, _, _, certificate := ownGuardFixture(t)
	defer guard.Close()
	guard.now = time.Now
	source.mu.Lock()
	source.snapshot.RevocationSafeTo = time.Now().Add(200 * time.Millisecond)
	source.mu.Unlock()
	if err := guard.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer server.Close()
	selected := postgresOwnSelection{leafDigest: postgresOwnDigest(certificate.Leaf.Raw),
		issuerDigest: postgresOwnDigest(ca.Raw), serial: postgresOwnSerial(certificate.Leaf)}
	if err := guard.track(client, selected); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)
	done := make(chan error, 1)
	go func() { _, err := server.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) || guard.Ready() {
			t.Fatalf("hard CRL deadline did not close the socket: %v", err)
		}
	case <-deadline:
		t.Fatal("hard CRL deadline waited for a polling response")
	}
}

func TestPostgresOwnGuardCapturesClientLeafInRealTLSHandshake(t *testing.T) {
	guard, _, _, ca, caKey, _, clientCertificate := ownGuardFixture(t)
	defer guard.Close()
	if err := guard.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(100), NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(10 * time.Minute), DNSNames: []string{"postgres.sandbox-runtime.test"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	config := testPostgresPeerConfig(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	config.ConnConfig.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: "postgres.sandbox-runtime.test", RootCAs: roots,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &clientCertificate, nil }}
	config.BeforeConnect = func(context.Context, *pgx.ConnConfig) error { return nil }
	config.ConnConfig.AfterNetConnect = func(_ context.Context, _ *pgconn.Config, connection net.Conn) (net.Conn, error) {
		return connection, nil
	}
	if err := BindPostgresOwnGuard(config, guard); err != nil {
		t.Fatal(err)
	}
	connectionConfig := config.ConnConfig.Copy()
	if err := config.BeforeConnect(t.Context(), connectionConfig); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	server := tls.Server(right, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER, ca.Raw}, PrivateKey: serverKey}},
		ClientAuth:   tls.RequireAnyClientCert})
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Handshake() }()
	client := tls.Client(left, connectionConfig.TLSConfig)
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	wrapped, err := connectionConfig.AfterNetConnect(t.Context(), nil, client)
	if err != nil || wrapped == nil || len(guard.active) != 1 {
		t.Fatalf("actual client leaf not tracked: %v", err)
	}
	_ = right.Close()
	_ = wrapped.Close()
	if len(guard.active) != 0 {
		t.Fatal("closed TLS connection retained")
	}
}
