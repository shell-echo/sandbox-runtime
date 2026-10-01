package workloadtlsagent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

type fakeCertificateClient struct {
	mu               sync.Mutex
	now              *time.Time
	policy           workloadpki.Policy
	ca               *x509.Certificate
	caKey            *ecdsa.PrivateKey
	serial           int64
	crlNumber        int64
	forceCRLNumber   int64
	revoked          map[string]struct{}
	issueErr         error
	revocationErr    error
	revokeErr        error
	revokeCalls      []string
	issuedPrivateKey bool
}

func newFakeCertificateClient(t *testing.T, now *time.Time, policy workloadpki.Policy) *fakeCertificateClient {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "workload TLS test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte{1, 2, 3, 4, 5}}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeCertificateClient{now: now, policy: policy, ca: ca, caKey: caKey, serial: 0x010203040506070, revoked: make(map[string]struct{})}
}

func (f *fakeCertificateClient) Issue(_ context.Context, csrPEM []byte, ttl time.Duration) (workloadpki.IssuedCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issueErr != nil {
		return workloadpki.IssuedCertificate{}, f.issueErr
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return workloadpki.IssuedCertificate{}, err
	}
	f.serial++
	serial := new(big.Int).SetInt64(f.serial)
	notBefore, notAfter := f.now.Add(-time.Second), f.now.Add(ttl)
	identity, _ := url.Parse(f.policy.URI)
	subject := pkix.Name{}
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	if f.policy.Purpose == workloadpki.PostgresClientPurpose {
		if workloadpki.ValidatePostgresClientCSR(csrPEM, f.policy.Postgres) != nil {
			return workloadpki.IssuedCertificate{}, workloadpki.ErrDenied
		}
		subject.CommonName = f.policy.Postgres.CommonName
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	template := &x509.Certificate{SerialNumber: serial, NotBefore: notBefore, NotAfter: notAfter, DNSNames: append([]string(nil), f.policy.DNSNames...),
		Subject: subject, BasicConstraintsValid: true, URIs: []*url.URL{identity}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, f.ca, csr.PublicKey, f.caKey)
	if err != nil {
		return workloadpki.IssuedCertificate{}, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})
	return workloadpki.IssuedCertificate{IssuerRevision: "vault-pki-test", CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		IssuingCAPEM: caPEM, CAChainPEM: caPEM, Serial: serialString(serial), NotBefore: notBefore, NotAfter: notAfter}, nil
}

func (f *fakeCertificateClient) Revocations(context.Context) (workloadpki.RevocationSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revocationErr != nil {
		return workloadpki.RevocationSnapshot{}, f.revocationErr
	}
	entries := make([]x509.RevocationListEntry, 0, len(f.revoked))
	for serial := range f.revoked {
		value, ok := serialBigInt(serial)
		if !ok {
			return workloadpki.RevocationSnapshot{}, ErrUnavailable
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: value, RevocationTime: *f.now})
	}
	thisUpdate, nextUpdate := f.now.Add(-time.Second), f.now.Add(10*time.Minute)
	f.crlNumber++
	crlNumber := f.crlNumber
	if f.forceCRLNumber > 0 {
		crlNumber = f.forceCRLNumber
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(crlNumber), ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate, RevokedCertificateEntries: entries}, f.ca, f.caKey)
	if err != nil {
		return workloadpki.RevocationSnapshot{}, err
	}
	return workloadpki.RevocationSnapshot{IssuerRevision: "vault-crl-test", DER: der, ThisUpdate: thisUpdate, NextUpdate: nextUpdate}, nil
}

func (f *fakeCertificateClient) Revoke(_ context.Context, serial string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeCalls = append(f.revokeCalls, serial)
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revoked[serial] = struct{}{}
	return nil
}

func TestManagerCloseKeepsFailedRevocationResultAfterLocalKeyDestruction(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	manager, client := testManager(t, &now)
	if err := manager.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.revokeErr = errors.New("remote revocation unavailable")
	if err := manager.Close(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first Close() error = %v", err)
	}
	if manager.current != nil || manager.previous != nil || !manager.closed || len(client.revokeCalls) != 1 {
		t.Fatal("failed remote revocation retained a local key or did not attempt exactly once")
	}
	client.revokeErr = nil
	if err := manager.Close(context.Background()); !errors.Is(err, ErrUnavailable) || len(client.revokeCalls) != 1 {
		t.Fatalf("repeated Close() erased pending revocation: error=%v attempts=%d", err, len(client.revokeCalls))
	}
}

func testManager(t *testing.T, now *time.Time) (*Manager, *fakeCertificateClient) {
	t.Helper()
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	registry, err := securityprincipal.NewRegistry(digest("a"), digest("b"), nil)
	if err != nil {
		t.Fatal(err)
	}
	requester, _ := registry.New(securityprincipal.KindTLSAgent, "product_tls_agent", securityprincipal.RoleProduct, digest("c"))
	subject, _ := registry.New(securityprincipal.KindRuntimeRole, "product", securityprincipal.RoleProduct, digest("d"))
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := workloadpki.Policy{ID: "product-runtime-tls", Registry: registry, Requester: requester, Subject: subject,
		TrustDomain: "sandbox-runtime.test", URI: "spiffe://sandbox-runtime.test/product-runtime", DNSNames: []string{"product.example.test"},
		Usages: []string{"client_auth", "server_auth"}, VaultRole: "product-runtime", MaxTTLSeconds: 360, PublicKey: publicKey}
	client := newFakeCertificateClient(t, now, policy)
	manager, err := New(Config{Policy: policy, Client: client, TTL: 6 * time.Minute, RotateAfter: 2 * time.Minute, Overlap: 30 * time.Second,
		CheckInterval: time.Second, RevocationPollInterval: 10 * time.Second, RevocationMaxStaleness: 30 * time.Second,
		OperationTimeout: 3 * time.Second, Now: func() time.Time { return *now }, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	return manager, client
}

func TestManagerUsesSeparatePostgresClientCSRAndSigner(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	digest := "sha256:" + strings.Repeat("a", 64)
	registry, err := securityprincipal.NewRegistry(digest, digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	requester, err := registry.New(securityprincipal.KindTLSAgent, "provider_tls_agent", securityprincipal.RoleProvider, digest)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := registry.New(securityprincipal.KindRuntimeRole, "provider", securityprincipal.RoleProvider, digest)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	postgres := workloadpki.PostgresClientIdentity{OwnerDeployment: "provider-browser-runtime",
		DatabaseName: "provider_browser", RuntimeRole: "browser_provider_runtime", ServiceName: "postgres",
		URI: "spiffe://sandbox-runtime.test/provider-browser-runtime", MaxTTL: 7 * time.Minute}
	postgres.CommonName = workloadpki.PostgresClientCommonName(postgres.RuntimeRole)
	policy := workloadpki.Policy{ID: "provider-browser-postgres-client", Registry: registry,
		Requester: requester, Subject: subject, TrustDomain: "sandbox-runtime.test",
		URI: postgres.URI, Usages: []string{"client_auth"}, VaultRole: "provider-browser-postgres-client",
		MaxTTLSeconds: 420, PublicKey: publicKey, Purpose: workloadpki.PostgresClientPurpose, Postgres: postgres}
	client := newFakeCertificateClient(t, &now, policy)
	manager, err := New(Config{Policy: policy, Client: client, TTL: 6 * time.Minute,
		RotateAfter: 2 * time.Minute, Overlap: 30 * time.Second, CheckInterval: time.Second,
		RevocationPollInterval: 10 * time.Second, RevocationMaxStaleness: 30 * time.Second,
		OperationTimeout: 3 * time.Second, Now: func() time.Time { return now }, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(context.Background())
	if err := manager.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	certificate, err := manager.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || workloadpki.ValidatePostgresClientLeaf(leaf, postgres, now) != nil {
		t.Fatalf("dedicated PostgreSQL leaf = %v", err)
	}
	if leaf.Subject.CommonName != postgres.CommonName || len(leaf.DNSNames) != 0 {
		t.Fatal("agent emitted ordinary or unbound PostgreSQL certificate")
	}
}

func TestManagerGeneratesLocalKeySignsAndRotatesWithBoundedOverlap(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	manager, client := testManager(t, &now)
	if err := manager.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := manager.Snapshot()
	if err != nil || first.Generation != 1 || len(first.PublicKeyDER) == 0 || len(first.CertificateDER) < 2 {
		t.Fatalf("Snapshot() = %#v, %v", first, err)
	}
	digest := sha256.Sum256([]byte("TLS transcript"))
	signature, err := manager.Sign(first.Generation, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(first.PublicKeyDER)
	if err != nil || !ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), digest[:], signature) {
		t.Fatal("agent signature did not verify")
	}
	now = now.Add(2 * time.Minute)
	if err := manager.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := manager.Snapshot()
	if err != nil || second.Generation != 2 || second.Serial == first.Serial {
		t.Fatalf("rotated Snapshot() = %#v, %v", second, err)
	}
	if _, err := manager.Sign(first.Generation, digest[:], crypto.SHA256); err != nil {
		t.Fatal("previous generation was not retained during overlap")
	}
	now = now.Add(31 * time.Second)
	if err := manager.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Sign(first.Generation, digest[:], crypto.SHA256); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("retired generation sign error = %v", err)
	}
	first.Destroy()
	second.Destroy()
	if err := manager.Close(context.Background()); err != nil || len(client.revokeCalls) != 2 {
		t.Fatalf("Close() error=%v revocations=%#v", err, client.revokeCalls)
	}
}

func TestManagerRejectsRevokedAndStaleCRLAndClockRollback(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	manager, client := testManager(t, &now)
	if err := manager.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	client.revoked[snapshot.Serial] = struct{}{}
	client.mu.Unlock()
	now = now.Add(10 * time.Second)
	if err := manager.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Snapshot(); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked Snapshot() error = %v", err)
	}
	if err := manager.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if current, err := manager.Snapshot(); err != nil || current.Serial == snapshot.Serial {
		t.Fatalf("replacement Snapshot() = %#v, %v", current, err)
	}
	client.revocationErr = ErrUnavailable
	now = now.Add(31 * time.Second)
	if err := manager.Tick(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stale CRL Tick() error = %v", err)
	}
	if _, err := manager.Snapshot(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stale CRL Snapshot() error = %v", err)
	}
	now = now.Add(-time.Minute)
	if _, err := manager.Snapshot(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("clock rollback Snapshot() error = %v", err)
	}
}

func TestManagerRejectsCRLRollbackAndOwnLeafResurrection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	manager, client := testManager(t, &now)
	if err := manager.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := manager.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()
	client.mu.Lock()
	client.forceCRLNumber = 1
	client.mu.Unlock()
	now = now.Add(10 * time.Second)
	if err := manager.Tick(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("same-number changed CRL admitted: %v", err)
	}
	if _, err := manager.Snapshot(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("same-number changed CRL left signer available: %v", err)
	}
	client.mu.Lock()
	client.forceCRLNumber = 0
	client.mu.Unlock()
	if err := manager.Tick(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("fatal CRL equivocation recovered in the same process: %v", err)
	}

	now = time.Now().UTC().Truncate(time.Second)
	manager, client = testManager(t, &now)
	if err := manager.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, err := manager.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	defer current.Destroy()
	client.mu.Lock()
	client.revoked[current.Serial] = struct{}{}
	client.mu.Unlock()
	now = now.Add(10 * time.Second)
	if err := manager.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Snapshot(); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked own leaf admitted: %v", err)
	}
	client.mu.Lock()
	delete(client.revoked, current.Serial)
	client.mu.Unlock()
	if err := manager.refreshRevocations(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unexpired observed revocation disappeared without rejection: %v", err)
	}
	if _, err := manager.Snapshot(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("resurrected own leaf left signer available: %v", err)
	}
}

func TestManagerKeepsCurrentOnlyUntilSafetyDeadlineOnIssuanceOutage(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	manager, client := testManager(t, &now)
	if err := manager.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.issueErr = ErrUnavailable
	now = now.Add(2 * time.Minute)
	if err := manager.Tick(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("rotation outage error = %v", err)
	}
	// A missed rotation may use only its explicitly bounded overlap window.
	now = now.Add(31 * time.Second)
	if _, err := manager.Snapshot(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unsafe certificate remained available: %v", err)
	}
}

func serialBigInt(serial string) (*big.Int, bool) {
	decoded, err := hex.DecodeString(strings.ReplaceAll(serial, ":", ""))
	if err != nil || len(decoded) == 0 {
		return nil, false
	}
	return new(big.Int).SetBytes(decoded), true
}
