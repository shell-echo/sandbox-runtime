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
	revoked          map[string]struct{}
	issueErr         error
	revocationErr    error
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
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
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
	template := &x509.Certificate{SerialNumber: serial, NotBefore: notBefore, NotAfter: notAfter, DNSNames: append([]string(nil), f.policy.DNSNames...),
		URIs: []*url.URL{identity}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
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
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(f.serial), ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate, RevokedCertificateEntries: entries}, f.ca, f.caKey)
	if err != nil {
		return workloadpki.RevocationSnapshot{}, err
	}
	return workloadpki.RevocationSnapshot{IssuerRevision: "vault-crl-test", DER: der, ThisUpdate: thisUpdate, NextUpdate: nextUpdate}, nil
}

func (f *fakeCertificateClient) Revoke(_ context.Context, serial string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[serial] = struct{}{}
	f.revokeCalls = append(f.revokeCalls, serial)
	return nil
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
