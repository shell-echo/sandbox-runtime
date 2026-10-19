//go:build linux && integration

package phase6tls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

// TestHeldPeerAgentProcess is invoked as a separate Linux process by the
// integration harness. Its JSON configuration and issuer key stay private to
// this process. A ready line certifies only signer socket startup.
func TestHeldPeerAgentProcess(t *testing.T) {
	configPath := os.Getenv("PEER_AGENT_CONFIG")
	if configPath == "" {
		t.Skip("explicit peer agent fixture required")
	}
	document, err := secretfile.Read(configPath, 1<<20)
	if err != nil {
		t.Fatal("peer agent fixture config unavailable")
	}
	defer clear(document)
	var config peerFixtureAgentConfig
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		t.Fatal("invalid peer agent fixture config")
	}
	clear(document)
	defer clear(config.IssuerKeyPEM)
	authority, err := loadPeerFixtureAuthority(config)
	if err != nil {
		t.Fatal("peer agent fixture authority unavailable")
	}
	client, err := newPeerFixtureCertificateClient(authority)
	if err != nil {
		t.Fatal("peer agent fixture issuer unavailable")
	}
	clear(config.IssuerKeyPEM)
	defer client.destroy()
	identity := authority.subject.TLS
	requestTTL, err := phase6security.Slice6ManagedCertificateRequestTTL(identity.TTLSeconds, identity.RotateAfterSeconds)
	if err != nil {
		t.Fatal("peer agent fixture certificate lifetime invalid")
	}
	manager, err := workloadtlsagent.NewProduction(workloadtlsagent.Config{Policy: authority.policy, Client: client,
		TTL: time.Duration(requestTTL) * time.Second, RotateAfter: time.Duration(identity.RotateAfterSeconds) * time.Second,
		Overlap: time.Duration(identity.OverlapSeconds) * time.Second, CheckInterval: time.Second,
		RevocationPollInterval: time.Second,
		RevocationMaxStaleness: time.Duration(identity.RevocationMaxStalenessSeconds) * time.Second,
		OperationTimeout:       5 * time.Second, Now: time.Now})
	if err != nil {
		t.Fatal("peer agent manager unavailable")
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(closeCtx)
	}()
	bootstrapCtx, bootstrapCancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = manager.Bootstrap(bootstrapCtx)
	bootstrapCancel()
	if err != nil {
		t.Fatal("peer agent bootstrap failed")
	}
	syscall.Umask(0o077)
	binding := authority.binding
	server, err := workloadtlsagent.Listen(workloadtlsagent.ServerConfig{SocketPath: binding.SocketPath,
		SocketUID: binding.AgentUID, SocketGID: binding.SubjectGID, AgentGID: binding.AgentGID,
		ExpectedClientUID: binding.SubjectUID, ExpectedClientGID: binding.SubjectGID,
		MaxConnections: 8, ReplayCapacity: 64, Now: time.Now, PeerCRLProvider: authority}, manager)
	if err != nil {
		t.Fatal("peer agent signer socket unavailable")
	}
	defer server.Close()
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, 600*time.Second)
	defer cancel()
	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatal("peer agent certificate snapshot unavailable")
	}
	serial := snapshot.Serial
	snapshot.Destroy()
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal("peer agent groups unavailable")
	}
	ready, err := json.Marshal(struct {
		Event     string `json:"event"`
		PID       int    `json:"pid"`
		UID       int    `json:"uid"`
		GID       int    `json:"gid"`
		Groups    []int  `json:"groups"`
		Serial    string `json:"serial"`
		Subject   string `json:"subject"`
		Socket    string `json:"socket"`
		LeafFault string `json:"leaf_fault"`
	}{Event: "agent-ready", PID: os.Getpid(), UID: os.Getuid(), GID: os.Getgid(), Groups: groups,
		Serial: serial, Subject: config.Subject, Socket: binding.SocketPath, LeafFault: config.LeafFault})
	if err != nil {
		t.Fatal("peer agent ready encoding failed")
	}
	if _, err := fmt.Fprintln(os.Stdout, string(ready)); err != nil {
		t.Fatal("peer agent ready output failed")
	}
	results := make(chan error, 2)
	go func() { results <- manager.Run(ctx) }()
	go func() { results <- server.Serve(ctx) }()
	first := <-results
	timedOut := ctx.Err() == context.DeadlineExceeded
	cancel()
	_ = server.Close()
	second := <-results
	if timedOut || first != nil && !errors.Is(first, context.Canceled) ||
		second != nil && !errors.Is(second, context.Canceled) {
		t.Fatal("peer agent process ended abnormally")
	}
}

type peerFixtureCertificateClient struct {
	mu      sync.Mutex
	policy  workloadpki.Policy
	issuer  *x509.Certificate
	key     *ecdsa.PrivateKey
	crlDER  []byte
	fault   string
	revoked map[string]bool // test-only Close receipt; no production revocation claim
}

func newPeerFixtureCertificateClient(a *peerFixtureAuthority) (*peerFixtureCertificateClient, error) {
	block, trailing := pem.Decode(a.config.IssuerKeyPEM)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, workloadtlsagent.ErrUnavailable
	}
	defer clear(block.Bytes)
	var key *ecdsa.PrivateKey
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*ecdsa.PrivateKey)
	default:
		return nil, workloadtlsagent.ErrUnavailable
	}
	public, ok := a.issuer.PublicKey.(*ecdsa.PublicKey)
	if err != nil || key == nil || !ok || !public.Equal(&key.PublicKey) {
		return nil, workloadtlsagent.ErrUnavailable
	}
	return &peerFixtureCertificateClient{policy: a.policy, issuer: a.issuer, key: key,
		crlDER: bytes.Clone(a.config.OwnCRLDER), fault: a.config.LeafFault,
		revoked: make(map[string]bool)}, nil
}

func (c *peerFixtureCertificateClient) Issue(ctx context.Context, csrPEM []byte, ttl time.Duration) (workloadpki.IssuedCertificate, error) {
	if ctx == nil || ctx.Err() != nil || ttl < time.Minute || ttl > time.Duration(c.policy.MaxTTLSeconds)*time.Second {
		return workloadpki.IssuedCertificate{}, workloadtlsagent.ErrUnavailable
	}
	block, trailing := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(trailing)) != 0 {
		return workloadpki.IssuedCertificate{}, workloadtlsagent.ErrUnavailable
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || len(csr.URIs) != 1 || csr.URIs[0].String() != c.policy.URI ||
		!reflect.DeepEqual(csr.DNSNames, c.policy.DNSNames) {
		return workloadpki.IssuedCertificate{}, workloadtlsagent.ErrUnavailable
	}
	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return workloadpki.IssuedCertificate{}, workloadtlsagent.ErrUnavailable
	}
	serialBytes[0] &= 0x7f
	serialBytes[0] |= 0x01
	serial := new(big.Int).SetBytes(serialBytes)
	identity, _ := url.Parse(c.policy.URI)
	dnsNames := append([]string(nil), c.policy.DNSNames...)
	usages := make([]x509.ExtKeyUsage, 0, len(c.policy.Usages))
	for _, usage := range c.policy.Usages {
		switch usage {
		case "client_auth":
			usages = append(usages, x509.ExtKeyUsageClientAuth)
		case "server_auth":
			usages = append(usages, x509.ExtKeyUsageServerAuth)
		default:
			return workloadpki.IssuedCertificate{}, workloadtlsagent.ErrUnavailable
		}
	}
	switch c.fault {
	case "uri":
		identity, _ = url.Parse("spiffe://fault.invalid/wrong-subject")
	case "dns":
		dnsNames = []string{"fault.invalid"}
	case "eku":
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{},
		NotBefore: now.Add(-time.Second), NotAfter: now.Add(ttl), BasicConstraintsValid: true,
		DNSNames: dnsNames, URIs: []*url.URL{identity}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usages}
	der, err := x509.CreateCertificate(rand.Reader, template, c.issuer, csr.PublicKey, c.key)
	if err != nil {
		return workloadpki.IssuedCertificate{}, workloadtlsagent.ErrUnavailable
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return workloadpki.IssuedCertificate{}, workloadtlsagent.ErrUnavailable
	}
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.issuer.Raw})
	return workloadpki.IssuedCertificate{IssuerRevision: "peer-fixture-general", CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		IssuingCAPEM: issuerPEM, CAChainPEM: bytes.Clone(issuerPEM), Serial: peerFixtureSerial(leaf.SerialNumber),
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
}

func (c *peerFixtureCertificateClient) Revocations(ctx context.Context) (workloadpki.RevocationSnapshot, error) {
	if ctx == nil || ctx.Err() != nil {
		return workloadpki.RevocationSnapshot{}, workloadtlsagent.ErrUnavailable
	}
	list, err := x509.ParseRevocationList(c.crlDER)
	if err != nil {
		return workloadpki.RevocationSnapshot{}, workloadtlsagent.ErrUnavailable
	}
	return workloadpki.RevocationSnapshot{IssuerRevision: "peer-fixture-general", DER: bytes.Clone(c.crlDER),
		ThisUpdate: list.ThisUpdate, NextUpdate: list.NextUpdate}, nil
}

func (c *peerFixtureCertificateClient) Revoke(ctx context.Context, serial string) error {
	if ctx == nil || ctx.Err() != nil || serial == "" {
		return workloadtlsagent.ErrUnavailable
	}
	c.mu.Lock()
	c.revoked[serial] = true
	c.mu.Unlock()
	return nil
}

func (c *peerFixtureCertificateClient) destroy() {
	if c == nil {
		return
	}
	clear(c.crlDER)
	if c.key != nil {
		c.key.D.SetInt64(0)
		c.key.X, c.key.Y = nil, nil
	}
}

func peerFixtureSerial(value *big.Int) string {
	if value == nil {
		return ""
	}
	bytesValue := value.Bytes()
	parts := make([]string, len(bytesValue))
	for index, b := range bytesValue {
		parts[index] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}
