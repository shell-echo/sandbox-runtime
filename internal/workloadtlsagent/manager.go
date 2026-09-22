// Package workloadtlsagent owns workload TLS private keys, certificate
// rotation and revocation state. Role processes receive public chains and a
// constrained signing capability; private keys never leave this package's
// agent process.
package workloadtlsagent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

var (
	ErrUnavailable = errors.New("workload TLS agent unavailable")
	ErrRevoked     = errors.New("workload TLS certificate revoked")
)

type CertificateClient interface {
	Issue(context.Context, []byte, time.Duration) (workloadpki.IssuedCertificate, error)
	Revocations(context.Context) (workloadpki.RevocationSnapshot, error)
	Revoke(context.Context, string) error
}

type Config struct {
	Policy                 workloadpki.Policy
	Client                 CertificateClient
	TTL                    time.Duration
	RotateAfter            time.Duration
	Overlap                time.Duration
	CheckInterval          time.Duration
	RevocationPollInterval time.Duration
	RevocationMaxStaleness time.Duration
	OperationTimeout       time.Duration
	Now                    func() time.Time
	Random                 io.Reader
}

type Snapshot struct {
	Generation       int64
	IssuerRevision   string
	Serial           string
	CertificateDER   [][]byte
	PublicKeyDER     []byte
	NotBefore        time.Time
	NotAfter         time.Time
	RevocationSafeTo time.Time
}

func (s *Snapshot) Destroy() {
	if s == nil {
		return
	}
	for _, certificate := range s.CertificateDER {
		clear(certificate)
	}
	clear(s.PublicKeyDER)
	s.CertificateDER, s.PublicKeyDER = nil, nil
}

type keyMaterial struct {
	generation     int64
	key            *ecdsa.PrivateKey
	certificateDER [][]byte
	issuerRevision string
	serial         string
	notBefore      time.Time
	notAfter       time.Time
	rotateAt       time.Time
	retireAt       time.Time
	revoked        bool
}

type Manager struct {
	mu                    sync.RWMutex
	config                Config
	current               *keyMaterial
	previous              *keyMaterial
	lastNow               time.Time
	lastRevocationSuccess time.Time
	revocationNextUpdate  time.Time
	revokedSerials        map[string]struct{}
	nextRevocationPoll    time.Time
	closing               bool
	closed                bool
}

func New(config Config) (*Manager, error) {
	if config.Policy.Validate() != nil || config.Client == nil || config.TTL < time.Minute || config.TTL > time.Hour ||
		config.RotateAfter < time.Second || config.RotateAfter > config.TTL*2/3 || config.Overlap < 0 || config.Overlap >= config.RotateAfter ||
		config.CheckInterval < 100*time.Millisecond || config.CheckInterval > time.Minute || config.RevocationPollInterval < time.Second ||
		config.RevocationPollInterval > time.Minute || config.RevocationMaxStaleness < time.Second || config.RevocationMaxStaleness > 5*time.Minute ||
		config.OperationTimeout < time.Second || config.OperationTimeout > time.Minute || config.Now == nil || config.Now().IsZero() || config.Random == nil {
		return nil, ErrUnavailable
	}
	return &Manager{config: config, revokedSerials: make(map[string]struct{})}, nil
}

func NewProduction(config Config) (*Manager, error) {
	if config.Random != nil {
		return nil, ErrUnavailable
	}
	config.Random = rand.Reader
	return New(config)
}

func (m *Manager) Bootstrap(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrUnavailable
	}
	if err := m.rotate(ctx, true); err != nil {
		return err
	}
	return m.refreshRevocations(ctx)
}

func (m *Manager) Run(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrUnavailable
	}
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_ = m.Tick(ctx)
		}
	}
}

func (m *Manager) Tick(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrUnavailable
	}
	now, err := m.observeTime()
	if err != nil {
		return err
	}
	m.mu.RLock()
	if m.closed || m.closing {
		m.mu.RUnlock()
		return ErrUnavailable
	}
	poll := m.nextRevocationPoll.IsZero() || !now.Before(m.nextRevocationPoll)
	rotate := m.current == nil || !now.Before(m.current.rotateAt) || m.current.revoked
	m.mu.RUnlock()
	var firstErr error
	if err := m.retirePrevious(ctx, now, false); err != nil {
		firstErr = err
	}
	if rotate {
		if err := m.rotate(ctx, false); err != nil && firstErr == nil {
			firstErr = err
		}
		poll = true
	}
	if poll {
		if err := m.refreshRevocations(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *Manager) Snapshot() (Snapshot, error) {
	now, err := m.observeTime()
	if err != nil {
		return Snapshot{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed || m.current == nil || m.current.revoked || now.Before(m.current.notBefore) || !now.Before(m.current.notAfter) {
		if m.current != nil && m.current.revoked {
			return Snapshot{}, ErrRevoked
		}
		return Snapshot{}, ErrUnavailable
	}
	safety := m.safetyDeadlineLocked()
	if safety.IsZero() || !now.Before(safety) {
		return Snapshot{}, ErrUnavailable
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&m.current.key.PublicKey)
	if err != nil {
		return Snapshot{}, ErrUnavailable
	}
	return Snapshot{Generation: m.current.generation, IssuerRevision: m.current.issuerRevision, Serial: m.current.serial,
		CertificateDER: cloneDER(m.current.certificateDER), PublicKeyDER: publicKey, NotBefore: m.current.notBefore,
		NotAfter: m.current.notAfter, RevocationSafeTo: safety}, nil
}

func (m *Manager) Certificate() (tls.Certificate, error) {
	snapshot, err := m.Snapshot()
	if err != nil {
		return tls.Certificate{}, err
	}
	defer snapshot.Destroy()
	publicKey, err := x509.ParsePKIXPublicKey(snapshot.PublicKeyDER)
	if err != nil {
		return tls.Certificate{}, ErrUnavailable
	}
	return tls.Certificate{Certificate: cloneDER(snapshot.CertificateDER), PrivateKey: &managerSigner{manager: m,
		generation: snapshot.Generation, publicKey: publicKey}, Leaf: mustParseCertificate(snapshot.CertificateDER[0])}, nil
}

type managerSigner struct {
	manager    *Manager
	generation int64
	publicKey  crypto.PublicKey
}

func (s *managerSigner) Public() crypto.PublicKey {
	if s == nil {
		return nil
	}
	return s.publicKey
}

func (s *managerSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s == nil || s.manager == nil {
		return nil, ErrUnavailable
	}
	return s.manager.Sign(s.generation, digest, opts)
}

func (m *Manager) Sign(generation int64, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(digest) != sha256.Size || opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, ErrUnavailable
	}
	now, err := m.observeTime()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || !now.Before(m.safetyDeadlineLocked()) {
		return nil, ErrUnavailable
	}
	material := m.current
	if material == nil || material.generation != generation {
		material = m.previous
	}
	if material == nil || material.generation != generation || material.revoked || now.Before(material.notBefore) || !now.Before(material.notAfter) ||
		(!material.retireAt.IsZero() && !now.Before(material.retireAt)) {
		return nil, ErrUnavailable
	}
	signature, err := ecdsa.SignASN1(m.config.Random, material.key, digest)
	if err != nil {
		return nil, ErrUnavailable
	}
	return signature, nil
}

func (m *Manager) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	if m.closing {
		m.mu.Unlock()
		return ErrUnavailable
	}
	m.closing = true
	current, previous := m.current, m.previous
	m.mu.Unlock()
	var result error
	// Revoke the current certificate last: it is still needed to authenticate
	// the controller's own final Vault revocation calls.
	for _, material := range []*keyMaterial{previous, current} {
		if material == nil {
			continue
		}
		if ctx != nil && material.serial != "" {
			if err := m.config.Client.Revoke(ctx, material.serial); err != nil && result == nil {
				result = ErrUnavailable
			}
		}
	}
	m.mu.Lock()
	m.closed, m.closing = true, false
	m.current, m.previous = nil, nil
	m.mu.Unlock()
	destroyMaterial(previous)
	destroyMaterial(current)
	return result
}

func (m *Manager) rotate(ctx context.Context, initial bool) error {
	operationContext, cancel := context.WithTimeout(ctx, m.config.OperationTimeout)
	defer cancel()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), m.config.Random)
	if err != nil {
		return ErrUnavailable
	}
	identity, err := url.Parse(m.config.Policy.URI)
	if err != nil {
		destroyPrivateKey(privateKey)
		return ErrUnavailable
	}
	csrDER, err := x509.CreateCertificateRequest(m.config.Random, &x509.CertificateRequest{Subject: pkix.Name{},
		DNSNames: append([]string(nil), m.config.Policy.DNSNames...), URIs: []*url.URL{identity}}, privateKey)
	if err != nil {
		destroyPrivateKey(privateKey)
		return ErrUnavailable
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	clear(csrDER)
	issued, err := m.config.Client.Issue(operationContext, csrPEM, m.config.TTL)
	clear(csrPEM)
	if err != nil {
		destroyPrivateKey(privateKey)
		return normalizeClientError(err)
	}
	defer issued.Destroy()
	material, err := materialFromIssued(privateKey, issued, m.config.RotateAfter)
	if err != nil {
		destroyPrivateKey(privateKey)
		return err
	}
	now, err := m.observeTime()
	if err != nil {
		destroyMaterial(material)
		return err
	}
	if err := m.retirePrevious(ctx, now, true); err != nil {
		destroyMaterial(material)
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, revoked := m.revokedSerials[material.serial]
	if m.closed || m.closing || revoked {
		destroyMaterial(material)
		return ErrRevoked
	}
	if m.current != nil {
		if initial {
			destroyMaterial(material)
			return ErrUnavailable
		}
		m.current.retireAt = now.Add(m.config.Overlap)
		m.previous = m.current
		material.generation = m.current.generation + 1
	} else {
		material.generation = 1
	}
	m.current = material
	m.nextRevocationPoll = time.Time{}
	return nil
}

func (m *Manager) refreshRevocations(ctx context.Context) error {
	operationContext, cancel := context.WithTimeout(ctx, m.config.OperationTimeout)
	defer cancel()
	snapshot, err := m.config.Client.Revocations(operationContext)
	if err != nil {
		return normalizeClientError(err)
	}
	defer snapshot.Destroy()
	list, err := x509.ParseRevocationList(snapshot.DER)
	if err != nil || !list.ThisUpdate.Equal(snapshot.ThisUpdate) || !list.NextUpdate.Equal(snapshot.NextUpdate) {
		return ErrUnavailable
	}
	m.mu.RLock()
	var issuerDER []byte
	if m.current != nil && len(m.current.certificateDER) > 1 {
		issuerDER = append([]byte(nil), m.current.certificateDER[1]...)
	}
	m.mu.RUnlock()
	issuer, issuerErr := x509.ParseCertificate(issuerDER)
	clear(issuerDER)
	if issuerErr != nil || !issuer.IsCA || list.CheckSignatureFrom(issuer) != nil {
		return ErrUnavailable
	}
	now, err := m.observeTime()
	if err != nil || now.Before(snapshot.ThisUpdate) || !now.Before(snapshot.NextUpdate) {
		return ErrUnavailable
	}
	revoked := make(map[string]struct{}, len(list.RevokedCertificateEntries))
	for _, entry := range list.RevokedCertificateEntries {
		revoked[serialString(entry.SerialNumber)] = struct{}{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing {
		return ErrUnavailable
	}
	m.revokedSerials = revoked
	m.lastRevocationSuccess = now
	m.revocationNextUpdate = snapshot.NextUpdate
	m.nextRevocationPoll = now.Add(m.config.RevocationPollInterval)
	if m.current != nil {
		_, m.current.revoked = revoked[m.current.serial]
	}
	if m.previous != nil {
		_, m.previous.revoked = revoked[m.previous.serial]
	}
	return nil
}

func (m *Manager) observeTime() (time.Time, error) {
	if m == nil || m.config.Now == nil {
		return time.Time{}, ErrUnavailable
	}
	now := m.config.Now().UTC()
	if now.IsZero() {
		return time.Time{}, ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.lastNow.IsZero() && now.Before(m.lastNow) {
		m.closed = true
		return time.Time{}, ErrUnavailable
	}
	m.lastNow = now
	return now, nil
}

func (m *Manager) revocationSafetyDeadlineLocked() time.Time {
	if m.lastRevocationSuccess.IsZero() || m.revocationNextUpdate.IsZero() {
		return time.Time{}
	}
	safety := m.lastRevocationSuccess.Add(m.config.RevocationMaxStaleness)
	if m.revocationNextUpdate.Before(safety) {
		safety = m.revocationNextUpdate
	}
	return safety
}

func (m *Manager) safetyDeadlineLocked() time.Time {
	safety := m.revocationSafetyDeadlineLocked()
	if m.current == nil {
		return time.Time{}
	}
	rotationSafety := m.current.rotateAt.Add(m.config.Overlap)
	for _, candidate := range []time.Time{rotationSafety, m.current.notAfter} {
		if safety.IsZero() || candidate.Before(safety) {
			safety = candidate
		}
	}
	return safety
}

func (m *Manager) retirePrevious(ctx context.Context, now time.Time, force bool) error {
	m.mu.RLock()
	previous := m.previous
	eligible := previous != nil && (force || !previous.retireAt.IsZero() && !now.Before(previous.retireAt))
	m.mu.RUnlock()
	if !eligible {
		return nil
	}
	operationContext, cancel := context.WithTimeout(ctx, m.config.OperationTimeout)
	defer cancel()
	if err := m.config.Client.Revoke(operationContext, previous.serial); err != nil {
		return normalizeClientError(err)
	}
	m.mu.Lock()
	if m.previous == previous {
		m.previous = nil
	}
	m.mu.Unlock()
	destroyMaterial(previous)
	return nil
}

func materialFromIssued(privateKey *ecdsa.PrivateKey, issued workloadpki.IssuedCertificate, rotateAfter time.Duration) (*keyMaterial, error) {
	certificateBlock, trailing := pem.Decode(issued.CertificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, ErrUnavailable
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, ErrUnavailable
	}
	publicKey, ecdsaKey := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ecdsaKey || !publicKey.Equal(&privateKey.PublicKey) || serialString(certificate.SerialNumber) != issued.Serial ||
		!certificate.NotBefore.Equal(issued.NotBefore) || !certificate.NotAfter.Equal(issued.NotAfter) {
		return nil, ErrUnavailable
	}
	chain := [][]byte{append([]byte(nil), certificateBlock.Bytes...)}
	remaining := issued.CAChainPEM
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(chain) >= 9 {
			return nil, ErrUnavailable
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, ErrUnavailable
		}
		chain = append(chain, append([]byte(nil), block.Bytes...))
		remaining = rest
	}
	if len(chain) < 2 {
		return nil, ErrUnavailable
	}
	rotateAt := issued.NotBefore.Add(rotateAfter)
	maximum := issued.NotBefore.Add(issued.NotAfter.Sub(issued.NotBefore) * 2 / 3)
	if rotateAt.After(maximum) {
		rotateAt = maximum
	}
	return &keyMaterial{key: privateKey, certificateDER: chain, issuerRevision: issued.IssuerRevision, serial: issued.Serial,
		notBefore: issued.NotBefore, notAfter: issued.NotAfter, rotateAt: rotateAt}, nil
}

func destroyMaterial(material *keyMaterial) {
	if material == nil {
		return
	}
	destroyPrivateKey(material.key)
	for _, certificate := range material.certificateDER {
		clear(certificate)
	}
	material.key, material.certificateDER = nil, nil
}

func destroyPrivateKey(key *ecdsa.PrivateKey) {
	if key == nil {
		return
	}
	key.D.SetInt64(0)
	key.X, key.Y = nil, nil
}

func cloneDER(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = append([]byte(nil), values[index]...)
	}
	return result
}

func serialString(value *big.Int) string {
	if value == nil {
		return ""
	}
	bytesValue := value.Bytes()
	parts := make([]byte, 0, len(bytesValue)*3-1)
	for index, item := range bytesValue {
		if index > 0 {
			parts = append(parts, ':')
		}
		encoded := make([]byte, 2)
		hex.Encode(encoded, []byte{item})
		parts = append(parts, encoded...)
	}
	return string(parts)
}

func normalizeClientError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, workloadpki.ErrDenied) {
		return workloadpki.ErrDenied
	}
	return ErrUnavailable
}
