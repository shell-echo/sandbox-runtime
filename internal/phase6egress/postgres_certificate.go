package phase6egress

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/remotetls"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

// newPostgresClientCertificate checks the second, PostgreSQL-only signer at
// construction and on every handshake. A role's ordinary empty-Subject TLS
// certificate cannot pass this verifier. The signer remains in its own agent.
func newPostgresClientCertificate(ctx context.Context, roots *x509.CertPool,
	identity workloadpki.PostgresClientIdentity, source remotetls.CertificateSource,
	now func() time.Time) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	if ctx == nil || ctx.Err() != nil || roots == nil || identity.Validate() != nil || source == nil || now == nil || now().IsZero() {
		return nil, ErrUnavailable
	}
	rootCopy := roots.Clone()
	load := func(loadCtx context.Context) (*tls.Certificate, error) {
		if loadCtx == nil || loadCtx.Err() != nil {
			return nil, ErrUnavailable
		}
		certificate, err := source(loadCtx)
		if err != nil || loadCtx.Err() != nil || len(certificate.Certificate) < 2 || len(certificate.Certificate) > 9 {
			return nil, ErrUnavailable
		}
		chain := make([][]byte, len(certificate.Certificate))
		for index, item := range certificate.Certificate {
			if len(item) < 1 || len(item) > 64<<10 {
				return nil, ErrUnavailable
			}
			chain[index] = bytes.Clone(item)
		}
		certificate.Certificate = chain
		if validatePostgresClientCertificate(certificate, rootCopy, identity, now()) != nil {
			return nil, ErrUnavailable
		}
		leaf, _ := x509.ParseCertificate(certificate.Certificate[0])
		certificate.Leaf = leaf
		return &certificate, nil
	}
	bootstrap, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := load(bootstrap); err != nil {
		return nil, ErrUnavailable
	}
	return func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if request == nil {
			return nil, ErrUnavailable
		}
		return load(request.Context())
	}, nil
}

func validatePostgresClientCertificate(certificate tls.Certificate, roots *x509.CertPool,
	identity workloadpki.PostgresClientIdentity, now time.Time) error {
	if identity.Validate() != nil || roots == nil || now.IsZero() || certificate.PrivateKey == nil ||
		len(certificate.Certificate) < 2 || len(certificate.Certificate) > 9 ||
		len(certificate.OCSPStaple) != 0 || len(certificate.SignedCertificateTimestamps) != 0 ||
		len(certificate.SupportedSignatureAlgorithms) != 0 {
		return ErrUnavailable
	}
	parsed := make([]*x509.Certificate, 0, len(certificate.Certificate))
	intermediates := x509.NewCertPool()
	for index, raw := range certificate.Certificate {
		if len(raw) < 1 || len(raw) > 64<<10 {
			return ErrUnavailable
		}
		item, err := x509.ParseCertificate(raw)
		if err != nil || index > 0 && (!item.IsCA || now.Before(item.NotBefore) || !now.Before(item.NotAfter)) {
			return ErrUnavailable
		}
		parsed = append(parsed, item)
		if index > 0 {
			intermediates.AddCert(item)
		}
	}
	leaf := parsed[0]
	if certificate.Leaf != nil && !bytes.Equal(certificate.Leaf.Raw, leaf.Raw) ||
		workloadpki.ValidatePostgresClientLeaf(leaf, identity, now) != nil {
		return ErrUnavailable
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return ErrUnavailable
	}
	actualPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return ErrUnavailable
	}
	expectedPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(actualPublic, expectedPublic) {
		return ErrUnavailable
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return ErrUnavailable
	}
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return ErrUnavailable
	}
	signature, err := signer.Sign(rand.Reader, challenge[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(publicKey, challenge[:], signature) {
		return ErrUnavailable
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || len(chains) != 1 || len(chains[0]) != len(parsed) {
		return ErrUnavailable
	}
	for index := range parsed {
		if !bytes.Equal(chains[0][index].Raw, parsed[index].Raw) {
			return ErrUnavailable
		}
	}
	return nil
}
