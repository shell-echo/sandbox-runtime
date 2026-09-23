package providerapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"
)

// RemoteServerIdentity is the exact, profile-bound identity of a TLS-agent
// issued server certificate. The signer, not this process, owns the key.
type RemoteServerIdentity struct {
	URI      string
	DNSNames []string
	MaxTTL   time.Duration
}

type RemoteClientIdentity struct {
	URI      string
	DNSNames []string
}

// LoadMTLSConfigRemote uses a live signer for each new handshake. Both CA
// bundles are pinned independently: the server issuer is not implicitly a
// trusted client issuer. A signer outage fails new handshakes closed.
func LoadMTLSConfigRemote(serverCAPEM, clientCAPEM []byte, client RemoteClientIdentity, identity RemoteServerIdentity,
	certificate func(context.Context) (tls.Certificate, error), now func() time.Time) (*tls.Config, error) {
	if certificate == nil || now == nil || now().IsZero() || identity.URI == "" ||
		identity.MaxTTL < time.Minute || identity.MaxTTL > time.Hour {
		return nil, errors.New("invalid remote mTLS server identity")
	}
	serverRoots, err := loadCertPoolMaterial(serverCAPEM, now())
	if err != nil {
		return nil, fmt.Errorf("remote server CA: %w", err)
	}
	clientRoots, err := loadCertPoolMaterial(clientCAPEM, now())
	if err != nil {
		return nil, fmt.Errorf("remote client CA: %w", err)
	}
	admission, err := newClientIdentityAdmission([]string{client.URI})
	if err != nil {
		return nil, err
	}
	load := func(ctx context.Context) (*tls.Certificate, error) {
		if ctx == nil {
			ctx = context.Background()
		}
		issued, err := certificate(ctx)
		if err != nil {
			return nil, errors.New("remote TLS signer unavailable")
		}
		if err := validateRemoteServerCertificate(issued, serverRoots, identity, now()); err != nil {
			return nil, err
		}
		return &issued, nil
	}
	// Bootstrap is an actual agent/issuer check; a listener must not appear
	// ready with a missing or mismatched signer.
	if _, err := load(context.Background()); err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
		VerifyConnection: func(state tls.ConnectionState) error {
			if admission.VerifyConnection(state) != nil || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) != 1 {
				return errors.New("remote mTLS client identity is not verified")
			}
			leaf := state.VerifiedChains[0][0]
			if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
				!slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) ||
				len(leaf.UnknownExtKeyUsage) != 0 || leaf.Subject.String() != "" ||
				len(leaf.URIs) != 1 || leaf.URIs[0].String() != client.URI ||
				!slices.Equal(leaf.DNSNames, client.DNSNames) || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
				return errors.New("remote mTLS client does not match bound identity")
			}
			return nil
		},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello == nil {
				return nil, errors.New("missing TLS client hello")
			}
			return load(hello.Context())
		}}, nil
}

func validateRemoteServerCertificate(certificate tls.Certificate, roots *x509.CertPool, identity RemoteServerIdentity, now time.Time) error {
	if len(certificate.Certificate) < 2 || len(certificate.Certificate) > 9 || certificate.PrivateKey == nil {
		return errors.New("remote server chain or signer is missing")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		!slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) ||
		len(leaf.UnknownExtKeyUsage) != 0 || leaf.Subject.String() != "" ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity.URI ||
		!slices.Equal(leaf.DNSNames, identity.DNSNames) || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 ||
		!leaf.NotBefore.Before(leaf.NotAfter) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.NotAfter.Sub(leaf.NotBefore) > identity.MaxTTL {
		return errors.New("remote server leaf does not match bound identity")
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("remote server key is not a signer")
	}
	actualPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return errors.New("remote server signer public key is invalid")
	}
	expectedPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(actualPublic, expectedPublic) {
		return errors.New("remote server signer does not match certificate")
	}
	intermediates := x509.NewCertPool()
	parsed := []*x509.Certificate{leaf}
	for _, raw := range certificate.Certificate[1:] {
		chainCertificate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil || !chainCertificate.IsCA || now.Before(chainCertificate.NotBefore) || !now.Before(chainCertificate.NotAfter) {
			return errors.New("remote server chain is invalid")
		}
		intermediates.AddCert(chainCertificate)
		parsed = append(parsed, chainCertificate)
	}
	verified, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil || len(verified) != 1 || len(verified[0]) != len(parsed) {
		return errors.New("remote server issuer is not pinned")
	}
	for index := range parsed {
		if !bytes.Equal(verified[0][index].Raw, parsed[index].Raw) {
			return errors.New("remote server chain differs from verified chain")
		}
	}
	return nil
}
