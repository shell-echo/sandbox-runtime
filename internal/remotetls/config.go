// Package remotetls builds live TLS 1.3 configurations around a private
// remote signing capability. It contains no Product or Provider authority.
package remotetls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
)

type Identity struct {
	URI      string
	DNSNames []string
	Usages   []string
	MaxTTL   time.Duration
}

type CertificateSource func(context.Context) (tls.Certificate, error)

type ServerOptions struct {
	IssuerRoots *x509.CertPool
	ClientRoots *x509.CertPool
	Identity    Identity
	Client      *Identity
	Source      CertificateSource
	Now         func() time.Time
}

type ClientOptions struct {
	IssuerRoots *x509.CertPool
	ServerRoots *x509.CertPool
	ServerName  string
	Identity    Identity
	Server      Identity
	Source      CertificateSource
	Now         func() time.Time
}

func NewServer(options ServerOptions) (*tls.Config, error) {
	config, _, err := NewServerWithProbe(options)
	return config, err
}

// NewServerWithProbe exposes the same fresh certificate/issuer/signature
// check used by handshakes to a role's readiness monitor.
func NewServerWithProbe(options ServerOptions) (*tls.Config, func(context.Context) error, error) {
	if options.IssuerRoots == nil || options.Source == nil || options.Now == nil || options.Now().IsZero() ||
		validateIdentity(options.Identity) != nil || !slices.Contains(options.Identity.Usages, "server_auth") ||
		(options.Client == nil) != (options.ClientRoots == nil) {
		return nil, nil, errors.New("invalid live TLS server authority")
	}
	if options.Client != nil && (validateIdentity(*options.Client) != nil || !slices.Contains(options.Client.Usages, "client_auth")) {
		return nil, nil, errors.New("invalid live TLS client admission")
	}
	options.Identity = cloneIdentity(options.Identity)
	options.IssuerRoots = options.IssuerRoots.Clone()
	if options.Client != nil {
		client := cloneIdentity(*options.Client)
		options.Client = &client
		options.ClientRoots = options.ClientRoots.Clone()
	}
	load := certificateLoader(options.Source, options.IssuerRoots, options.Identity, options.Now)
	bootstrap, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := load(bootstrap); err != nil {
		return nil, nil, err
	}
	probe := func(ctx context.Context) error {
		_, err := load(ctx)
		return err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello == nil {
				return nil, errors.New("missing TLS client hello")
			}
			return load(hello.Context())
		}}
	if options.Client != nil {
		peer := *options.Client
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = options.ClientRoots
		config.VerifyConnection = func(state tls.ConnectionState) error { return verifyPeer(state, peer, options.Now()) }
	}
	return config, probe, nil
}

func NewClient(options ClientOptions) (*tls.Config, error) {
	if options.IssuerRoots == nil || options.ServerRoots == nil || options.Source == nil ||
		options.Now == nil || options.Now().IsZero() || validateIdentity(options.Identity) != nil ||
		validateIdentity(options.Server) != nil || !slices.Contains(options.Identity.Usages, "client_auth") ||
		!slices.Contains(options.Server.Usages, "server_auth") ||
		!slices.Contains(options.Server.DNSNames, options.ServerName) || options.ServerName == "" ||
		net.ParseIP(options.ServerName) != nil {
		return nil, errors.New("invalid live TLS client authority")
	}
	options.Identity = cloneIdentity(options.Identity)
	options.Server = cloneIdentity(options.Server)
	options.IssuerRoots = options.IssuerRoots.Clone()
	options.ServerRoots = options.ServerRoots.Clone()
	load := certificateLoader(options.Source, options.IssuerRoots, options.Identity, options.Now)
	bootstrap, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := load(bootstrap); err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: options.ServerRoots, ServerName: options.ServerName, ClientSessionCache: nil,
		VerifyConnection: func(state tls.ConnectionState) error { return verifyPeer(state, options.Server, options.Now()) },
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if info == nil {
				return nil, errors.New("missing TLS certificate request")
			}
			return load(info.Context())
		}}, nil
}

// NewClientCertificate validates a freshly obtained workload certificate at
// construction and again for every TLS certificate request. This is for
// external clients whose server identity is verified by a different, pinned
// protocol boundary; it does not export or persist a private key.
func NewClientCertificate(ctx context.Context, roots *x509.CertPool, identity Identity, source CertificateSource,
	now func() time.Time) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	if ctx == nil || ctx.Err() != nil || roots == nil || source == nil || now == nil || now().IsZero() ||
		validateIdentity(identity) != nil || !slices.Contains(identity.Usages, "client_auth") {
		return nil, errors.New("invalid live TLS client certificate authority")
	}
	load := certificateLoader(source, roots.Clone(), cloneIdentity(identity), now)
	bootstrap, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := load(bootstrap); err != nil {
		return nil, err
	}
	return func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if request == nil {
			return nil, errors.New("missing TLS certificate request")
		}
		return load(request.Context())
	}, nil
}

func certificateLoader(source CertificateSource, roots *x509.CertPool, identity Identity, now func() time.Time) func(context.Context) (*tls.Certificate, error) {
	return func(ctx context.Context) (*tls.Certificate, error) {
		if ctx == nil {
			return nil, errors.New("live TLS context is required")
		}
		if err := ctx.Err(); err != nil {
			return nil, errors.New("live TLS context ended")
		}
		certificate, err := source(ctx)
		if err != nil {
			return nil, errors.New("live TLS signer is unavailable")
		}
		if err := ctx.Err(); err != nil {
			return nil, errors.New("live TLS context ended")
		}
		if len(certificate.Certificate) < 2 || len(certificate.Certificate) > 9 {
			return nil, errors.New("live TLS chain length is invalid")
		}
		chain := make([][]byte, len(certificate.Certificate))
		for index := range certificate.Certificate {
			if len(certificate.Certificate[index]) < 1 || len(certificate.Certificate[index]) > 64<<10 {
				return nil, errors.New("live TLS certificate size is invalid")
			}
			chain[index] = bytes.Clone(certificate.Certificate[index])
		}
		certificate.Certificate = chain
		if err := validateLocal(certificate, roots, identity, now()); err != nil {
			return nil, err
		}
		certificate.Leaf, _ = x509.ParseCertificate(certificate.Certificate[0])
		return &certificate, nil
	}
}

func cloneIdentity(identity Identity) Identity {
	identity.DNSNames = slices.Clone(identity.DNSNames)
	identity.Usages = slices.Clone(identity.Usages)
	return identity
}

func validateIdentity(identity Identity) error {
	parsed, err := url.Parse(identity.URI)
	if err != nil || parsed == nil || parsed.Scheme != "spiffe" || parsed.Host == "" || parsed.Path == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != identity.URI ||
		identity.MaxTTL < time.Minute || identity.MaxTTL > time.Hour || len(identity.DNSNames) > 8 {
		return errors.New("invalid live TLS identity")
	}
	if _, err := requiredUsages(identity.Usages); err != nil {
		return err
	}
	previous := ""
	for _, name := range identity.DNSNames {
		if name <= previous || !validDNSName(name) {
			return errors.New("invalid live TLS DNS identity")
		}
		previous = name
	}
	return nil
}

func validDNSName(name string) bool {
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil || strings.ToLower(name) != name {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character < 'a' || character > 'z' {
				if character < '0' || character > '9' {
					if character != '-' {
						return false
					}
				}
			}
		}
	}
	return true
}

func requiredUsages(values []string) ([]x509.ExtKeyUsage, error) {
	if len(values) < 1 || len(values) > 2 || !slices.IsSorted(values) {
		return nil, errors.New("invalid live TLS usages")
	}
	result := make([]x509.ExtKeyUsage, 0, len(values))
	previous := ""
	for _, value := range values {
		if value == previous {
			return nil, errors.New("duplicate live TLS usage")
		}
		switch value {
		case "client_auth":
			result = append(result, x509.ExtKeyUsageClientAuth)
		case "server_auth":
			result = append(result, x509.ExtKeyUsageServerAuth)
		default:
			return nil, errors.New("invalid live TLS usage")
		}
		previous = value
	}
	return result, nil
}

func validateLeaf(leaf *x509.Certificate, identity Identity, now time.Time) error {
	usages, _ := requiredUsages(identity.Usages)
	if leaf == nil || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		!equalUsages(leaf.ExtKeyUsage, usages) || len(leaf.UnknownExtKeyUsage) != 0 || leaf.Subject.String() != "" ||
		len(leaf.URIs) != 1 || leaf.URIs[0] == nil || leaf.URIs[0].String() != identity.URI ||
		!slices.Equal(leaf.DNSNames, identity.DNSNames) || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 ||
		!leaf.NotBefore.Before(leaf.NotAfter) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.NotAfter.Sub(leaf.NotBefore) > identity.MaxTTL {
		return errors.New("live TLS leaf does not match bound identity")
	}
	return nil
}

func equalUsages(actual, expected []x509.ExtKeyUsage) bool {
	if len(actual) != len(expected) {
		return false
	}
	actual = slices.Clone(actual)
	expected = slices.Clone(expected)
	slices.Sort(actual)
	slices.Sort(expected)
	return slices.Equal(actual, expected)
}

func validateLocal(certificate tls.Certificate, roots *x509.CertPool, identity Identity, now time.Time) error {
	if len(certificate.Certificate) < 2 || len(certificate.Certificate) > 9 || certificate.PrivateKey == nil || now.IsZero() ||
		len(certificate.OCSPStaple) != 0 || len(certificate.SignedCertificateTimestamps) != 0 ||
		len(certificate.SupportedSignatureAlgorithms) != 0 {
		return errors.New("live TLS chain or signer is missing")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || (certificate.Leaf != nil && !bytes.Equal(certificate.Leaf.Raw, leaf.Raw)) ||
		validateLeaf(leaf, identity, now) != nil {
		return errors.New("live TLS leaf is invalid")
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("live TLS key is not a signer")
	}
	actualPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return errors.New("live TLS signer public key is invalid")
	}
	expectedPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(actualPublic, expectedPublic) {
		return errors.New("live TLS signer does not match certificate")
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return errors.New("live TLS signer key type is invalid")
	}
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return errors.New("live TLS signer challenge is unavailable")
	}
	signature, err := signer.Sign(rand.Reader, challenge[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(publicKey, challenge[:], signature) {
		return errors.New("live TLS signer challenge failed")
	}
	intermediates := x509.NewCertPool()
	parsed := []*x509.Certificate{leaf}
	for _, raw := range certificate.Certificate[1:] {
		chainCertificate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil || !chainCertificate.IsCA || now.Before(chainCertificate.NotBefore) || !now.Before(chainCertificate.NotAfter) {
			return errors.New("live TLS chain is invalid")
		}
		intermediates.AddCert(chainCertificate)
		parsed = append(parsed, chainCertificate)
	}
	usages, _ := requiredUsages(identity.Usages)
	verified, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		CurrentTime: now, KeyUsages: usages})
	if err != nil || len(verified) != 1 || len(verified[0]) != len(parsed) {
		return errors.New("live TLS issuer is not pinned")
	}
	for index := range parsed {
		if !bytes.Equal(verified[0][index].Raw, parsed[index].Raw) {
			return errors.New("live TLS chain differs from verified chain")
		}
	}
	return nil
}

func verifyPeer(state tls.ConnectionState, identity Identity, now time.Time) error {
	if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) < 1 ||
		len(state.VerifiedChains) != 1 || len(state.VerifiedChains[0]) < 2 ||
		validateLeaf(state.VerifiedChains[0][0], identity, now) != nil {
		return errors.New("live TLS peer identity is not verified")
	}
	return nil
}
